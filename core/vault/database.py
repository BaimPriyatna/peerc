"""core/vault/database.py — Phase 39.2: encrypted database lifecycle.

See docs/SECURE_STORAGE_DESIGN.md §5, §12, §17. The database itself is
ordinary SQLite — encryption is applied to the *whole file* at rest, not
per-column (§5 explicitly rejects field-level encryption as redundant
complexity for no benefit once the whole file is already ciphertext).

Lifecycle, in one sentence: decrypt the vault file into a plaintext
working copy on unlock, work against that copy with normal sqlite3,
periodically (and always on lock) re-encrypt it back over the vault file,
then destroy the working copy.

Where the plaintext working copy lives matters:
  - Linux: /dev/shm (tmpfs, RAM-backed) when available — a crash or power
    loss leaves nothing on disk to recover.
  - Windows/macOS (no reliable tmpfs equivalent from Python without a new
    dependency): falls back to the OS temp directory. This is a real,
    documented gap versus the Linux path (§17) — the working copy sits on
    disk, if briefly. Best-effort mitigation: overwrite-then-delete on
    lock() rather than a plain unlink.
  - `force_fallback=True` lets tests exercise the fallback path on Linux
    without needing actual Windows/macOS hardware.
"""

import asyncio
import os
import secrets
import sqlite3
import tempfile
import time
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_VAULT_DB_PATH = os.path.expanduser("~/.peerc/vault.db")
RAM_BACKED_DIR = "/dev/shm"

DB_KEY_LEN = 32
NONCE_LEN = 12
DEFAULT_FLUSH_INTERVAL = 30.0  # seconds (§17)

# Unified schema (§12): Phase 4's trusted_devices (+ Phase 40's
# identity_transitions, added after this design doc was first written)
# plus Phase 27's messages/transfers/settings, plus Phase 42's
# groups/group_memberships/group_policies/group_admins (per the Phase 42.1 discuss-before-build
# decision: group data lives in this same encrypted file too, not a
# separate DB — the vault is always unlocked before this code runs).
SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id     TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    name          TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    status        TEXT NOT NULL,
    revoked_by    TEXT,
    revoked_at    REAL,
    revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS identity_transitions (
    old_device_id  TEXT NOT NULL,
    new_device_id  TEXT NOT NULL,
    old_public_key TEXT NOT NULL,
    new_public_key TEXT NOT NULL,
    timestamp      REAL NOT NULL,
    signature      TEXT NOT NULL,
    recorded_at    REAL NOT NULL,
    PRIMARY KEY (old_device_id, new_device_id)
);
CREATE TABLE IF NOT EXISTS messages (
    message_id      TEXT PRIMARY KEY,
    peer_device_id  TEXT NOT NULL,
    direction       TEXT NOT NULL,
    text            TEXT NOT NULL,
    timestamp       REAL NOT NULL,
    status          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers (
    transfer_id     TEXT PRIMARY KEY,
    peer_device_id  TEXT NOT NULL,
    direction       TEXT NOT NULL,
    filename        TEXT NOT NULL,
    size            INTEGER NOT NULL,
    checksum        TEXT NOT NULL,
    storage_mode    TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    status          TEXT NOT NULL,
    timestamp       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
    group_id         TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    admin_device_id  TEXT NOT NULL,
    admin_public_key TEXT NOT NULL,
    created_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS group_memberships (
    group_id          TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    role              TEXT NOT NULL,
    permissions       TEXT NOT NULL,
    issued_at         REAL NOT NULL,
    expires_at        REAL,
    admin_device_id   TEXT NOT NULL,
    signature         TEXT NOT NULL,
    status            TEXT NOT NULL,
    revoked_by        TEXT,
    revoked_at        REAL,
    revoke_reason     TEXT,
    PRIMARY KEY (group_id, device_id)
);
CREATE TABLE IF NOT EXISTS group_policies (
    group_id                      TEXT PRIMARY KEY,
    allow_external_trust          INTEGER NOT NULL DEFAULT 1,
    allow_export                  INTEGER NOT NULL DEFAULT 1,
    leave_requires_admin          INTEGER NOT NULL DEFAULT 0,
    allow_inter_group             INTEGER NOT NULL DEFAULT 1,
    communication_matrix          TEXT NOT NULL DEFAULT '[]',
    default_communication_effect  TEXT NOT NULL DEFAULT 'allow',
    version                       INTEGER NOT NULL DEFAULT 1,
    updated_at                    REAL NOT NULL,
    admin_device_id               TEXT,
    signature                     TEXT
);
CREATE TABLE IF NOT EXISTS group_admins (
    group_id    TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    added_at    REAL NOT NULL,
    added_by    TEXT,
    status      TEXT NOT NULL,
    removed_at  REAL,
    removed_by  TEXT,
    PRIMARY KEY (group_id, device_id)
);
"""


class VaultDatabaseError(Exception):
    """Base class for vault database lifecycle errors."""


class VaultCorruptError(VaultDatabaseError):
    """Raised when the on-disk vault file can't be decrypted with the
    given DEK — either a wrong DEK, or the file is corrupted/tampered."""


def _derive_db_key(dek: bytes) -> bytes:
    """HKDF(DEK, info=domain-separation label) -> a key used only for
    encrypting this one file. Keeping it distinct from the raw DEK means
    a future per-purpose key (e.g. Phase 39.5's secure file storage) can
    derive its own subkey the same way without ever reusing key material
    across purposes."""
    return HKDF(
        algorithm=hashes.SHA256(), length=DB_KEY_LEN, salt=None,
        info=b"peerc-vault-database-v1",
    ).derive(dek)


def _pick_working_dir(force_fallback: bool = False) -> tuple[str, bool]:
    """Returns (directory, is_ram_backed)."""
    if not force_fallback and os.path.isdir(RAM_BACKED_DIR) and os.access(RAM_BACKED_DIR, os.W_OK):
        return RAM_BACKED_DIR, True
    return tempfile.gettempdir(), False


def _secure_delete(path: str) -> None:
    """Best-effort overwrite-then-unlink. On tmpfs this is unnecessary
    (nothing ever hit a disk platter) but harmless; on the non-Linux
    fallback path it's the only mitigation available for a working copy
    that briefly existed on real disk (§17)."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


class VaultDatabase:
    """An unlocked vault: a live sqlite3.Connection backed by a plaintext
    working copy, plus everything needed to re-encrypt it back to
    `vault_db_path` on flush()/lock()."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        working_path: str,
        vault_db_path: str,
        db_key: bytes,
        is_ram_backed: bool,
    ):
        self.conn = conn
        self.working_path = working_path
        self.vault_db_path = vault_db_path
        self._db_key = db_key
        self.is_ram_backed = is_ram_backed
        self._auto_flush_task: Optional[asyncio.Task] = None

    @classmethod
    def unlock(
        cls,
        dek: bytes,
        vault_db_path: str = DEFAULT_VAULT_DB_PATH,
        force_fallback: bool = False,
    ) -> "VaultDatabase":
        db_key = _derive_db_key(dek)
        working_dir, is_ram_backed = _pick_working_dir(force_fallback)
        os.makedirs(working_dir, exist_ok=True)
        working_path = os.path.join(working_dir, f"peerc-vault-{secrets.token_hex(8)}.db")

        if os.path.exists(vault_db_path):
            with open(vault_db_path, "rb") as f:
                blob = f.read()
            nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
            try:
                plaintext = AESGCM(db_key).decrypt(nonce, ciphertext, None)
            except InvalidTag as e:
                raise VaultCorruptError(
                    f"could not decrypt {vault_db_path} — wrong DEK, or the file is corrupted"
                ) from e
            with open(working_path, "wb") as f:
                f.write(plaintext)
        # else: first run — sqlite3.connect() below creates a fresh empty
        # file at working_path, and the CREATE TABLE IF NOT EXISTS schema
        # populates it.

        conn = sqlite3.connect(working_path)
        conn.executescript(SCHEMA)
        conn.commit()

        return cls(conn, working_path, vault_db_path, db_key, is_ram_backed)

    def flush(self) -> None:
        """Re-encrypt the current working copy back over vault_db_path.
        Write-temp-then-atomic-rename (same crash-safety pattern used
        throughout this design) so a crash mid-flush never corrupts the
        last-known-good vault file."""
        self.conn.commit()
        with open(self.working_path, "rb") as f:
            plaintext = f.read()
        nonce = secrets.token_bytes(NONCE_LEN)  # fresh nonce every flush (§16)
        ciphertext = AESGCM(self._db_key).encrypt(nonce, plaintext, None)

        directory = os.path.dirname(self.vault_db_path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = self.vault_db_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(nonce + ciphertext)
        os.replace(tmp_path, self.vault_db_path)

    async def start_auto_flush(self, interval: float = DEFAULT_FLUSH_INTERVAL) -> None:
        """Periodic flush (§17) so an unclean shutdown loses at most
        `interval` seconds of writes, not everything since unlock."""
        if self._auto_flush_task is not None:
            return
        self._auto_flush_task = asyncio.create_task(self._auto_flush_loop(interval))

    async def _auto_flush_loop(self, interval: float) -> None:
        try:
            while True:
                await asyncio.sleep(interval)
                self.flush()
        except asyncio.CancelledError:
            pass

    def lock(self) -> None:
        """Flush one last time, close the connection, and destroy the
        plaintext working copy. After this, the VaultDatabase instance
        must not be used again."""
        if self._auto_flush_task is not None:
            self._auto_flush_task.cancel()
            self._auto_flush_task = None
        self.flush()
        self.conn.close()
        _secure_delete(self.working_path)
