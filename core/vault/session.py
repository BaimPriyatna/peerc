"""core/vault/session.py — Phase 39.3: session / auto-lock model.

Implements SECURE_STORAGE_DESIGN.md §4 (and the §11.4 default):

  - Text chat is session-based (WhatsApp-like): once unlocked, reading
    and sending text needs no further prompts.
  - Auto-lock after 5 minutes idle by default (sudo's own
    timestamp_timeout — the analogy this model is built on),
    user-configurable via the vault `settings` table.
  - File actions (Open / Export / Move-to-Secure / Delete) re-prompt
    every time by default; "don't ask again this session" opts into
    reusing the unlocked session for those actions until the next lock.
  - Incoming Transfer is the one file-adjacent exception: accept/reject
    needs no key unless the user turns that on.

Lock here is a *hard* lock: the DEK is wiped from memory and the vault
database working copy is flushed + destroyed (VaultDatabase.lock()).
Re-unlock rebuilds a fresh VaultDatabase; callers (UI) rewire
TrustStore / VaultPersistence onto the new connection.

Critical-action key for Export (AND-gate HKDF) is Phase 39.4 — not here.
Actual Open/Export/Delete UI gates land with file actions in 39.5; this
module just exposes the authorization decisions those gates will call.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from .database import VaultDatabase
from .keyfile import VaultKeyfile, unlock_with_passphrase
from .crypto import WrongSecretError

# sudo's well-known default timestamp_timeout (§11.4 / §4).
DEFAULT_AUTO_LOCK_SECONDS = 300.0

SETTING_AUTO_LOCK_SECONDS = "auto_lock_timeout_seconds"
SETTING_REQUIRE_PASSPHRASE_INCOMING = "require_passphrase_for_incoming"

# File actions that re-prompt by default (§4). Incoming Transfer is
# deliberately not in this set.
FILE_ACTIONS_REQUIRING_AUTH = frozenset({
    "open",
    "export",
    "move_to_secure",
    "delete",
})


class SessionLockedError(Exception):
    """Raised when an operation needs an unlocked session and it isn't."""


class VaultSession:
    """In-memory unlock state, idle timer, and file-action re-auth policy.

    Owns the live VaultDatabase while unlocked. After lock(), `vault_db`
    is None and the previous instance must not be used.
    """

    def __init__(
        self,
        auto_lock_seconds: float = DEFAULT_AUTO_LOCK_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if auto_lock_seconds < 0:
            raise ValueError("auto_lock_seconds must be >= 0 (0 = never auto-lock)")
        self._monotonic = monotonic
        self.auto_lock_seconds = float(auto_lock_seconds)
        self.require_passphrase_for_incoming = False

        self._dek: Optional[bytearray] = None
        self.vault_db: Optional[VaultDatabase] = None
        self._last_activity: float = 0.0
        self._dont_ask_again_files: bool = False

    # ---- state --------------------------------------------------------

    @property
    def is_unlocked(self) -> bool:
        return self._dek is not None and self.vault_db is not None

    @property
    def dont_ask_again_files(self) -> bool:
        return self._dont_ask_again_files

    def dek_bytes(self) -> bytes:
        """Copy of the live DEK. Raises SessionLockedError if locked."""
        if self._dek is None:
            raise SessionLockedError("vault session is locked")
        return bytes(self._dek)

    # ---- unlock / lock / activity ------------------------------------

    def unlock(self, dek: bytes, vault_db: VaultDatabase) -> None:
        """Mark the session unlocked with this DEK + live database.

        Loads persisted auto-lock / incoming-auth settings from the vault
        `settings` table (creating defaults on first run).
        """
        if len(dek) != 32:
            raise ValueError("DEK must be 32 bytes")
        self._wipe_dek()
        self._dek = bytearray(dek)
        self.vault_db = vault_db
        self._dont_ask_again_files = False
        self._load_settings()
        self.touch()

    def touch(self) -> None:
        """Reset the idle timer. No-op while locked."""
        if self.is_unlocked:
            self._last_activity = self._monotonic()

    def lock(self) -> None:
        """Hard-lock: wipe DEK, flush+destroy the vault working copy,
        clear the per-session "don't ask again" flag."""
        vault_db = self.vault_db
        self.vault_db = None
        self._dont_ask_again_files = False
        self._wipe_dek()
        if vault_db is not None:
            vault_db.lock()

    def idle_expired(self) -> bool:
        """True when unlocked, auto-lock is enabled, and idle past timeout."""
        if not self.is_unlocked:
            return False
        if self.auto_lock_seconds == 0:
            return False  # 0 = never auto-lock
        return (self._monotonic() - self._last_activity) >= self.auto_lock_seconds

    def seconds_until_lock(self) -> Optional[float]:
        """Seconds remaining before auto-lock, or None if locked / disabled."""
        if not self.is_unlocked or self.auto_lock_seconds == 0:
            return None
        remaining = self.auto_lock_seconds - (self._monotonic() - self._last_activity)
        return max(0.0, remaining)

    def check_and_auto_lock(self) -> bool:
        """If idle has expired, lock and return True; else False."""
        if self.idle_expired():
            self.lock()
            return True
        return False

    # ---- file-action authorization (§4) ------------------------------

    def set_dont_ask_again_files(self, enabled: bool) -> None:
        """Per-session toggle. Cleared automatically on the next lock().
        Enabling while locked is a no-op (nothing to reuse yet)."""
        if enabled and not self.is_unlocked:
            return
        self._dont_ask_again_files = bool(enabled)

    def requires_reauth(self, action: str) -> bool:
        """Whether `action` needs a fresh passphrase prompt right now.

        - chat: never (session covers it while unlocked; caller must
          unlock first if locked).
        - incoming_transfer: only if require_passphrase_for_incoming.
        - open / export / move_to_secure / delete: yes, unless the
          per-session "don't ask again" flag is on *and* we're unlocked.
        """
        action = action.lower().strip()
        if action == "chat":
            return False
        if action == "incoming_transfer":
            return bool(self.require_passphrase_for_incoming)
        if action in FILE_ACTIONS_REQUIRING_AUTH:
            if self._dont_ask_again_files and self.is_unlocked:
                return False
            return True
        # Unknown action: fail closed.
        return True

    def verify_passphrase(self, keyfile: VaultKeyfile, passphrase: str) -> bool:
        """True iff passphrase unwraps to this session's live DEK.

        Used for step-up re-auth on file actions without locking the
        vault. Returns False (does not raise) on a wrong passphrase.
        Raises SessionLockedError if there is no live DEK to compare.
        """
        if self._dek is None:
            raise SessionLockedError("vault session is locked")
        candidate: Optional[bytearray] = None
        try:
            unwrapped = unlock_with_passphrase(keyfile, passphrase)
            candidate = bytearray(unwrapped)
            return secrets_equal(bytes(candidate), bytes(self._dek))
        except WrongSecretError:
            return False
        finally:
            if candidate is not None:
                for i in range(len(candidate)):
                    candidate[i] = 0

    # ---- settings (persisted in vault `settings` table) --------------

    def set_auto_lock_seconds(self, seconds: float) -> None:
        """Update the in-memory timeout and persist it. 0 = never."""
        if seconds < 0:
            raise ValueError("auto_lock_seconds must be >= 0")
        self.auto_lock_seconds = float(seconds)
        self._save_setting(SETTING_AUTO_LOCK_SECONDS, self.auto_lock_seconds)
        self.touch()  # changing the timeout shouldn't instantly lock

    def set_require_passphrase_for_incoming(self, required: bool) -> None:
        self.require_passphrase_for_incoming = bool(required)
        self._save_setting(
            SETTING_REQUIRE_PASSPHRASE_INCOMING,
            self.require_passphrase_for_incoming,
        )

    def _load_settings(self) -> None:
        assert self.vault_db is not None
        raw_timeout = self._read_setting(SETTING_AUTO_LOCK_SECONDS)
        if raw_timeout is not None:
            try:
                value = float(raw_timeout)
                if value >= 0:
                    self.auto_lock_seconds = value
            except (TypeError, ValueError):
                pass
        else:
            # First unlock of a fresh vault — write the default so the
            # setting is visible/editable without a separate seed step.
            self._save_setting(SETTING_AUTO_LOCK_SECONDS, self.auto_lock_seconds)

        raw_incoming = self._read_setting(SETTING_REQUIRE_PASSPHRASE_INCOMING)
        if raw_incoming is not None:
            self.require_passphrase_for_incoming = bool(raw_incoming)
        else:
            self._save_setting(
                SETTING_REQUIRE_PASSPHRASE_INCOMING,
                self.require_passphrase_for_incoming,
            )

    def _read_setting(self, key: str):
        if self.vault_db is None:
            return None
        row = self.vault_db.conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return None

    def _save_setting(self, key: str, value) -> None:
        if self.vault_db is None:
            return
        self.vault_db.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, json.dumps(value)),
        )
        self.vault_db.conn.commit()

    # ---- internals ----------------------------------------------------

    def _wipe_dek(self) -> None:
        if self._dek is not None:
            for i in range(len(self._dek)):
                self._dek[i] = 0
            self._dek = None


def secrets_equal(a: bytes, b: bytes) -> bool:
    """Constant-time equality for DEK comparison on step-up re-auth."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
