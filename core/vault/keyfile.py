"""core/vault/keyfile.py — Phase 39.1's vault_keyfile.json (§13).

Not secret by itself (same idea as a LUKS header) — safe to back up
alongside the encrypted database (Phase 39.2). Holds two independently
wrapped copies of the DEK (one under the passphrase, one under the
recovery code) plus everything needed to re-derive their KEKs.

This module only implements the vault *keyfile* — creating/loading it,
wrapping/unwrapping the DEK via a passphrase or recovery code, and
changing the passphrase. It deliberately does NOT implement (later
Phase 39 sub-steps):
  - the encrypted database lifecycle (39.2)
  - the session/auto-lock model (39.3) — implemented in session.py;
    this module only notes it so the keyfile stays focused on wraps
  - the critical-action key for Export (39.4) — its keyfile fields
    exist below per §13's documented format, but stay `None` until
    39.4 wires up the actual set/use flow.
  - file actions / magic-byte detection (39.5)
"""

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from .crypto import (
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    derive_kek,
    new_dek,
    new_salt,
    unwrap_dek,
    wrap_dek,
)
from .recovery_code import generate_recovery_code, normalize_recovery_code

VAULT_SCHEMA_VERSION = 1
# Same convention as core/identity/identity_file.py's DEFAULT_IDENTITY_DIR
# (os.path.expanduser("~/.peerc")) — deliberately not platformdirs/XDG,
# just a fixed dotfolder under the home dir. os.path.expanduser resolves
# correctly on Windows (via USERPROFILE) and macOS too, so this is
# portable without adding a new dependency.
DEFAULT_VAULT_DIR = os.path.expanduser("~/.peerc")
DEFAULT_VAULT_KEYFILE = os.path.join(DEFAULT_VAULT_DIR, "vault_keyfile.json")

MIN_PASSPHRASE_LEN = 8


class VaultError(Exception):
    """Base class for vault keyfile errors."""


class WeakPassphraseError(VaultError):
    """Raised by validate_passphrase() — see §14 for the (deliberately
    short) list of hard rejections; no forced complexity rules."""


class VaultExistsError(VaultError):
    """Raised by create_vault() if a keyfile already exists at that path
    — creating a vault is a one-time first-setup action, never silently
    overwritten by a second call."""


def validate_passphrase(passphrase: str, device_name: Optional[str] = None) -> None:
    """§14: length-only floor (current NIST 800-63B guidance — forced
    complexity rules push people toward predictable patterns like
    "Passw0rd!" more than toward real strength, while length is the
    dominant factor in actual brute-force resistance). The only hard
    rejections: empty, under 8 characters, or exactly the device's own
    display name (an easy, worth-catching mistake, not a meaningful
    security control by itself)."""
    if not passphrase:
        raise WeakPassphraseError("passphrase cannot be empty")
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise WeakPassphraseError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
    if device_name is not None and passphrase == device_name:
        raise WeakPassphraseError("passphrase must not be the same as the device's display name")


@dataclass
class VaultKeyfile:
    version: int
    kdf: str
    kdf_params: dict
    passphrase_salt: bytes
    wrapped_dek_passphrase: bytes
    wrapped_dek_passphrase_nonce: bytes
    recovery_salt: bytes
    wrapped_dek_recovery: bytes
    wrapped_dek_recovery_nonce: bytes
    created_at: float
    # §13: null until Phase 39.4 wires up the critical-action key.
    critical_key_salt: Optional[bytes] = None
    critical_key_verifier_salt: Optional[bytes] = None

    def to_json_dict(self) -> dict:
        def b64(b: Optional[bytes]) -> Optional[str]:
            return None if b is None else base64.b64encode(b).decode("ascii")

        return {
            "version": self.version,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "passphrase_salt": b64(self.passphrase_salt),
            "wrapped_dek_passphrase": b64(self.wrapped_dek_passphrase),
            "wrapped_dek_passphrase_nonce": b64(self.wrapped_dek_passphrase_nonce),
            "recovery_salt": b64(self.recovery_salt),
            "wrapped_dek_recovery": b64(self.wrapped_dek_recovery),
            "wrapped_dek_recovery_nonce": b64(self.wrapped_dek_recovery_nonce),
            "critical_key_salt": b64(self.critical_key_salt),
            "critical_key_verifier_salt": b64(self.critical_key_verifier_salt),
            "created_at": self.created_at,
        }

    @staticmethod
    def from_json_dict(d: dict) -> "VaultKeyfile":
        def unb64(s: Optional[str]) -> Optional[bytes]:
            return None if s is None else base64.b64decode(s)

        return VaultKeyfile(
            version=d["version"],
            kdf=d["kdf"],
            kdf_params=d["kdf_params"],
            passphrase_salt=unb64(d["passphrase_salt"]),
            wrapped_dek_passphrase=unb64(d["wrapped_dek_passphrase"]),
            wrapped_dek_passphrase_nonce=unb64(d["wrapped_dek_passphrase_nonce"]),
            recovery_salt=unb64(d["recovery_salt"]),
            wrapped_dek_recovery=unb64(d["wrapped_dek_recovery"]),
            wrapped_dek_recovery_nonce=unb64(d["wrapped_dek_recovery_nonce"]),
            critical_key_salt=unb64(d.get("critical_key_salt")),
            critical_key_verifier_salt=unb64(d.get("critical_key_verifier_salt")),
            created_at=d["created_at"],
        )


def vault_exists(path: str = DEFAULT_VAULT_KEYFILE) -> bool:
    return os.path.exists(path)


def save_vault_keyfile(keyfile: VaultKeyfile, path: str = DEFAULT_VAULT_KEYFILE) -> None:
    """Write-temp-then-atomic-rename (same crash-safety pattern used
    elsewhere in this design, §17) — a crash mid-write must never leave
    a half-written, corrupt keyfile."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(keyfile.to_json_dict(), f, indent=2)
    os.replace(tmp_path, path)


def load_vault_keyfile(path: str = DEFAULT_VAULT_KEYFILE) -> VaultKeyfile:
    with open(path, "r") as f:
        return VaultKeyfile.from_json_dict(json.load(f))


def create_vault(
    passphrase: str,
    device_name: Optional[str] = None,
    path: str = DEFAULT_VAULT_KEYFILE,
) -> tuple[VaultKeyfile, str]:
    """First-time setup (§2, §3). Returns (keyfile, recovery_code).

    The recovery code is returned exactly once, here, and is NEVER
    stored by this module in any recoverable form — the caller is
    responsible for showing it to the user with an explicit "write this
    down, we cannot show it again" prompt (§3) and then discarding it.

    Raises VaultExistsError if a keyfile is already at `path` — this is
    a one-time action, not something to silently redo and orphan the
    previous DEK.
    """
    if vault_exists(path):
        raise VaultExistsError(f"a vault keyfile already exists at {path}")
    validate_passphrase(passphrase, device_name)

    dek = new_dek()
    recovery_code = generate_recovery_code()
    recovery_raw = normalize_recovery_code(recovery_code)

    passphrase_salt = new_salt()
    passphrase_kek = derive_kek(passphrase.encode("utf-8"), passphrase_salt)
    wrapped_dek_passphrase, wrapped_dek_passphrase_nonce = wrap_dek(passphrase_kek, dek)

    recovery_salt = new_salt()
    recovery_kek = derive_kek(recovery_raw, recovery_salt)
    wrapped_dek_recovery, wrapped_dek_recovery_nonce = wrap_dek(recovery_kek, dek)

    keyfile = VaultKeyfile(
        version=VAULT_SCHEMA_VERSION,
        kdf="scrypt",
        kdf_params={"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        passphrase_salt=passphrase_salt,
        wrapped_dek_passphrase=wrapped_dek_passphrase,
        wrapped_dek_passphrase_nonce=wrapped_dek_passphrase_nonce,
        recovery_salt=recovery_salt,
        wrapped_dek_recovery=wrapped_dek_recovery,
        wrapped_dek_recovery_nonce=wrapped_dek_recovery_nonce,
        created_at=time.time(),
    )
    save_vault_keyfile(keyfile, path)
    return keyfile, recovery_code


def unlock_with_passphrase(keyfile: VaultKeyfile, passphrase: str) -> bytes:
    """Unwrap and return the DEK. Raises crypto.WrongSecretError (via
    AES-GCM's own auth tag — §13, no separate verifier hash stored) if
    the passphrase is wrong."""
    kek = derive_kek(passphrase.encode("utf-8"), keyfile.passphrase_salt)
    return unwrap_dek(kek, keyfile.wrapped_dek_passphrase, keyfile.wrapped_dek_passphrase_nonce)


def unlock_with_recovery_code(keyfile: VaultKeyfile, recovery_code: str) -> bytes:
    """Unwrap and return the DEK using the recovery code instead of the
    passphrase. normalize_recovery_code() raises RecoveryCodeError first
    for a mistyped code, before this ever reaches the (slow) KDF step."""
    raw = normalize_recovery_code(recovery_code)
    kek = derive_kek(raw, keyfile.recovery_salt)
    return unwrap_dek(kek, keyfile.wrapped_dek_recovery, keyfile.wrapped_dek_recovery_nonce)


def change_passphrase(
    keyfile: VaultKeyfile,
    old_passphrase: str,
    new_passphrase: str,
    device_name: Optional[str] = None,
) -> VaultKeyfile:
    """§2: re-wrap the DEK under a new KEK. Nothing already encrypted
    (the database, secure files — Phase 39.2/39.5) needs to be touched;
    this only replaces the passphrase-wrapped copy of the DEK. Returns
    the updated VaultKeyfile — the caller is responsible for persisting
    it via save_vault_keyfile(). Raises WrongSecretError if
    old_passphrase doesn't unlock the current keyfile, or
    WeakPassphraseError if new_passphrase fails validation — either way
    the keyfile passed in is left unmodified."""
    validate_passphrase(new_passphrase, device_name)
    dek = unlock_with_passphrase(keyfile, old_passphrase)

    new_passphrase_salt = new_salt()
    new_kek = derive_kek(new_passphrase.encode("utf-8"), new_passphrase_salt)
    new_wrapped, new_nonce = wrap_dek(new_kek, dek)

    keyfile.passphrase_salt = new_passphrase_salt
    keyfile.wrapped_dek_passphrase = new_wrapped
    keyfile.wrapped_dek_passphrase_nonce = new_nonce
    return keyfile
