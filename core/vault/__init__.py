"""core/vault/ — Phase 39: Secure Storage envelope encryption.

39.1: DEK/KEK envelope encryption, vault_keyfile.json, recovery code
      generation/validation. See docs/SECURE_STORAGE_DESIGN.md
      (§2 envelope encryption, §3 recovery code, §13 keyfile format,
      §14 passphrase requirements, §15 recovery code format,
      §16 nonce management).
39.2: Encrypted database lifecycle + chat/transfer persistence wiring.
39.3: Session / auto-lock model (idle timeout, hard lock, file-action
      re-auth policy, settings). See §4 / §11.4.

Not yet implemented here (later Phase 39 sub-steps):
  - the critical-action key for Export, AND-gate HKDF combining (39.4)
  - file actions: Open/Export/Move-to-Secure/Delete, magic-byte
    executable detection (39.5)
"""

from .crypto import VaultCryptoError, WrongSecretError
from .database import (
    DEFAULT_VAULT_DB_PATH,
    VaultCorruptError,
    VaultDatabase,
    VaultDatabaseError,
)
from .keyfile import (
    DEFAULT_VAULT_DIR,
    DEFAULT_VAULT_KEYFILE,
    MIN_PASSPHRASE_LEN,
    VaultError,
    VaultExistsError,
    VaultKeyfile,
    WeakPassphraseError,
    change_passphrase,
    create_vault,
    load_vault_keyfile,
    save_vault_keyfile,
    unlock_with_passphrase,
    unlock_with_recovery_code,
    validate_passphrase,
    vault_exists,
)
from .migration import migrate_plaintext_trust_db
from .persistence import VaultPersistence
from .recovery_code import RecoveryCodeError, generate_recovery_code, normalize_recovery_code
from .session import (
    DEFAULT_AUTO_LOCK_SECONDS,
    FILE_ACTIONS_REQUIRING_AUTH,
    SETTING_AUTO_LOCK_SECONDS,
    SETTING_REQUIRE_PASSPHRASE_INCOMING,
    SessionLockedError,
    VaultSession,
)

__all__ = [
    "VaultCryptoError",
    "WrongSecretError",
    "VaultDatabase",
    "VaultDatabaseError",
    "VaultCorruptError",
    "DEFAULT_VAULT_DB_PATH",
    "migrate_plaintext_trust_db",
    "VaultPersistence",
    "VaultSession",
    "SessionLockedError",
    "DEFAULT_AUTO_LOCK_SECONDS",
    "FILE_ACTIONS_REQUIRING_AUTH",
    "SETTING_AUTO_LOCK_SECONDS",
    "SETTING_REQUIRE_PASSPHRASE_INCOMING",
    "VaultError",
    "VaultExistsError",
    "VaultKeyfile",
    "WeakPassphraseError",
    "change_passphrase",
    "create_vault",
    "load_vault_keyfile",
    "save_vault_keyfile",
    "unlock_with_passphrase",
    "unlock_with_recovery_code",
    "validate_passphrase",
    "vault_exists",
    "DEFAULT_VAULT_DIR",
    "DEFAULT_VAULT_KEYFILE",
    "MIN_PASSPHRASE_LEN",
    "RecoveryCodeError",
    "generate_recovery_code",
    "normalize_recovery_code",
]
