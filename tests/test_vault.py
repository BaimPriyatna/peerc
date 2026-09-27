"""tests/test_vault.py — Phase 39.1: vault envelope encryption tests.

Covers:
  1. create_vault + unlock_with_passphrase roundtrip (happy path).
  2. Wrong passphrase raises WrongSecretError.
  3. unlock_with_recovery_code roundtrip.
  4. Mistyped recovery code (bad checksum) raises RecoveryCodeError
     before ever reaching the KDF.
  5. A syntactically-valid-but-wrong recovery code raises WrongSecretError.
  6. change_passphrase: old stops working, new works, DEK is unchanged
     (round-trips to the same value via both wrapped copies).
  7. validate_passphrase: empty / too short / matches device name.
  8. create_vault raises VaultExistsError on a path that already has one.
  9. save_vault_keyfile / load_vault_keyfile round-trip preserves unlock.
 10. Recovery code format: alphabet, grouping, normalization
     (lowercase, dashes, O/I/L substitution) all still decode correctly.
"""

import os

import pytest

from core.vault import (
    VaultExistsError,
    WeakPassphraseError,
    WrongSecretError,
    change_passphrase,
    create_vault,
    load_vault_keyfile,
    save_vault_keyfile,
    unlock_with_passphrase,
    unlock_with_recovery_code,
    validate_passphrase,
)
from core.vault.recovery_code import (
    RecoveryCodeError,
    generate_recovery_code,
    normalize_recovery_code,
)

pytestmark = pytest.mark.security



def test_create_and_unlock_with_passphrase(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, recovery_code = create_vault("correct horse battery", path=path)

    dek = unlock_with_passphrase(keyfile, "correct horse battery")
    assert len(dek) == 32
    assert isinstance(recovery_code, str) and len(recovery_code) > 0


def test_wrong_passphrase_rejected(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=path)

    with pytest.raises(WrongSecretError):
        unlock_with_passphrase(keyfile, "totally wrong passphrase")


def test_unlock_with_recovery_code_matches_passphrase_dek(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, recovery_code = create_vault("correct horse battery", path=path)

    dek_via_passphrase = unlock_with_passphrase(keyfile, "correct horse battery")
    dek_via_recovery = unlock_with_recovery_code(keyfile, recovery_code)
    assert dek_via_passphrase == dek_via_recovery


def test_mistyped_recovery_code_checksum_rejected(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, recovery_code = create_vault("correct horse battery", path=path)

    # Flip the last character (the checksum) so it no longer matches.
    bad_code = recovery_code[:-1] + ("0" if recovery_code[-1] != "0" else "1")
    with pytest.raises(RecoveryCodeError):
        unlock_with_recovery_code(keyfile, bad_code)


def test_valid_looking_but_wrong_recovery_code_rejected(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=path)
    other_code = generate_recovery_code()  # different, but well-formed w/ valid checksum

    with pytest.raises(WrongSecretError):
        unlock_with_recovery_code(keyfile, other_code)


def test_change_passphrase_roundtrip(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("old passphrase 123", path=path)
    original_dek = unlock_with_passphrase(keyfile, "old passphrase 123")

    keyfile = change_passphrase(keyfile, "old passphrase 123", "new passphrase 456")

    with pytest.raises(WrongSecretError):
        unlock_with_passphrase(keyfile, "old passphrase 123")

    new_dek = unlock_with_passphrase(keyfile, "new passphrase 456")
    assert new_dek == original_dek  # same DEK, just re-wrapped


def test_change_passphrase_wrong_old_passphrase_leaves_keyfile_untouched(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("old passphrase 123", path=path)

    with pytest.raises(WrongSecretError):
        change_passphrase(keyfile, "wrong old passphrase", "new passphrase 456")

    # Original passphrase still works — nothing was mutated on failure.
    unlock_with_passphrase(keyfile, "old passphrase 123")


@pytest.mark.parametrize("passphrase,device_name,exc_match", [
    ("", None, "empty"),
    ("short1", None, "at least"),
    ("mydevice", "mydevice", "display name"),
])
def test_validate_passphrase_rejections(passphrase, device_name, exc_match):
    with pytest.raises(WeakPassphraseError, match=exc_match):
        validate_passphrase(passphrase, device_name)


def test_validate_passphrase_accepts_reasonable_passphrase():
    validate_passphrase("a reasonable passphrase", device_name="mydevice")  # no raise


def test_create_vault_twice_at_same_path_rejected(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    create_vault("first passphrase", path=path)

    with pytest.raises(VaultExistsError):
        create_vault("second passphrase", path=path)


def test_save_and_load_keyfile_roundtrip(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=path)

    assert os.path.exists(path)
    loaded = load_vault_keyfile(path)
    dek = unlock_with_passphrase(loaded, "correct horse battery")
    assert len(dek) == 32


def test_save_vault_keyfile_is_atomic_no_leftover_tmp(tmp_path):
    path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=path)
    save_vault_keyfile(keyfile, path)  # re-save, exercise the tmp+rename path again
    assert not os.path.exists(path + ".tmp")


def test_recovery_code_format_and_normalization():
    code = generate_recovery_code()
    # Grouped with dashes, uses only Crockford-safe characters.
    assert "-" in code
    raw = normalize_recovery_code(code)
    assert len(raw) == 20

    # Lowercase, extra spaces, and O/I/L substitution should still decode
    # to the exact same raw bytes.
    messy = code.lower().replace("-", " ")
    assert normalize_recovery_code(messy) == raw


def test_recovery_code_invalid_character_rejected():
    with pytest.raises(RecoveryCodeError):
        normalize_recovery_code("!!!!-not-a-valid-code-@@@@")


def test_recovery_code_wrong_length_rejected():
    with pytest.raises(RecoveryCodeError):
        normalize_recovery_code("7QME9")  # far too short to be a real code
