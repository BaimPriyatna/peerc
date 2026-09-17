"""tests/test_identity_file.py — Phase 3.4: DeviceIdentity.is_new.

is_new distinguishes "just generated this identity for the very first
time" from "loaded an existing one" — ui.py uses it to show the
first-run NameSetupModal exactly once, never on later launches.
"""

from core.identity.identity_file import load_or_create_identity
from core.identity.key_storage import KeyStore


def _keystore(tmp_path):
    return KeyStore(plaintext_fallback_path=str(tmp_path / "key.pem"))


def test_is_new_true_on_first_creation(tmp_path):
    id_file = str(tmp_path / "identity.json")
    identity = load_or_create_identity(identity_file=id_file, key_store=_keystore(tmp_path))
    assert identity.is_new is True


def test_is_new_false_on_subsequent_load(tmp_path):
    id_file = str(tmp_path / "identity.json")
    ks = _keystore(tmp_path)

    first = load_or_create_identity(identity_file=id_file, key_store=ks)
    assert first.is_new is True

    second = load_or_create_identity(identity_file=id_file, key_store=ks)
    assert second.is_new is False
    assert second.device_id == first.device_id  # same identity, just reloaded


def test_is_new_false_default_when_constructed_directly():
    """Existing callers (rotation, tests) construct DeviceIdentity directly
    without passing is_new — must default to False, not True, or every
    identity-rotation would incorrectly re-trigger the first-run prompt."""
    from core.identity.device_identity import generate_keypair
    from core.identity.identity_file import DeviceIdentity

    identity = DeviceIdentity(
        keypair=generate_keypair(), name="Alice", created_at=100.0, storage_backend="plaintext-file",
    )
    assert identity.is_new is False
