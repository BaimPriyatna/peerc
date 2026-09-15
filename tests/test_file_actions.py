"""tests/test_file_actions.py — Phase 39.5: file action integration tests.

Covers:
  1. open_secure_file decrypts to temp, strips executable bits, calls checker.
  2. open_secure_file with ExecutableBlockedError cleans up temp file.
  3. open_secure_file requires re-auth when session.requires_reauth('open') is True.
  4. export_secure_file requires authorize_export (critical-action key gate).
  5. export_secure_file creates permanent plaintext copy.
  6. export_secure_file rejects when authorization fails.
  7. move_to_secure_storage encrypts local file into secure storage.
  8. move_to_secure_storage requires re-auth when session.requires_reauth('move_to_secure').
  9. delete_secure_file_action removes secure file + metadata.
 10. delete_secure_file_action requires re-auth when session.requires_reauth('delete').
 11. handle_incoming_transfer checks authorization for accept/reject.
 12. All actions raise SessionLockedError when vault is locked.
"""

import os

import pytest

from core.vault import (
    VaultDatabase,
    VaultKeyfile,
    VaultSession,
    create_vault,
)
from core.vault.crypto import new_dek
from core.vault.executable_detection import ExecutableDetectionError
from core.vault.file_actions import (
    AuthorizationError,
    ExecutableBlockedError,
    SessionLockedError,
    delete_secure_file_action,
    export_secure_file,
    handle_incoming_transfer,
    move_to_secure_storage,
    open_secure_file,
)
from core.vault.secure_file import encrypt_file, list_secure_files


@pytest.fixture
def vault_session(tmp_path):
    """Create an unlocked VaultSession for testing."""
    dek = new_dek()
    vault_db_path = str(tmp_path / "vault.db")
    vault_db = VaultDatabase.unlock(dek, vault_db_path)
    
    session = VaultSession()
    session.unlock(dek, vault_db)
    
    yield session
    
    if session.is_unlocked:
        session.lock()


@pytest.fixture
def vault_keyfile(tmp_path):
    """Create a VaultKeyfile for testing."""
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("test_passphrase_123", path=keyfile_path)
    return keyfile


def test_open_secure_file_decrypts_to_temp(tmp_path, vault_session):
    """open_secure_file must decrypt file to temporary location."""
    # Create a secure file
    plaintext = tmp_path / "original.txt"
    plaintext.write_text("Hello, secure world!")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Open re-prompts every time by default (§4); bypass for this test
    # since re-auth flow is covered separately.
    vault_session.set_dont_ask_again_files(True)
    
    # Open it
    temp_path, meta_restored = open_secure_file(
        metadata.secure_id,
        str(secure_dir),
        vault_session,
        temp_dir=str(tmp_path / "temp"),
    )
    
    assert os.path.exists(temp_path)
    assert open(temp_path).read() == "Hello, secure world!"
    assert meta_restored.original_filename == "original.txt"


def test_open_secure_file_with_executable_checker(tmp_path, vault_session):
    """open_secure_file must call executable_checker and handle ExecutableBlockedError."""
    # Create a secure file with executable content
    plaintext = tmp_path / "malware.exe"
    plaintext.write_bytes(b"MZ" + b"\x00" * 100)  # PE executable
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Open re-prompts every time by default (§4); bypass for this test
    # since re-auth flow is covered separately.
    vault_session.set_dont_ask_again_files(True)
    
    from core.vault.executable_detection import check_executable_for_open
    
    # Open with executable checker should raise ExecutableBlockedError
    with pytest.raises(ExecutableBlockedError):
        open_secure_file(
            metadata.secure_id,
            str(secure_dir),
            vault_session,
            executable_checker=check_executable_for_open,
        )


def test_open_requires_reauth_when_session_policy_demands(tmp_path, vault_session):
    """open_secure_file must raise AuthorizationError when re-auth required."""
    # Don't enable "don't ask again" → re-auth required
    assert vault_session.requires_reauth("open")
    
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("content")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Should raise AuthorizationError (caller must verify passphrase first)
    with pytest.raises(AuthorizationError, match="passphrase re-authentication required"):
        open_secure_file(metadata.secure_id, str(secure_dir), vault_session)


def test_open_proceeds_with_dont_ask_again(tmp_path, vault_session):
    """open_secure_file must proceed when 'don't ask again' is enabled."""
    vault_session.set_dont_ask_again_files(True)
    assert not vault_session.requires_reauth("open")
    
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("content")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Should succeed without extra auth
    temp_path, _ = open_secure_file(
        metadata.secure_id,
        str(secure_dir),
        vault_session,
        temp_dir=str(tmp_path / "temp"),
    )
    
    assert os.path.exists(temp_path)


def test_export_requires_authorize_export(tmp_path, vault_session, vault_keyfile):
    """export_secure_file must check authorize_export."""
    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("Sensitive data")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # authorize_export returns False if critical key is configured but not provided
    # For this test, no critical key configured → should succeed
    assert vault_session.authorize_export(vault_keyfile, None)
    
    dest = tmp_path / "exported.txt"
    exported_meta = export_secure_file(
        metadata.secure_id,
        str(secure_dir),
        str(dest),
        vault_session,
        vault_keyfile,
        critical_secret=None,
    )
    
    assert dest.exists()
    assert dest.read_text() == "Sensitive data"
    assert exported_meta.original_filename == "secret.txt"


def test_export_rejects_without_authorization(tmp_path, vault_session, vault_keyfile):
    """export_secure_file must raise AuthorizationError when authorization fails."""
    # Set a critical-action key
    vault_session.set_critical_action_key(vault_keyfile, "export_key_456")
    
    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("Sensitive data")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    dest = tmp_path / "exported.txt"
    
    # Export without critical_secret → should fail authorization
    with pytest.raises(AuthorizationError, match="Export authorization failed"):
        export_secure_file(
            metadata.secure_id,
            str(secure_dir),
            str(dest),
            vault_session,
            vault_keyfile,
            critical_secret=None,  # missing required secret
        )


def test_export_creates_permanent_plaintext_copy(tmp_path, vault_session, vault_keyfile):
    """export_secure_file must create a permanent plaintext file."""
    plaintext = tmp_path / "original.txt"
    plaintext.write_text("Export me!")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    dest = tmp_path / "downloads" / "exported.txt"
    export_secure_file(
        metadata.secure_id,
        str(secure_dir),
        str(dest),
        vault_session,
        vault_keyfile,
    )
    
    assert dest.exists()
    assert dest.read_text() == "Export me!"
    # Original secure file still exists
    assert (secure_dir / f"{metadata.secure_id}.peercfile").exists()


def test_move_to_secure_storage_encrypts_local_file(tmp_path, vault_session):
    """move_to_secure_storage must encrypt an existing local file."""
    vault_session.set_dont_ask_again_files(True)  # bypass re-auth for test
    
    local_file = tmp_path / "local.txt"
    local_file.write_text("Local plaintext file")
    
    secure_dir = tmp_path / "secure"
    
    from core.transfer.hashing import sha256_file
    checksum = sha256_file(str(local_file))
    
    metadata = move_to_secure_storage(
        str(local_file),
        str(secure_dir),
        vault_session,
        checksum=checksum,
        delete_source=False,
    )
    
    # Secure file created
    assert (secure_dir / f"{metadata.secure_id}.peercfile").exists()
    assert metadata.original_filename == "local.txt"
    assert metadata.checksum == checksum
    
    # Original still exists (delete_source=False)
    assert local_file.exists()


def test_move_to_secure_requires_reauth(tmp_path, vault_session):
    """move_to_secure_storage must raise AuthorizationError when re-auth required."""
    # Don't enable "don't ask again"
    assert vault_session.requires_reauth("move_to_secure")
    
    local_file = tmp_path / "file.txt"
    local_file.write_text("content")
    
    secure_dir = tmp_path / "secure"
    
    with pytest.raises(AuthorizationError, match="passphrase re-authentication required"):
        move_to_secure_storage(str(local_file), str(secure_dir), vault_session)


def test_delete_secure_file_action_removes_file(tmp_path, vault_session):
    """delete_secure_file_action must remove both ciphertext and metadata."""
    vault_session.set_dont_ask_again_files(True)  # bypass re-auth
    
    plaintext = tmp_path / "temp.txt"
    plaintext.write_text("Temporary")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    cipher_path = secure_dir / f"{metadata.secure_id}.peercfile"
    meta_path = secure_dir / f"{metadata.secure_id}.meta"
    
    assert cipher_path.exists()
    assert meta_path.exists()
    
    deleted_meta = delete_secure_file_action(
        metadata.secure_id,
        str(secure_dir),
        vault_session,
    )
    
    assert deleted_meta.original_filename == "temp.txt"
    assert not cipher_path.exists()
    assert not meta_path.exists()


def test_delete_requires_reauth(tmp_path, vault_session):
    """delete_secure_file_action must raise AuthorizationError when re-auth required."""
    assert vault_session.requires_reauth("delete")
    
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("content")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    with pytest.raises(AuthorizationError, match="passphrase re-authentication required"):
        delete_secure_file_action(metadata.secure_id, str(secure_dir), vault_session)


def test_handle_incoming_transfer_accept(vault_session):
    """handle_incoming_transfer must return True when authorized to accept."""
    # Default: require_passphrase_for_incoming = False
    assert not vault_session.require_passphrase_for_incoming
    
    result = handle_incoming_transfer(vault_session, accept=True, storage_mode="secure")
    assert result is True


def test_handle_incoming_transfer_reject(vault_session):
    """handle_incoming_transfer must return False when user rejects."""
    result = handle_incoming_transfer(vault_session, accept=False)
    assert result is False


def test_handle_incoming_transfer_requires_auth_when_configured(vault_session):
    """handle_incoming_transfer must raise AuthorizationError when passphrase required."""
    vault_session.set_require_passphrase_for_incoming(True)
    assert vault_session.requires_reauth("incoming_transfer")
    
    with pytest.raises(AuthorizationError, match="passphrase required for incoming"):
        handle_incoming_transfer(vault_session, accept=True)


def test_open_raises_session_locked_error_when_locked(tmp_path):
    """open_secure_file must raise SessionLockedError when vault is locked."""
    session = VaultSession()
    assert not session.is_unlocked
    
    with pytest.raises(SessionLockedError, match="vault session is locked"):
        open_secure_file("dummy_id", str(tmp_path), session)


def test_export_raises_session_locked_error_when_locked(tmp_path, vault_keyfile):
    """export_secure_file must raise SessionLockedError when vault is locked."""
    session = VaultSession()
    assert not session.is_unlocked
    
    with pytest.raises(SessionLockedError, match="vault session is locked"):
        export_secure_file("dummy_id", str(tmp_path), str(tmp_path / "out"), session, vault_keyfile)


def test_move_to_secure_raises_session_locked_error_when_locked(tmp_path):
    """move_to_secure_storage must raise SessionLockedError when vault is locked."""
    session = VaultSession()
    local_file = tmp_path / "file.txt"
    local_file.write_text("content")
    
    with pytest.raises(SessionLockedError, match="vault session is locked"):
        move_to_secure_storage(str(local_file), str(tmp_path), session)


def test_delete_raises_session_locked_error_when_locked(tmp_path):
    """delete_secure_file_action must raise SessionLockedError when vault is locked."""
    session = VaultSession()
    
    with pytest.raises(SessionLockedError, match="vault session is locked"):
        delete_secure_file_action("dummy_id", str(tmp_path), session)


def test_open_strips_executable_bits(tmp_path, vault_session):
    """open_secure_file must strip executable permission bits from decrypted file."""
    vault_session.set_dont_ask_again_files(True)
    
    # Create a secure file (doesn't matter if content is executable for this test)
    plaintext = tmp_path / "script.txt"
    plaintext.write_text("#!/bin/bash\necho hello")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Open it
    temp_path, _ = open_secure_file(
        metadata.secure_id,
        str(secure_dir),
        vault_session,
        temp_dir=str(tmp_path / "temp"),
    )
    
    # Check permissions (Unix-like systems only)
    import stat
    mode = os.stat(temp_path).st_mode
    # No execute bits should be set
    assert not (mode & stat.S_IXUSR)
    assert not (mode & stat.S_IXGRP)
    assert not (mode & stat.S_IXOTH)


def test_export_raises_on_existing_destination(tmp_path, vault_session, vault_keyfile):
    """export_secure_file must raise FileExistsError if destination exists."""
    vault_session.set_dont_ask_again_files(True)
    
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("content")
    
    secure_dir = tmp_path / "secure"
    dek = vault_session.dek_bytes()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    dest = tmp_path / "existing.txt"
    dest.write_text("already exists")
    
    with pytest.raises(FileExistsError, match="destination already exists"):
        export_secure_file(
            metadata.secure_id,
            str(secure_dir),
            str(dest),
            vault_session,
            vault_keyfile,
        )
