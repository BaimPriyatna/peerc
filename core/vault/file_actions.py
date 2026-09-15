"""core/vault/file_actions.py — Phase 39.5: file action primitives.

See docs/SECURE_STORAGE_DESIGN.md §4, §6, §8. Five distinct actions:
  - Incoming Transfer: accept/reject (no passphrase by default)
  - Open: decrypt to ephemeral temp, hand to viewer, best-effort cleanup
  - Export: decrypt to permanent plaintext copy (explicit confirmation)
  - Move to Secure Storage: encrypt existing local file
  - Delete: remove secure file + metadata

Each action integrates with VaultSession.requires_reauth() and
authorize_export() for the §4 authentication policy.
"""

import os
import shutil
import tempfile
from typing import Optional

from .secure_file import (
    SecureFileError,
    SecureFileMetadata,
    decrypt_file,
    delete_secure_file,
    encrypt_file,
    load_metadata,
)
from .executable_detection import ExecutableDetectionError, describe_file_type
from .session import SessionLockedError, VaultSession


class FileActionError(Exception):
    """Base class for file action errors."""


class AuthorizationError(FileActionError):
    """Raised when authorization fails (re-auth required or Export denied)."""


class ExecutableBlockedError(FileActionError):
    """Raised when Open is blocked because the file is/may be executable."""


def open_secure_file(
    secure_id: str,
    secure_storage_dir: str,
    session: VaultSession,
    temp_dir: Optional[str] = None,
    executable_checker=None,
) -> tuple[str, SecureFileMetadata]:
    """Decrypt a secure file to an ephemeral temporary location for viewing.
    
    Must never execute the file (§6) — the caller must strip executable bits
    and check content via executable_checker before opening.
    
    Args:
        secure_id: Opaque identifier of the secure file
        secure_storage_dir: Directory where secure files are stored
        session: Active VaultSession (must be unlocked)
        temp_dir: Where to write the decrypted temp file (None = system temp)
        executable_checker: Optional callable(file_path) that raises
            ExecutableBlockedError or ExecutableDetectionError if the
            file should not be opened (either is normalized to
            ExecutableBlockedError below)
    
    Returns:
        (temp_file_path, metadata) — caller is responsible for cleanup
    
    Raises:
        SessionLockedError: If session is locked
        AuthorizationError: If re-auth is required but not satisfied
        ExecutableBlockedError: If the file is/may be executable
        SecureFileError: If decryption fails
    """
    if not session.is_unlocked:
        raise SessionLockedError("vault session is locked")
    
    # Authorization check: Open requires re-auth by default unless
    # "don't ask again" is enabled (caller must call
    # session.verify_passphrase() first if requires_reauth returned True)
    if session.requires_reauth("open"):
        raise AuthorizationError(
            "passphrase re-authentication required for Open action"
        )
    
    # Load metadata first to get the original filename
    metadata = load_metadata(secure_storage_dir, secure_id)
    
    # Create temporary directory with restrictive permissions
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp(prefix="peerc_open_")
    else:
        os.makedirs(temp_dir, mode=0o700, exist_ok=True)
    
    # Decrypt to temp location
    temp_path = os.path.join(temp_dir, metadata.original_filename)
    dek = session.dek_bytes()
    decrypt_file(secure_id, secure_storage_dir, dek, temp_path)
    
    # Strip executable permission bits (§6 — Open is view-only, never execute)
    try:
        current_mode = os.stat(temp_path).st_mode
        os.chmod(temp_path, current_mode & ~0o111)  # clear all execute bits
    except OSError:
        pass  # best-effort, not critical
    
    # Check if file is/may be executable (§11.6 magic-byte detection)
    if executable_checker is not None:
        try:
            executable_checker(temp_path)
        except (ExecutableBlockedError, ExecutableDetectionError) as e:
            # Describe the detected type *before* deleting the temp file —
            # callers (e.g. ui.py) can't inspect the file themselves once
            # it's gone, since the temp_path/metadata tuple this function
            # would have returned is never bound on the caller's side when
            # this function raises instead of returning.
            detected_type = describe_file_type(temp_path)
            # Clean up temp file before re-raising. Checkers may raise either
            # ExecutableBlockedError (this module's contract) or
            # ExecutableDetectionError (raised by check_executable_for_open,
            # the checker actually wired up in ui.py) — normalize to
            # ExecutableBlockedError either way so callers only need to
            # handle one exception type.
            _secure_delete_temp(temp_path)
            message = f"{e} (Detected as: {detected_type})"
            if isinstance(e, ExecutableBlockedError):
                raise ExecutableBlockedError(message) from None
            raise ExecutableBlockedError(message) from e
    
    return temp_path, metadata


def export_secure_file(
    secure_id: str,
    secure_storage_dir: str,
    destination_path: str,
    session: VaultSession,
    keyfile,
    critical_secret: Optional[str] = None,
) -> SecureFileMetadata:
    """Decrypt a secure file to a permanent plaintext location (§8).
    
    This is the one irreversible action — plaintext leaves secure storage.
    Requires explicit authorization via authorize_export() which gates on
    both the unlocked session and the optional critical-action key (§11.7).
    
    Args:
        secure_id: Opaque identifier of the secure file
        secure_storage_dir: Directory where secure files are stored
        destination_path: Where to write the permanent plaintext copy
        session: Active VaultSession (must be unlocked)
        keyfile: VaultKeyfile (for critical-action key check)
        critical_secret: Optional critical-action secret (required if configured)
    
    Returns:
        SecureFileMetadata of the exported file
    
    Raises:
        SessionLockedError: If session is locked
        AuthorizationError: If Export authorization fails
        SecureFileError: If decryption fails
        FileExistsError: If destination already exists
    """
    if not session.is_unlocked:
        raise SessionLockedError("vault session is locked")
    
    # Export authorization: always requires authorize_export() even if
    # "don't ask again" is enabled — Export is the critical action (§4)
    if not session.authorize_export(keyfile, critical_secret):
        raise AuthorizationError(
            "Export authorization failed — critical-action key required or wrong"
        )
    
    # Don't overwrite existing files without explicit confirmation
    if os.path.exists(destination_path):
        raise FileExistsError(f"destination already exists: {destination_path}")
    
    # Decrypt to final location
    dek = session.dek_bytes()
    metadata = decrypt_file(secure_id, secure_storage_dir, dek, destination_path)
    
    return metadata


def move_to_secure_storage(
    plaintext_path: str,
    secure_storage_dir: str,
    session: VaultSession,
    checksum: Optional[str] = None,
    delete_source: bool = False,
) -> SecureFileMetadata:
    """Encrypt an existing local plaintext file into secure storage.
    
    This is different from Incoming Transfer (§4) — it's about taking an
    existing file already on disk and moving it into secure storage.
    
    Args:
        plaintext_path: Path to the plaintext file to encrypt
        secure_storage_dir: Directory where secure files are stored
        session: Active VaultSession (must be unlocked)
        checksum: Optional SHA-256 checksum for verification
        delete_source: Whether to delete the plaintext source after encryption
    
    Returns:
        SecureFileMetadata of the newly encrypted file
    
    Raises:
        SessionLockedError: If session is locked
        AuthorizationError: If re-auth is required but not satisfied
        SecureFileError: If encryption fails
        FileNotFoundError: If plaintext_path doesn't exist
    """
    if not session.is_unlocked:
        raise SessionLockedError("vault session is locked")
    
    # Authorization check: Move to Secure requires re-auth by default
    # (same as Open/Delete, not Incoming Transfer)
    if session.requires_reauth("move_to_secure"):
        raise AuthorizationError(
            "passphrase re-authentication required for Move to Secure Storage"
        )
    
    if not os.path.exists(plaintext_path):
        raise FileNotFoundError(f"plaintext file not found: {plaintext_path}")
    
    # Encrypt into secure storage
    dek = session.dek_bytes()
    metadata = encrypt_file(
        plaintext_path,
        secure_storage_dir,
        dek,
        original_filename=os.path.basename(plaintext_path),
        checksum=checksum,
    )
    
    # Delete source if requested (secure wipe, not plain unlink)
    if delete_source:
        _secure_delete_file(plaintext_path)
    
    return metadata


def delete_secure_file_action(
    secure_id: str,
    secure_storage_dir: str,
    session: VaultSession,
) -> SecureFileMetadata:
    """Delete a secure file and its metadata (§6).
    
    Args:
        secure_id: Opaque identifier of the secure file
        secure_storage_dir: Directory where secure files are stored
        session: Active VaultSession (must be unlocked)
    
    Returns:
        SecureFileMetadata of the deleted file (for confirmation/undo)
    
    Raises:
        SessionLockedError: If session is locked
        AuthorizationError: If re-auth is required but not satisfied
        FileNotFoundError: If secure file doesn't exist
    """
    if not session.is_unlocked:
        raise SessionLockedError("vault session is locked")
    
    # Authorization check: Delete requires re-auth by default
    if session.requires_reauth("delete"):
        raise AuthorizationError(
            "passphrase re-authentication required for Delete action"
        )
    
    # Load metadata first (for confirmation/return value)
    metadata = load_metadata(secure_storage_dir, secure_id)
    
    # Delete the secure file + metadata
    delete_secure_file(secure_id, secure_storage_dir)
    
    return metadata


def handle_incoming_transfer(
    session: VaultSession,
    accept: bool,
    storage_mode: str = "secure",
) -> bool:
    """Check authorization for accepting an incoming file transfer (§4).
    
    This is different from the other actions: no file exists yet locally,
    so there's nothing to decrypt/expose. By default, only yes/no is
    needed (no passphrase), unless the user turned on
    require_passphrase_for_incoming.
    
    Args:
        session: Active VaultSession
        accept: Whether the user accepts the transfer
        storage_mode: 'secure' or 'normal'
    
    Returns:
        True if authorized to proceed, False otherwise
    
    Raises:
        SessionLockedError: If session is locked (must unlock first)
    """
    if not session.is_unlocked:
        raise SessionLockedError("vault session is locked")
    
    if not accept:
        return False  # rejection needs no auth check
    
    # Authorization check: Incoming Transfer only needs passphrase if
    # require_passphrase_for_incoming is enabled (§4)
    if session.requires_reauth("incoming_transfer"):
        raise AuthorizationError(
            "passphrase required for incoming transfers (per settings)"
        )
    
    return True


# ---- Internal helpers ------------------------------------------------


def _secure_delete_file(path: str) -> None:
    """Best-effort secure deletion: overwrite then unlink.
    
    This is the same pattern as VaultDatabase._secure_delete() (§17) —
    not a guarantee (OS can still swap, cache, or journal), but better
    than plain unlink for plaintext sources being moved to secure storage.
    """
    try:
        import secrets
        
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass  # best-effort
    
    try:
        os.remove(path)
    except OSError:
        pass


def _secure_delete_temp(path: str) -> None:
    """Best-effort cleanup of a temporary decrypted file.
    
    Called by open_secure_file() on error paths. Same overwrite-then-unlink
    pattern, though if the temp location is on tmpfs/RAM (Linux /dev/shm)
    this is unnecessary but harmless.
    """
    _secure_delete_file(path)
    
    # Also try to remove the parent temp directory if it's empty
    try:
        parent = os.path.dirname(path)
        if parent and os.path.isdir(parent):
            os.rmdir(parent)  # only succeeds if empty
    except OSError:
        pass
