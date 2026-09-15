"""core/transfer/receiver.py — Inbound file receiver state machine (Phases 13–17, 20, 39.5).

Enforces:
    - Path traversal protection & sandboxing inside downloads_dir (Phase 13).
    - Available disk space pre-flight validation (Phase 20).
    - Size limits & accumulated size enforcement (Phase 14).
    - Strict sequence & offset alignment (Phase 15).
    - Atomic .part write & rename on authoritative SHA-256 verification (Phases 16, 17).
    - Secure storage mode: encrypt-on-arrival for Phase 39.5 (optional).
"""

import os
import shutil
from typing import Optional

from .hashing import sha256_file
from .resume import cleanup_part_file, finalize_part_file, get_part_path, get_partial_bytes

MAX_INCOMING_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB safety cap
DISK_SAFETY_MARGIN = 10 * 1024 * 1024            # 10 MB headroom


class TransferSecurityError(Exception):
    """Raised when a transfer violates path traversal or security boundaries."""


class InsufficientDiskSpaceError(Exception):
    """Raised when the host filesystem has insufficient free space for the transfer."""


class ChunkValidationError(Exception):
    """Raised when a received chunk violates sequence, offset, or size boundaries."""


def check_disk_space(
    directory: str,
    required_bytes: int,
    safety_margin: int = DISK_SAFETY_MARGIN,
) -> bool:
    """Check if directory's filesystem has sufficient free space."""
    try:
        total, used, free = shutil.disk_usage(directory)
        return free >= (required_bytes + safety_margin)
    except OSError:
        return True  # fallback if OS does not support disk_usage


def resolve_safe_dest_path(filename: str, downloads_dir: str) -> str:
    """Turn a remote-supplied filename into a safe, unique path inside downloads_dir."""
    name = os.path.basename(filename.replace("\\", "/")).strip()
    if not name or name in (".", ".."):
        raise TransferSecurityError(f"Unsafe filename: {filename!r}")

    downloads_root = os.path.realpath(downloads_dir)
    base, ext = os.path.splitext(name)
    candidate = os.path.join(downloads_dir, name)

    counter = 1
    while os.path.exists(candidate) or os.path.exists(get_part_path(candidate)):
        candidate = os.path.join(downloads_dir, f"{base} ({counter}){ext}")
        counter += 1

    resolved = os.path.realpath(candidate)
    if os.path.commonpath([resolved, downloads_root]) != downloads_root:
        raise TransferSecurityError(f"Resolved path escapes downloads directory: {resolved!r}")

    return candidate


class FileReceiver:
    """Manages receipt, validation, incremental writing, and verification of an incoming file.
    
    Phase 39.5 addition: supports secure storage mode — when storage_mode='secure',
    the received plaintext file is encrypted into secure storage after verification,
    then the plaintext .part is securely deleted.
    """

    def __init__(
        self,
        transfer_id: str,
        filename: str,
        size: int,
        expected_checksum: str,
        sender_name: str,
        dest_path: str,
        chunk_size: int = 64 * 1024,
        storage_mode: str = "normal",
        secure_storage_dir: Optional[str] = None,
        dek: Optional[bytes] = None,
    ):
        self.transfer_id = transfer_id
        self.filename = filename
        self.size = size
        self.expected_checksum = expected_checksum
        self.sender_name = sender_name
        self.dest_path = dest_path
        self.part_path = get_part_path(dest_path)
        self.chunk_size = chunk_size
        
        # Phase 39.5: secure storage support
        self.storage_mode = storage_mode  # 'normal' or 'secure'
        self.secure_storage_dir = secure_storage_dir
        self.dek = dek
        self.secure_id: Optional[str] = None  # set after encryption

        self.bytes_received = 0
        self.expected_chunk_index = 0
        self.status = "offered"  # offered -> receiving -> verifying -> done / failed
        self._file_handle = None

    def prepare(self, resume: bool = False) -> int:
        """Initialize or resume the target .part file.

        Returns:
            Offset from which the sender should stream (0 for new, >0 for resume).
        """
        if resume:
            existing_bytes = get_partial_bytes(self.part_path)
            if 0 < existing_bytes < self.size:
                self.bytes_received = existing_bytes
                self.expected_chunk_index = existing_bytes // self.chunk_size
                self._file_handle = open(self.part_path, "ab")
                self.status = "receiving"
                return existing_bytes

        # Fresh start
        cleanup_part_file(self.part_path)
        self.bytes_received = 0
        self.expected_chunk_index = 0
        self._file_handle = open(self.part_path, "wb")
        self.status = "receiving"
        return 0

    def write_chunk(self, sequence: int, offset: int, data: bytes) -> None:
        """Validate and write a single file_data chunk to the .part file."""
        if self._file_handle is None or self.status != "receiving":
            raise ChunkValidationError("Cannot write chunk to uninitialized or inactive receiver")

        if sequence != self.expected_chunk_index or offset != self.bytes_received:
            raise ChunkValidationError(
                f"Out-of-order chunk: expected seq {self.expected_chunk_index} "
                f"offset {self.bytes_received}, got seq {sequence} offset {offset}"
            )

        if self.bytes_received + len(data) > self.size:
            raise ChunkValidationError(
                f"Declared size exceeded: {self.bytes_received + len(data)} > {self.size}"
            )

        self._file_handle.write(data)
        self.bytes_received += len(data)
        self.expected_chunk_index += 1

    def finish(self) -> bool:
        """Close .part file, verify authoritative SHA-256, and atomically finalize.
        
        Phase 39.5: if storage_mode='secure', encrypt the verified plaintext into
        secure storage, then securely delete the plaintext temp file.
        """
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

        self.status = "verifying"

        if self.bytes_received != self.size:
            self.abort(cleanup=True)
            return False

        actual_checksum = sha256_file(self.part_path)
        if actual_checksum.lower() != self.expected_checksum.lower():
            self.abort(cleanup=True)
            return False

        # Phase 39.5: handle secure storage mode
        if self.storage_mode == "secure":
            return self._finalize_secure()
        else:
            # Normal mode: atomic rename to final dest_path
            finalize_part_file(self.part_path, self.dest_path)
            self.status = "done"
            return True

    def _finalize_secure(self) -> bool:
        """Encrypt verified plaintext into secure storage (Phase 39.5).
        
        Returns True on success, False on failure (sets status='failed').
        """
        if self.dek is None or self.secure_storage_dir is None:
            # Secure mode requested but DEK not provided — fail
            self.abort(cleanup=True)
            return False
        
        try:
            # Import here to avoid circular dependency if vault imports transfer
            from ..vault.secure_file import encrypt_file
            
            # Encrypt the verified plaintext .part file into secure storage
            metadata = encrypt_file(
                plaintext_path=self.part_path,
                secure_storage_dir=self.secure_storage_dir,
                dek=self.dek,
                original_filename=self.filename,
                checksum=self.expected_checksum,
            )
            
            self.secure_id = metadata.secure_id
            
            # Securely delete the plaintext .part file
            self._secure_delete_plaintext(self.part_path)
            
            # Update dest_path to reflect secure storage location (for persistence)
            # Caller (persistence layer) will read secure_id to know where it went
            self.status = "done"
            return True
            
        except Exception:
            # Encryption failed — clean up and fail the transfer
            self.abort(cleanup=True)
            return False

    def _secure_delete_plaintext(self, path: str) -> None:
        """Best-effort secure deletion of plaintext temp file after encryption.
        
        Same pattern as VaultDatabase._secure_delete() — overwrite then unlink.
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

    def abort(self, cleanup: bool = True) -> None:
        """Abort transfer and close resources."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except OSError:
                pass
            self._file_handle = None

        self.status = "failed"
        if cleanup:
            cleanup_part_file(self.part_path)
