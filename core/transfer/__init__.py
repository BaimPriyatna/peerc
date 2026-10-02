"""core/transfer/ — File Transfer V2 for peerc (Phases 12–20).

Modules:
    hashing.py  — SHA-256 streaming and incremental hashing (Phase 17).
    chunker.py  — Binary chunk reading with offset resume support (Phase 12).
    resume.py   — .part file management, tracking, and atomic finalization (Phase 16).
    receiver.py — Inbound receiver validating disk space, bounds, and checksum (Phases 13-17, 20).
    sender.py   — Outbound sender streaming chunks and awaiting ack (Phases 12, 16, 19).
    manager.py  — FileTransferManager coordinating transfers and resource limits (Phases 12, 20).
    partial.py  — .part.meta sidecars that identify a resumable partial download (Phase 47).
    session.py  — FileTransferSession: the high-level offer/accept/chunk/done workflow over a
                  ConnectionManager (Phase 38; moved from the root file_transfer.py).
"""

from .chunker import DEFAULT_CHUNK_SIZE, read_chunks
from .hashing import IncrementalHasher, sha256_file
from .manager import (
    MAX_CONCURRENT_TRANSFERS,
    MAX_TOTAL_INCOMING_SIZE,
    FileTransferManager,
    OnComplete,
    OnOfferReceived,
    OnProgress,
)
from .receiver import (
    DISK_SAFETY_MARGIN,
    MAX_INCOMING_FILE_SIZE,
    ChunkValidationError,
    FileReceiver,
    InsufficientDiskSpaceError,
    TransferSecurityError,
    check_disk_space,
    resolve_safe_dest_path,
)
from .resume import (
    PART_EXTENSION,
    cleanup_part_file,
    finalize_part_file,
    get_part_path,
    get_partial_bytes,
)
from .sender import COMPLETE_ACK_TIMEOUT, FileSender

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "MAX_INCOMING_FILE_SIZE",
    "COMPLETE_ACK_TIMEOUT",
    "MAX_CONCURRENT_TRANSFERS",
    "MAX_TOTAL_INCOMING_SIZE",
    "DISK_SAFETY_MARGIN",
    "PART_EXTENSION",
    "TransferSecurityError",
    "InsufficientDiskSpaceError",
    "ChunkValidationError",
    "sha256_file",
    "IncrementalHasher",
    "read_chunks",
    "get_part_path",
    "get_partial_bytes",
    "cleanup_part_file",
    "finalize_part_file",
    "check_disk_space",
    "resolve_safe_dest_path",
    "FileReceiver",
    "FileSender",
    "FileTransferManager",
    "OnOfferReceived",
    "OnProgress",
    "OnComplete",
]
