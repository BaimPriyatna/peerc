"""core/transfer/manager.py — Central coordinator for file transfers (Phases 12, 19, 20).

Coordinates senders and receivers, enforces concurrency and disk limits, handles
message callbacks, and dispatches wire frames.
"""

import asyncio
import os
import uuid
from typing import Awaitable, Callable, Dict, Optional

from .receiver import (
    FileReceiver,
    InsufficientDiskSpaceError,
    MAX_INCOMING_FILE_SIZE,
    TransferSecurityError,
    check_disk_space,
    resolve_safe_dest_path,
)
from .sender import FileSender

MAX_CONCURRENT_TRANSFERS = 5
MAX_TOTAL_INCOMING_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB limit across all active inbound transfers

OnOfferReceived = Callable[[str, str, int, str], Awaitable[bool]]  # (id, name, size, sender) -> accept?
OnProgress = Callable[[str, int, int], None]                       # (id, current, total) -> None
OnComplete = Callable[[str, bool, Optional[str]], None]            # (id, success, path_or_none) -> None


class FileTransferManager:
    """Manages active file transfers, enforcing system limits and flow coordination."""

    def __init__(
        self,
        downloads_dir: str = "downloads",
        max_concurrent: int = MAX_CONCURRENT_TRANSFERS,
        max_total_incoming: int = MAX_TOTAL_INCOMING_SIZE,
        on_offer_received: Optional[OnOfferReceived] = None,
        on_progress: Optional[OnProgress] = None,
        on_complete: Optional[OnComplete] = None,
    ):
        self.downloads_dir = downloads_dir
        self.max_concurrent = max_concurrent
        self.max_total_incoming = max_total_incoming
        self.on_offer_received = on_offer_received
        self.on_progress = on_progress
        self.on_complete = on_complete

        os.makedirs(downloads_dir, exist_ok=True)

        self._senders: Dict[str, FileSender] = {}
        self._receivers: Dict[str, FileReceiver] = {}

    @property
    def active_incoming_count(self) -> int:
        return len([r for r in self._receivers.values() if r.status in ("receiving", "offered")])

    @property
    def total_incoming_bytes_pending(self) -> int:
        return sum(r.size for r in self._receivers.values() if r.status in ("receiving", "offered"))

    def create_sender(self, filepath: str, transfer_id: Optional[str] = None) -> FileSender:
        """Register a new outgoing transfer."""
        tid = transfer_id or str(uuid.uuid4())
        sender = FileSender(transfer_id=tid, filepath=filepath)
        self._senders[tid] = sender
        return sender

    def get_sender(self, transfer_id: str) -> Optional[FileSender]:
        return self._senders.get(transfer_id)

    def get_receiver(self, transfer_id: str) -> Optional[FileReceiver]:
        return self._receivers.get(transfer_id)

    def validate_offer(self, filename: str, size: int) -> str:
        """Validate an offer against size, concurrency, and disk space limits.

        Returns:
            Resolved safe destination path if valid.

        Raises:
            ValueError: If size exceeds MAX_INCOMING_FILE_SIZE or is negative.
            InsufficientDiskSpaceError: If disk lacks required space or total pending limit exceeded.
            TransferSecurityError: If filename violates path traversal checks.
        """
        if size <= 0 or size > MAX_INCOMING_FILE_SIZE:
            raise ValueError(f"Invalid file size: {size}")

        if self.active_incoming_count >= self.max_concurrent:
            raise InsufficientDiskSpaceError("Maximum concurrent transfers reached")

        if self.total_incoming_bytes_pending + size > self.max_total_incoming:
            raise InsufficientDiskSpaceError("Total pending incoming transfer limit exceeded")

        if not check_disk_space(self.downloads_dir, size):
            raise InsufficientDiskSpaceError("Insufficient free disk space in downloads directory")

        return resolve_safe_dest_path(filename, self.downloads_dir)

    def create_receiver(
        self,
        transfer_id: str,
        filename: str,
        size: int,
        checksum: str,
        sender_name: str,
        dest_path: str,
        storage_mode: str = "normal",
        secure_storage_dir: Optional[str] = None,
        dek: Optional[bytes] = None,
    ) -> FileReceiver:
        """Register a validated receiver for an incoming transfer.
        
        Phase 39.5: supports storage_mode='secure' for encrypt-on-arrival.
        """
        receiver = FileReceiver(
            transfer_id=transfer_id,
            filename=filename,
            size=size,
            expected_checksum=checksum,
            sender_name=sender_name,
            dest_path=dest_path,
            storage_mode=storage_mode,
            secure_storage_dir=secure_storage_dir,
            dek=dek,
        )
        self._receivers[transfer_id] = receiver
        return receiver

    def remove_transfer(self, transfer_id: str) -> None:
        """Clean up finished or failed transfer entries."""
        self._senders.pop(transfer_id, None)
        self._receivers.pop(transfer_id, None)
