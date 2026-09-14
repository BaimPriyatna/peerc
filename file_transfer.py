"""
file_transfer.py — staged file transfer: offer -> accept/reject -> chunks -> done.

Follows the same wrapping pattern as chat.ChatSession so multiple sessions
can be layered on one ConnectionManager: each session wraps
manager.on_message, handles the message types it owns, and passes anything
else down the chain to whatever was set before it.

Hardened per Phases 12–20:
    - Modular core.transfer architecture.
    - Pre-flight disk space check (Phase 20).
    - Atomic .part file writing and finalize rename on verified SHA-256 (Phases 16, 17).
    - Path traversal sandboxing and destination confinement (Phase 13).
    - Strict sequential chunk and size bound enforcement (Phases 14, 15).
"""

import asyncio
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import protocol
from core.transfer import (
    COMPLETE_ACK_TIMEOUT,
    DEFAULT_CHUNK_SIZE,
    MAX_INCOMING_FILE_SIZE,
    TransferSecurityError,
    check_disk_space,
    cleanup_part_file,
    finalize_part_file,
    get_part_path,
    read_chunks,
    resolve_safe_dest_path,
    sha256_file,
)
from peer import ConnectionManager

CHUNK_SIZE = DEFAULT_CHUNK_SIZE  # 64 KB per chunk

PathTraversalError = TransferSecurityError
_sha256_file = sha256_file

# (transfer_id, filename, size, sender_name) -> bool (accept?)
OnOfferReceived = Callable[[str, str, int, str], Awaitable[bool]]
# (transfer_id, bytes_done, total_bytes) -> None
OnProgress = Callable[[str, int, int], None]
# (transfer_id, success, filepath_or_none) -> None
OnComplete = Callable[[str, bool, Optional[str]], None]


@dataclass
class OutgoingTransfer:
    transfer_id: str
    addr_key: str
    filepath: str
    filename: str
    size: int
    checksum: str
    status: str = "offered"  # offered -> accepted/rejected -> sending -> awaiting_ack -> done/failed
    _ack_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _ack_success: bool = field(default=False, repr=False)


@dataclass
class IncomingTransfer:
    transfer_id: str
    addr_key: str
    filename: str
    size: int
    expected_checksum: str
    sender_name: str
    dest_path: str
    part_path: str = ""
    bytes_received: int = 0
    expected_chunk_index: int = 0
    status: str = "offered"
    _file_handle: object = field(default=None, repr=False)


class FileTransferSession:
    def __init__(
        self,
        manager: ConnectionManager,
        downloads_dir: str = "downloads",
        on_offer_received: Optional[OnOfferReceived] = None,
        on_progress: Optional[OnProgress] = None,
        on_complete: Optional[OnComplete] = None,
        event_bus: Optional[object] = None,
    ):
        self.manager = manager
        self.downloads_dir = downloads_dir
        self.on_offer_received = on_offer_received
        self.on_progress = on_progress
        self.on_complete = on_complete
        self.event_bus = event_bus or getattr(manager, "event_bus", None)

        os.makedirs(downloads_dir, exist_ok=True)

        self._outgoing: dict[str, OutgoingTransfer] = {}
        self._incoming: dict[str, IncomingTransfer] = {}

        if self.event_bus:
            from core.events import NetworkMessageReceived
            self.event_bus.subscribe(NetworkMessageReceived, self._on_network_message)
        else:
            # Chain onto whatever dispatcher is already set (e.g. ChatSession's) — legacy fallback.
            self._next_on_message = manager.on_message
            manager.on_message = self._dispatch

    async def _on_network_message(self, evt: Any) -> None:
        msg_type = evt.message.get("type")
        handlers = {
            "file_offer": self._handle_offer,
            "file_accept": self._handle_accept,
            "file_reject": self._handle_reject,
            "file_data": self._handle_chunk,
            "file_done": self._handle_done,
            "file_complete_ack": self._handle_complete_ack,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(evt.addr_key, evt.message)

    async def _dispatch(self, addr_key: str, message: dict) -> None:
        msg_type = message.get("type")
        handlers = {
            "file_offer": self._handle_offer,
            "file_accept": self._handle_accept,
            "file_reject": self._handle_reject,
            "file_data": self._handle_chunk,
            "file_done": self._handle_done,
            "file_complete_ack": self._handle_complete_ack,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(addr_key, message)
        elif getattr(self, "_next_on_message", None):
            await self._next_on_message(addr_key, message)

    def _notify_progress(self, transfer_id: str, done: int, total: int, is_upload: bool = False) -> None:
        if self.event_bus:
            from core.events import FileProgress
            self.event_bus.post(
                FileProgress(
                    transfer_id=transfer_id,
                    bytes_transferred=done,
                    total_bytes=total,
                    is_upload=is_upload,
                )
            )
        if self.on_progress:
            self.on_progress(transfer_id, done, total)

    def _notify_complete(
        self,
        transfer,  # OutgoingTransfer | IncomingTransfer
        success: bool,
        filepath: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        if self.event_bus:
            from core.events import TransferCompleted
            is_outgoing = isinstance(transfer, OutgoingTransfer)
            self.event_bus.post(
                TransferCompleted(
                    transfer_id=transfer.transfer_id,
                    success=success,
                    filepath=filepath,
                    error=error,
                    addr_key=transfer.addr_key,
                    peer_device_id=self.manager.get_peer_device_id(transfer.addr_key),
                    direction="sent" if is_outgoing else "received",
                    filename=transfer.filename,
                    size=transfer.size,
                    checksum=transfer.checksum if is_outgoing else transfer.expected_checksum,
                    timestamp=time.time(),
                )
            )
        if self.on_complete:
            self.on_complete(transfer.transfer_id, success, filepath)

    # ---- Sender side -------------------------------------------------

    async def offer_file(self, addr_key: str, filepath: str) -> Optional[str]:
        """Announce a file transfer to a connected peer."""
        size = os.path.getsize(filepath)
        checksum = sha256_file(filepath)
        filename = os.path.basename(filepath)
        transfer_id = str(uuid.uuid4())

        transfer = OutgoingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filepath=filepath,
            filename=filename, size=size, checksum=checksum,
        )

        offer = protocol.make_file_offer(
            transfer_id, sender_id=self.manager.my_identity.device_id,
            sender_name=self.manager.my_name, filename=filename,
            size=size, checksum=checksum,
        )
        ok = await self.manager.send(addr_key, offer)
        if not ok:
            return None

        self._outgoing[transfer_id] = transfer
        return transfer_id

    async def _handle_accept(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer.status = "sending"
        asyncio.create_task(self._send_chunks(transfer))

    async def _handle_reject(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer.status = "rejected"
        self._notify_complete(transfer, False, None, error="rejected")
        self._outgoing.pop(transfer.transfer_id, None)

    async def _send_chunks(self, transfer: OutgoingTransfer) -> None:
        bytes_sent = 0
        try:
            for index, offset, chunk in read_chunks(transfer.filepath, chunk_size=CHUNK_SIZE):
                payload = protocol.encode_file_data(transfer.transfer_id, index, offset, chunk)
                ok = await self.manager.send_binary(transfer.addr_key, payload)
                if not ok:
                    transfer.status = "failed"
                    self._notify_complete(transfer, False, None, error="send_failed")
                    return
                bytes_sent += len(chunk)
                self._notify_progress(transfer.transfer_id, bytes_sent, transfer.size, is_upload=True)

            done = protocol.make_file_done(transfer.transfer_id, transfer.checksum)
            await self.manager.send(transfer.addr_key, done)
            transfer.status = "awaiting_ack"

            try:
                await asyncio.wait_for(transfer._ack_event.wait(), COMPLETE_ACK_TIMEOUT)
                success = transfer._ack_success
            except asyncio.TimeoutError:
                success = False

            transfer.status = "done" if success else "failed"
            self._notify_complete(
                transfer,
                success,
                transfer.filepath if success else None,
                error=None if success else "ack_failed_or_timeout",
            )
        except OSError:
            transfer.status = "failed"
            self._notify_complete(transfer, False, None, error="os_error")
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    async def _handle_complete_ack(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        transfer._ack_success = bool(message.get("success"))
        transfer._ack_event.set()

    # ---- Receiver side -------------------------------------------------

    async def _handle_offer(self, addr_key: str, message: dict) -> None:
        transfer_id = message["transfer_id"]
        filename = message["filename"]
        size = message["size"]
        checksum = message["checksum"]
        sender_name = message.get("sender_name") or "peer"

        # BUG-002: reject oversized offers before ever asking the user.
        if size > MAX_INCOMING_FILE_SIZE:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        # Phase 20: Disk space pre-check
        if not check_disk_space(self.downloads_dir, size):
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        # BUG-001 / Phase 13: resolve safe destination path
        try:
            dest_path = self._safe_dest_path(filename)
        except PathTraversalError:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        if self.event_bus:
            from core.events import FileOffered
            await self.event_bus.publish(
                FileOffered(
                    transfer_id=transfer_id,
                    addr_key=addr_key,
                    filename=filename,
                    size=size,
                    checksum=checksum,
                    sender_name=sender_name,
                    sender_id=message.get("sender_id", ""),
                )
            )

        accept = True
        if self.on_offer_received:
            accept = await self.on_offer_received(transfer_id, filename, size, sender_name)

        if not accept:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        part_path = get_part_path(dest_path)
        cleanup_part_file(part_path)

        incoming = IncomingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filename=filename,
            size=size, expected_checksum=checksum, sender_name=sender_name,
            dest_path=dest_path, part_path=part_path,
        )
        incoming._file_handle = open(part_path, "wb")
        self._incoming[transfer_id] = incoming

        await self.manager.send(addr_key, protocol.make_file_accept(transfer_id))

    def _safe_dest_path(self, filename: str) -> str:
        return resolve_safe_dest_path(filename, self.downloads_dir)

    def _unique_dest_path(self, filename: str) -> str:
        base, ext = os.path.splitext(filename)
        candidate = os.path.join(self.downloads_dir, filename)
        counter = 1
        while os.path.exists(candidate) or os.path.exists(get_part_path(candidate)):
            candidate = os.path.join(self.downloads_dir, f"{base} ({counter}){ext}")
            counter += 1
        return candidate

    async def _handle_chunk(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.get(message["transfer_id"])
        if transfer is None:
            return

        sequence = message["sequence"]
        offset = message["offset"]
        if sequence != transfer.expected_chunk_index or offset != transfer.bytes_received:
            await self._abort_incoming(transfer, "out-of-order chunk")
            return

        data = message["data"]

        if transfer.bytes_received + len(data) > transfer.size:
            await self._abort_incoming(transfer, "declared size exceeded")
            return

        transfer._file_handle.write(data)
        transfer.bytes_received += len(data)
        transfer.expected_chunk_index += 1

        self._notify_progress(transfer.transfer_id, transfer.bytes_received, transfer.size, is_upload=False)

    async def _abort_incoming(self, transfer: "IncomingTransfer", reason: str) -> None:
        self._incoming.pop(transfer.transfer_id, None)
        if transfer._file_handle:
            try:
                transfer._file_handle.close()
            except OSError:
                pass
            transfer._file_handle = None
        if transfer.part_path and os.path.exists(transfer.part_path):
            cleanup_part_file(transfer.part_path)
        if os.path.exists(transfer.dest_path):
            try:
                os.remove(transfer.dest_path)
            except OSError:
                pass
        transfer.status = "failed"
        await self.manager.send(
            transfer.addr_key,
            protocol.make_file_complete_ack(transfer.transfer_id, False, reason),
        )
        self._notify_complete(transfer, False, None, error=reason)

    async def _handle_done(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.pop(message["transfer_id"], None)
        if transfer is None:
            return
        if transfer._file_handle:
            transfer._file_handle.close()
            transfer._file_handle = None

        actual_checksum = sha256_file(transfer.part_path)
        expected_checksum = transfer.expected_checksum
        success = actual_checksum == expected_checksum and transfer.bytes_received == transfer.size

        detail = "" if success else "checksum mismatch"
        await self.manager.send(
            addr_key, protocol.make_file_complete_ack(transfer.transfer_id, success, detail)
        )

        if not success:
            transfer.status = "failed"
            cleanup_part_file(transfer.part_path)
            self._notify_complete(transfer, False, None, error="checksum_mismatch")
            return

        # Atomically rename .part to final dest_path
        finalize_part_file(transfer.part_path, transfer.dest_path)

        transfer.status = "done"
        self._notify_complete(transfer, True, transfer.dest_path)