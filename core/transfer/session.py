"""
core/transfer/session.py — staged file transfer: offer -> accept/reject -> chunks -> done.

Phase 38: moved here from the root file_transfer.py, which is now a
compatibility shim. Behavior is unchanged.

Follows the same wrapping pattern as core.messaging.session.ChatSession so multiple sessions
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
import logging
import os
import shutil
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from core import protocol
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
from core.transfer.partial import (
    COMMIT_INTERVAL,
    discard,
    find_resumable,
    meta_path_for,
    resume_offset_for,
    sweep_expired,
    write_meta,
)
from core.transport.manager import ConnectionManager
from core.app_errors import log_not_applied, parse_or_log
from core.protocol import ErrorCode
from core.transfer_state import (
    IncomingTransferState,
    IncomingTransferStateMachine,
    InvalidTransferTransition,
    OutgoingTransferState,
    OutgoingTransferStateMachine,
)

CHUNK_SIZE = DEFAULT_CHUNK_SIZE  # 64 KB per chunk
logger = logging.getLogger("peerc.transfer")

# Phase 35.2: remember the last N (peer, code, transfer) errors already
# reported so a peer streaming chunks at a transfer we no longer have
# gets ONE error, not one per chunk.
_ERROR_REPORT_CAP = 256

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
    peer_device_id: str = ""
    resume_offset: int = 0  # Phase 47.5: byte offset requested by receiver
    # Phase 34.1: guarded state machine (OFFERED -> WAITING_FOR_ACCEPT ->
    # SENDING -> WAITING_FOR_COMPLETE_ACK -> COMPLETED/FAILED/REJECTED/
    # CANCELLED) replaces what used to be a free-form status string
    # nothing ever read back — see RELIABILITY_DESIGN.md §6.2.
    state: OutgoingTransferStateMachine = field(default_factory=OutgoingTransferStateMachine, repr=False)
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
    peer_device_id: str = ""
    bytes_received: int = 0
    expected_chunk_index: int = 0
    resume_offset: int = 0
    last_committed: int = 0
    _first_chunk_received: bool = False
    # Phase 34.1: guarded state machine (OFFERED -> ACCEPTED -> RECEIVING
    # -> VERIFYING -> COMPLETED, with PAUSED/RESUMING modeled for a
    # future resume feature) — see RELIABILITY_DESIGN.md §6.2.
    state: IncomingTransferStateMachine = field(default_factory=IncomingTransferStateMachine, repr=False)
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
        # Phase 32.1: same registry as the ConnectionManager, so an
        # in-flight _send_chunks task can be cancelled and awaited on
        # vault lock / app shutdown instead of running against a
        # just-detached store. None (bare asyncio.create_task) when the
        # manager wasn't given one either.
        self._task_registry = getattr(manager, "_task_registry", None)

        os.makedirs(downloads_dir, exist_ok=True)

        self._outgoing: dict[str, OutgoingTransfer] = {}
        self._incoming: dict[str, IncomingTransfer] = {}
        self._offer_resume_offsets: dict[str, int] = {}
        self._reported_errors: "OrderedDict[tuple, None]" = OrderedDict()

        # Phase 47.4 / §8: sweep expired partials (> 7 days with valid sidecar) at startup
        sweep_expired(self.downloads_dir)

        if self.event_bus:
            from core.events import NetworkMessageReceived, PeerDisconnected
            self.event_bus.subscribe(NetworkMessageReceived, self._on_network_message)
            self.event_bus.subscribe(PeerDisconnected, self._on_peer_disconnected)
        else:
            # Chain onto whatever dispatcher is already set (e.g. ChatSession's) — legacy fallback.
            self._next_on_message = manager.on_message
            manager.on_message = self._dispatch

    def resume_offset_for(self, transfer_id: str) -> int:
        """Phase 47.4 / §9: return the resume offset for an offer or incoming transfer."""
        if transfer_id in self._incoming:
            return self._incoming[transfer_id].resume_offset
        return self._offer_resume_offsets.get(transfer_id, 0)

    def _is_valid_resume_offset(self, offset: any, file_size: int) -> bool:
        """Phase 47.5 / §7: validate resume_offset from file_accept.
        
        Valid: int, 0 <= offset <= size, offset % CHUNK_SIZE == 0.
        Invalid offset is ignored (send from 0), not a protocol error.
        """
        if not isinstance(offset, int) or isinstance(offset, bool):
            return False
        if offset < 0 or offset > file_size:
            return False
        if offset % CHUNK_SIZE != 0:
            return False
        return True

    def _on_peer_disconnected(self, evt: Any) -> None:
        addr_key = getattr(evt, "addr_key", None)
        peer_id = getattr(evt, "peer_id", None)
        if addr_key:
            self.handle_connection_lost(addr_key, peer_device_id=peer_id)

    def handle_connection_lost(self, addr_key: str, peer_device_id: Optional[str] = None) -> None:
        """Phase 47.4 / §8: handle transport disconnect for all transfers with addr_key.

        For each incoming transfer: flushes and fsyncs, records committed in the
        sidecar, closes the file handle, moves to FAILED with error 'connection_lost',
        and keeps both the .part file and sidecar.
        For each outgoing transfer: fails with 'connection_lost'.
        """
        matching_incoming = [t for t in self._incoming.values() if t.addr_key == addr_key]
        for transfer in matching_incoming:
            self._incoming.pop(transfer.transfer_id, None)
            self._offer_resume_offsets.pop(transfer.transfer_id, None)
            if transfer._file_handle:
                try:
                    transfer._file_handle.flush()
                    os.fsync(transfer._file_handle.fileno())
                except OSError:
                    pass
                try:
                    transfer._file_handle.close()
                except OSError:
                    pass
                transfer._file_handle = None

            committed = transfer.bytes_received - (transfer.bytes_received % CHUNK_SIZE)
            getter = getattr(self.manager, "get_peer_device_id", None)
            dev_id = transfer.peer_device_id or peer_device_id or (getter(transfer.addr_key) if callable(getter) else None)
            if dev_id and transfer.part_path and os.path.exists(transfer.part_path):
                try:
                    write_meta(
                        transfer.part_path,
                        peer_device_id=dev_id,
                        filename=transfer.filename,
                        size=transfer.size,
                        checksum=transfer.expected_checksum,
                        dest_name=os.path.basename(transfer.dest_path),
                        committed=committed,
                    )
                except Exception:
                    pass

            try:
                transfer.state.transition_to(IncomingTransferState.FAILED)
            except InvalidTransferTransition:
                pass
            # Kept per Section 8: no discard / cleanup_part_file
            self._notify_complete(transfer, False, None, error="connection_lost")

        matching_outgoing = [t for t in self._outgoing.values() if t.addr_key == addr_key]
        for transfer in matching_outgoing:
            self._fail_outgoing(transfer, "connection_lost")

    def _checkpoint_incoming(self, transfer: IncomingTransfer) -> None:
        """Phase 47.4 / §5: flush + fsync data to disk and advance committed in sidecar."""
        if not transfer._file_handle:
            return
        getter = getattr(self.manager, "get_peer_device_id", None)
        peer_device_id = transfer.peer_device_id or (getter(transfer.addr_key) if callable(getter) else None)
        if not peer_device_id or not transfer.part_path:
            return
        try:
            transfer._file_handle.flush()
            os.fsync(transfer._file_handle.fileno())
        except OSError:
            return
        committed = transfer.bytes_received - (transfer.bytes_received % CHUNK_SIZE)
        transfer.last_committed = committed
        try:
            write_meta(
                transfer.part_path,
                peer_device_id=peer_device_id,
                filename=transfer.filename,
                size=transfer.size,
                checksum=transfer.expected_checksum,
                dest_name=os.path.basename(transfer.dest_path),
                committed=committed,
            )
        except Exception:
            pass

    async def _on_network_message(self, evt: Any) -> None:
        msg_type = evt.message.get("type")
        handlers = {
            "file_offer": self._handle_offer,
            "file_accept": self._handle_accept,
            "file_reject": self._handle_reject,
            "file_data": self._handle_chunk,
            "file_done": self._handle_done,
            "file_complete_ack": self._handle_complete_ack,
            "error": self._handle_error,
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
            "error": self._handle_error,
        }
        handler = handlers.get(msg_type)
        if handler:
            await handler(addr_key, message)
            if msg_type == "error" and getattr(self, "_next_on_message", None):
                await self._next_on_message(addr_key, message)  # ChatSession correlates message_id
        elif getattr(self, "_next_on_message", None):
            await self._next_on_message(addr_key, message)

    async def _report_once(self, addr_key: str, code: ErrorCode, transfer_id) -> None:
        """Phase 35.2: tell the peer about an outcome no existing response
        covers, at most once per (peer, code, transfer). Never answers an
        `error` (nothing that handles one calls this)."""
        if not isinstance(transfer_id, str) or not transfer_id or len(transfer_id) > 128:
            return
        key = (addr_key, code, transfer_id)
        if key in self._reported_errors:
            return
        self._reported_errors[key] = None
        while len(self._reported_errors) > _ERROR_REPORT_CAP:
            self._reported_errors.popitem(last=False)
        await self.manager.send_error(addr_key, code, context={"transfer_id": transfer_id})

    def _fail_outgoing(self, transfer: "OutgoingTransfer", error: str) -> bool:
        """Resolve an outgoing transfer as FAILED from anywhere (send
        failure, peer error, peer abort). Idempotent: returns False if it
        had already resolved, so a duplicate/late signal can't notify twice."""
        try:
            transfer.state.transition_to(OutgoingTransferState.FAILED)
        except InvalidTransferTransition:
            return False
        self._outgoing.pop(transfer.transfer_id, None)
        transfer._ack_success = False
        transfer._ack_event.set()  # wake _send_chunks if it's waiting on the ack
        self._notify_complete(transfer, False, None, error=error)
        return True

    def _fail_incoming(self, transfer: "IncomingTransfer", error: str) -> bool:
        """Resolve an incoming transfer as FAILED because the sender said
        so — cleans up locally and sends nothing back."""
        try:
            transfer.state.transition_to(IncomingTransferState.FAILED)
        except InvalidTransferTransition:
            return False
        self._incoming.pop(transfer.transfer_id, None)
        self._offer_resume_offsets.pop(transfer.transfer_id, None)
        if transfer._file_handle:
            try:
                transfer._file_handle.flush()
                os.fsync(transfer._file_handle.fileno())
            except OSError:
                pass
            try:
                transfer._file_handle.close()
            except OSError:
                pass
            transfer._file_handle = None

        committed = transfer.bytes_received - (transfer.bytes_received % CHUNK_SIZE)
        getter = getattr(self.manager, "get_peer_device_id", None)
        peer_device_id = transfer.peer_device_id or (getter(transfer.addr_key) if callable(getter) else None)
        if peer_device_id and transfer.part_path and os.path.exists(transfer.part_path):
            try:
                write_meta(
                    transfer.part_path,
                    peer_device_id=peer_device_id,
                    filename=transfer.filename,
                    size=transfer.size,
                    checksum=transfer.expected_checksum,
                    dest_name=os.path.basename(transfer.dest_path),
                    committed=committed,
                )
            except Exception:
                pass
        # Phase 47.4 / §8: peer-reported terminal error keeps the partial and sidecar
        self._notify_complete(transfer, False, None, error=error)
        return True

    async def _handle_error(self, addr_key: str, message: dict) -> None:
        """Phase 35.2 / §7.3: correlate a received `error` with an active
        transfer *with this same peer*. Only a terminal code fails it;
        unsolicited, duplicate, late, wrong-peer or non-terminal errors
        are logged at debug level and change nothing."""
        info = parse_or_log(message)
        if info is None:
            return
        transfer_id = info.context.get("transfer_id")
        if transfer_id is None:
            return  # not about a transfer — ChatSession / the UI handle other contexts
        out = self._outgoing.get(transfer_id)
        inc = self._incoming.get(transfer_id)
        if out is not None and out.addr_key != addr_key:
            out = None
        if inc is not None and inc.addr_key != addr_key:
            inc = None
        if out is None and inc is None:
            log_not_applied(info, "no matching active transfer with this peer")
            return
        if not info.terminal:
            log_not_applied(info, "code is not terminal; transfer state unchanged")
            return
        error = info.code.value.lower()
        applied = self._fail_outgoing(out, error) if out is not None else self._fail_incoming(inc, error)
        if not applied:
            log_not_applied(info, "transfer already resolved")

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
            getter = getattr(self.manager, "get_peer_device_id", None)
            peer_device_id = getattr(transfer, "peer_device_id", "") or (getter(transfer.addr_key) if callable(getter) else None)
            resumed_from = getattr(transfer, "resume_offset", 0) if not is_outgoing else 0
            self.event_bus.post(
                TransferCompleted(
                    transfer_id=transfer.transfer_id,
                    success=success,
                    filepath=filepath,
                    error=error,
                    addr_key=transfer.addr_key,
                    peer_device_id=peer_device_id,
                    direction="sent" if is_outgoing else "received",
                    filename=transfer.filename,
                    size=transfer.size,
                    checksum=transfer.checksum if is_outgoing else transfer.expected_checksum,
                    timestamp=time.time(),
                    resumed_from=resumed_from,
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

        getter = getattr(self.manager, "get_peer_device_id", None)
        peer_device_id = getter(addr_key) if callable(getter) else ""
        transfer = OutgoingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filepath=filepath,
            filename=filename, size=size, checksum=checksum,
            peer_device_id=peer_device_id or "",
        )

        offer = protocol.make_file_offer(
            transfer_id, sender_id=self.manager.my_identity.device_id,
            sender_name=self.manager.my_name, filename=filename,
            size=size, checksum=checksum,
        )
        ok = await self.manager.send(addr_key, offer)
        if not ok:
            return None

        transfer.state.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
        self._outgoing[transfer_id] = transfer
        return transfer_id

    async def _handle_accept(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            await self._report_once(addr_key, ErrorCode.TRANSFER_NOT_FOUND, message.get("transfer_id"))
            return
        
        # Phase 47.5 / §7: read and validate resume_offset from file_accept
        resume_offset = message.get("resume_offset", 0)
        if self._is_valid_resume_offset(resume_offset, transfer.size):
            transfer.resume_offset = resume_offset
            if resume_offset > 0:
                logger.info(
                    "Transfer %s: resuming from offset %d (%.1f%%)",
                    transfer.transfer_id,
                    resume_offset,
                    100.0 * resume_offset / transfer.size if transfer.size > 0 else 0,
                )
        else:
            # Invalid offset is logged and ignored (send from 0); receiver will detect restart
            if resume_offset != 0:
                logger.warning(
                    "Transfer %s: ignoring invalid resume_offset %r (type=%s, size=%d)",
                    transfer.transfer_id,
                    resume_offset,
                    type(resume_offset).__name__,
                    transfer.size,
                )
            transfer.resume_offset = 0
        
        try:
            transfer.state.transition_to(OutgoingTransferState.SENDING)
        except InvalidTransferTransition:
            return  # duplicate/late accept for a transfer already past this point — drop it
        if self._task_registry is not None:
            self._task_registry.create_task(
                self._send_chunks(transfer), group="transfer",
                name=f"send_chunks:{transfer.transfer_id}",
            )
        else:
            asyncio.create_task(self._send_chunks(transfer))

    async def _handle_reject(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        try:
            transfer.state.transition_to(OutgoingTransferState.REJECTED)
        except InvalidTransferTransition:
            return  # a reject arriving after this transfer already resolved — drop it
        self._notify_complete(transfer, False, None, error="rejected")
        self._outgoing.pop(transfer.transfer_id, None)

    async def _send_chunks(self, transfer: OutgoingTransfer) -> None:
        bytes_sent = transfer.resume_offset  # Phase 47.5: start progress from resume offset
        try:
            # Phase 47.5 / §7: stream from resume_offset
            for index, offset, chunk in read_chunks(
                transfer.filepath, start_offset=transfer.resume_offset, chunk_size=CHUNK_SIZE
            ):
                if transfer.state.state is not OutgoingTransferState.SENDING:
                    return  # resolved from outside (peer error / abort) — stop streaming
                payload = protocol.encode_file_data(transfer.transfer_id, index, offset, chunk)
                ok = await self.manager.send_binary(transfer.addr_key, payload)
                if not ok:
                    self._fail_outgoing(transfer, "send_failed")
                    return
                bytes_sent += len(chunk)
                self._notify_progress(transfer.transfer_id, bytes_sent, transfer.size, is_upload=True)

            # Phase 47.5 / §7: if offset == size, no chunk is sent, only file_done
            if transfer.state.state is not OutgoingTransferState.SENDING:
                return
            done = protocol.make_file_done(transfer.transfer_id, transfer.checksum)
            await self.manager.send(transfer.addr_key, done)
            try:
                transfer.state.transition_to(OutgoingTransferState.WAITING_FOR_COMPLETE_ACK)
            except InvalidTransferTransition:
                return  # resolved from outside while file_done was in flight

            try:
                await asyncio.wait_for(transfer._ack_event.wait(), COMPLETE_ACK_TIMEOUT)
                success = transfer._ack_success
            except asyncio.TimeoutError:
                success = False

            if transfer.state.state is not OutgoingTransferState.WAITING_FOR_COMPLETE_ACK:
                return  # resolved from outside while waiting — already notified
            transfer.state.transition_to(
                OutgoingTransferState.COMPLETED if success else OutgoingTransferState.FAILED
            )
            self._notify_complete(
                transfer,
                success,
                transfer.filepath if success else None,
                error=None if success else "ack_failed_or_timeout",
            )
        except OSError:
            self._fail_outgoing(transfer, "os_error")
        finally:
            self._outgoing.pop(transfer.transfer_id, None)

    async def _handle_complete_ack(self, addr_key: str, message: dict) -> None:
        transfer = self._outgoing.get(message["transfer_id"])
        if transfer is None:
            return
        state = transfer.state.state
        if state is OutgoingTransferState.WAITING_FOR_COMPLETE_ACK:
            transfer._ack_success = bool(message.get("success"))
            transfer._ack_event.set()
        elif state is OutgoingTransferState.SENDING and not message.get("success"):
            # The receiver aborted mid-stream (out-of-order chunk, size
            # exceeded, ...): stop streaming instead of finishing the file
            # and only then noticing.
            self._fail_outgoing(transfer, "peer_aborted")
        # anything else is a duplicate / premature / late ack — drop it

    # ---- Receiver side -------------------------------------------------

    async def _handle_offer(self, addr_key: str, message: dict) -> None:
        transfer_id = message["transfer_id"]
        filename = message["filename"]
        size = message["size"]
        checksum = message["checksum"]
        sender_name = message.get("sender_name") or "peer"

        # Phase 47.4 / §8: sweep expired partials (> 7 days) on every offer
        sweep_expired(self.downloads_dir)

        # BUG-002: reject oversized offers before ever asking the user.
        if size > MAX_INCOMING_FILE_SIZE:
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        # Phase 47.4 / §5: Busy partial hazard check — if an active incoming transfer
        # is already receiving this file from this peer, reject immediately rather than touching it.
        for active in self._incoming.values():
            if active.addr_key == addr_key and active.filename == filename:
                await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
                return

        # Phase 47.4 / §5: check for an authenticated match in partial downloads
        getter = getattr(self.manager, "get_peer_device_id", None)
        peer_device_id = getter(addr_key) if callable(getter) else None

        partial_info = None
        resume_offset = 0

        if peer_device_id:
            info = find_resumable(
                self.downloads_dir,
                peer_device_id=peer_device_id,
                filename=filename,
                size=size,
                checksum=checksum,
            )
            if info is not None:
                # If a live incoming transfer holds this partial, reject rather than touching it
                if any(active.part_path == info.part_path for active in self._incoming.values()):
                    await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
                    return

                offset = resume_offset_for(info, chunk_size=CHUNK_SIZE)
                if offset > 0:
                    try:
                        dest_path = resolve_safe_dest_path(
                            info.dest_name, self.downloads_dir, allow_existing_part=True
                        )
                        if os.path.basename(dest_path) == info.dest_name:
                            partial_info = info
                            resume_offset = offset
                        else:
                            discard(info.part_path)
                    except TransferSecurityError:
                        discard(info.part_path)
                else:
                    discard(info.part_path)

        if partial_info is not None:
            dest_path = os.path.join(self.downloads_dir, partial_info.dest_name)
            part_path = partial_info.part_path
        else:
            try:
                dest_path = self._safe_dest_path(filename)
            except PathTraversalError:
                await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
                return
            part_path = get_part_path(dest_path)

        # Phase 47.4 / §5: busy partial hazard check — if a live incoming transfer
        # already holds the partial's path, a second offer for it is rejected rather than touching it.
        for active in self._incoming.values():
            if active.part_path == part_path or active.dest_path == dest_path:
                await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
                return

        # Phase 47.4 / §5: disk-space pre-check using remaining bytes
        needed_bytes = size - resume_offset
        if not check_disk_space(self.downloads_dir, needed_bytes):
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        self._offer_resume_offsets[transfer_id] = resume_offset

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
            self._offer_resume_offsets.pop(transfer_id, None)
            if partial_info is not None:
                discard(partial_info.part_path)
            await self.manager.send(addr_key, protocol.make_file_reject(transfer_id))
            return

        self._offer_resume_offsets.pop(transfer_id, None)

        incoming = IncomingTransfer(
            transfer_id=transfer_id, addr_key=addr_key, filename=filename,
            size=size, expected_checksum=checksum, sender_name=sender_name,
            dest_path=dest_path, part_path=part_path,
            peer_device_id=peer_device_id or "",
            resume_offset=resume_offset,
            bytes_received=resume_offset,
            expected_chunk_index=resume_offset // CHUNK_SIZE,
            last_committed=resume_offset,
            _first_chunk_received=(resume_offset == 0),
        )

        if resume_offset > 0:
            try:
                handle = open(part_path, "r+b")
                handle.seek(resume_offset)
                handle.truncate(resume_offset)
                incoming._file_handle = handle
            except OSError:
                discard(part_path)
                resume_offset = 0
                incoming.resume_offset = 0
                incoming.bytes_received = 0
                incoming.expected_chunk_index = 0
                incoming.last_committed = 0
                incoming._first_chunk_received = True
                handle = open(part_path, "wb")
                incoming._file_handle = handle
        else:
            discard(part_path)
            incoming._file_handle = open(part_path, "wb")

        if peer_device_id:
            try:
                write_meta(
                    part_path,
                    peer_device_id=peer_device_id,
                    filename=filename,
                    size=size,
                    checksum=checksum,
                    dest_name=os.path.basename(dest_path),
                    committed=resume_offset,
                )
            except Exception:
                pass

        incoming.state.transition_to(IncomingTransferState.ACCEPTED)
        self._incoming[transfer_id] = incoming

        await self.manager.send(
            addr_key, protocol.make_file_accept(transfer_id, resume_offset=resume_offset)
        )

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
            await self._report_once(addr_key, ErrorCode.TRANSFER_NOT_FOUND, message.get("transfer_id"))
            return

        try:
            transfer.state.transition_to(IncomingTransferState.RECEIVING)
        except InvalidTransferTransition:
            # A chunk arrived for a transfer that's paused, or already
            # resolved to a terminal state — reject rather than write it,
            # and say so (once) instead of silently swallowing it.
            await self._report_once(addr_key, ErrorCode.INVALID_STATE, message.get("transfer_id"))
            return

        sequence = message["sequence"]
        offset = message["offset"]

        # Phase 47.4 / §6: restart detection (old sender or ignored offset)
        if transfer.resume_offset > 0 and not transfer._first_chunk_received:
            transfer._first_chunk_received = True
            if sequence == transfer.expected_chunk_index and offset == transfer.bytes_received:
                pass
            elif sequence == 0 and offset == 0:
                logger.info(
                    "Sender did not resume transfer %s; restarting from beginning",
                    transfer.transfer_id,
                )
                try:
                    transfer._file_handle.seek(0)
                    transfer._file_handle.truncate(0)
                except OSError:
                    await self._abort_incoming(transfer, "os_error")
                    return
                transfer.bytes_received = 0
                transfer.expected_chunk_index = 0
                transfer.resume_offset = 0
                transfer.last_committed = 0
                getter = getattr(self.manager, "get_peer_device_id", None)
                peer_device_id = getter(transfer.addr_key) if callable(getter) else None
                if peer_device_id:
                    try:
                        write_meta(
                            transfer.part_path,
                            peer_device_id=peer_device_id,
                            filename=transfer.filename,
                            size=transfer.size,
                            checksum=transfer.expected_checksum,
                            dest_name=os.path.basename(transfer.dest_path),
                            committed=0,
                        )
                    except Exception:
                        pass
            else:
                await self._abort_incoming(transfer, "out-of-order chunk")
                return
        else:
            transfer._first_chunk_received = True

        if sequence != transfer.expected_chunk_index or offset != transfer.bytes_received:
            await self._abort_incoming(transfer, "out-of-order chunk")
            return

        data = message["data"]

        if transfer.bytes_received + len(data) > transfer.size:
            await self._abort_incoming(transfer, "declared size exceeded")
            return

        # H-1 (security audit): wrap write in OSError so a full disk aborts cleanly
        # instead of propagating an unhandled exception through the dispatch loop.
        try:
            transfer._file_handle.write(data)
        except OSError:
            await self._abort_incoming(transfer, "disk_full")
            return
        transfer.bytes_received += len(data)
        transfer.expected_chunk_index += 1

        if transfer.bytes_received - transfer.last_committed >= COMMIT_INTERVAL:
            self._checkpoint_incoming(transfer)

        self._notify_progress(transfer.transfer_id, transfer.bytes_received, transfer.size, is_upload=False)

    async def _abort_incoming(self, transfer: "IncomingTransfer", reason: str) -> None:
        self._incoming.pop(transfer.transfer_id, None)
        self._offer_resume_offsets.pop(transfer.transfer_id, None)
        if transfer._file_handle:
            try:
                transfer._file_handle.close()
            except OSError:
                pass
            transfer._file_handle = None
        if transfer.part_path:
            discard(transfer.part_path)
        if os.path.exists(transfer.dest_path):
            try:
                os.remove(transfer.dest_path)
            except OSError:
                pass
        try:
            transfer.state.transition_to(IncomingTransferState.FAILED)
        except InvalidTransferTransition:
            pass  # already resolved — the file/dir cleanup above still ran either way
        await self.manager.send(
            transfer.addr_key,
            protocol.make_file_complete_ack(transfer.transfer_id, False, reason),
        )
        self._notify_complete(transfer, False, None, error=reason)

    async def _handle_done(self, addr_key: str, message: dict) -> None:
        transfer = self._incoming.get(message["transfer_id"])
        if transfer is None:
            await self._report_once(addr_key, ErrorCode.TRANSFER_NOT_FOUND, message.get("transfer_id"))
            return
        try:
            # A zero-byte file sends no chunks, so the transfer can still
            # be ACCEPTED here — step through RECEIVING so the table
            # (ACCEPTED -> RECEIVING -> VERIFYING) stays strict.
            if transfer.state.state is IncomingTransferState.ACCEPTED:
                transfer.state.transition_to(IncomingTransferState.RECEIVING)
            transfer.state.transition_to(IncomingTransferState.VERIFYING)
        except InvalidTransferTransition:
            # file_done for a paused/already-resolved transfer: leave the
            # entry alone (it isn't ours to finish) and say so, once.
            await self._report_once(addr_key, ErrorCode.INVALID_STATE, message.get("transfer_id"))
            return
        self._incoming.pop(transfer.transfer_id, None)
        self._offer_resume_offsets.pop(transfer.transfer_id, None)
        if transfer._file_handle:
            try:
                transfer._file_handle.close()
            except OSError:
                pass
            transfer._file_handle = None

        actual_checksum = sha256_file(transfer.part_path)
        expected_checksum = transfer.expected_checksum
        success = actual_checksum == expected_checksum and transfer.bytes_received == transfer.size

        detail = "" if success else "checksum mismatch"
        await self.manager.send(
            addr_key, protocol.make_file_complete_ack(transfer.transfer_id, success, detail)
        )

        if not success:
            transfer.state.transition_to(IncomingTransferState.FAILED)
            discard(transfer.part_path)
            self._notify_complete(transfer, False, None, error="checksum_mismatch")
            return

        # Atomically rename .part to final dest_path
        finalize_part_file(transfer.part_path, transfer.dest_path)
        # Phase 47.4: clean up sidecar metadata on success
        discard(transfer.part_path)

        transfer.state.transition_to(IncomingTransferState.COMPLETED)
        self._notify_complete(transfer, True, transfer.dest_path)