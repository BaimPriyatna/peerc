"""tests/test_error_integration.py — Phase 35.2: Error integration.

Producers (RELIABILITY_DESIGN.md §7.1/§7.3): INVALID_FRAME from the read
loop, TRANSFER_NOT_FOUND / INVALID_STATE from FileTransferSession — each
only where no existing response (file_reject, file_complete_ack) already
covers the outcome.

Consumers: FileTransferSession and ChatSession correlate an `error` with
an active operation *with the same peer* and only a terminal code fails
it; unsolicited, duplicate, late, wrong-peer and non-terminal errors
change nothing. And nothing that handles an `error` ever sends one back.
"""

import asyncio
import os
import random
import tempfile

import pytest

import chat
import file_transfer
import protocol
from core.identity.device_identity import generate_keypair
from core.task_registry import TaskRegistry
from core.transfer_state import IncomingTransferState, OutgoingTransferState
from peer import ConnectionManager

pytestmark = pytest.mark.integration


def _ports(n: int = 2):
    base = random.randint(20000, 40000)
    return [base + i for i in range(n)]


async def _pair(on_message_a=None, registry_a=None):
    port_a, port_b = _ports()
    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A",
        on_message=on_message_a, task_registry=registry_a,
    )
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()
    addr_key = await manager_a.connect_to("127.0.0.1", port_b)
    await asyncio.sleep(0.1)
    return manager_a, manager_b, addr_key


# ---------------------------------------------------------------------
# INVALID_FRAME producer
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malformed_authenticated_frame_gets_invalid_frame_error_then_drop():
    received = []

    async def on_a(addr_key, msg):
        received.append(msg)

    manager_a, manager_b, addr_key = await _pair(on_message_a=on_a)
    try:
        session = manager_a._connections[addr_key]
        # Authenticated, but missing the fields a chat needs.
        await session.send({"type": "chat", "version": 2, "message_id": "m-77"})
        await asyncio.sleep(0.3)

        errors = [m for m in received if m.get("type") == "error"]
        assert len(errors) == 1
        assert errors[0]["code"] == "INVALID_FRAME"
        assert errors[0]["context"] == {"message_id": "m-77"}
        # ...and B still drops the connection as it always has.
        assert not manager_b._connections
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_a_malformed_error_frame_is_never_answered_with_an_error():
    received = []

    async def on_a(addr_key, msg):
        received.append(msg)

    manager_a, manager_b, addr_key = await _pair(on_message_a=on_a)
    try:
        session = manager_a._connections[addr_key]
        await session.send({"type": "error", "version": 2, "code": "DISK_FULL"})  # no message
        await asyncio.sleep(0.3)

        assert [m for m in received if m.get("type") == "error"] == []  # no ping-pong
        assert not manager_b._connections  # still dropped
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_send_error_never_raises_and_rejects_unknown_codes_quietly():
    manager_a, manager_b, addr_key = await _pair()
    try:
        assert await manager_a.send_error("no-such-peer", "DISK_FULL") is False
        assert await manager_a.send_error(addr_key, "NOT_A_CODE") is False
        assert await manager_a.send_error(addr_key, "DISK_FULL", context={"path": "/etc"}) is True
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# TRANSFER_NOT_FOUND producer + sender reaction (real sockets)
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receiver_that_lost_the_transfer_makes_the_sender_stop_promptly():
    registry_a = TaskRegistry()
    manager_a, manager_b, addr_key = await _pair(registry_a=registry_a)
    tmp_a = tempfile.mkdtemp(prefix="peerc_err_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_err_b_")
    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir=tmp_a)
    ft_b = file_transfer.FileTransferSession(manager_b, downloads_dir=tmp_b)

    notified = []
    real_notify = ft_a._notify_complete

    def spy_notify(transfer, success, path, error=None):
        notified.append((transfer.transfer_id, success, error))
        return real_notify(transfer, success, path, error=error)

    ft_a._notify_complete = spy_notify

    sent_errors = []
    real_send_error = manager_b.send_error

    async def spy_send_error(*args, **kwargs):
        sent_errors.append((args, kwargs))
        return await real_send_error(*args, **kwargs)

    manager_b.send_error = spy_send_error

    real_send_binary = manager_a.send_binary
    chunks_sent = []

    async def slow_send_binary(*args, **kwargs):
        await asyncio.sleep(0.05)
        chunks_sent.append(1)
        return await real_send_binary(*args, **kwargs)

    manager_a.send_binary = slow_send_binary

    src = os.path.join(tmp_a, "payload.bin")
    with open(src, "wb") as f:
        f.write(os.urandom(2_000_000))  # ~31 chunks at 50 ms: far longer than the assertions below

    try:
        transfer_id = await ft_a.offer_file(addr_key, src)
        await asyncio.sleep(0.25)                      # transfer is streaming
        assert registry_a.active_count("transfer") == 1
        ft_b._incoming.clear()                         # B "forgets" the transfer

        for _ in range(40):                            # ≤ 2 s
            if notified:
                break
            await asyncio.sleep(0.05)

        assert notified == [(transfer_id, False, "transfer_not_found")]
        assert ft_a._outgoing.get(transfer_id) is None
        for _ in range(20):
            if registry_a.active_count("transfer") == 0:
                break
            await asyncio.sleep(0.05)
        assert registry_a.active_count("transfer") == 0  # streaming actually stopped

        settled = len(chunks_sent)
        await asyncio.sleep(0.3)
        assert len(chunks_sent) == settled              # ...and stays stopped

        # One error for the whole stream of chunks, not one per chunk.
        assert len(sent_errors) == 1
    finally:
        await registry_a.cancel_all()
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# FileTransferSession: correlating a received `error`
# ---------------------------------------------------------------------

class _SpyManager:
    """Just enough of ConnectionManager for handler-level tests; records
    everything sent so we can assert nothing is sent in reply to an error."""

    def __init__(self):
        self.event_bus = None
        self.on_message = None
        self.sent = []

    async def send(self, addr_key, message):
        self.sent.append(("send", addr_key, message))
        return True

    async def send_binary(self, addr_key, payload):
        self.sent.append(("send_binary", addr_key, payload))
        return True

    async def send_error(self, addr_key, code, *, context=None):
        self.sent.append(("send_error", addr_key, code))
        return True


def _ft():
    manager = _SpyManager()
    ft = file_transfer.FileTransferSession(manager, downloads_dir=tempfile.mkdtemp(prefix="peerc_err_ft_"))
    notified = []
    real = ft._notify_complete
    ft._notify_complete = lambda t, ok, path, error=None: (notified.append((t.transfer_id, ok, error)), real(t, ok, path, error=error))
    return ft, manager, notified


def _outgoing(ft, tid="t-out", addr_key="peer-a", state=OutgoingTransferState.SENDING):
    t = file_transfer.OutgoingTransfer(
        transfer_id=tid, addr_key=addr_key, filepath="/dev/null", filename="x", size=0, checksum="",
    )
    t.state.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    if state in (OutgoingTransferState.SENDING, OutgoingTransferState.WAITING_FOR_COMPLETE_ACK):
        t.state.transition_to(OutgoingTransferState.SENDING)
    if state is OutgoingTransferState.WAITING_FOR_COMPLETE_ACK:
        t.state.transition_to(OutgoingTransferState.WAITING_FOR_COMPLETE_ACK)
    ft._outgoing[tid] = t
    return t


def _err(code, **ctx):
    return protocol.make_error(code, context=ctx)


@pytest.mark.asyncio
async def test_terminal_error_fails_the_matching_outgoing_transfer_exactly_once():
    ft, manager, notified = _ft()
    t = _outgoing(ft)

    await ft._handle_error("peer-a", _err("TRANSFER_NOT_FOUND", transfer_id="t-out"))
    await ft._handle_error("peer-a", _err("TRANSFER_NOT_FOUND", transfer_id="t-out"))  # duplicate

    assert t.state.state is OutgoingTransferState.FAILED
    assert notified == [("t-out", False, "transfer_not_found")]
    assert "t-out" not in ft._outgoing
    assert manager.sent == []  # nothing is ever sent in reply to an error


@pytest.mark.asyncio
async def test_error_wakes_a_sender_waiting_for_the_completion_ack():
    ft, _, notified = _ft()
    t = _outgoing(ft, state=OutgoingTransferState.WAITING_FOR_COMPLETE_ACK)

    await ft._handle_error("peer-a", _err("INTERNAL_ERROR", transfer_id="t-out"))

    assert t._ack_event.is_set()
    assert t._ack_success is False
    assert t.state.state is OutgoingTransferState.FAILED
    assert len(notified) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", [
    "wrong_peer", "non_terminal_code", "unknown_transfer", "no_transfer_id", "malformed",
])
async def test_errors_that_should_change_nothing(scenario):
    ft, manager, notified = _ft()
    t = _outgoing(ft)

    if scenario == "wrong_peer":
        msg, sender = _err("TRANSFER_NOT_FOUND", transfer_id="t-out"), "some-other-peer"
    elif scenario == "non_terminal_code":
        msg, sender = _err("INVALID_STATE", transfer_id="t-out"), "peer-a"
    elif scenario == "unknown_transfer":
        msg, sender = _err("TRANSFER_NOT_FOUND", transfer_id="never-heard-of-it"), "peer-a"
    elif scenario == "no_transfer_id":
        msg, sender = _err("TRANSFER_NOT_FOUND"), "peer-a"
    else:
        msg, sender = {"type": "error", "code": "DISK_FULL"}, "peer-a"

    await ft._handle_error(sender, msg)  # must not raise

    assert t.state.state is OutgoingTransferState.SENDING
    assert "t-out" in ft._outgoing
    assert notified == []
    assert manager.sent == []


@pytest.mark.asyncio
async def test_terminal_error_fails_an_incoming_transfer_and_cleans_up_without_replying():
    ft, manager, notified = _ft()
    part = os.path.join(ft.downloads_dir, "x.part")
    incoming = file_transfer.IncomingTransfer(
        transfer_id="t-in", addr_key="peer-a", filename="x", size=100, expected_checksum="",
        sender_name="peer", dest_path=os.path.join(ft.downloads_dir, "x"), part_path=part,
    )
    incoming._file_handle = open(part, "wb")
    incoming.state.transition_to(IncomingTransferState.ACCEPTED)
    ft._incoming["t-in"] = incoming

    await ft._handle_error("peer-a", _err("TRANSFER_EXPIRED", transfer_id="t-in"))

    assert incoming.state.state is IncomingTransferState.FAILED
    assert "t-in" not in ft._incoming
    assert not os.path.exists(part)
    assert notified == [("t-in", False, "transfer_expired")]
    assert manager.sent == []


@pytest.mark.asyncio
async def test_negative_completion_ack_mid_stream_stops_the_sender():
    ft, _, notified = _ft()
    t = _outgoing(ft)  # SENDING

    await ft._handle_complete_ack(
        "peer-a", {"type": "file_complete_ack", "transfer_id": "t-out", "success": False},
    )

    assert t.state.state is OutgoingTransferState.FAILED
    assert notified == [("t-out", False, "peer_aborted")]


@pytest.mark.asyncio
async def test_unknown_transfer_reports_are_deduplicated_and_bounded():
    ft, manager, _ = _ft()
    for _ in range(50):
        await ft._report_once("peer-a", file_transfer.ErrorCode.TRANSFER_NOT_FOUND, "ghost")
    assert [s for s in manager.sent if s[0] == "send_error"] == [
        ("send_error", "peer-a", file_transfer.ErrorCode.TRANSFER_NOT_FOUND),
    ]

    # Junk / oversized ids are never echoed back at all.
    await ft._report_once("peer-a", file_transfer.ErrorCode.TRANSFER_NOT_FOUND, "x" * 500)
    await ft._report_once("peer-a", file_transfer.ErrorCode.TRANSFER_NOT_FOUND, None)
    await ft._report_once("peer-a", file_transfer.ErrorCode.TRANSFER_NOT_FOUND, 42)
    assert len([s for s in manager.sent if s[0] == "send_error"]) == 1

    for i in range(file_transfer._ERROR_REPORT_CAP + 50):
        await ft._report_once("peer-a", file_transfer.ErrorCode.INVALID_STATE, f"t-{i}")
    assert len(ft._reported_errors) <= file_transfer._ERROR_REPORT_CAP


@pytest.mark.asyncio
async def test_legacy_dispatch_handles_an_error_and_still_forwards_it():
    manager = _SpyManager()
    forwarded = []

    async def downstream(addr_key, message):
        forwarded.append(message["type"])

    manager.on_message = downstream
    ft = file_transfer.FileTransferSession(manager, downloads_dir=tempfile.mkdtemp(prefix="peerc_err_leg_"))
    t = _outgoing(ft)

    await ft._dispatch("peer-a", _err("SIZE_EXCEEDED", transfer_id="t-out"))

    assert t.state.state is OutgoingTransferState.FAILED
    assert forwarded == ["error"]  # ChatSession can correlate message_id too


# ---------------------------------------------------------------------
# ChatSession: correlating a received `error`
# ---------------------------------------------------------------------

def _chat_with_pending(message_id="m-1", addr_key="peer-a"):
    manager = _SpyManager()
    statuses = []
    session = chat.ChatSession(manager, on_status_change=lambda mid, s: statuses.append((mid, s)))
    session._pending[message_id] = chat.SentMessageState(message_id=message_id, addr_key=addr_key)
    return session, manager, statuses


def test_terminal_error_fails_the_matching_pending_chat_message_once():
    session, manager, statuses = _chat_with_pending()

    session._handle_error("peer-a", _err("INVALID_FRAME", message_id="m-1"))
    session._handle_error("peer-a", _err("INVALID_FRAME", message_id="m-1"))  # duplicate

    assert statuses == [("m-1", "failed")]
    assert "m-1" not in session._pending
    assert manager.sent == []


@pytest.mark.parametrize("scenario", [
    "wrong_peer", "non_terminal_code", "unknown_message", "no_message_id", "malformed",
])
def test_chat_errors_that_should_change_nothing(scenario):
    session, manager, statuses = _chat_with_pending()

    if scenario == "wrong_peer":
        session._handle_error("someone-else", _err("INVALID_FRAME", message_id="m-1"))
    elif scenario == "non_terminal_code":
        session._handle_error("peer-a", _err("RATE_LIMITED", message_id="m-1", retry_after=5))
    elif scenario == "unknown_message":
        session._handle_error("peer-a", _err("INVALID_FRAME", message_id="m-999"))
    elif scenario == "no_message_id":
        session._handle_error("peer-a", _err("INVALID_FRAME"))
    else:
        session._handle_error("peer-a", {"type": "error"})

    assert statuses == []
    assert "m-1" in session._pending
    assert manager.sent == []
