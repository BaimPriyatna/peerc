"""tests/test_transfer_fsm_integration.py — Phase 34.1: Transfer FSMs wired
into the live FileTransferSession.

The state machines themselves are covered in isolation by
tests/test_transfer_fsm.py; this confirms file_transfer.py actually drives
and honors them: a real transfer reaches COMPLETED on both sides, a
duplicate accept no longer spawns a second _send_chunks task (previously
unguarded — `.status` was a write-only string nothing read back), a
late/duplicate completion ack and a chunk after a terminal or paused
state are dropped, a reject lands in REJECTED, and a zero-byte file (no
chunks, so still ACCEPTED when file_done arrives) still completes.
"""

import asyncio
import os
import random
import tempfile

import pytest

from core.transfer.session import FileTransferSession, IncomingTransfer, OutgoingTransfer
from core import protocol
from core.identity.device_identity import generate_keypair
from core.task_registry import TaskRegistry
from core.transfer_state import (
    IncomingTransferState,
    OutgoingTransferState,
)
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.integration


def _ports(n: int = 2):
    base = random.randint(20000, 40000)
    return [base + i for i in range(n)]


async def _pair(registry_a=None, on_offer_received_b=None):
    port_a, port_b = _ports()
    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A", task_registry=registry_a,
    )
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()
    tmp_a = tempfile.mkdtemp(prefix="peerc_tfsm_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_tfsm_b_")
    ft_a = FileTransferSession(manager_a, downloads_dir=tmp_a)
    ft_b = FileTransferSession(
        manager_b, downloads_dir=tmp_b, on_offer_received=on_offer_received_b,
    )
    addr_key = await manager_a.connect_to("127.0.0.1", port_b)
    await asyncio.sleep(0.1)
    return manager_a, manager_b, ft_a, ft_b, addr_key, tmp_a


def _write(directory: str, name: str, size: int) -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


@pytest.mark.asyncio
async def test_real_transfer_reaches_completed_on_both_sides():
    manager_a, manager_b, ft_a, ft_b, addr_key, tmp_a = await _pair()
    done = asyncio.Event()
    ft_a.on_complete = lambda tid, ok, path: done.set()

    # Slow each chunk down so B's IncomingTransfer stays in _incoming long
    # enough to grab a reference (it's popped on completion) instead of
    # racing loopback I/O.
    real_send_binary = manager_a.send_binary

    async def slow_send_binary(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await real_send_binary(*args, **kwargs)

    manager_a.send_binary = slow_send_binary

    src = _write(tmp_a, "payload.bin", 300_000)
    try:
        transfer_id = await ft_a.offer_file(addr_key, src)
        outgoing = ft_a._outgoing[transfer_id]
        assert outgoing.state.state is OutgoingTransferState.WAITING_FOR_ACCEPT

        incoming = None
        for _ in range(100):
            incoming = ft_b._incoming.get(transfer_id)
            if incoming is not None:
                break
            await asyncio.sleep(0.01)
        assert incoming is not None

        await asyncio.wait_for(done.wait(), timeout=10.0)
        await asyncio.sleep(0.1)

        assert outgoing.state.state is OutgoingTransferState.COMPLETED
        assert incoming.state.state is IncomingTransferState.COMPLETED
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_duplicate_accept_does_not_spawn_second_send_task():
    """Previously nothing guarded this: a second file_accept re-ran
    _handle_accept and spawned a second _send_chunks task for the same
    transfer (found while writing the 29/30.1 reliability tests)."""
    registry_a = TaskRegistry()
    manager_a, manager_b, ft_a, ft_b, addr_key, tmp_a = await _pair(registry_a=registry_a)

    real_send_binary = manager_a.send_binary

    async def slow_send_binary(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await real_send_binary(*args, **kwargs)

    manager_a.send_binary = slow_send_binary
    src = _write(tmp_a, "payload.bin", 500_000)

    try:
        transfer_id = await ft_a.offer_file(addr_key, src)
        await asyncio.sleep(0.15)  # B's auto-accept has arrived; first chunk(s) in flight
        assert registry_a.active_count("transfer") == 1

        # A second, duplicate accept for the same transfer.
        b_addr_key = next(iter(manager_b._connections.keys()))
        await manager_b.send(b_addr_key, protocol.make_file_accept(transfer_id))
        await asyncio.sleep(0.1)

        assert registry_a.active_count("transfer") == 1  # still exactly one
    finally:
        await registry_a.cancel_all()
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_reject_lands_in_rejected():
    async def decline(transfer_id, filename, size, sender_name):
        return False

    manager_a, manager_b, ft_a, ft_b, addr_key, tmp_a = await _pair(on_offer_received_b=decline)
    done = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, ok, path: (result.update(ok=ok), done.set())

    src = _write(tmp_a, "payload.bin", 10_000)
    try:
        transfer_id = await ft_a.offer_file(addr_key, src)
        outgoing = ft_a._outgoing[transfer_id]
        await asyncio.wait_for(done.wait(), timeout=5.0)

        assert result["ok"] is False
        assert outgoing.state.state is OutgoingTransferState.REJECTED
        assert transfer_id not in ft_a._outgoing
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_zero_byte_file_still_completes():
    """No chunks means the incoming transfer is still ACCEPTED when
    file_done arrives — it must step through RECEIVING to VERIFYING
    rather than being rejected as an illegal ACCEPTED -> VERIFYING."""
    manager_a, manager_b, ft_a, ft_b, addr_key, tmp_a = await _pair()
    done = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, ok, path: (result.update(ok=ok), done.set())

    src = _write(tmp_a, "empty.bin", 0)
    try:
        await ft_a.offer_file(addr_key, src)
        await asyncio.wait_for(done.wait(), timeout=10.0)
        assert result["ok"] is True
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_late_or_duplicate_complete_ack_is_dropped():
    """A completion ack for a transfer that isn't WAITING_FOR_COMPLETE_ACK
    (e.g. a duplicate, or one that arrives while still SENDING) must not
    set the ack event or overwrite the outcome."""
    manager = ConnectionManager(listen_port=0, my_identity=generate_keypair(), my_name="A")
    ft = FileTransferSession(manager, downloads_dir=tempfile.mkdtemp(prefix="peerc_tfsm_ack_"))

    transfer = OutgoingTransfer(
        transfer_id="t1", addr_key="peer-x", filepath="/dev/null",
        filename="x", size=0, checksum="",
    )
    transfer.state.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    transfer.state.transition_to(OutgoingTransferState.SENDING)
    ft._outgoing["t1"] = transfer

    await ft._handle_complete_ack("peer-x", {"transfer_id": "t1", "success": True})

    assert not transfer._ack_event.is_set()
    assert transfer._ack_success is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocking_state",
    [IncomingTransferState.FAILED, IncomingTransferState.PAUSED],
)
async def test_chunk_after_terminal_or_paused_state_is_dropped(blocking_state):
    manager = ConnectionManager(listen_port=0, my_identity=generate_keypair(), my_name="B")
    tmp = tempfile.mkdtemp(prefix="peerc_tfsm_chunk_")
    ft = FileTransferSession(manager, downloads_dir=tmp)

    part_path = os.path.join(tmp, "x.part")
    incoming = IncomingTransfer(
        transfer_id="t2", addr_key="peer-y", filename="x", size=100,
        expected_checksum="", sender_name="peer", dest_path=os.path.join(tmp, "x"),
        part_path=part_path,
    )
    incoming._file_handle = open(part_path, "wb")
    incoming.state.transition_to(IncomingTransferState.ACCEPTED)
    incoming.state.transition_to(IncomingTransferState.RECEIVING)
    incoming.state.transition_to(blocking_state)
    ft._incoming["t2"] = incoming  # dict entry still present — simulates the race

    await ft._handle_chunk(
        "peer-y", {"transfer_id": "t2", "sequence": 0, "offset": 0, "data": b"late chunk"},
    )

    assert incoming.bytes_received == 0
    assert incoming.expected_chunk_index == 0
    incoming._file_handle.close()
    assert os.path.getsize(part_path) == 0
