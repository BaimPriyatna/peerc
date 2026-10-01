"""tests/test_connection_fsm_integration.py — Phase 33.1: Connection FSM,
wired into a real ConnectionManager pair.

Confirms the wiring in peer.py (not just the state machine class in
isolation, covered by tests/test_connection_fsm.py): a real handshake
reaches ESTABLISHED, disconnect reaches CLOSED, a duplicate/concurrent
close doesn't crash or resurrect the connection, and a late frame after
CLOSING is dropped rather than dispatched.
"""

import asyncio
import random

import pytest

from core.connection_state import ConnectionState
from core.identity.device_identity import generate_keypair
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.integration


def _ports(n: int = 2):
    base = random.randint(20000, 40000)
    return [base + i for i in range(n)]


@pytest.mark.asyncio
async def test_connection_reaches_established_after_real_handshake():
    port_a, port_b = _ports()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        assert manager_a.get_connection_state(addr_key) is ConnectionState.ESTABLISHED

        await asyncio.sleep(0.1)
        b_addr_key = next(iter(manager_b._connections.keys()))
        assert manager_b.get_connection_state(b_addr_key) is ConnectionState.ESTABLISHED
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_connection_reaches_closed_after_disconnect():
    port_a, port_b = _ports()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    addr_key = await manager_a.connect_to("127.0.0.1", port_b)
    await asyncio.sleep(0.1)

    await manager_a.close_all()
    await asyncio.sleep(0.1)

    # Popped once fully torn down — None is the "gone" signal, matching
    # get_peer_device_id()'s existing convention for a closed connection.
    assert manager_a.get_connection_state(addr_key) is None
    assert addr_key not in manager_a._connections

    await manager_b.close_all()


@pytest.mark.asyncio
async def test_duplicate_close_does_not_raise_or_resurrect():
    """Two overlapping close signals for the same connection (e.g. a
    send-path failure's defensive _mark_closing() racing with the read
    loop's own teardown) must not raise, and must not leave the
    connection in any state but CLOSED."""
    port_a, port_b = _ports()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    addr_key = await manager_a.connect_to("127.0.0.1", port_b)
    await asyncio.sleep(0.1)

    # First close signal, exactly as a send-path failure would trigger it.
    manager_a._mark_closing(addr_key)
    assert manager_a.get_connection_state(addr_key) is ConnectionState.CLOSING

    # A second, overlapping close signal — must be a no-op, not a crash.
    manager_a._mark_closing(addr_key)
    assert manager_a.get_connection_state(addr_key) is ConnectionState.CLOSING

    # The real teardown (close_all -> session.close() -> read_loop's
    # finally) then runs on top of that and reaches CLOSED, not an error.
    await manager_a.close_all()
    await asyncio.sleep(0.1)
    assert manager_a.get_connection_state(addr_key) is None

    await manager_b.close_all()


@pytest.mark.asyncio
async def test_late_frame_after_closing_is_dropped_not_dispatched():
    """A frame that arrives after this side has already moved to CLOSING
    (e.g. a racing send-path failure) must be dropped by
    require_established(), not handed to on_message()."""
    port_a, port_b = _ports()
    received = []

    async def on_message(addr_key, msg):
        received.append(msg)

    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(
        listen_port=port_b, my_identity=generate_keypair(), my_name="B", on_message=on_message,
    )
    await manager_a.start_server()
    await manager_b.start_server()

    addr_key_a = await manager_a.connect_to("127.0.0.1", port_b)
    await asyncio.sleep(0.1)
    b_addr_key = next(iter(manager_b._connections.keys()))

    from core import protocol
    msg = protocol.make_chat_message(manager_a.my_identity.device_id, "A", "should be dropped")

    # Force B's side of the connection into CLOSING without actually
    # closing the socket, then have A send one more frame — B's
    # _read_loop is still awaiting session.receive() and will get this
    # frame, but require_established() must reject it before on_message.
    manager_b._connection_states[b_addr_key].transition_to(ConnectionState.CLOSING)
    await manager_a.send(addr_key_a, msg)
    await asyncio.sleep(0.1)

    assert received == []

    await manager_a.close_all()
    await manager_b.close_all()
