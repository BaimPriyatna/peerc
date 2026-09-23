"""tests/test_relay_pipe.py — Phase 46.1: relay-tunnel primitive.

Covers:
  1. RelayedStreamReader/RelayedStreamWriter shim in isolation (no
     network): readexactly() across multiple feed_data() calls, partial
     buffering, and EOF behavior matching a real StreamReader.
  2. The wire-level `relay` channel: send_relay_data()/receive dispatch
     between two real, handshaked ConnectionManagers.
  3. R-side forwarding: open_relay_pipe() bridges two sessions, a
     `relay` chunk sent by one side arrives verbatim on the other via a
     registered tunnel reader, and R's own on_message is never called.
  4. Pipe lifecycle: closing one leg tears down the pipe mapping.
  5. End-to-end: a full, unmodified Phase 6 handshake (and one
     subsequent encrypted message) between A and B, running entirely
     over relay tunnels through R — R never decodes any of it.
"""

import asyncio

import pytest

from core.crypto.encryption import SecureChannel
from core.crypto.handshake import perform_handshake_initiator, perform_handshake_responder
from core.identity.device_identity import generate_keypair
from core.transport import EncryptedTransport, RelayedStreamReader, RelayedStreamWriter, SecureSession
from peer import ConnectionManager

PORT_R = 7601
PORT_A = 7602
PORT_B = 7603


# ---------------------------------------------------------------------------
# 1. Shim in isolation
# ---------------------------------------------------------------------------


async def test_relay_stream_shim_roundtrip():
    sent_chunks = []

    async def send_fn(chunk: bytes) -> None:
        sent_chunks.append(chunk)

    writer = RelayedStreamWriter(send_fn)
    reader = RelayedStreamReader()

    writer.write(b"hello ")
    writer.write(b"world")
    await writer.drain()
    assert sent_chunks == [b"hello world"]

    # Feed the "far side"'s reader in two separate chunks, and read
    # across the boundary — readexactly() must not care where one
    # feed_data() call ended and the next began.
    reader.feed_data(b"abc")
    reader.feed_data(b"defgh")
    assert await reader.readexactly(4) == b"abcd"
    assert await reader.readexactly(4) == b"efgh"


async def test_relay_stream_shim_readexactly_blocks_until_fed():
    reader = RelayedStreamReader()
    result = {}

    async def reader_task():
        result["data"] = await reader.readexactly(5)

    task = asyncio.create_task(reader_task())
    await asyncio.sleep(0.05)
    assert "data" not in result  # still blocked, not enough bytes yet

    reader.feed_data(b"12")
    await asyncio.sleep(0.05)
    assert "data" not in result

    reader.feed_data(b"345")
    await asyncio.wait_for(task, timeout=1.0)
    assert result["data"] == b"12345"


async def test_relay_stream_shim_eof_raises_incomplete_read():
    reader = RelayedStreamReader()
    reader.feed_data(b"ab")
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError) as exc_info:
        await reader.readexactly(5)
    assert exc_info.value.partial == b"ab"


async def test_relay_stream_writer_get_extra_info_and_close():
    writer = RelayedStreamWriter(send_fn=lambda chunk: None, peer_addr=("1.2.3.4", 9))
    assert writer.get_extra_info("peername") == ("1.2.3.4", 9)
    assert writer.get_extra_info("nonsense", "fallback") == "fallback"
    assert writer.is_closing() is False
    writer.close()
    assert writer.is_closing() is True
    await writer.wait_closed()  # must not raise


# ---------------------------------------------------------------------------
# Shared helper: connect two managers, return both sides' addr_keys.
# ---------------------------------------------------------------------------


async def _connect(manager_from, manager_to, host, port):
    addr_key_from = await manager_from.connect_to(host, port)
    await asyncio.sleep(0.2)
    return addr_key_from


# ---------------------------------------------------------------------------
# 2. Wire-level relay channel between two managers directly
# ---------------------------------------------------------------------------


async def test_relay_wire_channel_delivers_to_registered_tunnel():
    manager_a = ConnectionManager(listen_port=PORT_A, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=PORT_B, my_identity=generate_keypair(), my_name="B")
    try:
        await manager_a.start_server()
        await manager_b.start_server()

        addr_key_a_to_b = await _connect(manager_a, manager_b, "127.0.0.1", PORT_B)
        b_addr_keys = manager_b.list_connected_addr_keys()
        assert len(b_addr_keys) == 1
        addr_key_b_to_a = b_addr_keys[0]

        reader = RelayedStreamReader()
        manager_b.register_relay_tunnel(addr_key_b_to_a, reader)

        ok = await manager_a.send_relay_data(addr_key_a_to_b, b"tunnel-bytes")
        assert ok
        await asyncio.wait_for(reader.readexactly(len(b"tunnel-bytes")), timeout=1.0)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------------
# 3-4. R-side forwarding + pipe lifecycle
# ---------------------------------------------------------------------------


async def test_relay_pipe_forwards_and_r_never_decodes():
    on_message_calls = []

    async def r_on_message(addr_key, message):
        on_message_calls.append((addr_key, message))

    manager_r = ConnectionManager(
        listen_port=PORT_R, my_identity=generate_keypair(), my_name="R", on_message=r_on_message,
    )
    manager_a = ConnectionManager(listen_port=PORT_A, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=PORT_B, my_identity=generate_keypair(), my_name="B")
    try:
        await manager_r.start_server()
        await manager_a.start_server()
        await manager_b.start_server()

        addr_key_a_to_r = await _connect(manager_a, manager_r, "127.0.0.1", PORT_R)
        r_keys_after_a = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_a = next(iter(r_keys_after_a))

        addr_key_b_to_r = await _connect(manager_b, manager_r, "127.0.0.1", PORT_R)
        r_keys_after_b = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_b = next(iter(r_keys_after_b - r_keys_after_a))

        manager_r.open_relay_pipe(addr_key_r_to_a, addr_key_r_to_b)
        assert manager_r.is_relay_pipe_open(addr_key_r_to_a)
        assert manager_r.is_relay_pipe_open(addr_key_r_to_b)

        b_reader = RelayedStreamReader()
        manager_b.register_relay_tunnel(addr_key_b_to_r, b_reader)

        ok = await manager_a.send_relay_data(addr_key_a_to_r, b"from-a-via-r")
        assert ok
        got = await asyncio.wait_for(b_reader.readexactly(len(b"from-a-via-r")), timeout=1.0)
        assert got == b"from-a-via-r"

        # Round trip: B -> R -> A too, same pipe, both directions.
        a_reader = RelayedStreamReader()
        manager_a.register_relay_tunnel(addr_key_a_to_r, a_reader)
        ok = await manager_b.send_relay_data(addr_key_b_to_r, b"from-b-via-r")
        assert ok
        got = await asyncio.wait_for(a_reader.readexactly(len(b"from-b-via-r")), timeout=1.0)
        assert got == b"from-b-via-r"

        # R relayed opaque bytes only — never ran a relayed chunk through
        # its own on_message/application dispatch.
        assert on_message_calls == []

        # --- 4. lifecycle: dropping A's leg tears down the pipe on R ---
        await manager_a.close_all()
        await asyncio.sleep(0.3)
        assert not manager_r.is_relay_pipe_open(addr_key_r_to_a)
        assert not manager_r.is_relay_pipe_open(addr_key_r_to_b)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()
        await manager_r.close_all()


# ---------------------------------------------------------------------------
# 5. Full Phase 6 handshake + one encrypted message, tunneled through R
# ---------------------------------------------------------------------------


async def test_full_handshake_and_message_through_relay_tunnel():
    """The payoff test: perform_handshake_initiator/_responder and a
    SecureSession built manually on top run completely unmodified over
    open_relay_tunnel()'s TCPConnection shim, with R only ever forwarding
    opaque `relay` bytes between its two real sessions."""
    r_on_message_calls = []

    async def r_on_message(addr_key, message):
        r_on_message_calls.append((addr_key, message))

    manager_r = ConnectionManager(
        listen_port=PORT_R, my_identity=generate_keypair(), my_name="R", on_message=r_on_message,
    )
    alice_identity = generate_keypair()
    bob_identity = generate_keypair()
    manager_a = ConnectionManager(listen_port=PORT_A, my_identity=alice_identity, my_name="Alice")
    manager_b = ConnectionManager(listen_port=PORT_B, my_identity=bob_identity, my_name="Bob")
    try:
        await manager_r.start_server()
        await manager_a.start_server()
        await manager_b.start_server()

        addr_key_a_to_r = await _connect(manager_a, manager_r, "127.0.0.1", PORT_R)
        r_keys_after_a = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_a = next(iter(r_keys_after_a))

        addr_key_b_to_r = await _connect(manager_b, manager_r, "127.0.0.1", PORT_R)
        r_keys_after_b = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_b = next(iter(r_keys_after_b - r_keys_after_a))

        manager_r.open_relay_pipe(addr_key_r_to_a, addr_key_r_to_b)

        a_tcp_conn = manager_a.open_relay_tunnel(addr_key_a_to_r)
        b_tcp_conn = manager_b.open_relay_tunnel(addr_key_b_to_r)

        # Run both sides of the Phase 6 handshake concurrently, entirely
        # over the tunnel shims — identical calls to a real direct
        # connection (compare tests/test_handshake.py).
        alice_res, bob_res = await asyncio.wait_for(
            asyncio.gather(
                perform_handshake_initiator(
                    a_tcp_conn.reader, a_tcp_conn.writer, alice_identity, "Alice",
                ),
                perform_handshake_responder(
                    b_tcp_conn.reader, b_tcp_conn.writer, bob_identity, "Bob",
                ),
            ),
            timeout=5.0,
        )

        assert alice_res.peer_device_id == bob_identity.device_id
        assert bob_res.peer_device_id == alice_identity.device_id

        # Wrap exactly like initiate_secure_session/accept_secure_session
        # do internally, and exchange one real encrypted message.
        alice_keys = alice_res.derive_session_keys(is_initiator=True)
        bob_keys = bob_res.derive_session_keys(is_initiator=False)

        alice_session = SecureSession(
            transport=EncryptedTransport(a_tcp_conn, SecureChannel(alice_keys)),
            handshake_result=alice_res, session_id=alice_keys.session_id, is_initiator=True,
        )
        bob_session = SecureSession(
            transport=EncryptedTransport(b_tcp_conn, SecureChannel(bob_keys)),
            handshake_result=bob_res, session_id=bob_keys.session_id, is_initiator=False,
        )

        await alice_session.send({"type": "chat", "text": "Halo dari terowongan"})
        kind, message = await asyncio.wait_for(bob_session.receive(), timeout=2.0)
        assert kind == "json"
        assert message == {"type": "chat", "text": "Halo dari terowongan"}

        # R relayed the entire handshake and the message above blind —
        # its own application dispatch was never touched.
        assert r_on_message_calls == []
    finally:
        manager_a.unregister_relay_tunnel(addr_key_a_to_r)
        manager_b.unregister_relay_tunnel(addr_key_b_to_r)
        await manager_a.close_all()
        await manager_b.close_all()
        await manager_r.close_all()
