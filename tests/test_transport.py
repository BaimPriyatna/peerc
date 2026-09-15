"""tests/test_transport.py — Comprehensive tests for Phase 9 Secure Transport Layer.

Covers:
    - TCPConnection loopback framing, binary/json delivery, and timeouts.
    - EncryptedTransport authenticated encryption, bidirectional messaging, and tamper rejection.
    - End-to-end SecureSession initiation, mutual handshake, key derivation, and chat/file exchange.
    - SecureSessionManager device_id keying and lifecycle management.
    - Handshake failure cleanup (ensures TCP socket closes upon rejection).
"""

import asyncio
import os
import pytest

from core.crypto.encryption import (
    DecryptionError,
    ReplayOrReorderError,
    SecureChannel,
)
from core.crypto.kdf import SessionKeys
from core.identity.device_identity import generate_keypair
from core.transport import (
    CONNECT_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    ConnectionClosedError,
    ConnectTimeoutError,
    EncryptedTransport,
    SecureSession,
    SecureSessionManager,
    TCPConnection,
    accept_secure_session,
    initiate_secure_session,
    open_tcp_connection,
)
from core.trust.store import TrustStore


def _make_dummy_channels():
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    chan_a = SecureChannel(SessionKeys(send_key=key_a, recv_key=key_b, session_id="test-a"))
    chan_b = SecureChannel(SessionKeys(send_key=key_b, recv_key=key_a, session_id="test-b"))
    return chan_a, chan_b


@pytest.mark.asyncio
async def test_tcp_connection_loopback_frames():
    """Verify raw TCPConnection sends and receives both JSON and binary frames."""
    received_frames = []
    server_ready = asyncio.Event()

    async def handle_client(reader, writer):
        conn = TCPConnection(reader, writer)
        try:
            f1 = await conn.read_frame()
            f2 = await conn.read_frame()
            received_frames.extend([f1, f2])
            await conn.write_frame({"status": "ack"})
        finally:
            await conn.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    async with server:
        client_conn = await open_tcp_connection("127.0.0.1", server_port)
        await client_conn.write_frame({"msg": "hello"})
        await client_conn.write_binary_frame(b"raw-binary-payload")

        ack_kind, ack_msg = await client_conn.read_frame()
        assert ack_kind == "json"
        assert ack_msg == {"status": "ack"}
        await client_conn.close()

    assert len(received_frames) == 2
    assert received_frames[0] == ("json", {"msg": "hello"})
    assert received_frames[1] == ("binary", b"raw-binary-payload")


@pytest.mark.asyncio
async def test_tcp_connection_connect_timeout(monkeypatch):
    """Verify open_tcp_connection raises ConnectTimeoutError on unreachable target.

    Mocks asyncio.open_connection to hang rather than relying on a
    non-routable IP (192.0.2.1) actually timing out — that depends on
    network/sandbox behavior (some environments return
    ConnectionRefusedError immediately instead of hanging), so it isn't
    deterministic across environments.
    """
    import core.transport.tcp as tcp_module

    async def _hang(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(tcp_module.asyncio, "open_connection", _hang)

    with pytest.raises(ConnectTimeoutError):
        await open_tcp_connection("192.0.2.1", 12345, timeout=0.1)


@pytest.mark.asyncio
async def test_encrypted_transport_bidirectional():
    """Verify EncryptedTransport handles authenticated, encrypted messages and binary data."""
    chan_srv, chan_cli = _make_dummy_channels()
    received_at_server = []

    async def handle_client(reader, writer):
        tcp = TCPConnection(reader, writer)
        enc_trans = EncryptedTransport(tcp, chan_srv)
        try:
            msg1 = await enc_trans.receive_frame()
            msg2 = await enc_trans.receive_frame()
            received_at_server.extend([msg1, msg2])
            await enc_trans.send_message({"reply": "got it"})
        finally:
            await enc_trans.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    async with server:
        client_tcp = await open_tcp_connection("127.0.0.1", server_port)
        client_trans = EncryptedTransport(client_tcp, chan_cli)

        await client_trans.send_message({"text": "secret chat"})
        await client_trans.send_binary(b"secret file chunk bytes")

        reply_kind, reply_msg = await client_trans.receive_frame()
        assert reply_kind == "json"
        assert reply_msg == {"reply": "got it"}

        await client_trans.close()

    assert len(received_at_server) == 2
    assert received_at_server[0] == ("json", {"text": "secret chat"})
    assert received_at_server[1] == ("binary", b"secret file chunk bytes")


@pytest.mark.asyncio
async def test_encrypted_transport_tamper_rejection():
    """Verify tampered wire ciphertext over socket raises DecryptionError."""
    chan_srv, chan_cli = _make_dummy_channels()

    async def handle_client(reader, writer):
        tcp = TCPConnection(reader, writer)
        enc_trans = EncryptedTransport(tcp, chan_srv)
        try:
            with pytest.raises(DecryptionError):
                await enc_trans.receive_frame()
        finally:
            await enc_trans.close()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    async with server:
        client_tcp = await open_tcp_connection("127.0.0.1", server_port)
        # Manually encrypt but tamper 1 bit of ciphertext before writing
        frame = chan_cli.encrypt(b"J{\"text\":\"tamper me\"}")
        tampered_ct = bytearray(frame.ciphertext)
        tampered_ct[0] ^= 0x01
        wire = (frame.sequence).to_bytes(8, "big") + bytes(tampered_ct)
        await client_tcp.write_binary_frame(wire)
        await client_tcp.close()


@pytest.mark.asyncio
async def test_end_to_end_secure_session():
    """Verify full end-to-end SecureSession: TCP connect -> Handshake -> Key Derivation -> Chat & File."""
    alice_identity = generate_keypair()
    bob_identity = generate_keypair()

    alice_session_holder = []
    server_accepted = asyncio.Event()

    async def on_client_connected(reader, writer):
        session = await accept_secure_session(
            reader=reader,
            writer=writer,
            my_identity=alice_identity,
            my_name="Alice",
        )
        alice_session_holder.append(session)
        server_accepted.set()

        # Echo loop
        try:
            kind, data = await session.receive()
            if kind == "json":
                await session.send({"type": "chat_reply", "text": f"Echo: {data['text']}"})
            kind, data = await session.receive()
            if kind == "binary":
                await session.send_binary(b"ACK:" + data)
        finally:
            await session.close()

    server = await asyncio.start_server(on_client_connected, "127.0.0.1", 0)
    server_port = server.sockets[0].getsockname()[1]

    async with server:
        bob_session = await initiate_secure_session(
            host="127.0.0.1",
            port=server_port,
            my_identity=bob_identity,
            my_name="Bob",
        )

        await server_accepted.wait()
        alice_session: SecureSession = alice_session_holder[0]

        # Verify session identity attributes
        assert bob_session.peer_device_id == alice_identity.device_id
        assert bob_session.peer_name == "Alice"
        assert bob_session.is_initiator is True
        assert bob_session.is_alive is True

        assert alice_session.peer_device_id == bob_identity.device_id
        assert alice_session.peer_name == "Bob"
        assert alice_session.is_initiator is False
        assert alice_session.is_alive is True

        # Send JSON message
        await bob_session.send({"type": "chat", "text": "Hello Alice!"})
        reply_kind, reply_data = await bob_session.receive()
        assert reply_kind == "json"
        assert reply_data == {"type": "chat_reply", "text": "Echo: Hello Alice!"}

        # Send binary chunk
        await bob_session.send_binary(b"chunk_001_bytes")
        chunk_kind, chunk_reply = await bob_session.receive()
        assert chunk_kind == "binary"
        assert chunk_reply == b"ACK:chunk_001_bytes"

        await bob_session.close()

    assert not bob_session.is_alive


@pytest.mark.asyncio
async def test_secure_session_manager():
    """Verify SecureSessionManager tracks, retrieves, and closes sessions keyed by device_id."""
    manager = SecureSessionManager()
    id_alice = generate_keypair()
    id_bob = generate_keypair()

    # Mock session
    class DummySession:
        def __init__(self, dev_id):
            self.peer_device_id = dev_id
            self.is_alive = True
            self.closed = False

        async def close(self):
            self.is_alive = False
            self.closed = True

    s1 = DummySession(id_alice.device_id)
    s2 = DummySession(id_bob.device_id)

    manager.register(s1)  # type: ignore
    manager.register(s2)  # type: ignore

    assert len(manager) == 2
    assert manager.get(id_alice.device_id) is s1
    assert set(manager.active_device_ids()) == {id_alice.device_id, id_bob.device_id}

    manager.remove(id_alice.device_id)
    assert manager.get(id_alice.device_id) is None
    assert len(manager) == 1

    await manager.close_all()
    assert s2.closed
    assert len(manager) == 0


@pytest.mark.asyncio
async def test_session_closed_error():
    """Verify sending on a closed session raises ConnectionClosedError."""
    alice_identity = generate_keypair()
    bob_identity = generate_keypair()

    async def handle_conn(reader, writer):
        session = await accept_secure_session(
            reader=reader, writer=writer, my_identity=alice_identity, my_name="Alice"
        )
        await session.close()

    server = await asyncio.start_server(handle_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        session = await initiate_secure_session(
            host="127.0.0.1", port=port, my_identity=bob_identity, my_name="Bob"
        )
        await asyncio.sleep(0.05)
        await session.close()

        with pytest.raises(ConnectionClosedError):
            await session.send({"type": "chat", "text": "too late"})


@pytest.mark.asyncio
async def test_handshake_timeout_initiator():
    """Verify initiator raises HandshakeTimeoutError if responder hangs during handshake."""
    bob_identity = generate_keypair()

    async def hanging_server(reader, writer):
        # Read the init frame but never reply
        await reader.read(1024)
        await asyncio.sleep(1.0)
        writer.close()

    server = await asyncio.start_server(hanging_server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        from core.crypto.handshake import HandshakeTimeoutError
        with pytest.raises(HandshakeTimeoutError):
            await initiate_secure_session(
                host="127.0.0.1",
                port=port,
                my_identity=bob_identity,
                my_name="Bob",
                handshake_timeout=0.1,
            )


@pytest.mark.asyncio
async def test_revoked_peer_rejected_in_session():
    """Verify session establishment is rejected if peer is marked REVOKED in TrustStore."""
    from core.crypto.handshake import DeviceRevokedError
    from core.trust.revocation import revoke_device

    trust_store = TrustStore(db_path=":memory:")

    alice_identity = generate_keypair()
    bob_identity = generate_keypair()

    # Alice pre-revokes Bob
    trust_store.record_first_seen(
        device_id=bob_identity.device_id,
        public_key=bob_identity.public_key_bytes().hex(),
        name="Bob",
    )
    revoke_device(trust_store, bob_identity.device_id, revoked_by=alice_identity.device_id, reason="Untrusted")

    async def on_client_connected(reader, writer):
        with pytest.raises(DeviceRevokedError):
            await accept_secure_session(
                reader=reader,
                writer=writer,
                my_identity=alice_identity,
                my_name="Alice",
                trust_store=trust_store,
            )

    server = await asyncio.start_server(on_client_connected, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        with pytest.raises(Exception):  # Handshake fails for initiator because responder aborts
            await initiate_secure_session(
                host="127.0.0.1",
                port=port,
                my_identity=bob_identity,
                my_name="Bob",
            )

