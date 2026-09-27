"""tests/test_handshake.py — Automated tests for Phase 6 (Secure Handshake).

Covers:
    - Ephemeral X25519 key exchange (Phase 6.1)
    - Full 3-way mutual authenticated handshake over TCP (Phase 6.2)
    - TOFU TrustStore integration
    - Security test cases (Phase 30):
        1. Fake identity (device_id mismatch) -> IdentityVerificationError
        2. Invalid signature -> SignatureVerificationError
        3. MITM / parameter tampering -> SignatureVerificationError
        4. Replay attack (stale nonce reuse) -> HandshakeProtocolError
        5. Revoked device in TrustStore -> DeviceRevokedError
        6. Key change detection in TrustStore -> KeyChangedError
        7. Handshake timeout -> HandshakeTimeoutError
"""

import asyncio
import os
import tempfile
import pytest

from core.crypto import (
    DeviceRevokedError,
    EphemeralKeypair,
    HandshakeError,
    HandshakeProtocolError,
    HandshakeResult,
    HandshakeTimeoutError,
    IdentityVerificationError,
    KeyChangedError,
    NonceCache,
    SignatureVerificationError,
    compute_final_transcript_hash,
    compute_initiator_transcript,
    compute_responder_transcript,
    compute_shared_secret,
    ephemeral_public_from_bytes,
    ephemeral_public_from_hex,
    generate_ephemeral_keypair,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from core.identity import generate_keypair
from core.protocol.errors import ProtocolError
from core.protocol.frame import read_frame, write_frame
from core.protocol.messages import (
    make_handshake_finish,
    make_handshake_init,
    make_handshake_response,
    validate_message,
)
from core.trust.device import TrustStatus
from core.trust.store import TrustDecision, TrustStore

pytestmark = pytest.mark.security



# -----------------------------------------------------------------------------
# Unit Tests: Key Exchange & Primitives
# -----------------------------------------------------------------------------


def test_ephemeral_keypair_generation_and_exchange():
    alice_eph = generate_ephemeral_keypair()
    bob_eph = generate_ephemeral_keypair()

    assert len(alice_eph.public_key_bytes()) == 32
    assert len(alice_eph.public_key_hex()) == 64
    assert len(bob_eph.public_key_bytes()) == 32
    assert len(bob_eph.public_key_hex()) == 64

    # Deserialization
    alice_pub_restored = ephemeral_public_from_bytes(alice_eph.public_key_bytes())
    bob_pub_restored = ephemeral_public_from_hex(bob_eph.public_key_hex())

    # Shared secret exchange
    secret_a = compute_shared_secret(alice_eph.private_key, bob_pub_restored)
    secret_b = compute_shared_secret(bob_eph.private_key, alice_pub_restored)

    assert len(secret_a) == 32
    assert secret_a == secret_b, "Diffie-Hellman shared secrets must match"


def test_ephemeral_public_key_validation():
    with pytest.raises(ValueError):
        ephemeral_public_from_bytes(b"too_short")
    with pytest.raises(ValueError):
        ephemeral_public_from_hex("not_hex!")
    with pytest.raises(ValueError):
        ephemeral_public_from_hex("aabbcc")  # too short hex


def test_transcript_hashing_determinism():
    init_msg = {
        "type": "handshake_init",
        "device_id": "a" * 64,
        "public_key": "b" * 64,
        "ephemeral_key": "c" * 64,
        "nonce": "d" * 64,
        "sender_name": "Alice",
    }
    resp_msg_no_sig = {
        "type": "handshake_response",
        "device_id": "1" * 64,
        "public_key": "2" * 64,
        "ephemeral_key": "3" * 64,
        "nonce": "4" * 64,
        "sender_name": "Bob",
    }

    t1 = compute_responder_transcript(init_msg, resp_msg_no_sig)
    t2 = compute_responder_transcript(init_msg, resp_msg_no_sig)
    assert t1 == t2
    assert b"peerc-v2-handshake-responder\n" in t1

    sig_hex = "f" * 128
    init_t = compute_initiator_transcript(t1, sig_hex)
    assert b"peerc-v2-handshake-initiator\n" in init_t

    final_hash = compute_final_transcript_hash(init_t, sig_hex)
    assert len(final_hash) == 32


def test_handshake_messages_schema():
    init = make_handshake_init("devA", "pubA", "ephA", "nonceA", "Alice")
    assert init["type"] == "handshake_init"
    assert validate_message(init) == init

    resp = make_handshake_response("devB", "pubB", "ephB", "nonceB", "Bob", "sigB")
    assert resp["type"] == "handshake_response"
    assert validate_message(resp) == resp

    fin = make_handshake_finish("sigA")
    assert fin["type"] == "handshake_finish"
    assert validate_message(fin) == fin

    # Missing required field
    with pytest.raises(ProtocolError):
        validate_message({"type": "handshake_init", "device_id": "devA"})

    # Non-string field
    bad_init = dict(init)
    bad_init["nonce"] = 12345
    with pytest.raises(ProtocolError):
        validate_message(bad_init)


# -----------------------------------------------------------------------------
# Integration Tests: Full Mutual Handshake over Loopback TCP
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_mutual_handshake():
    alice_id = generate_keypair()
    bob_id = generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        alice_store = TrustStore(os.path.join(tmpdir, "alice_trust.db"))
        bob_store = TrustStore(os.path.join(tmpdir, "bob_trust.db"))
        try:
            server_res = None
            server_err = None
            server_done = asyncio.Event()

            async def handle_client(reader, writer):
                nonlocal server_res, server_err
                try:
                    server_res = await perform_handshake_responder(
                        reader, writer, bob_id, "Bob", trust_store=bob_store
                    )
                except Exception as e:
                    server_err = e
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
                    server_done.set()

            server = await asyncio.start_server(handle_client, host="127.0.0.1", port=0)
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            client_res = await perform_handshake_initiator(
                reader, writer, alice_id, "Alice", trust_store=alice_store
            )

            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

            # Wait for the server handler to fully complete before asserting.
            # server.close() would cancel any still-running handler task with
            # CancelledError (a BaseException, not Exception), so we must
            # ensure the handler finishes *before* we close the server.
            await asyncio.wait_for(server_done.wait(), timeout=5.0)

            server.close()
            await server.wait_closed()

            assert server_err is None, f"server error: {server_err}"
            assert server_res is not None
            assert client_res is not None

            # Verify matching shared secrets & transcript hashes
            assert client_res.shared_secret == server_res.shared_secret
            assert len(client_res.shared_secret) == 32
            assert client_res.transcript_hash == server_res.transcript_hash
            assert len(client_res.transcript_hash) == 32

            # Verify identities
            assert client_res.peer_device_id == bob_id.device_id
            assert client_res.peer_public_key == bob_id.public_key_bytes().hex()
            assert client_res.peer_name == "Bob"
            assert client_res.trust_decision == TrustDecision.PENDING

            assert server_res.peer_device_id == alice_id.device_id
            assert server_res.peer_public_key == alice_id.public_key_bytes().hex()
            assert server_res.peer_name == "Alice"
            assert server_res.trust_decision == TrustDecision.PENDING
        finally:
            alice_store.close()
            bob_store.close()


@pytest.mark.asyncio
async def test_handshake_with_pre_approved_trust():
    alice_id = generate_keypair()
    bob_id = generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        alice_store = TrustStore(os.path.join(tmpdir, "alice_trust.db"))
        try:
            # Alice already knows and trusted Bob
            alice_store.record_first_seen(bob_id.device_id, bob_id.public_key_bytes().hex(), "Bob")
            alice_store.approve(bob_id.device_id)

            async def handle_client(reader, writer):
                try:
                    await perform_handshake_responder(reader, writer, bob_id, "Bob")
                finally:
                    writer.close()

            server = await asyncio.start_server(handle_client, host="127.0.0.1", port=0)
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            client_res = await perform_handshake_initiator(
                reader, writer, alice_id, "Alice", trust_store=alice_store
            )
            writer.close()
            server.close()
            await server.wait_closed()

            assert client_res.trust_decision == TrustDecision.TRUSTED
        finally:
            alice_store.close()


# -----------------------------------------------------------------------------
# Security Tests (Phase 30)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fake_identity_rejected():
    """Security Case 1: Attacker claims device_id A but uses a different key."""
    real_keypair = generate_keypair()
    attacker_keypair = generate_keypair()
    server_error = None

    async def handle_client(reader, writer):
        nonlocal server_error
        try:
            await perform_handshake_responder(reader, writer, attacker_keypair, "Attacker")
        except Exception as e:
            server_error = e
        finally:
            writer.close()

    server = await asyncio.start_server(handle_client, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    # Initiator sends a forged init message where device_id != sha256(public_key)
    forged_init = make_handshake_init(
        device_id="deadbeef" * 8,
        public_key=real_keypair.public_key_bytes().hex(),
        ephemeral_key=generate_ephemeral_keypair().public_key_hex(),
        nonce="11" * 32,
        sender_name="Spoofer",
    )
    write_frame(writer, forged_init)
    await writer.drain()

    # The responder should reject and close connection
    await asyncio.sleep(0.1)
    writer.close()
    server.close()
    await server.wait_closed()

    assert isinstance(server_error, IdentityVerificationError)


@pytest.mark.asyncio
async def test_invalid_signature_rejected():
    """Security Case 2: Handshake response carries an invalid signature."""
    alice_id = generate_keypair()
    bob_id = generate_keypair()

    async def hostile_responder(reader, writer):
        # Read init
        await read_frame(reader)
        # Send response with bogus signature
        bogus_resp = make_handshake_response(
            device_id=bob_id.device_id,
            public_key=bob_id.public_key_bytes().hex(),
            ephemeral_key=generate_ephemeral_keypair().public_key_hex(),
            nonce="22" * 32,
            sender_name="Bob",
            signature="ff" * 64,  # Invalid signature
        )
        write_frame(writer, bogus_resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(hostile_responder, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(SignatureVerificationError):
        await perform_handshake_initiator(reader, writer, alice_id, "Alice")

    writer.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_tampered_transcript_mitm_rejected():
    """Security Case 3: MITM replaces ephemeral key on the wire."""
    alice_id = generate_keypair()
    bob_id = generate_keypair()

    async def mitm_responder(reader, writer):
        init_msg = await read_frame(reader)
        # Responder properly signs its response...
        eph = generate_ephemeral_keypair()
        pub_hex = bob_id.public_key_bytes().hex()
        resp_no_sig = {
            "type": "handshake_response",
            "device_id": bob_id.device_id,
            "public_key": pub_hex,
            "ephemeral_key": eph.public_key_hex(),
            "nonce": "33" * 32,
            "sender_name": "Bob",
        }
        resp_transcript = compute_responder_transcript(init_msg, resp_no_sig)
        valid_sig = bob_id.sign(resp_transcript).hex()

        # ...BUT MITM tampers with the ephemeral key in transit!
        tampered_resp = make_handshake_response(
            device_id=bob_id.device_id,
            public_key=pub_hex,
            ephemeral_key=generate_ephemeral_keypair().public_key_hex(),  # Tampered!
            nonce="33" * 32,
            sender_name="Bob",
            signature=valid_sig,
        )
        write_frame(writer, tampered_resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(mitm_responder, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(SignatureVerificationError):
        await perform_handshake_initiator(reader, writer, alice_id, "Alice")

    writer.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_replayed_nonce_rejected():
    """Security Case 4: Replaying a handshake message with an already-seen nonce."""
    nonce_cache = NonceCache(ttl=60.0)
    replayed_nonce = "44" * 32
    assert nonce_cache.check_and_add(replayed_nonce) is True
    # Second time with same nonce must be detected as replay
    assert nonce_cache.check_and_add(replayed_nonce) is False

    alice_id = generate_keypair()
    bob_id = generate_keypair()
    server_error = None

    async def responder(reader, writer):
        nonlocal server_error
        try:
            await perform_handshake_responder(
                reader, writer, bob_id, "Bob", nonce_cache=nonce_cache
            )
        except Exception as e:
            server_error = e
        finally:
            writer.close()

    server = await asyncio.start_server(responder, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    # Send handshake_init with the already seen replayed_nonce
    init_msg = make_handshake_init(
        device_id=alice_id.device_id,
        public_key=alice_id.public_key_bytes().hex(),
        ephemeral_key=generate_ephemeral_keypair().public_key_hex(),
        nonce=replayed_nonce,
        sender_name="Alice",
    )
    write_frame(writer, init_msg)
    await writer.drain()

    await asyncio.sleep(0.1)
    writer.close()
    server.close()
    await server.wait_closed()

    assert isinstance(server_error, HandshakeProtocolError)
    assert "replayed" in str(server_error)


@pytest.mark.asyncio
async def test_revoked_device_rejected():
    """Security Case 5: Valid signature from a device marked REVOKED in TrustStore."""
    alice_id = generate_keypair()
    bob_id = generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        alice_store = TrustStore(os.path.join(tmpdir, "alice_trust.db"))
        try:
            # Alice marked Bob as REVOKED
            alice_store.record_first_seen(bob_id.device_id, bob_id.public_key_bytes().hex(), "Bob")
            alice_store._set_revoked(bob_id.device_id, revoked_by="alice", reason="compromised")

            async def bob_responder(reader, writer):
                try:
                    await perform_handshake_responder(reader, writer, bob_id, "Bob")
                finally:
                    writer.close()

            server = await asyncio.start_server(bob_responder, host="127.0.0.1", port=0)
            port = server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            with pytest.raises(DeviceRevokedError):
                await perform_handshake_initiator(
                    reader, writer, alice_id, "Alice", trust_store=alice_store
                )

            writer.close()
            server.close()
            await server.wait_closed()
        finally:
            alice_store.close()


@pytest.mark.asyncio
async def test_key_changed_rejected():
    """Security Case 6: Known device presents a different public key."""
    bob_old_id = generate_keypair()
    bob_new_id = generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        alice_store = TrustStore(os.path.join(tmpdir, "alice_trust.db"))
        try:
            # Alice recorded Bob under bob_old_id's key
            alice_store.record_first_seen(bob_old_id.device_id, bob_old_id.public_key_bytes().hex(), "Bob")

            # Check with changed key returns KEY_CHANGED and handshake helper raises KeyChangedError
            with pytest.raises(KeyChangedError):
                from core.crypto.handshake import _check_and_update_trust
                _check_and_update_trust(
                    alice_store,
                    bob_old_id.device_id,
                    bob_new_id.public_key_bytes().hex(),
                    "Bob",
                )
        finally:
            alice_store.close()


@pytest.mark.asyncio
async def test_handshake_timeout():
    """Security Case 7: Handshake stalls and times out."""
    alice_id = generate_keypair()

    async def stalling_server(reader, writer):
        # Read init and do nothing, letting client time out
        await read_frame(reader)
        await asyncio.sleep(1.0)
        writer.close()

    server = await asyncio.start_server(stalling_server, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    # Set a very short timeout for test speed
    with pytest.raises(HandshakeTimeoutError):
        await perform_handshake_initiator(
            reader, writer, alice_id, "Alice", timeout=0.2
        )

    writer.close()
    server.close()
    await server.wait_closed()
