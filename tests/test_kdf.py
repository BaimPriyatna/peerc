"""tests/test_kdf.py — Unit and integration tests for Phase 7 (Session Keys / HKDF).

Verifies:
    1. Deterministic derivation from same inputs.
    2. Directional symmetry:
       - initiator.send_key == responder.recv_key
       - initiator.recv_key == responder.send_key
       - initiator.session_id == responder.session_id
    3. Key separation: send_key != recv_key (prevents reflection attacks).
    4. Transcript hash binding (salt changes cause avalanche effect).
    5. Shared secret sensitivity.
    6. Strict input validation (rejects invalid types / lengths).
    7. Secret masking in __repr__ (no leakage in logs/console).
    8. End-to-end integration with HandshakeResult from Phase 6.
"""

import asyncio
import os
import pytest
import secrets
import tempfile

from core.crypto import (
    KDFError,
    SessionKeys,
    derive_session_keys,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from core.identity.device_identity import DeviceKeypair
from core.trust.store import TrustStore

pytestmark = pytest.mark.security



def test_derive_session_keys_determinism():
    shared_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)

    keys1 = derive_session_keys(shared_secret, salt, is_initiator=True)
    keys2 = derive_session_keys(shared_secret, salt, is_initiator=True)

    assert keys1.send_key == keys2.send_key
    assert keys1.recv_key == keys2.recv_key
    assert keys1.session_id == keys2.session_id
    assert len(keys1.send_key) == 32
    assert len(keys1.recv_key) == 32
    assert len(keys1.session_id) == 32  # 16 bytes hex


def test_directional_keys_symmetry():
    shared_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)

    init_keys = derive_session_keys(shared_secret, salt, is_initiator=True)
    resp_keys = derive_session_keys(shared_secret, salt, is_initiator=False)

    # Initiator send matches Responder recv
    assert init_keys.send_key == resp_keys.recv_key
    # Initiator recv matches Responder send
    assert init_keys.recv_key == resp_keys.send_key
    # Both agree on session ID
    assert init_keys.session_id == resp_keys.session_id


def test_key_separation():
    shared_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)

    keys = derive_session_keys(shared_secret, salt, is_initiator=True)

    # Tx and Rx keys must not be equal
    assert keys.send_key != keys.recv_key
    # Neither key should be the shared secret
    assert keys.send_key != shared_secret
    assert keys.recv_key != shared_secret


def test_transcript_salt_binding():
    shared_secret = secrets.token_bytes(32)
    salt1 = secrets.token_bytes(32)
    # Flip the lowest bit of the first byte
    salt2 = bytes([salt1[0] ^ 1]) + salt1[1:]

    keys1 = derive_session_keys(shared_secret, salt1, is_initiator=True)
    keys2 = derive_session_keys(shared_secret, salt2, is_initiator=True)

    assert keys1.send_key != keys2.send_key
    assert keys1.recv_key != keys2.recv_key
    assert keys1.session_id != keys2.session_id


def test_shared_secret_sensitivity():
    secret1 = secrets.token_bytes(32)
    secret2 = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)

    keys1 = derive_session_keys(secret1, salt, is_initiator=True)
    keys2 = derive_session_keys(secret2, salt, is_initiator=True)

    assert keys1.send_key != keys2.send_key
    assert keys1.recv_key != keys2.recv_key
    assert keys1.session_id != keys2.session_id


def test_input_validation():
    valid = secrets.token_bytes(32)

    # Invalid secret length
    with pytest.raises(KDFError, match="shared_secret must be exactly 32 bytes"):
        derive_session_keys(b"short", valid, is_initiator=True)
    with pytest.raises(KDFError, match="shared_secret must be exactly 32 bytes"):
        derive_session_keys(valid + b"x", valid, is_initiator=True)

    # Invalid salt length
    with pytest.raises(KDFError, match="salt must be exactly 32 bytes"):
        derive_session_keys(valid, b"short", is_initiator=True)
    with pytest.raises(KDFError, match="salt must be exactly 32 bytes"):
        derive_session_keys(valid, valid + b"x", is_initiator=True)

    # Invalid types
    with pytest.raises(KDFError, match="shared_secret must be bytes"):
        derive_session_keys("not bytes", valid, is_initiator=True)  # type: ignore
    with pytest.raises(KDFError, match="salt must be bytes"):
        derive_session_keys(valid, "not bytes", is_initiator=True)  # type: ignore


def test_session_keys_repr_masked():
    keys = derive_session_keys(secrets.token_bytes(32), secrets.token_bytes(32), is_initiator=True)
    repr_str = repr(keys)

    assert keys.session_id in repr_str
    assert "***" in repr_str
    assert keys.send_key.hex() not in repr_str
    assert keys.recv_key.hex() not in repr_str


import tempfile

from core.identity import generate_keypair

@pytest.mark.asyncio
async def test_end_to_end_handshake_derivation():
    """Verify that full mutual handshake output seamlessly derives matched session keys."""
    alice_kp = generate_keypair()
    bob_kp = generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        alice_trust = TrustStore(db_path=os.path.join(tmpdir, "alice_trust.db"))
        bob_trust = TrustStore(db_path=os.path.join(tmpdir, "bob_trust.db"))
        try:
            server_res = None
            server_done = asyncio.Event()

            async def handle_client(reader, writer):
                nonlocal server_res
                try:
                    server_res = await perform_handshake_responder(
                        reader, writer, bob_kp, "Bob", trust_store=bob_trust
                    )
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
            alice_result = await perform_handshake_initiator(
                reader, writer, alice_kp, "Alice", trust_store=alice_trust
            )

            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

            await asyncio.wait_for(server_done.wait(), timeout=5.0)
            server.close()
            await server.wait_closed()

            bob_result = server_res
            assert bob_result is not None

            # Derive session keys on both sides via HandshakeResult convenience method
            alice_keys = alice_result.derive_session_keys(is_initiator=True)
            bob_keys = bob_result.derive_session_keys(is_initiator=False)

            # Cryptographic symmetry
            assert alice_keys.send_key == bob_keys.recv_key
            assert alice_keys.recv_key == bob_keys.send_key
            assert alice_keys.session_id == bob_keys.session_id
            assert alice_keys.send_key != alice_keys.recv_key

            # Session ID is consistent with 16-byte hex
            assert len(alice_keys.session_id) == 32
        finally:
            alice_trust.close()
            bob_trust.close()

