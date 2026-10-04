"""tests/test_handshake_trust_order.py — security audit finding #4.

The handshake must not write anything to the trust store about a peer until
that peer has proved it holds the private key by signing the transcript.
Before this fix `_check_and_update_trust` ran (and recorded a first-seen row)
*before* the signature was verified, so anyone who could generate a keypair
could leave a row with a name of their choosing in `trusted_devices` for every
connection attempt, even when the signature was deliberately wrong.
"""

import asyncio
import os
import secrets
import tempfile

import pytest

from core.crypto import generate_ephemeral_keypair, perform_handshake_initiator, perform_handshake_responder
from core.crypto.handshake import MAX_PEER_NAME_LENGTH, SignatureVerificationError
from core.identity import generate_keypair
from core.protocol.frame import read_frame, write_frame
from core.protocol.messages import make_handshake_response
from core.trust.store import TrustDecision, TrustStore

pytestmark = pytest.mark.asyncio


class ForgingIdentity:
    """A real identity whose signatures are garbage: it proves nothing."""

    def __init__(self, real):
        self.device_id = real.device_id
        self._real = real

    def public_key_bytes(self):
        return self._real.public_key_bytes()

    def sign(self, data):
        return b"\xff" * 64


async def _close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


async def _run_pair(initiator, responder, *, initiator_name="Alice", responder_name="Bob",
                    initiator_store=None, responder_store=None):
    """Run a real handshake over loopback; return what each side produced or raised."""
    outcome, done = {}, asyncio.Event()

    async def handle(reader, writer):
        try:
            outcome["responder"] = await perform_handshake_responder(
                reader, writer, responder, responder_name, trust_store=responder_store)
        except Exception as exc:                          # noqa: BLE001 - the test inspects it
            outcome["responder_error"] = exc
        finally:
            await _close(writer)
            done.set()

    server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        outcome["initiator"] = await perform_handshake_initiator(
            reader, writer, initiator, initiator_name, trust_store=initiator_store)
    except Exception as exc:                              # noqa: BLE001
        outcome["initiator_error"] = exc
    finally:
        await _close(writer)
    await asyncio.wait_for(done.wait(), timeout=10)
    server.close()
    await server.wait_closed()
    return outcome


async def test_initiator_records_nothing_about_a_responder_with_a_bad_signature():
    alice, bob = generate_keypair(), generate_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        store = TrustStore(os.path.join(tmp, "alice_trust.db"))
        done = asyncio.Event()

        async def hostile_responder(reader, writer):
            # a fresh nonce each time: the nonce replay cache is process-global
            await read_frame(reader)
            write_frame(writer, make_handshake_response(
                device_id=bob.device_id, public_key=bob.public_key_bytes().hex(),
                ephemeral_key=generate_ephemeral_keypair().public_key_hex(),
                nonce=secrets.token_hex(32), sender_name="attacker-chosen name", signature="ff" * 64,
            ))
            await writer.drain()
            await _close(writer)
            done.set()

        server = await asyncio.start_server(hostile_responder, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        with pytest.raises(SignatureVerificationError):
            await perform_handshake_initiator(reader, writer, alice, "Alice", trust_store=store)
        await _close(writer)
        await asyncio.wait_for(done.wait(), timeout=10)
        server.close()
        await server.wait_closed()

        assert store.list_all() == [], "a peer that failed to prove its key must leave no row behind"
        assert store.check(bob.device_id, bob.public_key_bytes().hex()) == TrustDecision.UNKNOWN
        store.close()


async def test_responder_records_nothing_about_an_initiator_that_cannot_sign():
    alice, bob = generate_keypair(), generate_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        store = TrustStore(os.path.join(tmp, "bob_trust.db"))
        # The initiator cannot know its own signature is rejected, so only the responder fails.
        outcome = await _run_pair(ForgingIdentity(alice), bob, responder_store=store)

        assert isinstance(outcome.get("responder_error"), SignatureVerificationError), outcome
        assert store.list_all() == [], "an initiator that never signed must leave no row behind"
        store.close()


async def test_a_successful_handshake_still_records_both_peers_as_pending():
    alice, bob = generate_keypair(), generate_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        alice_store = TrustStore(os.path.join(tmp, "a.db"))
        bob_store = TrustStore(os.path.join(tmp, "b.db"))
        outcome = await _run_pair(alice, bob, initiator_store=alice_store, responder_store=bob_store)

        assert "initiator_error" not in outcome and "responder_error" not in outcome, outcome
        assert outcome["initiator"].trust_decision == TrustDecision.PENDING
        assert outcome["responder"].trust_decision == TrustDecision.PENDING
        assert [d.device_id for d in alice_store.list_all()] == [bob.device_id]
        assert [d.device_id for d in bob_store.list_all()] == [alice.device_id]
        alice_store.close()
        bob_store.close()


async def test_a_recorded_peer_name_is_capped():
    alice, bob = generate_keypair(), generate_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        bob_store = TrustStore(os.path.join(tmp, "b.db"))
        outcome = await _run_pair(alice, bob, initiator_name="N" * 5000, responder_store=bob_store)

        assert "responder_error" not in outcome, outcome
        (device,) = bob_store.list_all()
        assert len(device.name) <= MAX_PEER_NAME_LENGTH
        bob_store.close()
