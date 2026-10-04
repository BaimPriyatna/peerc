"""core/crypto/handshake.py — Secure Authenticated Handshake (Phase 6).

Implements the 3-message mutual authenticated handshake:
    1. HandshakeInit     (Initiator -> Responder)
    2. HandshakeResponse (Responder -> Initiator, signed by Responder)
    3. HandshakeFinish   (Initiator -> Responder, signed by Initiator)

Security properties:
    - Mutual authentication: both parties prove possession of the private key
      for their advertised Ed25519 device_id.
    - Transcript binding: signatures sign the entire cumulative handshake
      transcript (including ephemeral keys and nonces), preventing MITM tampering.
    - Forward secrecy: session shared secret is computed via ephemeral X25519 keys.
    - Replay protection: fresh 32-byte nonces generated on both sides and cached.
    - Trust enforcement: verifies identity against TrustStore (rejects REVOKED
      and KEY_CHANGED devices).
    - Timeout: enforces HANDSHAKE_TIMEOUT (5.0 seconds).
"""

import asyncio
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Set

if TYPE_CHECKING:
    from .kdf import SessionKeys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.identity.device_identity import (
    DeviceKeypair,
    compute_device_id,
    public_key_from_bytes,
)
from core.protocol.errors import ProtocolError
from core.protocol.frame import read_frame, write_frame
from core.protocol.messages import (
    make_handshake_finish,
    make_handshake_init,
    make_handshake_response,
    validate_message,
)
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit
from core.trust.store import TrustDecision, TrustStore
from .key_exchange import (
    EphemeralKeypair,
    compute_shared_secret,
    ephemeral_public_from_hex,
    generate_ephemeral_keypair,
)

HANDSHAKE_TIMEOUT = 5.0  # seconds (IMPLEMENTATION_PLAN.md line 704)
MAX_PEER_NAME_LENGTH = 64     # display names are cut to this before being stored
NONCE_BYTES = 32


class HandshakeError(Exception):
    """Base class for all handshake errors."""


class HandshakeTimeoutError(HandshakeError):
    """Handshake timed out waiting for peer message."""


class IdentityVerificationError(HandshakeError):
    """Claimed device_id does not match SHA256 of the public key."""


class SignatureVerificationError(HandshakeError):
    """Handshake transcript signature is invalid or tampered."""


class DeviceRevokedError(HandshakeError):
    """Peer device is marked REVOKED in TrustStore."""


class KeyChangedError(HandshakeError):
    """Peer device_id is known but presented a different public key."""


class HandshakeProtocolError(HandshakeError):
    """Malformed handshake message, unexpected type, or replay detected."""


@dataclass
class HandshakeResult:
    peer_device_id: str
    peer_public_key: str       # 64-char hex
    peer_name: str
    shared_secret: bytes       # 32 bytes from X25519 exchange
    transcript_hash: bytes     # 32 bytes SHA256 of full transcript
    trust_decision: TrustDecision

    def derive_session_keys(self, is_initiator: bool) -> "SessionKeys":
        """Derive directional session keys (Phase 7) from this handshake's result."""
        from .kdf import derive_session_keys
        return derive_session_keys(
            shared_secret=self.shared_secret,
            salt=self.transcript_hash,
            is_initiator=is_initiator,
        )


class NonceCache:
    """Thread/asyncio safe set of seen nonces within an expiry window to prevent replay."""

    def __init__(self, ttl: float = 300.0):
        self._ttl = ttl
        self._seen: dict[str, float] = {}

    def check_and_add(self, nonce: str) -> bool:
        """Returns True if nonce is fresh (not seen), False if replayed."""
        now = time.time()
        # Clean expired
        expired = [k for k, t in self._seen.items() if now - t > self._ttl]
        for k in expired:
            del self._seen[k]

        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True


# Global default nonce cache
_GLOBAL_NONCE_CACHE = NonceCache()


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_responder_transcript(init_msg: dict, resp_msg_without_sig: dict) -> bytes:
    """Computes canonical bytes for the responder signature."""
    init_bytes = _canonical_json_bytes({
        "type": init_msg["type"],
        "device_id": init_msg["device_id"],
        "public_key": init_msg["public_key"],
        "ephemeral_key": init_msg["ephemeral_key"],
        "nonce": init_msg["nonce"],
        "sender_name": init_msg["sender_name"],
    })
    resp_bytes = _canonical_json_bytes({
        "type": resp_msg_without_sig["type"],
        "device_id": resp_msg_without_sig["device_id"],
        "public_key": resp_msg_without_sig["public_key"],
        "ephemeral_key": resp_msg_without_sig["ephemeral_key"],
        "nonce": resp_msg_without_sig["nonce"],
        "sender_name": resp_msg_without_sig["sender_name"],
    })
    return b"peerc-v2-handshake-responder\n" + init_bytes + b"\n" + resp_bytes


def compute_initiator_transcript(responder_transcript: bytes, responder_signature_hex: str) -> bytes:
    """Computes canonical bytes for the initiator signature."""
    return (
        b"peerc-v2-handshake-initiator\n"
        + responder_transcript
        + b"\n"
        + responder_signature_hex.encode("ascii")
    )


def compute_final_transcript_hash(
    initiator_transcript: bytes, initiator_signature_hex: str
) -> bytes:
    """Computes the 32-byte SHA256 digest of the entire completed handshake."""
    data = initiator_transcript + b"\n" + initiator_signature_hex.encode("ascii")
    return hashlib.sha256(data).digest()


def _verify_device_identity(device_id: str, public_key_hex: str) -> bytes:
    """Verify that device_id == sha256(raw public key). Returns raw public key bytes."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
    except ValueError as e:
        raise IdentityVerificationError(f"invalid hex for public_key: {e}") from e

    expected_id = compute_device_id(pub_bytes)
    if expected_id != device_id:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description=f"device_id mismatch: claimed {device_id!r}, computed {expected_id!r} from public key",
                device_id=device_id,
            )
        )
        raise IdentityVerificationError(
            f"device_id mismatch: claimed {device_id!r}, computed {expected_id!r} from public key"
        )
    return pub_bytes


def _check_trust(
    trust_store: Optional[TrustStore],
    device_id: str,
    public_key_hex: str,
) -> TrustDecision:
    """Read-only trust lookup. Rejects REVOKED and KEY_CHANGED devices.

    This never writes: at the point it runs the peer has only *claimed* an
    identity and has not yet proved it holds the private key.
    """
    if trust_store is None:
        return TrustDecision.UNKNOWN

    decision = trust_store.check(device_id, public_key_hex)
    if decision == TrustDecision.REVOKED:
        raise DeviceRevokedError(f"device {device_id} is REVOKED")
    if decision == TrustDecision.KEY_CHANGED:
        raise KeyChangedError(
            f"device {device_id} has CHANGED its public key (possible impersonation)"
        )
    return decision


def _record_trust(
    trust_store: Optional[TrustStore],
    device_id: str,
    public_key_hex: str,
    peer_name: str,
    decision: TrustDecision,
) -> TrustDecision:
    """Write the outcome of `_check_trust`. Call it only after the peer's
    signature over the handshake transcript has been verified; before that,
    anyone able to generate a keypair could fill the trust store."""
    if trust_store is None:
        return decision
    if decision == TrustDecision.UNKNOWN:
        trust_store.record_first_seen(device_id, public_key_hex, peer_name[:MAX_PEER_NAME_LENGTH])
        return TrustDecision.PENDING
    if decision in (TrustDecision.PENDING, TrustDecision.TRUSTED):
        trust_store.touch_last_seen(device_id)
    return decision


def _check_and_update_trust(
    trust_store: Optional[TrustStore],
    device_id: str,
    public_key_hex: str,
    peer_name: str,
) -> TrustDecision:
    """Look up and record in one step. The handshake itself no longer uses
    this (it records only after verifying the signature); kept for callers
    that already hold a verified identity."""
    decision = _check_trust(trust_store, device_id, public_key_hex)
    return _record_trust(trust_store, device_id, public_key_hex, peer_name, decision)


async def perform_handshake_initiator(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    my_identity: DeviceKeypair,
    my_name: str,
    trust_store: Optional[TrustStore] = None,
    timeout: float = HANDSHAKE_TIMEOUT,
    nonce_cache: Optional[NonceCache] = None,
) -> HandshakeResult:
    """Initiator side of the secure handshake."""
    cache = nonce_cache or _GLOBAL_NONCE_CACHE

    # 1. Generate initiator ephemeral keypair and nonce
    my_ephemeral = generate_ephemeral_keypair()
    my_nonce = secrets.token_hex(NONCE_BYTES)

    # 2. Build and send handshake_init
    my_pub_hex = my_identity.public_key_bytes().hex()
    init_msg = make_handshake_init(
        device_id=my_identity.device_id,
        public_key=my_pub_hex,
        ephemeral_key=my_ephemeral.public_key_hex(),
        nonce=my_nonce,
        sender_name=my_name,
    )
    write_frame(writer, init_msg)
    await writer.drain()

    # 3. Receive handshake_response with timeout
    try:
        resp_msg = await asyncio.wait_for(read_frame(reader), timeout=timeout)
    except asyncio.TimeoutError as e:
        raise HandshakeTimeoutError("timed out waiting for handshake_response") from e
    except Exception as e:
        raise HandshakeProtocolError(f"failed to read handshake_response: {e}") from e

    try:
        validate_message(resp_msg)
    except ProtocolError as e:
        raise HandshakeProtocolError(f"invalid handshake_response message: {e}") from e

    if resp_msg.get("type") != "handshake_response":
        raise HandshakeProtocolError(f"expected 'handshake_response', got {resp_msg.get('type')!r}")

    # 4. Replay check on responder nonce
    resp_nonce = resp_msg["nonce"]
    if not cache.check_and_add(resp_nonce):
        emit(
            SecurityEvent(
                event_type=SecurityEventType.REPLAY_DETECTED,
                severity=SecuritySeverity.HIGH,
                description="replayed responder nonce detected in handshake",
                device_id=resp_msg.get("device_id"),
            )
        )
        raise HandshakeProtocolError("replayed responder nonce detected")

    # 5. Verify responder device_id ties to its public key
    peer_pub_bytes = _verify_device_identity(resp_msg["device_id"], resp_msg["public_key"])

    # 6. Check trust store
    # Read-only: the responder has not yet proved it holds its private key.
    # Nothing is recorded until its signature has been verified below.
    pre_decision = _check_trust(trust_store, resp_msg["device_id"], resp_msg["public_key"])

    # 7. Verify responder signature over transcript
    resp_transcript = compute_responder_transcript(init_msg, resp_msg)
    responder_pub = public_key_from_bytes(peer_pub_bytes)
    try:
        sig_bytes = bytes.fromhex(resp_msg["signature"])
        responder_pub.verify(sig_bytes, resp_transcript)
    except (ValueError, InvalidSignature) as e:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description=f"invalid responder signature in handshake: {e}",
                device_id=resp_msg.get("device_id"),
            )
        )
        raise SignatureVerificationError(f"invalid responder signature: {e}") from e

    # The responder proved possession of its key; only now may it be recorded.
    trust_decision = _record_trust(
        trust_store,
        resp_msg["device_id"],
        resp_msg["public_key"],
        resp_msg["sender_name"],
        pre_decision,
    )

    # 8. Compute initiator signature over cumulative transcript
    init_transcript = compute_initiator_transcript(resp_transcript, resp_msg["signature"])
    my_signature = my_identity.sign(init_transcript).hex()

    # 9. Send handshake_finish
    finish_msg = make_handshake_finish(signature=my_signature)
    write_frame(writer, finish_msg)
    await writer.drain()

    # 10. Compute Diffie-Hellman shared secret
    try:
        peer_ephemeral_pub = ephemeral_public_from_hex(resp_msg["ephemeral_key"])
    except ValueError as e:
        raise HandshakeProtocolError(f"invalid peer ephemeral key: {e}") from e

    shared_secret = compute_shared_secret(my_ephemeral.private_key, peer_ephemeral_pub)
    transcript_hash = compute_final_transcript_hash(init_transcript, my_signature)

    return HandshakeResult(
        peer_device_id=resp_msg["device_id"],
        peer_public_key=resp_msg["public_key"],
        peer_name=resp_msg["sender_name"],
        shared_secret=shared_secret,
        transcript_hash=transcript_hash,
        trust_decision=trust_decision,
    )


async def perform_handshake_responder(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    my_identity: DeviceKeypair,
    my_name: str,
    trust_store: Optional[TrustStore] = None,
    timeout: float = HANDSHAKE_TIMEOUT,
    nonce_cache: Optional[NonceCache] = None,
) -> HandshakeResult:
    """Responder side of the secure handshake."""
    cache = nonce_cache or _GLOBAL_NONCE_CACHE

    # 1. Receive handshake_init with timeout
    try:
        init_msg = await asyncio.wait_for(read_frame(reader), timeout=timeout)
    except asyncio.TimeoutError as e:
        raise HandshakeTimeoutError("timed out waiting for handshake_init") from e
    except Exception as e:
        raise HandshakeProtocolError(f"failed to read handshake_init: {e}") from e

    try:
        validate_message(init_msg)
    except ProtocolError as e:
        raise HandshakeProtocolError(f"invalid handshake_init message: {e}") from e

    if init_msg.get("type") != "handshake_init":
        raise HandshakeProtocolError(f"expected 'handshake_init', got {init_msg.get('type')!r}")

    # 2. Replay check on initiator nonce
    init_nonce = init_msg["nonce"]
    if not cache.check_and_add(init_nonce):
        emit(
            SecurityEvent(
                event_type=SecurityEventType.REPLAY_DETECTED,
                severity=SecuritySeverity.HIGH,
                description="replayed initiator nonce detected in handshake",
                device_id=init_msg.get("device_id"),
            )
        )
        raise HandshakeProtocolError("replayed initiator nonce detected")

    # 3. Verify initiator device_id ties to its public key
    peer_pub_bytes = _verify_device_identity(init_msg["device_id"], init_msg["public_key"])

    # 4. Check trust store
    # Read-only: the initiator has not yet proved it holds its private key.
    # Nothing is recorded until its signature has been verified below.
    pre_decision = _check_trust(trust_store, init_msg["device_id"], init_msg["public_key"])

    # 5. Generate responder ephemeral keypair and nonce
    my_ephemeral = generate_ephemeral_keypair()
    my_nonce = secrets.token_hex(NONCE_BYTES)
    my_pub_hex = my_identity.public_key_bytes().hex()

    resp_msg_no_sig = {
        "type": "handshake_response",
        "device_id": my_identity.device_id,
        "public_key": my_pub_hex,
        "ephemeral_key": my_ephemeral.public_key_hex(),
        "nonce": my_nonce,
        "sender_name": my_name,
    }

    # 6. Compute responder signature over transcript
    resp_transcript = compute_responder_transcript(init_msg, resp_msg_no_sig)
    my_signature = my_identity.sign(resp_transcript).hex()

    # 7. Build and send handshake_response
    resp_msg = make_handshake_response(
        device_id=my_identity.device_id,
        public_key=my_pub_hex,
        ephemeral_key=my_ephemeral.public_key_hex(),
        nonce=my_nonce,
        sender_name=my_name,
        signature=my_signature,
    )
    write_frame(writer, resp_msg)
    await writer.drain()

    # 8. Receive handshake_finish with timeout
    try:
        finish_msg = await asyncio.wait_for(read_frame(reader), timeout=timeout)
    except asyncio.TimeoutError as e:
        raise HandshakeTimeoutError("timed out waiting for handshake_finish") from e
    except Exception as e:
        raise HandshakeProtocolError(f"failed to read handshake_finish: {e}") from e

    try:
        validate_message(finish_msg)
    except ProtocolError as e:
        raise HandshakeProtocolError(f"invalid handshake_finish message: {e}") from e

    if finish_msg.get("type") != "handshake_finish":
        raise HandshakeProtocolError(f"expected 'handshake_finish', got {finish_msg.get('type')!r}")

    # 9. Verify initiator signature over cumulative transcript
    init_transcript = compute_initiator_transcript(resp_transcript, my_signature)
    initiator_pub = public_key_from_bytes(peer_pub_bytes)
    try:
        sig_bytes = bytes.fromhex(finish_msg["signature"])
        initiator_pub.verify(sig_bytes, init_transcript)
    except (ValueError, InvalidSignature) as e:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description=f"invalid initiator signature in handshake: {e}",
                device_id=init_msg.get("device_id"),
            )
        )
        raise SignatureVerificationError(f"invalid initiator signature: {e}") from e

    # The initiator proved possession of its key; only now may it be recorded.
    trust_decision = _record_trust(
        trust_store,
        init_msg["device_id"],
        init_msg["public_key"],
        init_msg["sender_name"],
        pre_decision,
    )

    # 10. Compute Diffie-Hellman shared secret
    try:
        peer_ephemeral_pub = ephemeral_public_from_hex(init_msg["ephemeral_key"])
    except ValueError as e:
        raise HandshakeProtocolError(f"invalid peer ephemeral key: {e}") from e

    shared_secret = compute_shared_secret(my_ephemeral.private_key, peer_ephemeral_pub)
    transcript_hash = compute_final_transcript_hash(init_transcript, finish_msg["signature"])

    return HandshakeResult(
        peer_device_id=init_msg["device_id"],
        peer_public_key=init_msg["public_key"],
        peer_name=init_msg["sender_name"],
        shared_secret=shared_secret,
        transcript_hash=transcript_hash,
        trust_decision=trust_decision,
    )
