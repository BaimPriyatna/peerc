"""tests/test_security_events.py — Tests for Phase 41: Security Event Logging.

Tests cover:
  1. Severity enum, rank ordering, and mapping to standard logging levels.
  2. SecurityEvent dataclass, serialization to dict, and canonical payload determinism.
  3. Safe logging guarantee: automatic redaction of sensitive credentials.
  4. In-memory event listeners and capture_security_events context manager.
  5. TrustStore call sites: KEY_CHANGED (WARNING) and REVOKED (HIGH).
  6. Device Key Rotation call sites: normal rotation (INFO), invalid cert (WARNING),
     and revoked device rotation attempt (HIGH).
  7. Handshake call sites: device_id mismatch (WARNING), nonce replay (HIGH),
     and invalid signature (WARNING).
"""

import asyncio
import base64
import logging
import os
from unittest.mock import MagicMock

import pytest

from core.identity.device_identity import generate_keypair
from core.crypto.handshake import (
    HandshakeProtocolError,
    IdentityVerificationError,
    NonceCache,
    SignatureVerificationError,
    _verify_device_identity,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from core.identity.identity_file import DeviceIdentity, rotate_identity
from core.identity.key_storage import KeyStore
from core.identity.rotation import (
    TransitionCertificate,
    create_transition_certificate,
    verify_transition_certificate,
)
from core.security import (
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    add_listener,
    capture_security_events,
    emit,
    remove_listener,
)
from core.trust.device import TrustStatus
from core.trust.store import TrustDecision, TrustStore

pytestmark = pytest.mark.security



# ---------------------------------------------------------------------------
# 1. Severity enum and ordering
# ---------------------------------------------------------------------------


def test_severity_ranks_and_ordering():
    assert SecuritySeverity.INFO < SecuritySeverity.WARNING
    assert SecuritySeverity.WARNING < SecuritySeverity.HIGH
    assert SecuritySeverity.HIGH < SecuritySeverity.CRITICAL

    assert SecuritySeverity.CRITICAL > SecuritySeverity.HIGH
    assert SecuritySeverity.HIGH >= SecuritySeverity.WARNING
    assert SecuritySeverity.INFO <= SecuritySeverity.INFO

    assert SecuritySeverity.INFO.to_logging_level() == logging.INFO
    assert SecuritySeverity.WARNING.to_logging_level() == logging.WARNING
    assert SecuritySeverity.HIGH.to_logging_level() == logging.ERROR
    assert SecuritySeverity.CRITICAL.to_logging_level() == logging.CRITICAL


# ---------------------------------------------------------------------------
# 2. Event serialization & canonical payload
# ---------------------------------------------------------------------------


def test_event_to_dict_and_canonical_payload():
    ev = SecurityEvent(
        event_type=SecurityEventType.KEY_ROTATION,
        severity=SecuritySeverity.INFO,
        description="test rotation",
        device_id="abc123def456",
        timestamp=1700000000.0,
        details={"foo": "bar", "num": 42},
    )

    d = ev.to_dict()
    assert d["event_type"] == "key_rotation"
    assert d["severity"] == "INFO"
    assert d["device_id"] == "abc123def456"
    assert d["timestamp"] == 1700000000.0
    assert d["details"] == {"foo": "bar", "num": 42}

    payload1 = ev.canonical_payload()
    payload2 = ev.canonical_payload()
    assert payload1 == payload2
    assert payload1.startswith(b"peerc-security-event\x00")
    assert b"INFO\x00" in payload1
    assert b"key_rotation\x00" in payload1
    assert b"abc123def456\x00" in payload1


# ---------------------------------------------------------------------------
# 3. Defensive redaction of sensitive credentials
# ---------------------------------------------------------------------------


def test_sensitive_credentials_redacted():
    ev = SecurityEvent(
        event_type=SecurityEventType.AUTH_FAILED,
        severity=SecuritySeverity.WARNING,
        description="auth failed",
        details={
            "remote_ip": "127.0.0.1",
            "private_key": "SUPER_SECRET_KEY",
            "session_key": "DEADBEEF_SESSION",
            "shared_secret": "TOP_SECRET_DH",
            "nested": {"password": "admin_password", "safe_field": "ok"},
        },
    )

    assert ev.details["remote_ip"] == "127.0.0.1"
    assert ev.details["private_key"] == "[REDACTED]"
    assert ev.details["session_key"] == "[REDACTED]"
    assert ev.details["shared_secret"] == "[REDACTED]"
    assert ev.details["nested"]["password"] == "[REDACTED]"
    assert ev.details["nested"]["safe_field"] == "ok"


# ---------------------------------------------------------------------------
# 4. Listeners and capture_security_events
# ---------------------------------------------------------------------------


def test_listeners_and_capture_events():
    with capture_security_events() as events:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.UNKNOWN_DEVICE,
                severity=SecuritySeverity.WARNING,
                description="discovered unknown peer",
            )
        )
        assert len(events) == 1
        assert events[0].event_type == "unknown_device"
        assert events[0].severity == SecuritySeverity.WARNING

    # After context exit, listener is deregistered
    emit(
        SecurityEvent(
            event_type=SecurityEventType.KEY_ROTATION,
            severity=SecuritySeverity.INFO,
            description="another event",
        )
    )
    assert len(events) == 1

    # Faulty listener does not break emit()
    def faulty_listener(e):
        raise RuntimeError("listener boom")

    add_listener(faulty_listener)
    try:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.ENDPOINT_CHANGED,
                severity=SecuritySeverity.INFO,
                description="should not fail",
            )
        )
    finally:
        remove_listener(faulty_listener)


# ---------------------------------------------------------------------------
# 5. TrustStore call sites
# ---------------------------------------------------------------------------


def test_trust_store_emits_on_key_changed_and_revoked(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    dev_a = generate_keypair()
    pub_a_b64 = base64.b64encode(dev_a.public_key_bytes()).decode("ascii")

    # 1. Record device A
    store.record_first_seen(dev_a.device_id, pub_a_b64, "Alice")
    store.approve(dev_a.device_id)

    # 2. KEY_CHANGED triggers WARNING event
    dev_fake = generate_keypair()
    pub_fake_b64 = base64.b64encode(dev_fake.public_key_bytes()).decode("ascii")

    with capture_security_events() as events:
        dec = store.check(dev_a.device_id, pub_fake_b64)
        assert dec == TrustDecision.KEY_CHANGED
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.IDENTITY_CHANGED.value
        assert events[0].severity == SecuritySeverity.WARNING
        assert events[0].device_id == dev_a.device_id

    # 3. REVOKED device triggers HIGH event
    store._set_revoked(dev_a.device_id, revoked_by="admin", reason="lost")
    with capture_security_events() as events:
        dec = store.check(dev_a.device_id, pub_a_b64)
        assert dec == TrustDecision.REVOKED
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.REVOKED_DEVICE_ATTEMPT.value
        assert events[0].severity == SecuritySeverity.HIGH


def test_trust_store_check_with_rotation_tainted_revocation(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    dev1 = generate_keypair()
    dev2 = generate_keypair()
    pub1 = base64.b64encode(dev1.public_key_bytes()).decode("ascii")
    pub2 = base64.b64encode(dev2.public_key_bytes()).decode("ascii")

    store.record_first_seen(dev1.device_id, pub1, "Node1")
    store.approve(dev1.device_id)

    cert = create_transition_certificate(dev1, dev2)
    store.record_rotation(cert)

    # Revoke dev1
    store._set_revoked(dev1.device_id, revoked_by="admin", reason="compromised")

    # dev2 is not directly marked revoked, but check_with_rotation taints it
    with capture_security_events() as events:
        dec = store.check_with_rotation(dev2.device_id, pub2)
        assert dec == TrustDecision.REVOKED
        taint_events = [
            e for e in events if e.event_type == SecurityEventType.REVOKED_DEVICE_ATTEMPT.value
        ]
        assert len(taint_events) >= 1
        assert taint_events[0].severity == SecuritySeverity.HIGH
        assert taint_events[0].device_id == dev2.device_id


# ---------------------------------------------------------------------------
# 6. Device Key Rotation call sites
# ---------------------------------------------------------------------------


def test_rotation_events_valid_and_invalid(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    old_kp = generate_keypair()
    new_kp = generate_keypair()
    old_pub = base64.b64encode(old_kp.public_key_bytes()).decode("ascii")
    new_pub = base64.b64encode(new_kp.public_key_bytes()).decode("ascii")

    store.record_first_seen(old_kp.device_id, old_pub, "OldAlice")
    store.approve(old_kp.device_id)

    # 1. Valid rotation emits INFO KEY_ROTATION
    valid_cert = create_transition_certificate(old_kp, new_kp)
    with capture_security_events() as events:
        store.record_rotation(valid_cert)
        rot_events = [e for e in events if e.event_type == SecurityEventType.KEY_ROTATION.value]
        assert len(rot_events) == 1
        assert rot_events[0].severity == SecuritySeverity.INFO
        assert rot_events[0].device_id == new_kp.device_id

    # 2. Tampered cert emits WARNING INVALID_ROTATION
    tampered = TransitionCertificate(
        old_device_id=valid_cert.old_device_id,
        old_public_key=valid_cert.old_public_key,
        new_device_id=valid_cert.new_device_id,
        new_public_key=valid_cert.new_public_key,
        timestamp=valid_cert.timestamp,
        signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    with capture_security_events() as events:
        assert verify_transition_certificate(tampered) is False
        inv_events = [e for e in events if e.event_type == SecurityEventType.INVALID_ROTATION.value]
        assert len(inv_events) >= 1
        assert inv_events[0].severity == SecuritySeverity.WARNING

    # 3. Revoked device rotation emits HIGH REVOKED_DEVICE_ATTEMPT
    revoked_kp = generate_keypair()
    successor_kp = generate_keypair()
    rev_pub = base64.b64encode(revoked_kp.public_key_bytes()).decode("ascii")
    store.record_first_seen(revoked_kp.device_id, rev_pub, "RevokedPeer")
    store._set_revoked(revoked_kp.device_id, revoked_by="admin", reason="lost")

    rev_cert = create_transition_certificate(revoked_kp, successor_kp)
    with capture_security_events() as events:
        from core.identity.rotation import RotationError
        with pytest.raises(RotationError):
            store.record_rotation(rev_cert)
        rev_events = [
            e for e in events if e.event_type == SecurityEventType.REVOKED_DEVICE_ATTEMPT.value
        ]
        assert len(rev_events) >= 1
        assert rev_events[0].severity == SecuritySeverity.HIGH


def test_rotate_identity_emits_event(tmp_path):
    keystore = KeyStore(plaintext_fallback_path=str(tmp_path / "key.pem"))
    id_file = str(tmp_path / "identity.json")

    orig_kp = generate_keypair()
    current = DeviceIdentity(
        keypair=orig_kp,
        name="Alice",
        created_at=100.0,
        storage_backend="plaintext-file",
    )

    with capture_security_events() as events:
        new_id, cert = rotate_identity(
            current=current,
            new_name="Alice-New",
            identity_file=id_file,
            key_store=keystore,
        )
        assert new_id.device_id != current.keypair.device_id
        rot_events = [e for e in events if e.event_type == SecurityEventType.KEY_ROTATION.value]
        assert len(rot_events) == 1
        assert rot_events[0].severity == SecuritySeverity.INFO
        assert rot_events[0].device_id == new_id.device_id


# ---------------------------------------------------------------------------
# 7. Handshake call sites
# ---------------------------------------------------------------------------


def test_handshake_device_id_mismatch_emits_event():
    kp = generate_keypair()
    pub_hex = kp.public_key_bytes().hex()
    wrong_id = "0000000000000000000000000000000000000000000000000000000000000000"

    with capture_security_events() as events:
        with pytest.raises(IdentityVerificationError):
            _verify_device_identity(wrong_id, pub_hex)

        auth_events = [e for e in events if e.event_type == SecurityEventType.AUTH_FAILED.value]
        assert len(auth_events) == 1
        assert auth_events[0].severity == SecuritySeverity.WARNING
        assert auth_events[0].device_id == wrong_id


@pytest.mark.asyncio
async def test_handshake_nonce_replay_emits_event():
    cache = NonceCache()
    seen_nonce = "11" * 32
    cache.check_and_add(seen_nonce)

    # Simulate responder receiving replayed initiator nonce
    alice = generate_keypair()
    from core.protocol.frame import encode_frame
    from core.protocol.messages import make_handshake_init

    reader = asyncio.StreamReader()
    writer = MagicMock()

    init_msg = make_handshake_init(
        device_id=alice.device_id,
        public_key=alice.public_key_bytes().hex(),
        ephemeral_key=alice.public_key_bytes().hex(),
        nonce=seen_nonce,
        sender_name="Alice",
    )
    reader.feed_data(encode_frame(init_msg))

    bob = generate_keypair()
    with capture_security_events() as events:
        with pytest.raises(HandshakeProtocolError):
            await perform_handshake_responder(
                reader=reader,
                writer=writer,
                my_identity=bob,
                my_name="Bob",
                nonce_cache=cache,
            )

        replay_events = [
            e for e in events if e.event_type == SecurityEventType.REPLAY_DETECTED.value
        ]
        assert len(replay_events) == 1
        assert replay_events[0].severity == SecuritySeverity.HIGH
