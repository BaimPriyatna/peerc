"""tests/test_rotation.py — Phase 40: Device Key Rotation tests.

Covers:
  1. Create + verify a TransitionCertificate (happy path).
  2. Tampered cert rejected (signature invalid).
  3. Wrong signing key rejected.
  4. Rotation carries TRUSTED status to new device_id.
  5. PENDING does NOT carry over (stays PENDING / UNKNOWN).
  6. REVOKED old device cannot rotate.
  7. Compromise rotation (no cert) → new device_id is UNKNOWN.
  8. Multi-hop rotation chain lookup.
  9. check_with_rotation — direct TRUSTED short-circuits.
 10. check_with_rotation — TRUSTED via ancestor chain.
 11. check_with_rotation — REVOKED ancestor propagates.
"""

import base64
import time

import pytest

from core.identity.device_identity import generate_keypair
from core.identity.rotation import (
    RotationError,
    TransitionCertificate,
    create_transition_certificate,
    verify_transition_certificate,
)
from core.trust.device import TrustStatus
from core.trust.store import TrustDecision, TrustStore

pytestmark = pytest.mark.security



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store(tmp_path):
    return TrustStore(db_path=str(tmp_path / "trust.db"))


def _pub_b64(keypair) -> str:
    return base64.b64encode(keypair.public_key_bytes()).decode("ascii")


def _seed_trusted(store: TrustStore, keypair) -> None:
    """Insert a device into the store and approve it (TRUSTED)."""
    store.record_first_seen(keypair.device_id, _pub_b64(keypair), name="Alice")
    store.approve(keypair.device_id)


def _seed_pending(store: TrustStore, keypair) -> None:
    """Insert a device into the store as PENDING (not yet approved)."""
    store.record_first_seen(keypair.device_id, _pub_b64(keypair), name="Bob")


# ---------------------------------------------------------------------------
# 1. Happy-path: create and verify
# ---------------------------------------------------------------------------


def test_create_and_verify_cert():
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    cert = create_transition_certificate(old_kp, new_kp)

    assert cert.old_device_id == old_kp.device_id
    assert cert.new_device_id == new_kp.device_id
    assert cert.old_public_key == _pub_b64(old_kp)
    assert cert.new_public_key == _pub_b64(new_kp)
    assert verify_transition_certificate(cert) is True


# ---------------------------------------------------------------------------
# 2. Tampered cert — modify new_device_id → invalid signature
# ---------------------------------------------------------------------------


def test_tampered_new_device_id_rejected():
    old_kp = generate_keypair()
    new_kp = generate_keypair()
    cert = create_transition_certificate(old_kp, new_kp)

    tampered = TransitionCertificate(
        old_device_id=cert.old_device_id,
        old_public_key=cert.old_public_key,
        new_device_id="deadbeef" * 8,   # 64 hex chars, wrong value
        new_public_key=cert.new_public_key,
        timestamp=cert.timestamp,
        signature=cert.signature,
    )
    assert verify_transition_certificate(tampered) is False


# ---------------------------------------------------------------------------
# 3. Wrong signing key — signature by a third key
# ---------------------------------------------------------------------------


def test_wrong_signing_key_rejected():
    old_kp = generate_keypair()
    new_kp = generate_keypair()
    impostor_kp = generate_keypair()

    # Build a cert but sign it with the impostor key, not old_kp.
    cert_real = create_transition_certificate(old_kp, new_kp)
    cert_impostor = create_transition_certificate(impostor_kp, new_kp)

    # Splice: same old_device_id/old_public_key as the real cert, but
    # the signature came from impostor_kp → verification must fail.
    spliced = TransitionCertificate(
        old_device_id=cert_real.old_device_id,
        old_public_key=cert_real.old_public_key,
        new_device_id=cert_real.new_device_id,
        new_public_key=cert_real.new_public_key,
        timestamp=cert_real.timestamp,
        signature=cert_impostor.signature,
    )
    assert verify_transition_certificate(spliced) is False


# ---------------------------------------------------------------------------
# 4. Rotation carries TRUSTED forward
# ---------------------------------------------------------------------------


def test_rotation_carries_trusted_status(tmp_path):
    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_trusted(store, old_kp)
    cert = create_transition_certificate(old_kp, new_kp)
    store.record_rotation(cert)

    new_device = store.get(new_kp.device_id)
    assert new_device is not None
    assert new_device.status == TrustStatus.TRUSTED


# ---------------------------------------------------------------------------
# 5. PENDING does NOT carry over
# ---------------------------------------------------------------------------


def test_rotation_from_pending_stays_unknown(tmp_path):
    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_pending(store, old_kp)   # PENDING, not approved
    cert = create_transition_certificate(old_kp, new_kp)
    store.record_rotation(cert)

    # Transition IS recorded (cert is valid), but new device_id is NOT inserted
    # automatically because old was PENDING, not TRUSTED.
    new_device = store.get(new_kp.device_id)
    assert new_device is None


# ---------------------------------------------------------------------------
# 6. REVOKED old device cannot rotate
# ---------------------------------------------------------------------------


def test_rotation_from_revoked_raises(tmp_path):
    from core.identity.rotation import RotationError
    from core.trust.revocation import revoke_device

    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_trusted(store, old_kp)
    revoke_device(store, old_kp.device_id, revoked_by="user", reason="test")

    cert = create_transition_certificate(old_kp, new_kp)

    with pytest.raises(RotationError, match="REVOKED"):
        store.record_rotation(cert)


# ---------------------------------------------------------------------------
# 7. Compromise rotation (no cert) → new device_id is UNKNOWN
# ---------------------------------------------------------------------------


def test_compromise_rotation_not_auto_trusted(tmp_path):
    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_trusted(store, old_kp)

    # Attacker/compromise: we just generate a brand-new keypair but produce
    # no TransitionCertificate.  The new device_id must look like a stranger.
    decision = store.check(new_kp.device_id, _pub_b64(new_kp))
    assert decision == TrustDecision.UNKNOWN


# ---------------------------------------------------------------------------
# 8. Multi-hop chain: A → B → C
# ---------------------------------------------------------------------------


def test_multihop_rotation_chain(tmp_path):
    store = _make_store(tmp_path)
    kp_a = generate_keypair()
    kp_b = generate_keypair()
    kp_c = generate_keypair()

    _seed_trusted(store, kp_a)

    cert_ab = create_transition_certificate(kp_a, kp_b)
    store.record_rotation(cert_ab)

    cert_bc = create_transition_certificate(kp_b, kp_c)
    store.record_rotation(cert_bc)

    chain = store.get_rotation_chain(kp_a.device_id)
    assert set(chain) == {kp_a.device_id, kp_b.device_id, kp_c.device_id}

    # Chain is ordered oldest → newest.
    assert chain.index(kp_a.device_id) < chain.index(kp_b.device_id)
    assert chain.index(kp_b.device_id) < chain.index(kp_c.device_id)

    # C is also TRUSTED (rotation carried over A → B → C).
    assert store.get(kp_c.device_id).status == TrustStatus.TRUSTED


# ---------------------------------------------------------------------------
# 9. check_with_rotation — direct TRUSTED short-circuits
# ---------------------------------------------------------------------------


def test_check_with_rotation_direct_trusted(tmp_path):
    store = _make_store(tmp_path)
    kp = generate_keypair()

    _seed_trusted(store, kp)

    result = store.check_with_rotation(kp.device_id, _pub_b64(kp))
    assert result == TrustDecision.TRUSTED


# ---------------------------------------------------------------------------
# 10. check_with_rotation — TRUSTED via ancestor chain (no direct DB entry)
# ---------------------------------------------------------------------------


def test_check_with_rotation_trusted_via_chain(tmp_path):
    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_trusted(store, old_kp)
    cert = create_transition_certificate(old_kp, new_kp)
    store.record_rotation(cert)

    # new_kp is trusted via rotation; check_with_rotation should return TRUSTED.
    result = store.check_with_rotation(new_kp.device_id, _pub_b64(new_kp))
    assert result == TrustDecision.TRUSTED


# ---------------------------------------------------------------------------
# 11. check_with_rotation — REVOKED ancestor propagates as REVOKED
# ---------------------------------------------------------------------------


def test_check_with_rotation_revoked_ancestor(tmp_path):
    from core.trust.revocation import revoke_device

    store = _make_store(tmp_path)
    old_kp = generate_keypair()
    new_kp = generate_keypair()

    _seed_trusted(store, old_kp)
    cert = create_transition_certificate(old_kp, new_kp)
    store.record_rotation(cert)

    # Now revoke the new device directly (simulating a scenario where the
    # new device is later revoked — ancestor walk should surface REVOKED).
    revoke_device(store, new_kp.device_id, revoked_by="user", reason="compromised")

    # Querying old_kp via check_with_rotation should surface REVOKED
    # because new_kp (successor in chain) is REVOKED.
    result = store.check_with_rotation(old_kp.device_id, _pub_b64(old_kp))
    assert result == TrustDecision.REVOKED


# ---------------------------------------------------------------------------
# 12. Same-device rotation raises RotationError
# ---------------------------------------------------------------------------


def test_same_keypair_rotation_raises():
    kp = generate_keypair()
    with pytest.raises(RotationError, match="same device_id"):
        create_transition_certificate(kp, kp)
