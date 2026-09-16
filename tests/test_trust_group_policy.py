"""tests/test_trust_group_policy.py — Phase 42.2: TrustStore wiring
with GroupStore and PolicyEnforcer for External Trust Restriction (§6).

Covers:
  1. Standalone TrustStore (no group) records UNKNOWN devices as PENDING unimpeded.
  2. TrustStore with GroupStore where allow_external_trust=True records UNKNOWN devices as PENDING unimpeded.
  3. TrustStore with GroupStore where allow_external_trust=False:
     - External device rejected with ExternalTrustDeniedError on record_first_seen().
     - External device is NOT persisted in trusted_devices.
     - SecurityEvent POLICY_VIOLATION is emitted.
     - Active group member device is successfully recorded as PENDING.
     - Group admin device is successfully recorded as PENDING.
  4. Integration with VaultDatabase:
     - Both TrustStore and GroupStore sharing VaultDatabase connection.
     - Policy survives vault lock() and re-unlock().
     - External trust restriction persists and enforces correctly after unlock.
"""

import os
import pytest

from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import ExternalTrustDeniedError, GroupPolicy
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from core.security import SecurityEventType, capture_security_events
from core.trust.device import TrustStatus
from core.trust.store import TrustDecision, TrustStore
from core.vault.database import VaultDatabase


# ---------------------------------------------------------------------------
# 1. Standalone & unrestricted group behavior
# ---------------------------------------------------------------------------


def test_trust_store_without_group_records_pending_unimpeded(tmp_path):
    store = TrustStore(str(tmp_path / "trust.db"))
    peer = generate_keypair()
    pub_hex = peer.public_key_bytes().hex()

    assert store.check(peer.device_id, pub_hex) == TrustDecision.UNKNOWN
    trusted_dev = store.record_first_seen(peer.device_id, pub_hex, name="Bob")

    assert trusted_dev.device_id == peer.device_id
    assert trusted_dev.status == TrustStatus.PENDING
    assert store.check(peer.device_id, pub_hex) == TrustDecision.PENDING


def test_trust_store_with_permissive_group_records_pending(tmp_path):
    trust_store = TrustStore(str(tmp_path / "trust.db"))
    group_store = GroupStore(str(tmp_path / "group.db"))
    trust_store.set_group_store(group_store)

    admin = generate_keypair()
    group = create_group(admin, name="OpenCorp")
    group_store.create_group(group)
    group_store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=True))

    peer = generate_keypair()
    pub_hex = peer.public_key_bytes().hex()

    trusted_dev = trust_store.record_first_seen(peer.device_id, pub_hex, name="Alice")
    assert trusted_dev.status == TrustStatus.PENDING


# ---------------------------------------------------------------------------
# 2. External Trust Restriction (§6) in TrustStore.record_first_seen()
# ---------------------------------------------------------------------------


def test_external_trust_restriction_rejects_external_peer(tmp_path):
    trust_store = TrustStore(str(tmp_path / "trust.db"))
    group_store = GroupStore(str(tmp_path / "group.db"))
    trust_store.set_group_store(group_store)

    admin = generate_keypair()
    group = create_group(admin, name="StrictCorp")
    group_store.create_group(group)
    group_store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

    external_peer = generate_keypair()
    pub_hex = external_peer.public_key_bytes().hex()

    with capture_security_events() as events:
        with pytest.raises(ExternalTrustDeniedError) as exc_info:
            trust_store.record_first_seen(external_peer.device_id, pub_hex, name="ExternalGuy")
        assert "is not an active member" in str(exc_info.value)

    # Verify device was NOT persisted in trust store
    assert trust_store.get(external_peer.device_id) is None
    assert trust_store.check(external_peer.device_id, pub_hex) == TrustDecision.UNKNOWN

    # Verify security event emitted
    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert events[0].device_id == external_peer.device_id


def test_external_trust_restriction_allows_group_member_and_admin(tmp_path):
    trust_store = TrustStore(str(tmp_path / "trust.db"))
    group_store = GroupStore(str(tmp_path / "group.db"))
    trust_store.set_group_store(group_store)

    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="StrictCorp")
    group_store.create_group(group)
    group_store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    group_store.record_membership(cert)

    # 1. Admin can be recorded
    admin_pub_hex = admin.public_key_bytes().hex()
    dev_admin = trust_store.record_first_seen(admin.device_id, admin_pub_hex, name="Admin")
    assert dev_admin.status == TrustStatus.PENDING

    # 2. Member can be recorded
    member_pub_hex = member.public_key_bytes().hex()
    dev_member = trust_store.record_first_seen(member.device_id, member_pub_hex, name="Member")
    assert dev_member.status == TrustStatus.PENDING


# ---------------------------------------------------------------------------
# 3. Vault Database Integration
# ---------------------------------------------------------------------------


def test_vault_database_group_policy_persistence_and_reunlock(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    dek = os.urandom(32)

    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        trust_store = TrustStore(conn=vdb.conn)
        group_store = GroupStore(conn=vdb.conn)
        trust_store.set_group_store(group_store)

        admin = generate_keypair()
        group = create_group(admin, name="VaultCorp")
        group_store.create_group(group)
        group_store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

        # Check policy is in the shared DB
        row = vdb.conn.execute(
            "SELECT allow_external_trust FROM group_policies WHERE group_id = ?", (group.group_id,)
        ).fetchone()
        assert row[0] == 0
    finally:
        vdb.lock()

    # Re-unlock vault and verify policy enforcement persists
    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        trust_store2 = TrustStore(conn=vdb2.conn)
        group_store2 = GroupStore(conn=vdb2.conn)
        trust_store2.set_group_store(group_store2)

        policy = group_store2.get_policy(group.group_id)
        assert policy is not None
        assert policy.allow_external_trust is False

        # Attempting to record an external device fails
        external_peer = generate_keypair()
        with pytest.raises(ExternalTrustDeniedError):
            trust_store2.record_first_seen(
                external_peer.device_id,
                external_peer.public_key_bytes().hex(),
                name="External",
            )
    finally:
        vdb2.lock()
