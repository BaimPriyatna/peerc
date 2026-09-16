"""tests/test_group_policy.py — Phase 42.2: Group Authority System
(policy schema, communication matrix, and core-level enforcement) tests.

Covers:
  1. GroupPolicy defaults, serialization (to_dict/from_dict), canonical_payload determinism.
  2. CommunicationRule matching (wildcards, roles, device IDs, actions).
  3. PolicyEnforcer — external trust restriction (§6).
  4. PolicyEnforcer — export authorization (§5, §11).
  5. PolicyEnforcer — controlled leave (§10).
  6. PolicyEnforcer — inter-group communication (§8).
  7. PolicyEnforcer — communication matrix evaluation (§7).
  8. GroupStore policy persistence (set_policy, get_policy, list_policies, upsert, validation).
"""

import os
import time
import pytest

from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import (
    CommunicationDeniedError,
    CommunicationRule,
    ExportDeniedError,
    ExternalTrustDeniedError,
    GroupPolicy,
    InterGroupDeniedError,
    LeaveRequiresAdminError,
    PolicyAction,
    PolicyEffect,
    PolicyEnforcer,
)
from core.group.store import GroupStore, GroupStoreError
from core.identity.device_identity import generate_keypair
from core.security import SecurityEventType, capture_security_events


# ---------------------------------------------------------------------------
# 1. Schema, serialization, canonical payload
# ---------------------------------------------------------------------------


def test_group_policy_defaults():
    policy = GroupPolicy(group_id="grp-1")
    assert policy.group_id == "grp-1"
    assert policy.allow_external_trust is True
    assert policy.allow_export is True
    assert policy.leave_requires_admin is False
    assert policy.allow_inter_group is True
    assert policy.communication_matrix == []
    assert policy.default_communication_effect == PolicyEffect.ALLOW
    assert policy.version == 1


def test_group_policy_serialization_roundtrip():
    rules = [
        CommunicationRule(source="engineering", destination="finance", action="chat", effect=PolicyEffect.DENY),
        CommunicationRule(source="*", destination="*", action="*", effect=PolicyEffect.ALLOW),
    ]
    policy = GroupPolicy(
        group_id="grp-100",
        allow_external_trust=False,
        allow_export=False,
        leave_requires_admin=True,
        allow_inter_group=False,
        communication_matrix=rules,
        default_communication_effect=PolicyEffect.DENY,
        version=3,
        admin_device_id="admin-dev",
        signature="dummy-sig",
    )

    d = policy.to_dict()
    assert d["group_id"] == "grp-100"
    assert d["allow_external_trust"] is False
    assert len(d["communication_matrix"]) == 2

    restored = GroupPolicy.from_dict(d)
    assert restored.group_id == policy.group_id
    assert restored.allow_external_trust is False
    assert restored.allow_export is False
    assert restored.leave_requires_admin is True
    assert restored.allow_inter_group is False
    assert restored.default_communication_effect == PolicyEffect.DENY
    assert len(restored.communication_matrix) == 2
    assert restored.communication_matrix[0].source == "engineering"
    assert restored.communication_matrix[0].effect == PolicyEffect.DENY


def test_canonical_payload_determinism():
    rules = [
        CommunicationRule(source="eng", destination="mgr", action="chat", effect=PolicyEffect.ALLOW),
    ]
    p1 = GroupPolicy(group_id="g1", communication_matrix=rules, version=1, admin_device_id="dev-a")
    p2 = GroupPolicy(group_id="g1", communication_matrix=rules, version=1, admin_device_id="dev-a")
    assert p1.canonical_payload() == p2.canonical_payload()
    assert p1.canonical_payload().startswith(b"peerc-group-policy\x00")


# ---------------------------------------------------------------------------
# 2. CommunicationRule matching
# ---------------------------------------------------------------------------


def test_communication_rule_matching():
    rule = CommunicationRule(
        source="engineering",
        destination="management",
        action="chat",
        effect=PolicyEffect.ALLOW,
    )

    # Matching roles and action
    assert rule.matches("dev1", "dev2", "chat", source_role="engineering", dest_role="management") is True

    # Case-insensitive matching
    assert rule.matches("dev1", "dev2", "CHAT", source_role="Engineering", dest_role="Management") is True

    # Wrong destination role
    assert rule.matches("dev1", "dev2", "chat", source_role="engineering", dest_role="finance") is False

    # Wrong action
    assert rule.matches("dev1", "dev2", "file_send", source_role="engineering", dest_role="management") is False

    # Wildcard rule matches anything
    wildcard_rule = CommunicationRule(source="*", destination="*", action="*", effect=PolicyEffect.ALLOW)
    assert wildcard_rule.matches("devA", "devB", "file_send", source_role="r1", dest_role="r2") is True


# ---------------------------------------------------------------------------
# 3. PolicyEnforcer: External Trust Restriction (§6)
# ---------------------------------------------------------------------------


def test_enforce_external_trust_allowed_when_no_restriction(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    group = create_group(admin, name="OpenGroup")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=True))

    # Any unknown device is allowed
    unknown_peer = generate_keypair()
    enforcer.check_external_trust(unknown_peer.device_id)
    assert enforcer.is_external_trust_allowed(unknown_peer.device_id) is True


def test_enforce_external_trust_denied_for_external_peer(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    group = create_group(admin, name="CorporateGroup")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

    external_peer = generate_keypair()

    with capture_security_events() as events:
        with pytest.raises(ExternalTrustDeniedError) as exc_info:
            enforcer.check_external_trust(external_peer.device_id)
        assert "is not an active member" in str(exc_info.value)
        assert group.group_id in str(exc_info.value)

    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert events[0].device_id == external_peer.device_id
    assert enforcer.is_external_trust_allowed(external_peer.device_id) is False


def test_enforce_external_trust_allowed_for_valid_member_and_admin(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="CorporateGroup")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    store.record_membership(cert)

    # Admin is allowed
    enforcer.check_external_trust(admin.device_id)
    assert enforcer.is_external_trust_allowed(admin.device_id) is True

    # Active member is allowed
    enforcer.check_external_trust(member.device_id)
    assert enforcer.is_external_trust_allowed(member.device_id) is True


def test_enforce_external_trust_denied_for_revoked_or_expired_member(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="CorporateGroup")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))

    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    store.record_membership(cert)

    # Revoke member
    store.revoke_membership(group.group_id, member.device_id, revoked_by=admin.device_id, reason="left")

    with pytest.raises(ExternalTrustDeniedError):
        enforcer.check_external_trust(member.device_id)


# ---------------------------------------------------------------------------
# 4. PolicyEnforcer: Export Authorization (§5, §11)
# ---------------------------------------------------------------------------


def test_enforce_export_policy(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    group = create_group(admin, name="StrictCorp")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_export=False))

    with capture_security_events() as events:
        with pytest.raises(ExportDeniedError):
            enforcer.check_export()

    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert enforcer.is_export_allowed() is False

    # Changing policy to allow_export=True permits export
    store.set_policy(GroupPolicy(group_id=group.group_id, allow_export=True))
    enforcer.check_export()
    assert enforcer.is_export_allowed() is True


# ---------------------------------------------------------------------------
# 5. PolicyEnforcer: Controlled Leave (§10)
# ---------------------------------------------------------------------------


def test_enforce_leave_policy(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="ManagedTeam")
    store.create_group(group)
    store.set_policy(GroupPolicy(group_id=group.group_id, leave_requires_admin=True))

    # Member attempting to leave without admin authority is rejected
    with capture_security_events() as events:
        with pytest.raises(LeaveRequiresAdminError):
            enforcer.check_leave(group.group_id, member.device_id, is_admin=False)

    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert enforcer.is_leave_allowed(group.group_id, member.device_id, is_admin=False) is False

    # Admin approval / action succeeds
    enforcer.check_leave(group.group_id, member.device_id, is_admin=True)
    assert enforcer.is_leave_allowed(group.group_id, member.device_id, is_admin=True) is True


# ---------------------------------------------------------------------------
# 6. PolicyEnforcer: Inter-Group Communication (§8)
# ---------------------------------------------------------------------------


def test_enforce_inter_group_policy(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    g1 = create_group(admin, name="GroupA")
    g2 = create_group(admin, name="GroupB")
    store.create_group(g1)
    store.create_group(g2)

    # Same group communication is always permitted by inter-group check
    enforcer.check_inter_group(g1.group_id, g1.group_id)

    # Both allow inter-group
    store.set_policy(GroupPolicy(group_id=g1.group_id, allow_inter_group=True))
    store.set_policy(GroupPolicy(group_id=g2.group_id, allow_inter_group=True))
    enforcer.check_inter_group(g1.group_id, g2.group_id)
    assert enforcer.is_inter_group_allowed(g1.group_id, g2.group_id) is True

    # GroupA restricts inter-group
    store.set_policy(GroupPolicy(group_id=g1.group_id, allow_inter_group=False))
    with capture_security_events() as events:
        with pytest.raises(InterGroupDeniedError):
            enforcer.check_inter_group(g1.group_id, g2.group_id)

    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert enforcer.is_inter_group_allowed(g1.group_id, g2.group_id) is False


# ---------------------------------------------------------------------------
# 7. PolicyEnforcer: Communication Matrix (§7)
# ---------------------------------------------------------------------------


def test_enforce_communication_matrix_rules(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    enforcer = PolicyEnforcer(store)

    admin = generate_keypair()
    group = create_group(admin, name="Company")
    store.create_group(group)

    # Rules matching docs/GROUP_AUTHORITY_DESIGN.md §7:
    # Engineering -> Engineering: ALLOW
    # Engineering -> Management:  ALLOW
    # Engineering -> Finance:     DENY
    # Engineering -> HR:          DENY
    rules = [
        CommunicationRule(source="engineering", destination="engineering", action="*", effect=PolicyEffect.ALLOW),
        CommunicationRule(source="engineering", destination="management", action="*", effect=PolicyEffect.ALLOW),
        CommunicationRule(source="engineering", destination="finance", action="*", effect=PolicyEffect.DENY),
        CommunicationRule(source="engineering", destination="hr", action="*", effect=PolicyEffect.DENY),
    ]
    store.set_policy(
        GroupPolicy(
            group_id=group.group_id,
            communication_matrix=rules,
            default_communication_effect=PolicyEffect.DENY,
        )
    )

    # Engineering -> Management allowed
    enforcer.check_communication(
        action=PolicyAction.CHAT,
        source_device_id="dev-eng",
        dest_device_id="dev-mgr",
        source_role="engineering",
        dest_role="management",
        source_group_id=group.group_id,
    )
    assert enforcer.is_communication_allowed(
        action=PolicyAction.CHAT,
        source_device_id="dev-eng",
        dest_device_id="dev-mgr",
        source_role="engineering",
        dest_role="management",
        source_group_id=group.group_id,
    ) is True

    # Engineering -> Finance denied
    with capture_security_events() as events:
        with pytest.raises(CommunicationDeniedError):
            enforcer.check_communication(
                action=PolicyAction.FILE_SEND,
                source_device_id="dev-eng",
                dest_device_id="dev-fin",
                source_role="engineering",
                dest_role="finance",
                source_group_id=group.group_id,
            )

    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.POLICY_VIOLATION
    assert enforcer.is_communication_allowed(
        action=PolicyAction.FILE_SEND,
        source_device_id="dev-eng",
        dest_device_id="dev-fin",
        source_role="engineering",
        dest_role="finance",
        source_group_id=group.group_id,
    ) is False

    # Unlisted role with default_communication_effect=DENY
    with pytest.raises(CommunicationDeniedError):
        enforcer.check_communication(
            action=PolicyAction.CHAT,
            source_device_id="dev-guest",
            dest_device_id="dev-mgr",
            source_role="guest",
            dest_role="management",
            source_group_id=group.group_id,
        )


# ---------------------------------------------------------------------------
# 8. GroupStore policy persistence & validation
# ---------------------------------------------------------------------------


def test_group_store_policy_crud_and_validation(tmp_path):
    store = GroupStore(str(tmp_path / "group.db"))
    admin = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    # Initially get_policy returns None
    assert store.get_policy(group.group_id) is None
    assert store.list_policies() == []

    # Setting policy for unknown group fails
    with pytest.raises(GroupStoreError):
        store.set_policy(GroupPolicy(group_id="non-existent"))

    # Setting policy with wrong admin_device_id fails
    with pytest.raises(GroupStoreError):
        store.set_policy(GroupPolicy(group_id=group.group_id, admin_device_id="imposter-admin"))

    # Successful set_policy
    policy = GroupPolicy(
        group_id=group.group_id,
        allow_external_trust=False,
        allow_export=False,
        leave_requires_admin=True,
        allow_inter_group=False,
        admin_device_id=admin.device_id,
        communication_matrix=[
            CommunicationRule(source="eng", destination="eng", action="*", effect=PolicyEffect.ALLOW)
        ],
    )
    store.set_policy(policy)

    retrieved = store.get_policy(group.group_id)
    assert retrieved is not None
    assert retrieved.group_id == group.group_id
    assert retrieved.allow_external_trust is False
    assert retrieved.allow_export is False
    assert retrieved.leave_requires_admin is True
    assert retrieved.allow_inter_group is False
    assert len(retrieved.communication_matrix) == 1

    # Upsert: update policy
    retrieved.allow_export = True
    retrieved.version = 2
    store.set_policy(retrieved)

    updated = store.get_policy(group.group_id)
    assert updated.allow_export is True
    assert updated.version == 2
    assert len(store.list_policies()) == 1
