"""tests/test_group_audit.py — Phase 42.5: Signed Audit Log tests.

Covers:
  1. create_group_audit_event validation and structure.
  2. sign_audit_event and verify_audit_event (happy path, tampered payload, wrong key).
  3. verify_group_audit_event (active admin accepted, removed admin rejected, unsigned rejected).
  4. GroupStore.record_audit_event and list_audit_events with filtering and limits.
  5. GroupStore.record_audit_event with verify_with_admins enforcement.
  6. Automatic lifecycle audit event emission (create_group, record_membership,
     revoke_membership, set_policy, add_admin, remove_admin).
  7. format_audit_event representation.
  8. ChatApp UI command /group audit.
"""

import time
import pytest

from core.group.store import AdminStatus, GroupStore, GroupStoreError, MembershipStatus
from core.group.audit import (
    AuditError,
    create_group_audit_event,
    format_audit_event,
    sign_audit_event,
    verify_audit_event,
    verify_group_audit_event,
)
from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import GroupPolicy
from core.identity.device_identity import generate_keypair
from core.security.events import SecurityEventType, SecuritySeverity
from ui import ChatApp


def test_create_group_audit_event_validation():
    with pytest.raises(AuditError):
        create_group_audit_event(
            group_id="",
            event_type=SecurityEventType.GROUP_CREATED,
            description="Empty group id",
        )

    ev = create_group_audit_event(
        group_id="corp-1",
        event_type=SecurityEventType.GROUP_CREATED,
        description="Created group corp-1",
        severity=SecuritySeverity.INFO,
        actor_device_id="admin-1",
        details={"name": "Corp"},
    )
    assert ev.event_type == "group_created"
    assert ev.severity == SecuritySeverity.INFO
    assert ev.details["group_id"] == "corp-1"
    assert ev.details["actor_device_id"] == "admin-1"
    assert ev.details["name"] == "Corp"
    assert ev.signature is None


def test_sign_and_verify_audit_event_happy_path():
    admin = generate_keypair()
    ev = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Changed allow_external_trust to false",
        severity=SecuritySeverity.INFO,
        admin_keypair=admin,
    )

    assert ev.signature is not None
    assert ev.signer_device_id == admin.device_id
    assert verify_audit_event(ev, admin.public_key_bytes()) is True


def test_verify_audit_event_tampered_payload_rejected():
    admin = generate_keypair()
    ev = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Original description",
        admin_keypair=admin,
    )

    # Tampering with description
    ev.description = "Tampered description"
    assert verify_audit_event(ev, admin.public_key_bytes()) is False


def test_verify_audit_event_wrong_key_rejected():
    admin1 = generate_keypair()
    admin2 = generate_keypair()
    ev = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Policy changed",
        admin_keypair=admin1,
    )

    assert verify_audit_event(ev, admin2.public_key_bytes()) is False


def test_verify_group_audit_event_active_admin():
    admin1 = generate_keypair()
    admin2 = generate_keypair()
    impostor = generate_keypair()

    active_admins = {
        admin1.device_id: admin1.public_key_bytes(),
        admin2.device_id: admin2.public_key_bytes(),
    }

    # Signed by active admin1
    ev1 = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.ADMIN_ADDED,
        description="Admin added",
        admin_keypair=admin1,
    )
    assert verify_group_audit_event(ev1, active_admins) is True

    # Signed by impostor (not in active_admins)
    ev_imp = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.ADMIN_ADDED,
        description="Impostor event",
        admin_keypair=impostor,
    )
    assert verify_group_audit_event(ev_imp, active_admins) is False

    # Unsigned event
    ev_unsig = create_group_audit_event(
        group_id="sec-1",
        event_type=SecurityEventType.ADMIN_ADDED,
        description="Unsigned event",
    )
    assert verify_group_audit_event(ev_unsig, active_admins) is False


def test_group_store_record_and_list_audit_events(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder = generate_keypair()
    group = create_group(founder, name="Engineering", group_id="eng-1")
    store.create_group(group)

    # create_group already recorded 1 event (group_created)
    events = store.list_audit_events("eng-1")
    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.GROUP_CREATED.value

    # Manually record custom audit events
    ev2 = create_group_audit_event(
        group_id="eng-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Policy changed to strict",
        severity=SecuritySeverity.WARNING,
        actor_device_id=founder.device_id,
        details={"event_id": "custom-ev-2"},
        admin_keypair=founder,
    )
    store.record_audit_event("eng-1", ev2)

    ev3 = create_group_audit_event(
        group_id="eng-1",
        event_type=SecurityEventType.MEMBERSHIP_ISSUED,
        description="Issued cert to dev-2",
        severity=SecuritySeverity.INFO,
        details={"event_id": "custom-ev-3"},
    )
    store.record_audit_event("eng-1", ev3)

    # Query all
    all_evs = store.list_audit_events("eng-1")
    assert len(all_evs) == 3

    # Query by event_type
    policy_evs = store.list_audit_events("eng-1", event_type="policy_changed")
    assert len(policy_evs) == 1
    assert policy_evs[0].description == "Policy changed to strict"

    # Query by severity
    warn_evs = store.list_audit_events("eng-1", severity=SecuritySeverity.WARNING)
    assert len(warn_evs) == 1
    assert warn_evs[0].event_type == "policy_changed"

    # Query with limit
    lim_evs = store.list_audit_events("eng-1", limit=2)
    assert len(lim_evs) == 2

    # Query by event_id
    single = store.get_audit_event("custom-ev-2")
    assert single is not None
    assert single.description == "Policy changed to strict"


def test_group_store_record_audit_event_verify_with_admins(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder = generate_keypair()
    other_peer = generate_keypair()
    group = create_group(founder, name="Engineering", group_id="eng-1")
    store.create_group(group)

    # Valid signed event by active admin
    valid_ev = create_group_audit_event(
        group_id="eng-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Signed by founder",
        admin_keypair=founder,
    )
    store.record_audit_event("eng-1", valid_ev, verify_with_admins=True)

    # Invalid signed event by non-admin
    invalid_ev = create_group_audit_event(
        group_id="eng-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Signed by non-admin",
        admin_keypair=other_peer,
    )
    with pytest.raises(GroupStoreError):
        store.record_audit_event("eng-1", invalid_ev, verify_with_admins=True)


def test_group_store_automatic_lifecycle_auditing(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, admin2, member = generate_keypair(), generate_keypair(), generate_keypair()

    # 1. create_group
    group = create_group(founder, name="Infra", group_id="infra-1")
    store.create_group(group)

    # 2. add_admin
    store.add_admin("infra-1", admin2.device_id, admin2.public_key_bytes(), added_by=founder.device_id)

    # 3. set_policy
    policy = GroupPolicy(
        group_id="infra-1",
        allow_external_trust=False,
        version=2,
        admin_device_id=founder.device_id,
    )
    store.set_policy(policy)

    # 4. record_membership
    cert = issue_membership_certificate(
        founder,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id="infra-1",
        role="operator",
    )
    store.record_membership(cert)

    # 5. revoke_membership
    store.revoke_membership("infra-1", member.device_id, revoked_by=founder.device_id, reason="rotation")

    # 6. remove_admin
    store.remove_admin("infra-1", admin2.device_id, removed_by=founder.device_id, reason="left team")

    # Verify all 6 lifecycle events were audited
    events = store.list_audit_events("infra-1")
    types = [e.event_type for e in events]
    assert types == [
        "group_created",
        "admin_added",
        "policy_changed",
        "membership_issued",
        "membership_revoked",
        "admin_removed",
    ]


def test_format_audit_event():
    admin = generate_keypair()
    ev = create_group_audit_event(
        group_id="ops-1",
        event_type=SecurityEventType.MEMBERSHIP_ISSUED,
        description="Approved member dev-1",
        admin_keypair=admin,
    )
    formatted = format_audit_event(ev)
    assert "ADMIN(" in formatted
    assert "membership_issued" in formatted
    assert "Approved member dev-1" in formatted
    assert "[signed]" in formatted


@pytest.mark.asyncio
async def test_ui_group_audit_command(tmp_path):
    app = ChatApp()
    keypair = generate_keypair()
    app.my_identity = keypair
    app.peer_id = keypair.device_id
    app.public_key_bytes = keypair.public_key_bytes()
    app.group_store = GroupStore(db_path=str(tmp_path / "ui_test.db"))
    app.logs = []
    app._log = lambda text: app.logs.append(text)

    # Create group (generates group_created event)
    await app._handle_group_command("create Production prod-1")

    # Add a signed audit event to the group
    audit_ev = create_group_audit_event(
        group_id="prod-1",
        event_type=SecurityEventType.POLICY_CHANGED,
        description="Emergency policy restriction",
        severity=SecuritySeverity.WARNING,
        admin_keypair=keypair,
    )
    app.group_store.record_audit_event("prod-1", audit_ev)

    # View audit log via /group audit
    app.logs.clear()
    await app._handle_group_command("audit prod-1")

    assert any("Group Audit Log: Production" in m for m in app.logs)
    assert any("group_created" in m for m in app.logs)
    assert any("policy_changed" in m and "Emergency policy restriction" in m for m in app.logs)
    assert any("✓ signed" in m for m in app.logs)
