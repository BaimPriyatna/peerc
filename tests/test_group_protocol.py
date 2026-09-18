"""tests/test_group_protocol.py — Phase 42.4: join/leave/revoke protocol.

Covers signed Group Authority control-plane messages and their core
application through GroupStore. UI commands are deliberately out of scope.
"""

import pytest

import protocol
from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import GroupPolicy, LeaveRequiresAdminError
from core.group.protocol import (
    GroupJoinRequest,
    GroupJoinResponse,
    create_join_request,
    create_join_response,
    create_leave_request,
    create_leave_response,
    create_membership_revocation,
    verify_join_request,
    verify_join_response,
    verify_leave_request,
    verify_membership_revocation,
)
from core.group.store import GroupStore, GroupStoreError, MembershipStatus
from core.identity.device_identity import generate_keypair
from core.protocol import ProtocolError, validate_message


def _setup_group(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)
    return store, admin, group


def _issue_member(store, admin, group, member):
    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
        role="employee",
        permissions=["chat"],
    )
    store.record_membership(cert)
    return cert


def test_join_request_signature_and_self_consistency():
    member = generate_keypair()
    req = create_join_request(
        member,
        group_id="group-1",
        requested_role="employee",
        requested_permissions=["chat"],
        reason="new laptop",
    )

    assert verify_join_request(req) is True

    tampered = GroupJoinRequest(**{**req.__dict__, "requested_role": "admin"})
    assert verify_join_request(tampered) is False

    mismatched = GroupJoinRequest(**{**req.__dict__, "device_id": "00" * 32})
    assert verify_join_request(mismatched) is False


def test_approved_join_response_records_membership(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    member = generate_keypair()
    req = create_join_request(member, group_id=group.group_id, requested_role="employee")
    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
        role="employee",
        permissions=["chat"],
    )
    res = create_join_response(admin, req, approved=True, certificate=cert, reason="approved")

    assert verify_join_response(res, admin.public_key_bytes()) is True
    store.process_join_response(res)

    stored = store.get_membership(group.group_id, member.device_id)
    assert stored is not None
    assert stored.role == "employee"
    assert stored.permissions == ["chat"]


def test_join_response_rejects_tampered_payload(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    member = generate_keypair()
    req = create_join_request(member, group_id=group.group_id)
    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    res = create_join_response(admin, req, approved=True, certificate=cert)
    tampered = GroupJoinResponse(**{**res.__dict__, "device_id": generate_keypair().device_id})

    with pytest.raises(GroupStoreError):
        store.process_join_response(tampered)


def test_member_signed_leave_request_tombstones_when_policy_allows(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    member = generate_keypair()
    _issue_member(store, admin, group, member)

    req = create_leave_request(member, group_id=group.group_id, reason="moving teams")

    assert verify_leave_request(req, member.public_key_bytes()) is True
    store.process_leave_request(req)

    assert store.get_membership_status(group.group_id, member.device_id) == MembershipStatus.REVOKED
    tombstone = store.get_membership_revocation(group.group_id, member.device_id)
    assert tombstone is not None
    assert tombstone.revoked_by == member.device_id
    assert tombstone.reason == "moving teams"


def test_member_signed_leave_request_respects_admin_required_policy(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    member = generate_keypair()
    _issue_member(store, admin, group, member)
    store.set_policy(GroupPolicy(group_id=group.group_id, leave_requires_admin=True))

    req = create_leave_request(member, group_id=group.group_id, reason="leaving")

    with pytest.raises(LeaveRequiresAdminError):
        store.process_leave_request(req)
    assert store.get_membership_status(group.group_id, member.device_id) == MembershipStatus.ACTIVE


def test_admin_leave_response_applies_signed_revocation(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    member = generate_keypair()
    _issue_member(store, admin, group, member)
    store.set_policy(GroupPolicy(group_id=group.group_id, leave_requires_admin=True))

    req = create_leave_request(member, group_id=group.group_id, reason="approved leave")
    revocation = create_membership_revocation(
        admin,
        group_id=group.group_id,
        device_id=member.device_id,
        reason="approved leave",
    )
    res = create_leave_response(admin, req, approved=True, revocation=revocation)
    store.process_leave_response(res)

    tombstone = store.get_membership_revocation(group.group_id, member.device_id)
    assert tombstone is not None
    assert tombstone.revoked_by == admin.device_id
    assert tombstone.reason == "approved leave"


def test_admin_revoke_message_tombstones_and_refuses_removed_admin(tmp_path):
    store, admin, group = _setup_group(tmp_path)
    second_admin = generate_keypair()
    member = generate_keypair()
    _issue_member(store, admin, group, member)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=admin.device_id)

    revocation = create_membership_revocation(
        second_admin,
        group_id=group.group_id,
        device_id=member.device_id,
        reason="device lost",
    )
    assert verify_membership_revocation(revocation, second_admin.public_key_bytes()) is True

    store.remove_admin(group.group_id, second_admin.device_id, removed_by=admin.device_id)
    with pytest.raises(GroupStoreError):
        store.record_revocation(revocation)

    fresh = create_membership_revocation(
        admin,
        group_id=group.group_id,
        device_id=member.device_id,
        reason="device lost",
    )
    store.record_revocation(fresh)
    assert store.get_membership_status(group.group_id, member.device_id) == MembershipStatus.REVOKED


def test_group_wire_messages_validate():
    member = generate_keypair()
    req = create_join_request(member, group_id="g1", requested_permissions=["chat"])
    msg = protocol.make_group_join_request(**req.to_dict())
    assert validate_message(msg) is msg

    revoke = create_membership_revocation(generate_keypair(), group_id="g1", device_id=member.device_id)
    revoke_msg = protocol.make_group_membership_revoke(**revoke.to_dict())
    assert validate_message(revoke_msg) is revoke_msg

    bad = {**msg, "requested_permissions": "chat"}
    with pytest.raises(ProtocolError):
        validate_message(bad)
