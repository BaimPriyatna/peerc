"""tests/test_group_membership.py — Phase 42.1: Group Authority System
(membership certificates + GroupStore) tests.

Covers:
  1. Create a group + issue + verify a membership certificate (happy path).
  2. Tampered cert rejected (signature invalid).
  3. Wrong verifying key rejected.
  4. is_membership_expired: never-expiring, not-yet-expired, expired.
  5. GroupStore.create_group + duplicate group_id refused.
  6. GroupStore.record_membership: happy path, unknown group refused,
     admin_device_id mismatch refused, invalid signature refused,
     duplicate membership refused.
  7. get_membership / list_memberships (with status filter) / revoke_membership.
  8. adopt_conn detach — operations raise once detached.
"""

import base64
import time

import pytest

from core.identity.device_identity import generate_keypair
from core.group.membership import (
    MembershipCertificate,
    create_group,
    is_membership_expired,
    issue_membership_certificate,
    verify_membership_certificate,
)
from core.group.store import GroupStore, GroupStoreError, MembershipStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue_cert(admin_keypair, member_keypair, group, **kwargs):
    return issue_membership_certificate(
        admin_keypair,
        device_id=member_keypair.device_id,
        device_public_key=member_keypair.public_key_bytes(),
        group_id=group.group_id,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# 1. Happy path: create group, issue + verify a certificate
# ---------------------------------------------------------------------------


def test_issue_and_verify_membership_certificate():
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")

    cert = _issue_cert(admin, member, group, role="employee", permissions=["chat", "file_send"])

    assert cert.device_id == member.device_id
    assert cert.group_id == group.group_id
    assert cert.admin_device_id == admin.device_id
    assert verify_membership_certificate(cert, admin.public_key_bytes()) is True


def test_never_expiring_by_default():
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")

    cert = _issue_cert(admin, member, group)

    assert cert.expires_at is None
    assert is_membership_expired(cert) is False


def test_ttl_expiry():
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")

    not_yet = _issue_cert(admin, member, group, ttl_seconds=3600)
    assert is_membership_expired(not_yet) is False

    already = _issue_cert(admin, member, group, ttl_seconds=-1)  # expired 1s ago
    assert is_membership_expired(already) is True


# ---------------------------------------------------------------------------
# 2/3. Tampering and wrong key rejected
# ---------------------------------------------------------------------------


def test_tampered_certificate_rejected():
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")

    cert = _issue_cert(admin, member, group, role="employee")
    tampered = MembershipCertificate(**{**cert.__dict__, "role": "admin"})

    assert verify_membership_certificate(tampered, admin.public_key_bytes()) is False


def test_wrong_verifying_key_rejected():
    admin = generate_keypair()
    impostor = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")

    cert = _issue_cert(admin, member, group)

    assert verify_membership_certificate(cert, impostor.public_key_bytes()) is False


# ---------------------------------------------------------------------------
# 5. GroupStore.create_group
# ---------------------------------------------------------------------------


def test_create_group_and_duplicate_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    group = create_group(admin, name="Engineering")

    store.create_group(group)
    assert store.get_group(group.group_id).name == "Engineering"

    with pytest.raises(GroupStoreError):
        store.create_group(group)


def test_list_groups(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    g1 = create_group(admin, name="Engineering")
    g2 = create_group(admin, name="Sales")
    store.create_group(g1)
    store.create_group(g2)

    names = {g.name for g in store.list_groups()}
    assert names == {"Engineering", "Sales"}


# ---------------------------------------------------------------------------
# 6. GroupStore.record_membership
# ---------------------------------------------------------------------------


def test_record_membership_happy_path(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    cert = _issue_cert(admin, member, group, role="employee", permissions=["chat"])
    store.record_membership(cert)

    stored = store.get_membership(group.group_id, member.device_id)
    assert stored is not None
    assert stored.role == "employee"
    assert stored.permissions == ["chat"]
    assert store.get_membership_status(group.group_id, member.device_id) == MembershipStatus.ACTIVE


def test_record_membership_unknown_group_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")  # never store.create_group()'d

    cert = _issue_cert(admin, member, group)
    with pytest.raises(GroupStoreError):
        store.record_membership(cert)


def test_record_membership_admin_mismatch_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    real_admin = generate_keypair()
    fake_admin = generate_keypair()
    member = generate_keypair()
    group = create_group(real_admin, name="Engineering")
    store.create_group(group)

    # A cert "signed" by someone else claiming to be the admin.
    forged = _issue_cert(fake_admin, member, group)
    with pytest.raises(GroupStoreError):
        store.record_membership(forged)


def test_record_membership_invalid_signature_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    cert = _issue_cert(admin, member, group, role="employee")
    tampered = MembershipCertificate(**{**cert.__dict__, "role": "admin"})
    with pytest.raises(GroupStoreError):
        store.record_membership(tampered)


def test_record_membership_duplicate_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    cert = _issue_cert(admin, member, group)
    store.record_membership(cert)

    with pytest.raises(GroupStoreError):
        store.record_membership(cert)


# ---------------------------------------------------------------------------
# 7. get_membership / list_memberships / revoke_membership
# ---------------------------------------------------------------------------


def test_list_memberships_with_status_filter(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    member1 = generate_keypair()
    member2 = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    store.record_membership(_issue_cert(admin, member1, group))
    store.record_membership(_issue_cert(admin, member2, group))
    store.revoke_membership(group.group_id, member1.device_id, revoked_by=admin.device_id, reason="left company")

    active = store.list_memberships(group.group_id, status=MembershipStatus.ACTIVE)
    revoked = store.list_memberships(group.group_id, status=MembershipStatus.REVOKED)
    assert [m.device_id for m in active] == [member2.device_id]
    assert [m.device_id for m in revoked] == [member1.device_id]
    assert len(store.list_memberships(group.group_id)) == 2


def test_revoke_unknown_membership_refused(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    admin = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)

    with pytest.raises(GroupStoreError):
        store.revoke_membership(group.group_id, "nonexistent-device", revoked_by=admin.device_id)


# ---------------------------------------------------------------------------
# 8. adopt_conn detach
# ---------------------------------------------------------------------------


def test_adopt_conn_detach_raises(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    store.adopt_conn(None)
    with pytest.raises(RuntimeError):
        store.list_groups()
