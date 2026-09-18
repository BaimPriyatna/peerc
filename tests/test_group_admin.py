"""tests/test_group_admin.py — Phase 42.3: multi-admin + k-of-n threshold
signature tests (core/group/admin.py + GroupStore's group_admins table).

Covers:
  1. create_threshold_approval validation.
  2. sign_approval / verify_approval_signature: happy path, duplicate
     signer refused, wrong key rejected, tampered payload rejected.
  3. count_valid_signatures / is_approved: k-of-n threshold math, and
     signatures from devices outside active_admins simply don't count.
  4. GroupStore.create_group auto-registers the founder as an active admin.
  5. add_admin: happy path, refuses a non-active adder, refuses a
     duplicate device_id.
  6. remove_admin: happy path, refuses removing the last active admin,
     refuses removing an already-inactive admin.
  7. list_admins (status filter) / get_active_admin_public_keys.
  8. record_membership() and set_policy() accept a signature from ANY
     active admin (not just the founder), and refuse a removed admin's.
"""

import pytest

from core.group.admin import (
    AdminError,
    count_valid_signatures,
    create_threshold_approval,
    is_approved,
    sign_approval,
    verify_approval_signature,
)
from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import GroupPolicy
from core.group.store import AdminStatus, GroupStore, GroupStoreError
from core.identity.device_identity import generate_keypair


# ---------------------------------------------------------------------------
# 1-3. ThresholdApproval (pure crypto/data, no storage)
# ---------------------------------------------------------------------------


def test_create_threshold_approval_validates_threshold():
    with pytest.raises(AdminError):
        create_threshold_approval("g1", "action1", b"payload", required_threshold=0)


def test_sign_and_verify_approval_happy_path():
    admin = generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=1)
    sign_approval(approval, admin)

    assert verify_approval_signature(approval, admin.device_id, admin.public_key_bytes()) is True


def test_sign_approval_duplicate_signer_refused():
    admin = generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=1)
    sign_approval(approval, admin)

    with pytest.raises(AdminError):
        sign_approval(approval, admin)


def test_verify_approval_signature_wrong_key_rejected():
    admin = generate_keypair()
    impostor = generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=1)
    sign_approval(approval, admin)

    assert verify_approval_signature(approval, admin.device_id, impostor.public_key_bytes()) is False


def test_verify_approval_signature_tampered_action_id_rejected():
    admin = generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=1)
    sign_approval(approval, admin)
    approval.action_id = "export-999"  # tamper after signing

    assert verify_approval_signature(approval, admin.device_id, admin.public_key_bytes()) is False


def test_threshold_math_2_of_3():
    admin_a, admin_b, admin_c = generate_keypair(), generate_keypair(), generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=2)
    active_admins = {
        admin_a.device_id: admin_a.public_key_bytes(),
        admin_b.device_id: admin_b.public_key_bytes(),
        admin_c.device_id: admin_c.public_key_bytes(),
    }

    sign_approval(approval, admin_a)
    assert count_valid_signatures(approval, active_admins) == 1
    assert is_approved(approval, active_admins) is False

    sign_approval(approval, admin_b)
    assert count_valid_signatures(approval, active_admins) == 2
    assert is_approved(approval, active_admins) is True


def test_signature_from_non_active_admin_does_not_count():
    admin_a, removed_admin = generate_keypair(), generate_keypair()
    approval = create_threshold_approval("g1", "export-42", b"payload", required_threshold=2)
    sign_approval(approval, admin_a)
    sign_approval(approval, removed_admin)

    # removed_admin isn't in the active set passed in (e.g. they were
    # removed after signing) — their signature simply doesn't count.
    active_admins = {admin_a.device_id: admin_a.public_key_bytes()}
    assert count_valid_signatures(approval, active_admins) == 1
    assert is_approved(approval, active_admins) is False


# ---------------------------------------------------------------------------
# 4-7. GroupStore admin CRUD
# ---------------------------------------------------------------------------


def test_create_group_auto_registers_founder_as_active_admin(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder = generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)

    assert store.is_admin(group.group_id, founder.device_id) is True
    admins = store.list_admins(group.group_id)
    assert [a.device_id for a in admins] == [founder.device_id]
    assert admins[0].added_by is None


def test_add_admin_happy_path(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, new_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)

    record = store.add_admin(group.group_id, new_admin.device_id, new_admin.public_key_bytes(), added_by=founder.device_id)

    assert record.added_by == founder.device_id
    assert store.is_admin(group.group_id, new_admin.device_id) is True
    assert {a.device_id for a in store.list_admins(group.group_id, status=AdminStatus.ACTIVE)} == {
        founder.device_id,
        new_admin.device_id,
    }


def test_add_admin_refuses_non_active_adder(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, impostor, new_admin = generate_keypair(), generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)

    with pytest.raises(GroupStoreError):
        store.add_admin(group.group_id, new_admin.device_id, new_admin.public_key_bytes(), added_by=impostor.device_id)


def test_add_admin_refuses_duplicate_device(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, new_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, new_admin.device_id, new_admin.public_key_bytes(), added_by=founder.device_id)

    with pytest.raises(GroupStoreError):
        store.add_admin(group.group_id, new_admin.device_id, new_admin.public_key_bytes(), added_by=founder.device_id)


def test_remove_admin_happy_path(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)

    store.remove_admin(group.group_id, second_admin.device_id, removed_by=founder.device_id, reason="left the company")

    assert store.is_admin(group.group_id, second_admin.device_id) is False
    active = store.list_admins(group.group_id, status=AdminStatus.ACTIVE)
    assert [a.device_id for a in active] == [founder.device_id]


def test_remove_admin_refuses_last_active_admin(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder = generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)

    with pytest.raises(GroupStoreError):
        store.remove_admin(group.group_id, founder.device_id, removed_by=founder.device_id)


def test_remove_admin_refuses_already_removed(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)
    store.remove_admin(group.group_id, second_admin.device_id, removed_by=founder.device_id)

    with pytest.raises(GroupStoreError):
        store.remove_admin(group.group_id, second_admin.device_id, removed_by=founder.device_id)


def test_get_active_admin_public_keys(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)

    keys = store.get_active_admin_public_keys(group.group_id)

    assert keys == {
        founder.device_id: founder.public_key_bytes(),
        second_admin.device_id: second_admin.public_key_bytes(),
    }


# ---------------------------------------------------------------------------
# 8. record_membership() / set_policy() accept ANY active admin
# ---------------------------------------------------------------------------


def test_record_membership_accepts_second_admins_signature(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin, member = generate_keypair(), generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)

    cert = issue_membership_certificate(
        second_admin,  # signed by the SECOND admin, not the founder
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    store.record_membership(cert)

    assert store.get_membership(group.group_id, member.device_id) is not None


def test_record_membership_refuses_removed_admins_signature(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin, member = generate_keypair(), generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)
    store.remove_admin(group.group_id, second_admin.device_id, removed_by=founder.device_id)

    cert = issue_membership_certificate(
        second_admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    with pytest.raises(GroupStoreError):
        store.record_membership(cert)


def test_set_policy_accepts_second_admin(tmp_path):
    store = GroupStore(db_path=str(tmp_path / "group.db"))
    founder, second_admin = generate_keypair(), generate_keypair()
    group = create_group(founder, name="Engineering")
    store.create_group(group)
    store.add_admin(group.group_id, second_admin.device_id, second_admin.public_key_bytes(), added_by=founder.device_id)

    policy = GroupPolicy(group_id=group.group_id, allow_export=False, admin_device_id=second_admin.device_id)
    store.set_policy(policy)

    assert store.get_policy(group.group_id).allow_export is False
