"""tests/test_relay_authorization.py — Phase 46.2: authorize_relay_request()
+ the relay_request/relay_response wire messages.

Covers:
  1. authorize_relay_request():
     a. happy path — relay mode on, active member, target connected -> no raise
     b. relay mode off for the group -> RelayNotHostingError
     c. requester not an active member -> RelayAuthError
     d. authorized but target not connected -> RelayTargetUnreachableError
     e. check ordering: not-hosting takes priority over not-a-member
        takes priority over target-unreachable
  2. Wire message factories: make_relay_request / make_relay_response
  3. validate_message() for both message types
"""

import sqlite3

import pytest

from core.connectivity.relay import (
    RelayAuthError,
    RelayNotHostingError,
    RelayTargetUnreachableError,
    authorize_relay_request,
)
from core.group.membership import create_group, issue_membership_certificate
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from core.protocol.errors import ProtocolError
from core.protocol.messages import make_relay_request, make_relay_response, validate_message

pytestmark = pytest.mark.security



# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def group_store(db_conn):
    return GroupStore(conn=db_conn)


@pytest.fixture
def admin_kp():
    return generate_keypair()


@pytest.fixture
def member_kp():
    return generate_keypair()


@pytest.fixture
def outsider_kp():
    return generate_keypair()


@pytest.fixture
def group_with_member(group_store, admin_kp, member_kp):
    grp = create_group(admin_kp, name="TestGroup")
    group_store.create_group(grp)
    cert = issue_membership_certificate(
        admin_kp,
        device_id=member_kp.device_id,
        device_public_key=member_kp.public_key_bytes(),
        group_id=grp.group_id,
    )
    group_store.record_membership(cert)
    return grp


# ---------------------------------------------------------------------------
# 1. authorize_relay_request()
# ---------------------------------------------------------------------------


def test_authorize_happy_path(group_store, group_with_member, member_kp):
    grp = group_with_member
    authorize_relay_request(
        group_id=grp.group_id,
        requester_device_id=member_kp.device_id,
        relay_active_groups={grp.group_id},
        group_store=group_store,
        is_target_connected=True,
    )  # must not raise


def test_authorize_relay_mode_off(group_store, group_with_member, member_kp):
    grp = group_with_member
    with pytest.raises(RelayNotHostingError):
        authorize_relay_request(
            group_id=grp.group_id,
            requester_device_id=member_kp.device_id,
            relay_active_groups=set(),  # not hosting this group
            group_store=group_store,
            is_target_connected=True,
        )


def test_authorize_requester_not_member(group_store, group_with_member, outsider_kp):
    grp = group_with_member
    with pytest.raises(RelayAuthError):
        authorize_relay_request(
            group_id=grp.group_id,
            requester_device_id=outsider_kp.device_id,
            relay_active_groups={grp.group_id},
            group_store=group_store,
            is_target_connected=True,
        )


def test_authorize_target_not_connected(group_store, group_with_member, member_kp):
    grp = group_with_member
    with pytest.raises(RelayTargetUnreachableError):
        authorize_relay_request(
            group_id=grp.group_id,
            requester_device_id=member_kp.device_id,
            relay_active_groups={grp.group_id},
            group_store=group_store,
            is_target_connected=False,
        )


def test_authorize_not_hosting_beats_not_member(group_store, group_with_member, outsider_kp):
    """When both checks would fail, not-hosting is raised first — the
    caller's silent-reply behavior should never depend on group
    membership state it has no business confirming/denying to an
    outsider."""
    grp = group_with_member
    with pytest.raises(RelayNotHostingError):
        authorize_relay_request(
            group_id=grp.group_id,
            requester_device_id=outsider_kp.device_id,
            relay_active_groups=set(),
            group_store=group_store,
            is_target_connected=True,
        )


def test_authorize_not_member_beats_target_unreachable(group_store, group_with_member, outsider_kp):
    grp = group_with_member
    with pytest.raises(RelayAuthError):
        authorize_relay_request(
            group_id=grp.group_id,
            requester_device_id=outsider_kp.device_id,
            relay_active_groups={grp.group_id},
            group_store=group_store,
            is_target_connected=False,
        )


# ---------------------------------------------------------------------------
# 2-3. Wire messages
# ---------------------------------------------------------------------------


def test_make_relay_request_shape():
    msg = make_relay_request("group-1", "device-b")
    assert msg["type"] == "relay_request"
    assert msg["group_id"] == "group-1"
    assert msg["target_device_id"] == "device-b"
    validate_message(msg)  # must not raise


def test_make_relay_response_shape():
    msg = make_relay_response("group-1", "device-b", accepted=True)
    assert msg["type"] == "relay_response"
    assert msg["accepted"] is True
    validate_message(msg)  # must not raise

    msg2 = make_relay_response("group-1", "device-b", accepted=False)
    validate_message(msg2)  # must not raise


def test_relay_request_missing_field_rejected():
    msg = make_relay_request("group-1", "device-b")
    del msg["target_device_id"]
    with pytest.raises(ProtocolError):
        validate_message(msg)


def test_relay_request_empty_group_id_rejected():
    msg = make_relay_request("", "device-b")
    with pytest.raises(ProtocolError):
        validate_message(msg)


def test_relay_response_non_bool_accepted_rejected():
    msg = make_relay_response("group-1", "device-b", accepted=True)
    msg["accepted"] = "yes"
    with pytest.raises(ProtocolError):
        validate_message(msg)


def test_relay_response_missing_field_rejected():
    msg = make_relay_response("group-1", "device-b", accepted=True)
    del msg["accepted"]
    with pytest.raises(ProtocolError):
        validate_message(msg)


# ---------------------------------------------------------------------------
# 4. Phase 46.3: authorize_relay_candidate_query() & candidate messages
# ---------------------------------------------------------------------------


def test_authorize_relay_candidate_query_happy_path(group_store, group_with_member, member_kp):
    grp = group_with_member
    from core.connectivity.relay import authorize_relay_candidate_query

    authorize_relay_candidate_query(
        group_id=grp.group_id,
        requester_device_id=member_kp.device_id,
        relay_active_groups={grp.group_id},
        group_store=group_store,
    )  # must not raise


def test_authorize_relay_candidate_query_not_hosting(group_store, group_with_member, member_kp):
    grp = group_with_member
    from core.connectivity.relay import authorize_relay_candidate_query

    with pytest.raises(RelayNotHostingError):
        authorize_relay_candidate_query(
            group_id=grp.group_id,
            requester_device_id=member_kp.device_id,
            relay_active_groups=set(),
            group_store=group_store,
        )


def test_authorize_relay_candidate_query_not_member(group_store, group_with_member, outsider_kp):
    grp = group_with_member
    from core.connectivity.relay import authorize_relay_candidate_query

    with pytest.raises(RelayAuthError):
        authorize_relay_candidate_query(
            group_id=grp.group_id,
            requester_device_id=outsider_kp.device_id,
            relay_active_groups={grp.group_id},
            group_store=group_store,
        )


def test_make_relay_candidate_query_shape():
    from core.protocol.messages import make_relay_candidate_query

    msg = make_relay_candidate_query("group-1")
    assert msg["type"] == "relay_candidate_query"
    assert msg["group_id"] == "group-1"
    validate_message(msg)


def test_make_relay_candidate_response_shape():
    from core.protocol.messages import make_relay_candidate_response

    msg = make_relay_candidate_response("group-1", available=True)
    assert msg["type"] == "relay_candidate_response"
    assert msg["available"] is True
    validate_message(msg)


def test_relay_candidate_query_missing_or_empty_group_id():
    from core.protocol.messages import make_relay_candidate_query

    msg = make_relay_candidate_query("group-1")
    msg["group_id"] = ""
    with pytest.raises(ProtocolError):
        validate_message(msg)

    msg2 = make_relay_candidate_query("group-1")
    del msg2["group_id"]
    with pytest.raises(ProtocolError):
        validate_message(msg2)


def test_relay_candidate_response_validation():
    from core.protocol.messages import make_relay_candidate_response

    msg = make_relay_candidate_response("group-1", available=True)
    msg["available"] = "yes"
    with pytest.raises(ProtocolError):
        validate_message(msg)

    msg2 = make_relay_candidate_response("group-1", available=True)
    del msg2["available"]
    with pytest.raises(ProtocolError):
        validate_message(msg2)

