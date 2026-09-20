"""tests/test_rendezvous_cache.py — Phase 45.2: RendezvousCache + three
rendezvous wire messages.

Covers:
  1. RendezvousCache.register():
     a. happy path — valid member, matching device_id, valid EndpointUpdate
     b. device_id mismatch (EndpointUpdate.device_id != authenticated peer)
     c. non-member sender raises RendezvousAuthError
     d. bad EndpointUpdate signature raises RendezvousSignatureError
  2. RendezvousCache.lookup():
     a. happy path — returns cached EndpointUpdate
     b. cache miss — returns None
     c. non-member requester raises RendezvousAuthError
     d. non-member target raises RendezvousAuthError
  3. RendezvousCache.evict() / evict_all_for_group() / size()
  4. Wire message factories (messages.py):
     make_rendezvous_register / make_rendezvous_lookup /
     make_rendezvous_lookup_response
  5. validate_message() for all three message types:
     a. well-formed accepted
     b. missing top-level required fields rejected
     c. nested endpoint_update field validation (register, lookup_response)
     d. null endpoint_update in lookup_response accepted
     e. non-dict endpoint_update in lookup_response rejected
"""

import sqlite3
import time
import uuid

import pytest

from core.connectivity.endpoint_update import (
    EndpointUpdate,
    create_endpoint_update,
    verify_endpoint_update,
)
from core.connectivity.rendezvous import (
    RendezvousAuthError,
    RendezvousCache,
    RendezvousDeviceIdMismatchError,
    RendezvousSignatureError,
)
from core.crypto.handshake import NonceCache
from core.group.membership import create_group, issue_membership_certificate
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from core.protocol.messages import (
    make_rendezvous_lookup,
    make_rendezvous_lookup_response,
    make_rendezvous_register,
    validate_message,
)
from core.protocol.errors import ProtocolError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_conn():
    """In-memory SQLite connection for GroupStore."""
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
def member2_kp():
    return generate_keypair()


@pytest.fixture
def group_with_two_members(group_store, admin_kp, member_kp):
    """Create a group with admin and one additional member."""
    grp = create_group(admin_kp, name="TestGroup")
    group_store.create_group(grp)

    # Member cert
    cert = issue_membership_certificate(
        admin_kp,
        device_id=member_kp.device_id,
        device_public_key=member_kp.public_key_bytes(),
        group_id=grp.group_id,
    )
    group_store.record_membership(cert)

    # Admin self-membership cert (so admin can also be looked up)
    admin_cert = issue_membership_certificate(
        admin_kp,
        device_id=admin_kp.device_id,
        device_public_key=admin_kp.public_key_bytes(),
        group_id=grp.group_id,
    )
    group_store.record_membership(admin_cert)

    return grp


@pytest.fixture
def nonce_cache():
    return NonceCache()


@pytest.fixture
def rendezvous_cache(nonce_cache):
    return RendezvousCache(nonce_cache=nonce_cache)


def _make_update(keypair) -> EndpointUpdate:
    """Create a fresh, fully-signed EndpointUpdate for a keypair."""
    return create_endpoint_update(keypair, kind="direct-v4", host="1.2.3.4", port=5000)


def _update_to_dict(update: EndpointUpdate) -> dict:
    """Convert an EndpointUpdate to the wire-dict shape."""
    return {
        "device_id": update.device_id,
        "kind": update.kind,
        "host": update.host,
        "port": update.port,
        "timestamp": update.timestamp,
        "nonce": update.nonce,
        "signature": update.signature,
    }


# ---------------------------------------------------------------------------
# 1. RendezvousCache.register()
# ---------------------------------------------------------------------------


def test_register_happy_path(
    rendezvous_cache, group_with_two_members, group_store, member_kp
):
    grp = group_with_two_members
    update = _make_update(member_kp)
    rendezvous_cache.register(
        group_id=grp.group_id,
        authenticated_device_id=member_kp.device_id,
        update=update,
        sender_public_key=member_kp.public_key_bytes(),
        group_store=group_store,
    )
    assert rendezvous_cache.size() == 1
    entry = rendezvous_cache.get_raw(grp.group_id, member_kp.device_id)
    assert entry is not None
    assert entry.device_id == member_kp.device_id
    assert entry.update.host == "1.2.3.4"


def test_register_device_id_mismatch(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member_kp
):
    """EndpointUpdate claims member_kp's device_id but auth says admin_kp's."""
    grp = group_with_two_members
    update = _make_update(member_kp)  # device_id = member_kp
    with pytest.raises(RendezvousDeviceIdMismatchError):
        rendezvous_cache.register(
            group_id=grp.group_id,
            authenticated_device_id=admin_kp.device_id,  # mismatch!
            update=update,
            sender_public_key=admin_kp.public_key_bytes(),
            group_store=group_store,
        )
    assert rendezvous_cache.size() == 0


def test_register_non_member_rejected(
    rendezvous_cache, group_with_two_members, group_store, member2_kp
):
    """A device with no membership in the group cannot register."""
    grp = group_with_two_members
    update = _make_update(member2_kp)
    with pytest.raises(RendezvousAuthError):
        rendezvous_cache.register(
            group_id=grp.group_id,
            authenticated_device_id=member2_kp.device_id,
            update=update,
            sender_public_key=member2_kp.public_key_bytes(),
            group_store=group_store,
        )
    assert rendezvous_cache.size() == 0


def test_register_bad_signature_rejected(
    rendezvous_cache, group_with_two_members, group_store, member_kp, admin_kp
):
    """EndpointUpdate with a tampered nonce (invalidating its signature)."""
    grp = group_with_two_members
    update = _make_update(member_kp)
    # Tamper the nonce — makes the signature invalid without touching it directly.
    tampered = EndpointUpdate(
        device_id=update.device_id,
        kind=update.kind,
        host=update.host,
        port=update.port,
        timestamp=update.timestamp,
        nonce="000000000000000000000000000000000000",  # different nonce
        signature=update.signature,  # signature still refers to original nonce
    )
    with pytest.raises(RendezvousSignatureError):
        rendezvous_cache.register(
            group_id=grp.group_id,
            authenticated_device_id=member_kp.device_id,
            update=tampered,
            sender_public_key=member_kp.public_key_bytes(),
            group_store=group_store,
        )
    assert rendezvous_cache.size() == 0


def test_register_overwrites_previous_entry(
    rendezvous_cache, group_with_two_members, group_store, member_kp
):
    """Re-registering with a new EndpointUpdate replaces the old entry."""
    grp = group_with_two_members
    update1 = _make_update(member_kp)
    rendezvous_cache.register(
        group_id=grp.group_id,
        authenticated_device_id=member_kp.device_id,
        update=update1,
        sender_public_key=member_kp.public_key_bytes(),
        group_store=group_store,
    )

    # Create a new update (fresh nonce) with a different host.
    update2 = create_endpoint_update(member_kp, kind="direct-v4", host="9.9.9.9", port=5001)
    rendezvous_cache.register(
        group_id=grp.group_id,
        authenticated_device_id=member_kp.device_id,
        update=update2,
        sender_public_key=member_kp.public_key_bytes(),
        group_store=group_store,
    )
    assert rendezvous_cache.size() == 1
    entry = rendezvous_cache.get_raw(grp.group_id, member_kp.device_id)
    assert entry.update.host == "9.9.9.9"


# ---------------------------------------------------------------------------
# 2. RendezvousCache.lookup()
# ---------------------------------------------------------------------------


def test_lookup_happy_path(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member_kp
):
    """Admin looks up member's cached update — should return the update."""
    grp = group_with_two_members
    update = _make_update(member_kp)
    rendezvous_cache.register(
        group_id=grp.group_id,
        authenticated_device_id=member_kp.device_id,
        update=update,
        sender_public_key=member_kp.public_key_bytes(),
        group_store=group_store,
    )

    result = rendezvous_cache.lookup(
        group_id=grp.group_id,
        requester_device_id=admin_kp.device_id,
        target_device_id=member_kp.device_id,
        group_store=group_store,
    )
    assert result is not None
    assert result.device_id == member_kp.device_id
    assert result.host == "1.2.3.4"


def test_lookup_cache_miss_returns_none(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member_kp
):
    """Looking up a member who hasn't registered yet should return None."""
    grp = group_with_two_members
    result = rendezvous_cache.lookup(
        group_id=grp.group_id,
        requester_device_id=admin_kp.device_id,
        target_device_id=member_kp.device_id,
        group_store=group_store,
    )
    assert result is None


def test_lookup_non_member_requester_rejected(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member_kp, member2_kp
):
    """Non-member cannot look up another device's location."""
    grp = group_with_two_members
    with pytest.raises(RendezvousAuthError):
        rendezvous_cache.lookup(
            group_id=grp.group_id,
            requester_device_id=member2_kp.device_id,  # not a member
            target_device_id=member_kp.device_id,
            group_store=group_store,
        )


def test_lookup_non_member_target_rejected(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member2_kp
):
    """Requester cannot ask for a device that is not a member of the group."""
    grp = group_with_two_members
    with pytest.raises(RendezvousAuthError):
        rendezvous_cache.lookup(
            group_id=grp.group_id,
            requester_device_id=admin_kp.device_id,
            target_device_id=member2_kp.device_id,  # not a member
            group_store=group_store,
        )


# ---------------------------------------------------------------------------
# 3. evict / evict_all_for_group / size
# ---------------------------------------------------------------------------


def test_evict_removes_single_entry(
    rendezvous_cache, group_with_two_members, group_store, member_kp
):
    grp = group_with_two_members
    update = _make_update(member_kp)
    rendezvous_cache.register(
        group_id=grp.group_id,
        authenticated_device_id=member_kp.device_id,
        update=update,
        sender_public_key=member_kp.public_key_bytes(),
        group_store=group_store,
    )
    assert rendezvous_cache.size() == 1
    rendezvous_cache.evict(grp.group_id, member_kp.device_id)
    assert rendezvous_cache.size() == 0


def test_evict_noop_when_not_present(rendezvous_cache, group_with_two_members, member_kp):
    grp = group_with_two_members
    # Should not raise — no-op
    rendezvous_cache.evict(grp.group_id, member_kp.device_id)
    assert rendezvous_cache.size() == 0


def test_evict_all_for_group(
    rendezvous_cache, group_with_two_members, group_store, admin_kp, member_kp
):
    grp = group_with_two_members
    # Register both admin and member.
    for kp in (admin_kp, member_kp):
        update = _make_update(kp)
        rendezvous_cache.register(
            group_id=grp.group_id,
            authenticated_device_id=kp.device_id,
            update=update,
            sender_public_key=kp.public_key_bytes(),
            group_store=group_store,
        )
    assert rendezvous_cache.size() == 2
    removed = rendezvous_cache.evict_all_for_group(grp.group_id)
    assert removed == 2
    assert rendezvous_cache.size() == 0


def test_evict_all_for_group_only_affects_that_group(
    rendezvous_cache, db_conn, group_store, admin_kp, member_kp, member2_kp
):
    """Evicting one group's entries must not disturb another group's cache."""
    # Group A
    grp_a = create_group(admin_kp, name="GroupA")
    group_store.create_group(grp_a)
    admin_cert_a = issue_membership_certificate(
        admin_kp,
        device_id=admin_kp.device_id,
        device_public_key=admin_kp.public_key_bytes(),
        group_id=grp_a.group_id,
    )
    group_store.record_membership(admin_cert_a)

    # Group B (re-using admin_kp as founder, member2_kp as member)
    grp_b = create_group(admin_kp, name="GroupB")
    group_store.create_group(grp_b)
    admin_cert_b = issue_membership_certificate(
        admin_kp,
        device_id=admin_kp.device_id,
        device_public_key=admin_kp.public_key_bytes(),
        group_id=grp_b.group_id,
    )
    group_store.record_membership(admin_cert_b)
    member2_cert_b = issue_membership_certificate(
        admin_kp,
        device_id=member2_kp.device_id,
        device_public_key=member2_kp.public_key_bytes(),
        group_id=grp_b.group_id,
    )
    group_store.record_membership(member2_cert_b)

    # Register admin in group A and member2 in group B.
    update_a = _make_update(admin_kp)
    rendezvous_cache.register(
        group_id=grp_a.group_id,
        authenticated_device_id=admin_kp.device_id,
        update=update_a,
        sender_public_key=admin_kp.public_key_bytes(),
        group_store=group_store,
    )
    update_b = _make_update(member2_kp)
    rendezvous_cache.register(
        group_id=grp_b.group_id,
        authenticated_device_id=member2_kp.device_id,
        update=update_b,
        sender_public_key=member2_kp.public_key_bytes(),
        group_store=group_store,
    )
    assert rendezvous_cache.size() == 2

    rendezvous_cache.evict_all_for_group(grp_a.group_id)
    assert rendezvous_cache.size() == 1
    assert rendezvous_cache.get_raw(grp_b.group_id, member2_kp.device_id) is not None


# ---------------------------------------------------------------------------
# 4. Wire message factories
# ---------------------------------------------------------------------------


def test_make_rendezvous_register_shape():
    eu_dict = {
        "device_id": "aabbcc",
        "kind": "direct-v4",
        "host": "1.2.3.4",
        "port": 5000,
        "timestamp": time.time(),
        "nonce": "abc",
        "signature": "sig==",
    }
    msg = make_rendezvous_register("group-1", eu_dict)
    assert msg["type"] == "rendezvous_register"
    assert msg["group_id"] == "group-1"
    assert msg["endpoint_update"] is eu_dict


def test_make_rendezvous_lookup_shape():
    msg = make_rendezvous_lookup("group-1", "target-device-id")
    assert msg["type"] == "rendezvous_lookup"
    assert msg["group_id"] == "group-1"
    assert msg["target_device_id"] == "target-device-id"


def test_make_rendezvous_lookup_response_with_update():
    eu_dict = {"device_id": "x", "kind": "direct-v4", "host": "1.2.3.4",
               "port": 5001, "timestamp": time.time(), "nonce": "n", "signature": "s"}
    msg = make_rendezvous_lookup_response("group-1", "target-id", eu_dict)
    assert msg["type"] == "rendezvous_lookup_response"
    assert msg["endpoint_update"] is eu_dict


def test_make_rendezvous_lookup_response_without_update():
    msg = make_rendezvous_lookup_response("group-1", "target-id", None)
    assert msg["type"] == "rendezvous_lookup_response"
    assert msg["endpoint_update"] is None


# ---------------------------------------------------------------------------
# 5. validate_message() for all three types
# ---------------------------------------------------------------------------

def _valid_eu_dict() -> dict:
    return {
        "device_id": "aabbcc",
        "kind": "direct-v4",
        "host": "1.2.3.4",
        "port": 5000,
        "timestamp": time.time(),
        "nonce": "abc123",
        "signature": "sig==",
    }


def test_validate_rendezvous_register_valid():
    msg = make_rendezvous_register("group-1", _valid_eu_dict())
    result = validate_message(msg)
    assert result["type"] == "rendezvous_register"


def test_validate_rendezvous_register_missing_group_id():
    msg = make_rendezvous_register("group-1", _valid_eu_dict())
    del msg["group_id"]
    with pytest.raises(ProtocolError, match="missing fields"):
        validate_message(msg)


def test_validate_rendezvous_register_missing_endpoint_update():
    msg = make_rendezvous_register("group-1", _valid_eu_dict())
    del msg["endpoint_update"]
    with pytest.raises(ProtocolError, match="missing fields"):
        validate_message(msg)


def test_validate_rendezvous_register_non_dict_endpoint_update():
    msg = make_rendezvous_register("group-1", _valid_eu_dict())
    msg["endpoint_update"] = "not-a-dict"
    with pytest.raises(ProtocolError, match="must be an object"):
        validate_message(msg)


def test_validate_rendezvous_register_nested_bad_port():
    eu = _valid_eu_dict()
    eu["port"] = 99999  # out of range
    msg = make_rendezvous_register("group-1", eu)
    with pytest.raises(ProtocolError, match="port out of range"):
        validate_message(msg)


def test_validate_rendezvous_register_nested_bad_kind():
    eu = _valid_eu_dict()
    eu["kind"] = "unknown-kind"
    msg = make_rendezvous_register("group-1", eu)
    with pytest.raises(ProtocolError, match="kind not recognized"):
        validate_message(msg)


def test_validate_rendezvous_register_nested_missing_device_id():
    eu = _valid_eu_dict()
    del eu["device_id"]
    msg = make_rendezvous_register("group-1", eu)
    with pytest.raises(ProtocolError, match="device_id must be a non-empty string"):
        validate_message(msg)


def test_validate_rendezvous_lookup_valid():
    msg = make_rendezvous_lookup("group-1", "target-device")
    result = validate_message(msg)
    assert result["type"] == "rendezvous_lookup"


def test_validate_rendezvous_lookup_missing_target():
    msg = make_rendezvous_lookup("group-1", "target-device")
    del msg["target_device_id"]
    with pytest.raises(ProtocolError, match="missing fields"):
        validate_message(msg)


def test_validate_rendezvous_lookup_empty_group_id():
    msg = make_rendezvous_lookup("group-1", "target-device")
    msg["group_id"] = ""
    with pytest.raises(ProtocolError, match="non-empty string"):
        validate_message(msg)


def test_validate_rendezvous_lookup_response_valid_with_update():
    msg = make_rendezvous_lookup_response("group-1", "target", _valid_eu_dict())
    result = validate_message(msg)
    assert result["type"] == "rendezvous_lookup_response"


def test_validate_rendezvous_lookup_response_valid_null_update():
    msg = make_rendezvous_lookup_response("group-1", "target", None)
    result = validate_message(msg)
    assert result["endpoint_update"] is None


def test_validate_rendezvous_lookup_response_invalid_nested_port():
    eu = _valid_eu_dict()
    eu["port"] = 0  # invalid
    msg = make_rendezvous_lookup_response("group-1", "target", eu)
    with pytest.raises(ProtocolError, match="port out of range"):
        validate_message(msg)


def test_validate_rendezvous_lookup_response_non_dict_update():
    msg = make_rendezvous_lookup_response("group-1", "target", _valid_eu_dict())
    msg["endpoint_update"] = 42  # must be dict or null
    with pytest.raises(ProtocolError, match="must be an object or null"):
        validate_message(msg)


def test_validate_rendezvous_lookup_response_missing_target_device_id():
    msg = make_rendezvous_lookup_response("group-1", "target", None)
    del msg["target_device_id"]
    with pytest.raises(ProtocolError, match="missing fields"):
        validate_message(msg)
