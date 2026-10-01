"""tests/test_rendezvous_ui.py — Phase 45.3: rendezvous wired into
app/ui/app.py's ChatApp (host-side register/lookup handling, requester-side
lookup_response verification, the /group rendezvous on|off|find
command, and self-registration on hello/hello_ack/IP-change).

core/connectivity/rendezvous.py's RendezvousCache logic itself is
already covered by tests/test_rendezvous_cache.py (45.2) — these tests
exercise the app/ui/app.py plumbing around it: the not-hosting gate, wiring
authenticated identity through correctly, and the requester re-
verifying a lookup_response against ITS OWN copy of the target's
MembershipCertificate rather than trusting the host.
"""

import dataclasses
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.discovery import broadcast as discovery_broadcast
from core.connectivity.endpoint_update import create_endpoint_update
from core.connectivity.locator import KIND_DIRECT_V4
from core.connectivity.store import LocatorStore
from core.group.membership import create_group, issue_membership_certificate
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from app.ui.app import ChatApp

pytestmark = pytest.mark.ui



def _issue_cert(admin_keypair, member_keypair, group, **kwargs):
    return issue_membership_certificate(
        admin_keypair,
        device_id=member_keypair.device_id,
        device_public_key=member_keypair.public_key_bytes(),
        group_id=group.group_id,
        **kwargs,
    )


@pytest.fixture
def rendezvous_app(tmp_path):
    """A ChatApp acting as `self` (device A), plus a real Group with
    device A and a second member B already active, so membership/
    authorization checks pass end to end."""
    app = ChatApp()
    keypair_a = generate_keypair()
    keypair_b = generate_keypair()
    app.my_identity = keypair_a
    app.peer_id = keypair_a.device_id
    app.display_name = "A"

    app.group_store = GroupStore(db_path=str(tmp_path / "group.db"))
    app.locator_store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    group = create_group(keypair_a, name="Test Group")
    app.group_store.create_group(group)
    cert_a = _issue_cert(keypair_a, keypair_a, group)
    app.group_store.record_membership(cert_a)
    cert_b = _issue_cert(keypair_a, keypair_b, group)
    app.group_store.record_membership(cert_b)

    app.manager = MagicMock()
    app.manager.send = AsyncMock(return_value=True)
    app.manager.get_peer_public_key = MagicMock(return_value=None)
    app.manager.get_peer_device_id = MagicMock(return_value=None)
    app.manager.list_connected_addr_keys = MagicMock(return_value=[])
    app._connect_to_link_endpoint = AsyncMock(return_value=True)

    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    app._keypair_b = keypair_b
    app._group = group
    return app


# ---------------------------------------------------------------------------
# /group rendezvous <id> on|off|find
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rendezvous_on_unknown_group_refused(rendezvous_app):
    await rendezvous_app._handle_group_rendezvous("nonexistent-group", "on")
    assert "nonexistent-group" not in rendezvous_app._rendezvous_active_groups
    assert any("Unknown group_id" in m for m in rendezvous_app.logs)


@pytest.mark.asyncio
async def test_rendezvous_on_not_a_member_refused(rendezvous_app):
    group2 = create_group(rendezvous_app._keypair_b, name="Other Group")
    rendezvous_app.group_store.create_group(group2)  # A is not a member of this one

    await rendezvous_app._handle_group_rendezvous(group2.group_id, "on")

    assert group2.group_id not in rendezvous_app._rendezvous_active_groups


@pytest.mark.asyncio
async def test_rendezvous_on_happy_path(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    await rendezvous_app._handle_group_rendezvous(group_id, "on")
    assert group_id in rendezvous_app._rendezvous_active_groups
    assert any("Rendezvous mode ON" in m for m in rendezvous_app.logs)


@pytest.mark.asyncio
async def test_rendezvous_off_clears_cache(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    await rendezvous_app._handle_group_rendezvous(group_id, "on")
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    rendezvous_app.rendezvous_cache.register(
        group_id=group_id,
        authenticated_device_id=rendezvous_app._keypair_b.device_id,
        update=update,
        sender_public_key=rendezvous_app._keypair_b.public_key_bytes(),
        group_store=rendezvous_app.group_store,
    )
    assert rendezvous_app.rendezvous_cache.size() == 1

    await rendezvous_app._handle_group_rendezvous(group_id, "off")

    assert group_id not in rendezvous_app._rendezvous_active_groups
    assert rendezvous_app.rendezvous_cache.size() == 0


@pytest.mark.asyncio
async def test_rendezvous_find_no_connected_peers(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app.manager.list_connected_addr_keys = MagicMock(return_value=[])

    await rendezvous_app._handle_group_rendezvous(group_id, f"find {rendezvous_app._keypair_b.device_id}")

    rendezvous_app.manager.send.assert_not_awaited()
    assert any("Not connected to any peer" in m for m in rendezvous_app.logs)


@pytest.mark.asyncio
async def test_rendezvous_find_sends_lookup_to_all_connected(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app.manager.list_connected_addr_keys = MagicMock(return_value=["1.1.1.1:5656", "2.2.2.2:5656"])

    await rendezvous_app._handle_group_rendezvous(group_id, f"find {rendezvous_app._keypair_b.device_id}")

    assert rendezvous_app.manager.send.await_count == 2
    for call in rendezvous_app.manager.send.await_args_list:
        assert call.args[1]["type"] == "rendezvous_lookup"
        assert call.args[1]["group_id"] == group_id
        assert call.args[1]["target_device_id"] == rendezvous_app._keypair_b.device_id


# ---------------------------------------------------------------------------
# Host side: _on_rendezvous_register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_rendezvous_register_not_hosting_ignored(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app._keypair_b.device_id)
    rendezvous_app.manager.get_peer_public_key = MagicMock(return_value=rendezvous_app._keypair_b.public_key_bytes())
    msg = {"group_id": group_id, "endpoint_update": dataclasses.asdict(update)}

    await rendezvous_app._on_rendezvous_register("addr-1", msg)

    assert rendezvous_app.rendezvous_cache.size() == 0  # not in _rendezvous_active_groups


@pytest.mark.asyncio
async def test_on_rendezvous_register_happy_path_caches(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app._rendezvous_active_groups.add(group_id)
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app._keypair_b.device_id)
    rendezvous_app.manager.get_peer_public_key = MagicMock(return_value=rendezvous_app._keypair_b.public_key_bytes())
    msg = {"group_id": group_id, "endpoint_update": dataclasses.asdict(update)}

    await rendezvous_app._on_rendezvous_register("addr-1", msg)

    cached = rendezvous_app.rendezvous_cache.get_raw(group_id, rendezvous_app._keypair_b.device_id)
    assert cached is not None
    assert cached.update.host == "1.2.3.4"


@pytest.mark.asyncio
async def test_on_rendezvous_register_device_id_mismatch_refused(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app._rendezvous_active_groups.add(group_id)
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    # Authenticated as A, but the update claims to be from B.
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app.peer_id)
    rendezvous_app.manager.get_peer_public_key = MagicMock(return_value=rendezvous_app.my_identity.public_key_bytes())
    msg = {"group_id": group_id, "endpoint_update": dataclasses.asdict(update)}

    await rendezvous_app._on_rendezvous_register("addr-1", msg)

    assert rendezvous_app.rendezvous_cache.size() == 0
    assert any("Rendezvous register refused" in m for m in rendezvous_app.logs)


# ---------------------------------------------------------------------------
# Host side: _on_rendezvous_lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_rendezvous_lookup_not_hosting_no_response(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app._keypair_b.device_id)
    msg = {"group_id": group_id, "target_device_id": rendezvous_app.peer_id}

    await rendezvous_app._on_rendezvous_lookup("addr-1", msg)

    rendezvous_app.manager.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_rendezvous_lookup_found_responds_with_update(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app._rendezvous_active_groups.add(group_id)
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    rendezvous_app.rendezvous_cache.register(
        group_id=group_id,
        authenticated_device_id=rendezvous_app._keypair_b.device_id,
        update=update,
        sender_public_key=rendezvous_app._keypair_b.public_key_bytes(),
        group_store=rendezvous_app.group_store,
    )
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app.peer_id)  # requester = A (self, but valid member)
    msg = {"group_id": group_id, "target_device_id": rendezvous_app._keypair_b.device_id}

    await rendezvous_app._on_rendezvous_lookup("addr-1", msg)

    rendezvous_app.manager.send.assert_awaited_once()
    sent = rendezvous_app.manager.send.await_args.args[1]
    assert sent["type"] == "rendezvous_lookup_response"
    assert sent["endpoint_update"]["host"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_on_rendezvous_lookup_not_found_responds_none(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    rendezvous_app._rendezvous_active_groups.add(group_id)
    rendezvous_app.manager.get_peer_device_id = MagicMock(return_value=rendezvous_app.peer_id)
    msg = {"group_id": group_id, "target_device_id": rendezvous_app._keypair_b.device_id}

    await rendezvous_app._on_rendezvous_lookup("addr-1", msg)

    sent = rendezvous_app.manager.send.await_args.args[1]
    assert sent["endpoint_update"] is None


# ---------------------------------------------------------------------------
# Requester side: _on_rendezvous_lookup_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_lookup_response_none_endpoint_noop(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    msg = {"group_id": group_id, "target_device_id": rendezvous_app._keypair_b.device_id, "endpoint_update": None}

    await rendezvous_app._on_rendezvous_lookup_response("addr-1", msg)

    rendezvous_app._connect_to_link_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_lookup_response_unknown_target_noop(rendezvous_app):
    stranger = generate_keypair()
    update = create_endpoint_update(stranger, KIND_DIRECT_V4, "1.2.3.4", 5656)
    msg = {
        "group_id": rendezvous_app._group.group_id,
        "target_device_id": stranger.device_id,  # not a member A knows about
        "endpoint_update": dataclasses.asdict(update),
    }

    await rendezvous_app._on_rendezvous_lookup_response("addr-1", msg)

    rendezvous_app._connect_to_link_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_lookup_response_device_id_mismatch_noop(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    msg = {
        "group_id": group_id,
        "target_device_id": rendezvous_app.peer_id,  # claims A, but update.device_id is B's
        "endpoint_update": dataclasses.asdict(update),
    }

    await rendezvous_app._on_rendezvous_lookup_response("addr-1", msg)

    rendezvous_app._connect_to_link_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_on_lookup_response_invalid_signature_noop(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    eu_dict = dataclasses.asdict(update)
    eu_dict["host"] = "9.9.9.9"  # tampered after signing
    msg = {"group_id": group_id, "target_device_id": rendezvous_app._keypair_b.device_id, "endpoint_update": eu_dict}

    await rendezvous_app._on_rendezvous_lookup_response("addr-1", msg)

    rendezvous_app._connect_to_link_endpoint.assert_not_awaited()
    assert rendezvous_app.locator_store.list_endpoints(rendezvous_app._keypair_b.device_id) == []


@pytest.mark.asyncio
async def test_on_lookup_response_happy_path_connects(rendezvous_app):
    group_id = rendezvous_app._group.group_id
    update = create_endpoint_update(rendezvous_app._keypair_b, KIND_DIRECT_V4, "1.2.3.4", 5656)
    msg = {
        "group_id": group_id,
        "target_device_id": rendezvous_app._keypair_b.device_id,
        "endpoint_update": dataclasses.asdict(update),
    }

    await rendezvous_app._on_rendezvous_lookup_response("addr-1", msg)

    stored = rendezvous_app.locator_store.list_endpoints(rendezvous_app._keypair_b.device_id)
    assert len(stored) == 1
    assert stored[0].host == "1.2.3.4"
    rendezvous_app._connect_to_link_endpoint.assert_awaited_once()


# ---------------------------------------------------------------------------
# _register_with_rendezvous_hosts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_with_rendezvous_hosts_sends_per_group(rendezvous_app, monkeypatch):
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": ["192.168.1.20"]})

    await rendezvous_app._register_with_rendezvous_hosts("addr-1")

    rendezvous_app.manager.send.assert_awaited_once()
    sent = rendezvous_app.manager.send.await_args.args[1]
    assert sent["type"] == "rendezvous_register"
    assert sent["group_id"] == rendezvous_app._group.group_id
    assert sent["endpoint_update"]["device_id"] == rendezvous_app.peer_id


@pytest.mark.asyncio
async def test_register_with_rendezvous_hosts_no_local_ip_noop(rendezvous_app, monkeypatch):
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": []})

    await rendezvous_app._register_with_rendezvous_hosts("addr-1")

    rendezvous_app.manager.send.assert_not_awaited()
