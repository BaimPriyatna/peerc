"""tests/test_relay_ui.py — Phase 46.2: relay_request/relay_response
wired into ui.py's ChatApp.

core/connectivity/relay.py's authorize_relay_request() itself is
already covered by tests/test_relay_authorization.py — these tests
exercise the ui.py plumbing around it: the not-hosting/not-member
silent gates, the explicit accepted=False reply for "not connected to
target", and wiring ConnectionManager.open_relay_pipe() on the happy
path. Mirrors tests/test_rendezvous_ui.py's structure.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from core.group.membership import create_group, issue_membership_certificate
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from ui import ChatApp


def _issue_cert(admin_keypair, member_keypair, group, **kwargs):
    return issue_membership_certificate(
        admin_keypair,
        device_id=member_keypair.device_id,
        device_public_key=member_keypair.public_key_bytes(),
        group_id=group.group_id,
        **kwargs,
    )


@pytest.fixture
def relay_app(tmp_path):
    """A ChatApp acting as R (the relay), with device A as an active
    member of a group and device B as another active member A wants
    relayed to."""
    app = ChatApp()
    keypair_r = generate_keypair()
    keypair_a = generate_keypair()
    keypair_b = generate_keypair()
    app.my_identity = keypair_r
    app.peer_id = keypair_r.device_id
    app.display_name = "R"

    app.group_store = GroupStore(db_path=str(tmp_path / "group.db"))
    group = create_group(keypair_r, name="Test Group")
    app.group_store.create_group(group)
    app.group_store.record_membership(_issue_cert(keypair_r, keypair_r, group))
    app.group_store.record_membership(_issue_cert(keypair_r, keypair_a, group))
    app.group_store.record_membership(_issue_cert(keypair_r, keypair_b, group))

    app.manager = MagicMock()
    app.manager.send = AsyncMock(return_value=True)
    app.manager.get_peer_device_id = MagicMock(return_value=keypair_a.device_id)
    app.manager.find_addr_key_for_device = MagicMock(return_value=None)
    app.manager.open_relay_pipe = MagicMock()

    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    app._keypair_a = keypair_a
    app._keypair_b = keypair_b
    app._group = group
    return app


# ---------------------------------------------------------------------------
# Phase 46.4: /group relay <id> on|off
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_on_unknown_group_refused(relay_app):
    await relay_app._handle_group_relay("nonexistent-group", "on")

    assert "nonexistent-group" not in relay_app._relay_active_groups
    assert any("Unknown group_id" in message for message in relay_app.logs)


@pytest.mark.asyncio
async def test_relay_on_not_a_member_refused(relay_app):
    other_group = create_group(relay_app._keypair_b, name="Other Group")
    relay_app.group_store.create_group(other_group)

    await relay_app._handle_group_relay(other_group.group_id, "on")

    assert other_group.group_id not in relay_app._relay_active_groups
    assert any("active member" in message for message in relay_app.logs)


@pytest.mark.asyncio
async def test_relay_on_off_are_independent_from_rendezvous(relay_app):
    group_id = relay_app._group.group_id

    await relay_app._handle_group_relay(group_id, "on")

    assert group_id in relay_app._relay_active_groups
    assert group_id not in relay_app._rendezvous_active_groups
    assert any("Relay mode ON" in message for message in relay_app.logs)

    await relay_app._handle_group_relay(group_id, "off")

    assert group_id not in relay_app._relay_active_groups
    assert group_id not in relay_app._rendezvous_active_groups
    assert any("Relay mode OFF" in message for message in relay_app.logs)


@pytest.mark.asyncio
async def test_relay_invalid_mode_shows_usage(relay_app):
    await relay_app._handle_group_relay(relay_app._group.group_id, "find device")

    assert relay_app._group.group_id not in relay_app._relay_active_groups
    assert any("Usage: /group relay" in message for message in relay_app.logs)


# ---------------------------------------------------------------------------
# Host (R) side: _on_relay_request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_request_not_hosting_is_silent(relay_app):
    """Relay mode never turned on for this group -> no reply, no pipe."""
    msg = {"group_id": relay_app._group.group_id, "target_device_id": relay_app._keypair_b.device_id}

    await relay_app._on_relay_request("addr-a", msg)

    relay_app.manager.send.assert_not_awaited()
    relay_app.manager.open_relay_pipe.assert_not_called()


@pytest.mark.asyncio
async def test_relay_request_not_member_is_silent(relay_app):
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    outsider = generate_keypair()
    relay_app.manager.get_peer_device_id = MagicMock(return_value=outsider.device_id)
    msg = {"group_id": group_id, "target_device_id": relay_app._keypair_b.device_id}

    await relay_app._on_relay_request("addr-outsider", msg)

    relay_app.manager.send.assert_not_awaited()
    relay_app.manager.open_relay_pipe.assert_not_called()


@pytest.mark.asyncio
async def test_relay_request_target_not_connected_replies_declined(relay_app):
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    relay_app.manager.find_addr_key_for_device = MagicMock(return_value=None)  # not connected to B
    msg = {"group_id": group_id, "target_device_id": relay_app._keypair_b.device_id}

    await relay_app._on_relay_request("addr-a", msg)

    relay_app.manager.open_relay_pipe.assert_not_called()
    relay_app.manager.send.assert_awaited_once()
    sent_addr, sent_msg = relay_app.manager.send.await_args.args
    assert sent_addr == "addr-a"
    assert sent_msg["type"] == "relay_response"
    assert sent_msg["accepted"] is False


@pytest.mark.asyncio
async def test_relay_request_happy_path_opens_pipe_and_accepts(relay_app):
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    relay_app.manager.find_addr_key_for_device = MagicMock(return_value="addr-b")
    msg = {"group_id": group_id, "target_device_id": relay_app._keypair_b.device_id}

    await relay_app._on_relay_request("addr-a", msg)

    relay_app.manager.open_relay_pipe.assert_called_once_with("addr-a", "addr-b")
    relay_app.manager.send.assert_awaited_once()
    sent_addr, sent_msg = relay_app.manager.send.await_args.args
    assert sent_addr == "addr-a"
    assert sent_msg["type"] == "relay_response"
    assert sent_msg["accepted"] is True
    assert any("Relaying" in m for m in relay_app.logs)


@pytest.mark.asyncio
async def test_relay_request_unknown_addr_key_ignored(relay_app):
    """No authenticated session for this addr_key at all — must not
    crash or open a pipe."""
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    relay_app.manager.get_peer_device_id = MagicMock(return_value=None)
    msg = {"group_id": group_id, "target_device_id": relay_app._keypair_b.device_id}

    await relay_app._on_relay_request("addr-ghost", msg)

    relay_app.manager.send.assert_not_awaited()
    relay_app.manager.open_relay_pipe.assert_not_called()


# ---------------------------------------------------------------------------
# Requester (A) side: _on_relay_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_response_accepted_logs(relay_app):
    msg = {
        "group_id": relay_app._group.group_id,
        "target_device_id": relay_app._keypair_b.device_id,
        "accepted": True,
    }
    await relay_app._on_relay_response("addr-r", msg)
    assert any("Relay accepted" in m for m in relay_app.logs)


@pytest.mark.asyncio
async def test_relay_response_declined_logs(relay_app):
    msg = {
        "group_id": relay_app._group.group_id,
        "target_device_id": relay_app._keypair_b.device_id,
        "accepted": False,
    }
    await relay_app._on_relay_response("addr-r", msg)
    assert any("Relay declined" in m for m in relay_app.logs)


# ---------------------------------------------------------------------------
# Phase 46.3: Candidate query / response & _try_relay_connect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_candidate_query_not_hosting_is_silent(relay_app):
    msg = {"group_id": relay_app._group.group_id}
    await relay_app._on_relay_candidate_query("addr-a", msg)
    relay_app.manager.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_relay_candidate_query_not_member_is_silent(relay_app):
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    outsider = generate_keypair()
    relay_app.manager.get_peer_device_id = MagicMock(return_value=outsider.device_id)
    msg = {"group_id": group_id}

    await relay_app._on_relay_candidate_query("addr-outsider", msg)
    relay_app.manager.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_relay_candidate_query_happy_path_replies_available(relay_app):
    group_id = relay_app._group.group_id
    relay_app._relay_active_groups.add(group_id)
    msg = {"group_id": group_id}

    await relay_app._on_relay_candidate_query("addr-a", msg)
    relay_app.manager.send.assert_awaited_once()
    sent_addr, sent_msg = relay_app.manager.send.await_args.args
    assert sent_addr == "addr-a"
    assert sent_msg["type"] == "relay_candidate_response"
    assert sent_msg["available"] is True


@pytest.mark.asyncio
async def test_relay_candidate_response_feeds_queue(relay_app):
    import asyncio
    group_id = relay_app._group.group_id
    q = asyncio.Queue()
    relay_app._relay_candidate_queues[group_id] = q

    msg = {"group_id": group_id, "available": True}
    await relay_app._on_relay_candidate_response("addr-r", msg)

    assert not q.empty()
    item = await q.get()
    assert item == "addr-r"


@pytest.mark.asyncio
async def test_try_relay_connect_direct_success(relay_app):
    from unittest.mock import AsyncMock
    target_id = relay_app._keypair_b.device_id
    peer_mock = MagicMock()
    peer_mock.ip = "192.168.1.50"
    peer_mock.port = 7600
    relay_app.registry = {target_id: peer_mock}
    relay_app.manager.connect_to = AsyncMock(return_value="direct-addr")

    res = await relay_app._try_relay_connect(target_id, relay_app._group.group_id)
    assert res == "direct-addr"


@pytest.mark.asyncio
async def test_try_relay_connect_fallback_success(relay_app):
    import asyncio
    from unittest.mock import AsyncMock

    target_id = relay_app._keypair_b.device_id
    group_id = relay_app._group.group_id

    # Direct connect fails
    relay_app.registry = {}
    relay_app.manager.find_addr_key_for_device = MagicMock(return_value=None)
    relay_app.manager.list_connected_addr_keys = MagicMock(return_value=["r-addr"])

    # Simulate R candidate response arriving via queue feeding
    orig_send = relay_app.manager.send

    async def mock_send(addr, msg):
        if msg.get("type") == "relay_candidate_query":
            q = relay_app._relay_candidate_queues.get(group_id)
            if q:
                await q.put("r-addr")
        elif msg.get("type") == "relay_request":
            fut = relay_app._relay_response_futures.get(("r-addr", group_id, target_id))
            if fut and not fut.done():
                fut.set_result(True)
        return True

    relay_app.manager.send = AsyncMock(side_effect=mock_send)
    relay_app.manager.connect_via_relay_tunnel = AsyncMock(return_value="relay-tunneled-addr")

    res = await relay_app._try_relay_connect(target_id, group_id)
    assert res == "relay-tunneled-addr"

