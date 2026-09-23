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
