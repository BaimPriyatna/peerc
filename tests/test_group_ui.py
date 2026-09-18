"""tests/test_group_ui.py — Phase 42.4: Group Authority UI commands and handlers.

Tests the command dispatcher /groups, /group subcommands, and network callbacks
for group join/leave/revoke in ui.py.
"""

import asyncio
import base64
import pytest
from unittest.mock import AsyncMock, MagicMock

import discovery
from core.group.membership import create_group, issue_membership_certificate
from core.group.policy import GroupPolicy
from core.group.protocol import (
    create_join_request,
    create_leave_request,
    create_membership_revocation,
)
from core.group.store import AdminStatus, GroupStore, MembershipStatus
from core.identity.device_identity import generate_keypair
import protocol
from ui import ChatApp


@pytest.fixture
def test_app(tmp_path):
    """Create an isolated ChatApp with test identity and GroupStore."""
    app = ChatApp()
    keypair = generate_keypair()
    app.my_identity = keypair
    app.peer_id = keypair.device_id
    app.public_key_bytes = keypair.public_key_bytes()
    app.display_name = "test-node"

    # Setup isolated GroupStore
    db_path = str(tmp_path / "test_group.db")
    app.group_store = GroupStore(db_path=db_path)

    # Setup registry and manager mocks
    app.registry = discovery.PeerRegistry()
    app.manager = MagicMock()
    app.manager.send = AsyncMock()
    app.manager.is_connected = MagicMock(return_value=True)

    # Capture logs
    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    return app


@pytest.mark.asyncio
async def test_group_create_and_list(test_app):
    # Empty list
    await test_app._handle_group_command("list")
    assert any("No groups found" in m for m in test_app.logs)

    # Create group
    await test_app._handle_group_command("create Engineering eng-1")
    assert any("Group Engineering created" in m or "created! ID:" in m for m in test_app.logs)

    group = test_app.group_store.get_group("eng-1")
    assert group is not None
    assert group.name == "Engineering"
    assert test_app.group_store.is_admin("eng-1", test_app.peer_id) is True

    # List groups now shows it
    test_app.logs.clear()
    await test_app._handle_group_command("list")
    assert any("Engineering" in m and "eng-1" in m for m in test_app.logs)


@pytest.mark.asyncio
async def test_group_info_members_admins(test_app):
    await test_app._handle_group_command("create Developers dev-1")
    test_app.logs.clear()

    await test_app._handle_group_command("info dev-1")
    assert any("Developers" in m for m in test_app.logs) and any("dev-1" in m for m in test_app.logs)

    test_app.logs.clear()
    await test_app._handle_group_command("members dev-1")
    assert any(test_app.peer_id[:8] in m for m in test_app.logs)

    test_app.logs.clear()
    await test_app._handle_group_command("admins dev-1")
    assert any(test_app.peer_id[:8] in m for m in test_app.logs)


@pytest.mark.asyncio
async def test_group_policy_view_and_update(test_app):
    await test_app._handle_group_command("create Research res-1")
    test_app.logs.clear()

    # View default policy
    await test_app._handle_group_command("policy res-1")
    assert any("allow_external_trust" in m for m in test_app.logs)

    test_app.logs.clear()
    # Update policy
    await test_app._handle_group_command("policy res-1 allow_external_trust=false leave_requires_admin=true")
    assert any("Updated policy" in m for m in test_app.logs)

    policy = test_app.group_store.get_policy("res-1")
    assert policy is not None
    assert policy.allow_external_trust is False
    assert policy.leave_requires_admin is True


@pytest.mark.asyncio
async def test_group_join_request_and_approval(test_app):
    # 1. Admin creates group
    await test_app._handle_group_command("create Ops ops-1")

    # 2. Member creates join request wire message
    member = generate_keypair()
    req = create_join_request(
        member,
        group_id="ops-1",
        requested_role="analyst",
        requested_permissions=["chat"],
        reason="joining ops team",
    )
    wire_req = protocol.make_group_join_request(
        request_id=req.request_id,
        group_id=req.group_id,
        device_id=req.device_id,
        device_public_key=req.device_public_key,
        requested_role=req.requested_role,
        requested_permissions=req.requested_permissions,
        signature=req.signature,
        reason=req.reason,
        timestamp=req.timestamp,
    )

    test_app.logs.clear()
    # Admin receives join request
    await test_app._on_group_join_request("127.0.0.1:5656", wire_req)
    assert any("Group Join Request" in m for m in test_app.logs) and any(req.device_id[:8] in m for m in test_app.logs)
    assert f"ops-1:{req.device_id}" in test_app._pending_join_requests

    # 3. Admin approves join request
    test_app.logs.clear()
    await test_app._handle_group_command(f"approve ops-1 {req.device_id}")
    assert any("Approved membership" in m for m in test_app.logs)
    assert test_app.manager.send.called

    # Check membership recorded in store
    cert = test_app.group_store.get_membership("ops-1", req.device_id)
    assert cert is not None
    assert cert.role == "analyst"


@pytest.mark.asyncio
async def test_group_join_response_applied_by_member(tmp_path):
    # Member app receives approved response
    member_app = ChatApp()
    member_kp = generate_keypair()
    member_app.my_identity = member_kp
    member_app.peer_id = member_kp.device_id
    member_app.public_key_bytes = member_kp.public_key_bytes()
    member_app.group_store = GroupStore(db_path=str(tmp_path / "member_group.db"))
    member_app.registry = discovery.PeerRegistry()
    member_app.logs = []
    member_app._log = lambda text: member_app.logs.append(text)

    # Admin issues certificate and sends response
    admin_kp = generate_keypair()
    admin_group = create_group(admin_kp, name="CoreGroup", group_id="core-1")

    # Record admin in registry so member can find admin public key
    member_app.registry.upsert(
        admin_kp.device_id,
        "admin-peer",
        "127.0.0.1",
        5656,
        public_key=admin_kp.public_key_bytes(),
    )

    cert = issue_membership_certificate(
        admin_kp,
        device_id=member_kp.device_id,
        device_public_key=member_kp.public_key_bytes(),
        group_id="core-1",
        role="engineer",
    )
    from core.group.protocol import create_join_response, GroupJoinRequest
    dummy_req = GroupJoinRequest("req-123", "core-1", member_kp.device_id, base64.b64encode(member_kp.public_key_bytes()).decode("ascii"))
    proper_res = create_join_response(admin_kp, dummy_req, approved=True, certificate=cert, reason="Welcome")
    res = protocol.make_group_join_response(
        request_id="req-123",
        group_id="core-1",
        device_id=member_kp.device_id,
        approved=True,
        admin_device_id=admin_kp.device_id,
        signature=proper_res.signature,
        certificate=cert.to_dict(),
        reason="Welcome",
        timestamp=proper_res.timestamp,
    )

    await member_app._on_group_join_response("127.0.0.1:5656", res)
    assert any("Joined group" in m and "core-1" in m for m in member_app.logs)
    assert member_app.group_store.get_membership("core-1", member_kp.device_id) is not None


@pytest.mark.asyncio
async def test_group_revoke_and_leave(test_app):
    await test_app._handle_group_command("create Team team-1")

    # Add a member
    member = generate_keypair()
    cert = issue_membership_certificate(
        test_app.my_identity,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id="team-1",
        role="contractor",
    )
    test_app.group_store.record_membership(cert)

    # Admin revokes membership
    test_app.logs.clear()
    await test_app._handle_group_command(f"revoke team-1 {member.device_id} SecurityAudit")
    assert any("Revoked membership" in m for m in test_app.logs)
    assert test_app.group_store.get_membership_status("team-1", member.device_id) == MembershipStatus.REVOKED
