import base64
import hashlib
import os
import tempfile
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.group.export_auth import (
    ExportCapability,
    ExportRequest,
    create_export_request,
    issue_export_capability,
    verify_export_capability,
    verify_export_request,
)
from core.group.membership import Group
from core.group.policy import ExportDeniedError, PolicyEnforcer
from core.group.store import AdminStatus, GroupStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gen_keypair():
    """Return (Ed25519PrivateKey, device_id, public_key_b64)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    device_id = hashlib.sha256(pub_bytes).hexdigest()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv, device_id, pub_b64


def _make_store_with_group():
    """Create an in-memory GroupStore with one group + one admin."""
    store = GroupStore(":memory:")
    admin_priv, admin_id, admin_pub = _gen_keypair()
    group = Group(
        group_id=str(uuid.uuid4()),
        name="Test Corp",
        admin_device_id=admin_id,
        admin_public_key=admin_pub,
        created_at=time.time(),
    )
    store.create_group(group)
    return store, group, admin_priv, admin_id, admin_pub


def _make_request(device_priv, device_id, device_pub, group_id, file_id="filexyz"):
    return create_export_request(
        device_private_key=device_priv,
        device_id=device_id,
        device_public_key_b64=device_pub,
        group_id=group_id,
        file_id=file_id,
        reason="unit test",
    )


# ---------------------------------------------------------------------------
# Test 1: happy-path issue + verify
# ---------------------------------------------------------------------------

def test_issue_and_verify_capability():
    admin_priv, admin_id, admin_pub = _gen_keypair()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    req = _make_request(dev_priv, dev_id, dev_pub, "group-1")
    cap = issue_export_capability(admin_priv, admin_id, req)

    assert cap.device_id == dev_id
    assert cap.group_id == "group-1"
    assert cap.signature is not None
    assert verify_export_capability(cap, [admin_pub]) is True


# ---------------------------------------------------------------------------
# Test 2: expired capability
# ---------------------------------------------------------------------------

def test_expired_capability_rejected():
    admin_priv, admin_id, admin_pub = _gen_keypair()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    req = _make_request(dev_priv, dev_id, dev_pub, "group-2")
    cap = issue_export_capability(admin_priv, admin_id, req, ttl=0.001)

    # Even a valid signature is rejected once expired
    time.sleep(0.01)
    assert verify_export_capability(cap, [admin_pub]) is False


# ---------------------------------------------------------------------------
# Test 3: wrong admin key
# ---------------------------------------------------------------------------

def test_wrong_admin_key_rejected():
    admin_priv, admin_id, admin_pub = _gen_keypair()
    _, _, wrong_pub = _gen_keypair()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    req = _make_request(dev_priv, dev_id, dev_pub, "group-3")
    cap = issue_export_capability(admin_priv, admin_id, req)

    # Verifying with the wrong public key must fail
    assert verify_export_capability(cap, [wrong_pub]) is False
    # But the correct key succeeds
    assert verify_export_capability(cap, [admin_pub]) is True


# ---------------------------------------------------------------------------
# Test 4: store + retrieve round-trip
# ---------------------------------------------------------------------------

def test_store_and_retrieve_capability():
    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    req = _make_request(dev_priv, dev_id, dev_pub, group.group_id)
    cap = issue_export_capability(admin_priv, admin_id, req)

    store.store_capability(cap)

    retrieved = store.get_valid_capability(group.group_id, dev_id, req.file_id)
    assert retrieved is not None
    assert retrieved.capability_id == cap.capability_id
    assert retrieved.device_id == dev_id


# ---------------------------------------------------------------------------
# Test 5: mark_capability_used → get_valid_capability returns None
# ---------------------------------------------------------------------------

def test_mark_used_burns_capability():
    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    req = _make_request(dev_priv, dev_id, dev_pub, group.group_id)
    cap = issue_export_capability(admin_priv, admin_id, req)
    store.store_capability(cap)

    # Before burn — visible
    assert store.get_valid_capability(group.group_id, dev_id, req.file_id) is not None

    store.mark_capability_used(cap.capability_id)

    # After burn — invisible
    assert store.get_valid_capability(group.group_id, dev_id, req.file_id) is None


# ---------------------------------------------------------------------------
# Test 6: PolicyEnforcer passes when valid capability exists
# ---------------------------------------------------------------------------

def test_policy_enforcer_passes_with_valid_capability():
    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    # Set policy to deny export
    from core.group.policy import GroupPolicy
    policy = GroupPolicy(group_id=group.group_id, allow_export=False)
    store.set_policy(policy)
    req = _make_request(dev_priv, dev_id, dev_pub, group.group_id, file_id="secure-file-abc")
    cap = issue_export_capability(admin_priv, admin_id, req)
    store.store_capability(cap)

    enforcer = PolicyEnforcer(group_store=store)
    # Should NOT raise — the capability gates open
    enforcer.check_export(
        group_id=group.group_id,
        device_id=dev_id,
        file_id="secure-file-abc",
    )


# ---------------------------------------------------------------------------
# Test 7: PolicyEnforcer denies when no capability
# ---------------------------------------------------------------------------

def test_policy_enforcer_denies_without_capability():
    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    _, dev_id, _ = _gen_keypair()

    from core.group.policy import GroupPolicy
    policy = GroupPolicy(group_id=group.group_id, allow_export=False)
    store.set_policy(policy)

    enforcer = PolicyEnforcer(group_store=store)
    with pytest.raises(ExportDeniedError):
        enforcer.check_export(
            group_id=group.group_id,
            device_id=dev_id,
            file_id="some-file-id",
        )


# ---------------------------------------------------------------------------
# Test 8: PolicyEnforcer denies when capability expired
# ---------------------------------------------------------------------------

def test_policy_enforcer_denies_expired_capability():
    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    from core.group.policy import GroupPolicy
    policy = GroupPolicy(group_id=group.group_id, allow_export=False)
    store.set_policy(policy)

    # Issue a near-expiry capability, store while still valid, then wait
    req = _make_request(dev_priv, dev_id, dev_pub, group.group_id, file_id="f1")
    cap = issue_export_capability(admin_priv, admin_id, req, ttl=300)
    store.store_capability(cap)

    # Force the capability to be "expired" by checking with a future `now`
    enforcer = PolicyEnforcer(group_store=store)

    # Patch time.time in get_valid_capability to simulate expiry
    with patch("time.time", return_value=time.time() + 999):
        with pytest.raises(ExportDeniedError):
            enforcer.check_export(
                group_id=group.group_id,
                device_id=dev_id,
                file_id="f1",
            )


# ---------------------------------------------------------------------------
# Test 9: export_secure_file AND-gate — both gates must pass
# ---------------------------------------------------------------------------

def test_export_and_gate_both_must_pass():
    """Group gate passes, but personal gate fails (no critical key configured
    BUT session.authorize_export returns False) → AuthorizationError."""
    from core.vault.file_actions import AuthorizationError, export_secure_file
    from core.group.policy import GroupPolicy

    store, group, admin_priv, admin_id, admin_pub = _make_store_with_group()
    dev_priv, dev_id, dev_pub = _gen_keypair()

    policy = GroupPolicy(group_id=group.group_id, allow_export=False)
    store.set_policy(policy)

    req = _make_request(dev_priv, dev_id, dev_pub, group.group_id, file_id="secure-id-001")
    cap = issue_export_capability(admin_priv, admin_id, req)
    store.store_capability(cap)

    enforcer = PolicyEnforcer(group_store=store)

    # Mock session: unlocked but authorize_export returns False (personal gate blocks)
    mock_session = MagicMock()
    mock_session.is_unlocked = True
    mock_session.authorize_export.return_value = False

    mock_keyfile = MagicMock()

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = os.path.join(tmpdir, "output.txt")
        # Group gate passes (valid capability), personal gate blocks
        with pytest.raises(AuthorizationError):
            export_secure_file(
                secure_id="secure-id-001",
                secure_storage_dir=tmpdir,
                destination_path=dest,
                session=mock_session,
                keyfile=mock_keyfile,
                policy_enforcer=enforcer,
                group_id=group.group_id,
                device_id=dev_id,
            )


# ---------------------------------------------------------------------------
# Test 10: export_secure_file with no policy_enforcer (backward compat)
# ---------------------------------------------------------------------------

def test_export_no_policy_enforcer_personal_gate_only():
    """Without a policy_enforcer, group gate is skipped; only personal gate runs."""
    from core.vault.file_actions import AuthorizationError, export_secure_file

    mock_session = MagicMock()
    mock_session.is_unlocked = True
    mock_session.authorize_export.return_value = False  # personal gate blocks

    mock_keyfile = MagicMock()

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = os.path.join(tmpdir, "output.txt")
        with pytest.raises(AuthorizationError, match="critical-action"):
            export_secure_file(
                secure_id="any-id",
                secure_storage_dir=tmpdir,
                destination_path=dest,
                session=mock_session,
                keyfile=mock_keyfile,
                # policy_enforcer intentionally NOT passed
            )

    # Verify the group gate was never consulted (no group_store call)
    mock_session.authorize_export.assert_called_once()


# ---------------------------------------------------------------------------
# Test 11: Wire message creation and schema validation
# ---------------------------------------------------------------------------

def test_export_wire_messages_and_validation():
    import protocol
    from core.protocol.errors import ProtocolError

    # group_export_request
    wire_req = protocol.make_group_export_request(
        request_id="req-1",
        group_id="grp-1",
        device_id="dev-1",
        device_public_key="pub-1",
        file_id="sec-1",
        signature="sig-1",
        reason="compliance backup",
    )
    validated = protocol.validate_message(wire_req)
    assert validated["type"] == "group_export_request"
    assert validated["reason"] == "compliance backup"

    # Missing field
    invalid_req = dict(wire_req)
    del invalid_req["file_id"]
    with pytest.raises(ProtocolError):
        protocol.validate_message(invalid_req)

    # group_export_capability
    wire_cap = protocol.make_group_export_capability(
        capability_id="cap-1",
        request_id="req-1",
        group_id="grp-1",
        device_id="dev-1",
        file_id="sec-1",
        issued_at=100.0,
        expires_at=400.0,
        nonce="nonce-1",
        admin_device_id="adm-1",
        signature="sig-1",
    )
    validated_cap = protocol.validate_message(wire_cap)
    assert validated_cap["type"] == "group_export_capability"

    # Invalid timestamp
    invalid_cap = dict(wire_cap)
    invalid_cap["expires_at"] = "never"
    with pytest.raises(ProtocolError):
        protocol.validate_message(invalid_cap)


# ---------------------------------------------------------------------------
# Test 12: UI /group req-export, authorize-export, and network callbacks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ui_group_export_flow(tmp_path):
    from unittest.mock import AsyncMock
    from ui import ChatApp
    import discovery
    from core.identity.device_identity import generate_keypair

    # Setup admin app
    admin_app = ChatApp()
    admin_kp = generate_keypair()
    admin_app.my_identity = admin_kp
    admin_app.peer_id = admin_kp.device_id
    admin_app.public_key_bytes = admin_kp.public_key_bytes()
    admin_app.group_store = GroupStore(db_path=str(tmp_path / "admin_grp.db"))
    admin_app.registry = discovery.PeerRegistry()
    admin_app.manager = MagicMock()
    admin_app.manager.send = AsyncMock()
    admin_app.manager.is_connected = MagicMock(return_value=True)
    admin_logs = []
    admin_app._log = lambda t: admin_logs.append(t)

    # Admin creates group
    await admin_app._handle_group_command("create Finance fin-1")

    # Setup member app
    member_app = ChatApp()
    member_kp = generate_keypair()
    member_app.my_identity = member_kp
    member_app.peer_id = member_kp.device_id
    member_app.public_key_bytes = member_kp.public_key_bytes()
    member_app.group_store = GroupStore(db_path=str(tmp_path / "member_grp.db"))
    member_app.registry = discovery.PeerRegistry()
    member_app.manager = MagicMock()
    member_app.manager.send = AsyncMock()
    member_app.manager.is_connected = MagicMock(return_value=True)
    member_logs = []
    member_app._log = lambda t: member_logs.append(t)

    # Add member to group
    from core.group.membership import issue_membership_certificate
    cert = issue_membership_certificate(
        admin_kp,
        device_id=member_kp.device_id,
        device_public_key=member_kp.public_key_bytes(),
        group_id="fin-1",
        role="accountant",
    )
    admin_app.group_store.record_membership(cert)
    # Give member the group and cert in member's store
    from core.group.membership import create_group as make_group
    member_app.group_store.create_group(make_group(admin_kp, name="Finance", group_id="fin-1"))
    member_app.group_store.record_membership(cert)

    # Member knows admin
    member_app.registry.upsert(
        admin_kp.device_id, "admin-node", "127.0.0.1", 5656, public_key=admin_kp.public_key_bytes()
    )

    # 1. Member requests export authorization
    await member_app._handle_group_command("req-export fin-1 file-abc Annual audit export")
    assert any("Sent export request" in m for m in member_logs)
    assert member_app.manager.send.called

    # Extract the wire message sent by member
    call_args = member_app.manager.send.call_args[0]
    sent_addr, wire_req = call_args

    # 2. Admin receives the wire request
    await admin_app._on_group_export_request("127.0.0.1:5657", wire_req)
    assert any("Group Export Request" in m for m in admin_logs)
    assert f"fin-1:{member_kp.device_id}:file-abc" in admin_app._pending_export_requests

    # 3. Admin authorizes export
    admin_logs.clear()
    await admin_app._handle_group_command(f"authorize-export fin-1 {member_kp.device_id[:8]} file-abc 600")
    assert any("Authorized export" in m for m in admin_logs)
    assert admin_app.manager.send.called

    # Extract the wire capability sent by admin
    admin_call = admin_app.manager.send.call_args[0]
    _, wire_cap = admin_call

    # 4. Member receives the export capability
    await member_app._on_group_export_capability("127.0.0.1:5656", wire_cap)
    assert any("Received Export Authorization" in m for m in member_logs)

    # Member now has valid capability in store
    valid_cap = member_app.group_store.get_valid_capability("fin-1", member_kp.device_id, "file-abc")
    assert valid_cap is not None
    assert valid_cap.file_id == "file-abc"

    # 5. Member can view active capabilities via /group caps
    member_logs.clear()
    await member_app._handle_group_command("caps fin-1")
    assert any("Active Export Capabilities: Finance" in m for m in member_logs)
    assert any("file-abc" in m for m in member_logs)
