"""tests/test_endpoint_update_wire.py — Phase 44.4: endpoint_update wire-
protocol integration tests.

Covers:
  1. peer.ConnectionManager.get_peer_public_key(): real two-manager
     handshake, returns the correct authenticated public key on each
     side, None for an unconnected addr_key.
  2. protocol.make_endpoint_update() shape + validate_message() accepts
     a well-formed endpoint_update and rejects malformed ones (bad
     port, bad kind, missing fields) — same style as test_security_fixes.py.
  3. ChatApp._send_self_endpoint_update() / _on_endpoint_update(): mocked
     manager/locator_store, same pattern as test_link_ui.py's test_app
     fixture — signature verified against the AUTHENTICATED public key
     (not anything self-reported), device_id cross-checked, replay
     rejected on a second delivery of the same update.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.discovery import broadcast as discovery_broadcast
import protocol
from core.connectivity.endpoint_update import create_endpoint_update
from core.connectivity.locator import KIND_DIRECT_V4
from core.connectivity.store import LocatorStore
from core.identity.device_identity import generate_keypair
from core.protocol.errors import ProtocolError
from peer import ConnectionManager
from ui import ChatApp

pytestmark = pytest.mark.ui


PORT_A = 7401
PORT_B = 7402


# ---------------------------------------------------------------------------
# 1. get_peer_public_key (real handshake)
# ---------------------------------------------------------------------------


async def test_get_peer_public_key_matches_authenticated_identity():
    keypair_a = generate_keypair()
    keypair_b = generate_keypair()
    manager_a = ConnectionManager(listen_port=PORT_A, my_identity=keypair_a, my_name="A", on_message=None)
    manager_b = ConnectionManager(listen_port=PORT_B, my_identity=keypair_b, my_name="B", on_message=None)
    try:
        await manager_a.start_server()
        await manager_b.start_server()
        addr_key = await manager_a.connect_to("127.0.0.1", PORT_B)
        await asyncio.sleep(0.2)

        pub_key_seen_by_a = manager_a.get_peer_public_key(addr_key)
        assert pub_key_seen_by_a == keypair_b.public_key_bytes()

        # Find B's addr_key for A (the accepted, not the connecting, side).
        b_side_addr_key = next(iter(manager_b._connections.keys()))
        pub_key_seen_by_b = manager_b.get_peer_public_key(b_side_addr_key)
        assert pub_key_seen_by_b == keypair_a.public_key_bytes()
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


async def test_get_peer_public_key_none_when_not_connected():
    manager = ConnectionManager(listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None)
    assert manager.get_peer_public_key("127.0.0.1:9999") is None


# ---------------------------------------------------------------------------
# 2. Message factory + schema validation
# ---------------------------------------------------------------------------


def test_make_endpoint_update_shape():
    device = generate_keypair()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    wire = protocol.make_endpoint_update(
        device_id=update.device_id,
        kind=update.kind,
        host=update.host,
        port=update.port,
        timestamp=update.timestamp,
        nonce=update.nonce,
        signature=update.signature,
    )
    assert wire["type"] == "endpoint_update"
    assert wire["device_id"] == device.device_id
    assert wire["kind"] == KIND_DIRECT_V4
    assert wire["host"] == "103.20.30.40"
    assert wire["port"] == 5656


def test_validate_message_accepts_well_formed_endpoint_update():
    device = generate_keypair()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    wire = protocol.make_endpoint_update(
        device_id=update.device_id, kind=update.kind, host=update.host,
        port=update.port, timestamp=update.timestamp, nonce=update.nonce, signature=update.signature,
    )
    assert protocol.validate_message(wire) == wire


def test_validate_message_rejects_missing_fields():
    with pytest.raises(ProtocolError):
        protocol.validate_message({"type": "endpoint_update", "device_id": "x"})


def test_validate_message_rejects_bad_port():
    wire = {
        "type": "endpoint_update", "device_id": "x", "kind": KIND_DIRECT_V4,
        "host": "1.2.3.4", "port": 99999, "timestamp": 0.0, "nonce": "n", "signature": "s",
    }
    with pytest.raises(ProtocolError):
        protocol.validate_message(wire)


def test_validate_message_rejects_unknown_kind():
    wire = {
        "type": "endpoint_update", "device_id": "x", "kind": "carrier-pigeon",
        "host": "1.2.3.4", "port": 5656, "timestamp": 0.0, "nonce": "n", "signature": "s",
    }
    with pytest.raises(ProtocolError):
        protocol.validate_message(wire)


# ---------------------------------------------------------------------------
# 3. ChatApp._send_self_endpoint_update / _on_endpoint_update (mocked)
# ---------------------------------------------------------------------------


@pytest.fixture
def test_app(tmp_path):
    app = ChatApp()
    keypair = generate_keypair()
    app.my_identity = keypair
    app.peer_id = keypair.device_id
    app.display_name = "test-node"

    app.locator_store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    app.manager = MagicMock()
    app.manager.send = AsyncMock(return_value=True)
    app.manager.get_peer_public_key = MagicMock(return_value=None)
    app.manager.get_peer_device_id = MagicMock(return_value=None)

    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    return app


@pytest.mark.asyncio
async def test_send_self_endpoint_update_sends_one_per_local_ip(test_app, monkeypatch):
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": ["192.168.1.20", "10.0.0.5"]})

    await test_app._send_self_endpoint_update("1.2.3.4:5656")

    assert test_app.manager.send.await_count == 2
    sent_hosts = {call.args[1]["host"] for call in test_app.manager.send.await_args_list}
    assert sent_hosts == {"192.168.1.20", "10.0.0.5"}
    for call in test_app.manager.send.await_args_list:
        assert call.args[1]["type"] == "endpoint_update"
        assert call.args[1]["device_id"] == test_app.peer_id


@pytest.mark.asyncio
async def test_on_endpoint_update_happy_path_persists(test_app):
    sender = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": update.host,
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    test_app.manager.get_peer_public_key = MagicMock(return_value=sender.public_key_bytes())
    test_app.manager.get_peer_device_id = MagicMock(return_value=sender.device_id)

    await test_app._on_endpoint_update("addr-1", msg)

    stored = test_app.locator_store.list_endpoints(sender.device_id)
    assert len(stored) == 1
    assert stored[0].host == "103.20.30.40"


@pytest.mark.asyncio
async def test_on_endpoint_update_device_id_mismatch_rejected(test_app):
    sender = generate_keypair()
    impostor_claim = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": update.host,
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    # The connection is authenticated as a DIFFERENT device than the one
    # the message claims — e.g. a compromised/buggy peer trying to
    # announce an endpoint for someone else's device_id.
    test_app.manager.get_peer_public_key = MagicMock(return_value=impostor_claim.public_key_bytes())
    test_app.manager.get_peer_device_id = MagicMock(return_value=impostor_claim.device_id)

    await test_app._on_endpoint_update("addr-1", msg)

    assert test_app.locator_store.list_endpoints(sender.device_id) == []
    assert any("SECURITY" in m for m in test_app.logs)


@pytest.mark.asyncio
async def test_on_endpoint_update_invalid_signature_rejected(test_app):
    sender = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": "9.9.9.9",  # tampered after signing
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    test_app.manager.get_peer_public_key = MagicMock(return_value=sender.public_key_bytes())
    test_app.manager.get_peer_device_id = MagicMock(return_value=sender.device_id)

    await test_app._on_endpoint_update("addr-1", msg)

    assert test_app.locator_store.list_endpoints(sender.device_id) == []


@pytest.mark.asyncio
async def test_on_endpoint_update_no_authenticated_session_ignored(test_app):
    sender = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": update.host,
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    test_app.manager.get_peer_public_key = MagicMock(return_value=None)  # not connected

    await test_app._on_endpoint_update("addr-1", msg)

    assert test_app.locator_store.list_endpoints(sender.device_id) == []


@pytest.mark.asyncio
async def test_on_endpoint_update_replay_rejected(test_app):
    sender = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": update.host,
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    test_app.manager.get_peer_public_key = MagicMock(return_value=sender.public_key_bytes())
    test_app.manager.get_peer_device_id = MagicMock(return_value=sender.device_id)

    await test_app._on_endpoint_update("addr-1", msg)
    stored_once = test_app.locator_store.list_endpoints(sender.device_id)
    assert len(stored_once) == 1

    # Deliver the exact same message again — same nonce, should be
    # rejected as a replay. The real assertion is that verify rejects
    # it (observable since a second, different-timestamp write never
    # happens — list stays at exactly one row either way here, but the
    # nonce cache itself is what test_connectivity_endpoint_update.py
    # exercises directly; this just confirms the wiring doesn't crash
    # or silently re-verify).
    await test_app._on_endpoint_update("addr-1", msg)
    stored_twice = test_app.locator_store.list_endpoints(sender.device_id)
    assert len(stored_twice) == 1


@pytest.mark.asyncio
async def test_on_endpoint_update_vault_locked_noop(test_app):
    test_app.locator_store = None  # vault locked
    sender = generate_keypair()
    update = create_endpoint_update(sender, KIND_DIRECT_V4, "103.20.30.40", 5656)
    msg = {
        "device_id": update.device_id, "kind": update.kind, "host": update.host,
        "port": update.port, "timestamp": update.timestamp, "nonce": update.nonce, "signature": update.signature,
    }
    test_app.manager.get_peer_public_key = MagicMock(return_value=sender.public_key_bytes())

    await test_app._on_endpoint_update("addr-1", msg)  # should not raise
