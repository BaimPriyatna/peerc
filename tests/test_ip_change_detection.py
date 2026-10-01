"""tests/test_ip_change_detection.py — Phase 45.1: own-IP-change
detection + re-announce to currently-connected peers.

Covers:
  1. peer.ConnectionManager.list_connected_addr_keys(): empty when
     nothing's connected, correct set after a real handshake.
  2. ChatApp._check_ip_change(): no-op when local_ips is unchanged,
     triggers a re-announce when changed, and does NOT clobber
     _last_known_local_ips or trigger anything on a transient empty
     reading (e.g. network blip) — avoids a false "changed" signal.
  3. ChatApp._reannounce_endpoint_to_connected_peers(): calls
     _send_self_endpoint_update() once per currently-connected addr_key.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.discovery import broadcast as discovery_broadcast
from core.identity.device_identity import generate_keypair
from core.transport.manager import ConnectionManager
from app.ui.app import ChatApp

pytestmark = pytest.mark.ui


PORT_A = 7501
PORT_B = 7502


# ---------------------------------------------------------------------------
# 1. list_connected_addr_keys
# ---------------------------------------------------------------------------


def test_list_connected_addr_keys_empty_when_disconnected():
    manager = ConnectionManager(listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None)
    assert manager.list_connected_addr_keys() == []


async def test_list_connected_addr_keys_after_real_handshake():
    manager_a = ConnectionManager(listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None)
    manager_b = ConnectionManager(listen_port=PORT_B, my_identity=generate_keypair(), my_name="B", on_message=None)
    try:
        await manager_a.start_server()
        await manager_b.start_server()
        addr_key = await manager_a.connect_to("127.0.0.1", PORT_B)
        await asyncio.sleep(0.2)

        assert manager_a.list_connected_addr_keys() == [addr_key]
        assert len(manager_b.list_connected_addr_keys()) == 1
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------------
# 2-3. ChatApp._check_ip_change / _reannounce_endpoint_to_connected_peers
# ---------------------------------------------------------------------------


@pytest.fixture
def test_app():
    app = ChatApp()
    app.manager = MagicMock()
    app.manager.list_connected_addr_keys = MagicMock(return_value=[])
    app._send_self_endpoint_update = AsyncMock()
    app._reannounce_endpoint_to_connected_peers = MagicMock()  # spy, don't actually run the @work method

    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    return app


def test_check_ip_change_no_change_is_noop(test_app, monkeypatch):
    test_app._last_known_local_ips = {"192.168.1.20"}
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": ["192.168.1.20"]})

    test_app._check_ip_change()

    test_app._reannounce_endpoint_to_connected_peers.assert_not_called()
    assert test_app._last_known_local_ips == {"192.168.1.20"}


def test_check_ip_change_detects_change(test_app, monkeypatch):
    test_app._last_known_local_ips = {"192.168.1.20"}
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": ["10.0.0.5"]})

    test_app._check_ip_change()

    test_app._reannounce_endpoint_to_connected_peers.assert_called_once()
    assert test_app._last_known_local_ips == {"10.0.0.5"}


def test_check_ip_change_ignores_transient_empty_reading(test_app, monkeypatch):
    test_app._last_known_local_ips = {"192.168.1.20"}
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": []})

    test_app._check_ip_change()

    # An empty reading (network blip / interface briefly down) must not
    # be treated as "IP changed" — that would spuriously re-announce
    # with zero real info, and would also clobber the baseline so the
    # NEXT real reading always looks "new" even if it's actually the
    # same address as before the blip.
    test_app._reannounce_endpoint_to_connected_peers.assert_not_called()
    assert test_app._last_known_local_ips == {"192.168.1.20"}


def test_check_ip_change_detects_added_interface(test_app, monkeypatch):
    test_app._last_known_local_ips = {"192.168.1.20"}
    monkeypatch.setattr(discovery_broadcast, "get_network_info", lambda: {"local_ips": ["192.168.1.20", "10.0.0.5"]})

    test_app._check_ip_change()

    test_app._reannounce_endpoint_to_connected_peers.assert_called_once()
    assert test_app._last_known_local_ips == {"192.168.1.20", "10.0.0.5"}


@pytest.mark.asyncio
async def test_reannounce_sends_to_every_connected_peer():
    app = ChatApp()
    app.manager = MagicMock()
    app.manager.list_connected_addr_keys = MagicMock(return_value=["1.1.1.1:5656", "2.2.2.2:5656"])
    app._send_self_endpoint_update = AsyncMock()
    logs = []
    app._log = lambda text: logs.append(text)

    # _reannounce_endpoint_to_connected_peers is @work-decorated; call
    # the underlying coroutine function directly to run it synchronously
    # in this test rather than scheduling a Textual worker.
    await ChatApp._reannounce_endpoint_to_connected_peers.__wrapped__(app)

    assert app._send_self_endpoint_update.await_count == 2
    called_addr_keys = {call.args[0] for call in app._send_self_endpoint_update.await_args_list}
    assert called_addr_keys == {"1.1.1.1:5656", "2.2.2.2:5656"}
    assert any("re-announcing to 2 connected peer" in m for m in logs)


@pytest.mark.asyncio
async def test_reannounce_noop_when_no_peers_connected():
    app = ChatApp()
    app.manager = MagicMock()
    app.manager.list_connected_addr_keys = MagicMock(return_value=[])
    app._send_self_endpoint_update = AsyncMock()
    app._log = MagicMock()

    await ChatApp._reannounce_endpoint_to_connected_peers.__wrapped__(app)

    app._send_self_endpoint_update.assert_not_awaited()
    app._log.assert_not_called()
