"""tests/test_link_ui.py — Phase 44.3 UI: Add-by-Link click flow tests.

Tests _parse_endpoint_line() (pure parsing) and the ChatApp flow methods
(_generate_link_flow, _add_link_flow, _connect_to_link_endpoint) with
push_screen_wait/manager/registry mocked out, same pattern as
test_group_ui.py — no real Textual screen stack needed to exercise the
underlying logic.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

import discovery
from core.connectivity.link import create_link, decode_link
from core.connectivity.locator import KIND_DIRECT_V4, KIND_DIRECT_V6, KIND_RENDEZVOUS, Endpoint
from core.connectivity.store import LocatorStore
from core.identity.device_identity import generate_keypair
from ui import LinkAddModal, LinkGenerateModal, LinkMenuModal, LinkResultModal, UI_TCP_PORT, ChatApp, _parse_endpoint_line


# ---------------------------------------------------------------------------
# _parse_endpoint_line (pure function)
# ---------------------------------------------------------------------------


def test_parse_ipv4_with_port():
    ep = _parse_endpoint_line("103.20.30.40:5656", "dev1")
    assert ep.kind == KIND_DIRECT_V4
    assert ep.host == "103.20.30.40"
    assert ep.port == 5656


def test_parse_ipv4_without_port_defaults():
    ep = _parse_endpoint_line("103.20.30.40", "dev1")
    assert ep.kind == KIND_DIRECT_V4
    assert ep.port == UI_TCP_PORT


def test_parse_ipv6_bracket_notation():
    ep = _parse_endpoint_line("[2001:db8::1]:5656", "dev1")
    assert ep.kind == KIND_DIRECT_V6
    assert ep.host == "2001:db8::1"
    assert ep.port == 5656


def test_parse_ipv6_bare_no_brackets_defaults_port():
    ep = _parse_endpoint_line("2001:db8::1", "dev1")
    assert ep.kind == KIND_DIRECT_V6
    assert ep.port == UI_TCP_PORT


def test_parse_hostname_as_rendezvous():
    ep = _parse_endpoint_line("rendez.example.com:443", "dev1")
    assert ep.kind == KIND_RENDEZVOUS
    assert ep.host == "rendez.example.com"
    assert ep.port == 443


def test_parse_empty_line_raises():
    with pytest.raises(ValueError):
        _parse_endpoint_line("", "dev1")


def test_parse_unterminated_bracket_raises():
    with pytest.raises(ValueError):
        _parse_endpoint_line("[2001:db8::1", "dev1")


# ---------------------------------------------------------------------------
# Flow methods, with push_screen_wait/manager/registry mocked
# ---------------------------------------------------------------------------


@pytest.fixture
def test_app(tmp_path):
    app = ChatApp()
    keypair = generate_keypair()
    app.my_identity = keypair
    app.peer_id = keypair.device_id
    app.public_key_bytes = keypair.public_key_bytes()
    app.display_name = "test-node"

    app.locator_store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    app.registry = discovery.PeerRegistry()
    app.manager = MagicMock()
    app.manager.connect_to = AsyncMock(return_value="addr-key-1")
    app.manager.send = AsyncMock()
    app._discovery = MagicMock()
    app._discovery.probe_peer = MagicMock()
    app._refresh_peer_list = MagicMock()  # needs a mounted screen otherwise, out of scope here

    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs

    return app


@pytest.mark.asyncio
async def test_generate_link_flow_happy_path(test_app, monkeypatch):
    captured = {}

    async def fake_push_screen_wait(screen):
        if isinstance(screen, LinkGenerateModal):
            return ("103.20.30.40:5656", "482913")
        if isinstance(screen, LinkResultModal):
            captured["result"] = screen
            return None
        return None

    test_app.push_screen_wait = fake_push_screen_wait
    monkeypatch.setattr(discovery, "get_network_info", lambda: {"local_ips": ["192.168.1.20"]})

    await test_app._generate_link_flow()

    assert "result" in captured
    link, pin = captured["result"].link, captured["result"].pin
    assert link.startswith("PEERC1:")
    assert pin == "482913"
    payload = decode_link(link, pin)
    assert payload.device_id == test_app.peer_id
    assert payload.endpoints[0].host == "103.20.30.40"


@pytest.mark.asyncio
async def test_generate_link_flow_cancel(test_app):
    async def fake_push_screen_wait(screen):
        return None  # user cancelled

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._generate_link_flow()  # should not raise


@pytest.mark.asyncio
async def test_generate_link_flow_invalid_endpoint_line_skipped(test_app):
    async def fake_push_screen_wait(screen):
        if isinstance(screen, LinkGenerateModal):
            return ("[2001:db8::1", "482913")  # unterminated bracket -> unparsable
        return None  # LinkResultModal never reached if no valid endpoints

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._generate_link_flow()

    assert any("No valid endpoints" in m for m in test_app.logs)


@pytest.mark.asyncio
async def test_add_link_flow_happy_path_connects(test_app):
    sender = generate_keypair()
    link = create_link(
        sender,
        [Endpoint(device_id=sender.device_id, kind=KIND_DIRECT_V4, host="103.20.30.40", port=5656)],
        "482913",
    )

    async def fake_push_screen_wait(screen):
        if isinstance(screen, LinkAddModal):
            return (link, "482913")
        return None

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._add_link_flow()

    test_app.manager.connect_to.assert_awaited_once_with("103.20.30.40", 5656)
    assert test_app.active_peer_id == sender.device_id
    assert any("Connected to 103.20.30.40:5656" in m for m in test_app.logs)
    stored = test_app.locator_store.list_endpoints(sender.device_id)
    assert len(stored) == 1


@pytest.mark.asyncio
async def test_add_link_flow_wrong_pin_does_not_connect(test_app):
    sender = generate_keypair()
    link = create_link(
        sender,
        [Endpoint(device_id=sender.device_id, kind=KIND_DIRECT_V4, host="103.20.30.40", port=5656)],
        "482913",
    )

    async def fake_push_screen_wait(screen):
        if isinstance(screen, LinkAddModal):
            return (link, "000000")  # wrong PIN
        return None

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._add_link_flow()

    test_app.manager.connect_to.assert_not_awaited()
    assert any("Wrong PIN" in m for m in test_app.logs)


@pytest.mark.asyncio
async def test_add_link_flow_cancel(test_app):
    async def fake_push_screen_wait(screen):
        return None

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._add_link_flow()  # should not raise

    test_app.manager.connect_to.assert_not_awaited()


@pytest.mark.asyncio
async def test_link_menu_routes_to_generate(test_app):
    calls = []
    test_app._generate_link_flow = AsyncMock(side_effect=lambda: calls.append("generate"))
    test_app._add_link_flow = AsyncMock(side_effect=lambda: calls.append("add"))

    async def fake_push_screen_wait(screen):
        assert isinstance(screen, LinkMenuModal)
        return "generate"

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._open_link_menu()

    assert calls == ["generate"]


@pytest.mark.asyncio
async def test_link_menu_cancel_calls_neither_flow(test_app):
    test_app._generate_link_flow = AsyncMock()
    test_app._add_link_flow = AsyncMock()

    async def fake_push_screen_wait(screen):
        return ""

    test_app.push_screen_wait = fake_push_screen_wait

    await test_app._open_link_menu()

    test_app._generate_link_flow.assert_not_awaited()
    test_app._add_link_flow.assert_not_awaited()
