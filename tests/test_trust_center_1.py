"""tests/test_trust_center_36_1.py — Phase 36.1: Read-only Trust Center inventory.

Tests covering:
- Empty device list state
- Full device inventory (Pending, Trusted, Revoked)
- Status filter switching
- Device lookup / prefix matching for /trust <device_id>
- Vault-locked protection (both command dispatch and modal render)
- Fingerprint copying from device detail modal
- /pairs alias for /devices
"""

import base64
import time
from unittest.mock import AsyncMock, MagicMock
import pytest
from textual.app import App, ComposeResult
from textual.widgets import Label, ListView

from core.identity.device_identity import generate_keypair
from core.identity.fingerprint import format_fingerprint
from core.trust.device import TrustedDevice, TrustStatus
from core.trust.revocation import revoke_device
from core.trust.store import TrustStore
from ui import ChatApp, TrustCenterModal, TrustDeviceDetailModal


class ModalHostApp(App):
    """Minimal Textual app to host modals during pilot tests."""

    def __init__(self, trust_store=None):
        super().__init__()
        self.trust_store = trust_store
        self.clipboard_content = None

    def copy_to_clipboard(self, text: str) -> None:
        self.clipboard_content = text


def _b64(kp) -> str:
    return base64.b64encode(kp.public_key_bytes()).decode("ascii")


def _create_sample_devices(store: TrustStore) -> tuple[TrustedDevice, TrustedDevice, TrustedDevice]:
    now = time.time()
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    kp3 = generate_keypair()

    store.record_first_seen(kp1.device_id, _b64(kp1), name="Alice-Phone")
    store.approve(kp1.device_id)

    store.record_first_seen(kp2.device_id, _b64(kp2), name="Bob-Laptop")

    store.record_first_seen(kp3.device_id, _b64(kp3), name="Charlie-Desktop")
    revoke_device(store, kp3.device_id, revoked_by="Admin", reason="Stolen device")

    dev_trusted = store.get(kp1.device_id)
    dev_pending = store.get(kp2.device_id)
    dev_revoked = store.get(kp3.device_id)
    return dev_pending, dev_trusted, dev_revoked


@pytest.mark.asyncio
async def test_devices_empty(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    app = ModalHostApp(trust_store=store)

    async with app.run_test() as pilot:
        modal = TrustCenterModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#trust-center-list", ListView)
        empty_label = modal.query_one("#trust-center-empty", Label)

        assert len(list_view.children) == 0
        assert "No devices" in str(empty_label.render())


@pytest.mark.asyncio
async def test_devices_all(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    p, t, r = _create_sample_devices(store)
    app = ModalHostApp(trust_store=store)

    async with app.run_test() as pilot:
        modal = TrustCenterModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#trust-center-list", ListView)
        empty_label = modal.query_one("#trust-center-empty", Label)

        assert len(list_view.children) == 3
        assert str(empty_label.render()) == ""


@pytest.mark.asyncio
async def test_devices_pending_filter(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    p, t, r = _create_sample_devices(store)
    app = ModalHostApp(trust_store=store)

    async with app.run_test() as pilot:
        # Initialized with pending filter
        modal = TrustCenterModal(filter_status=TrustStatus.PENDING)
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#trust-center-list", ListView)
        assert len(list_view.children) == 1
        item_label = list_view.children[0].query_one(Label)
        assert "Bob-Laptop" in str(item_label.render())

        # Switch to Trusted
        await pilot.click("#tc-filter-trusted")
        await pilot.pause()
        assert len(list_view.children) == 1
        item_label = list_view.children[0].query_one(Label)
        assert "Alice-Phone" in str(item_label.render())

        # Switch to Revoked
        await pilot.click("#tc-filter-revoked")
        await pilot.pause()
        assert len(list_view.children) == 1
        item_label = list_view.children[0].query_one(Label)
        assert "Charlie-Desktop" in str(item_label.render())

        # Switch to All
        await pilot.click("#tc-filter-all")
        await pilot.pause()
        assert len(list_view.children) == 3


@pytest.mark.asyncio
async def test_vault_locked(tmp_path):
    # 1. Inside TrustCenterModal directly when trust_store is None
    app = ModalHostApp(trust_store=None)
    async with app.run_test() as pilot:
        modal = TrustCenterModal()
        await app.push_screen(modal)
        await pilot.pause()

        empty_label = modal.query_one("#trust-center-empty", Label)
        assert "Vault is locked" in str(empty_label.render())

    # 2. Command dispatch guards
    chat_app = ChatApp()
    chat_app.trust_store = None
    chat_app.push_screen = MagicMock()
    logs = []
    chat_app._log = lambda text: logs.append(text)

    await chat_app._cmd_devices("")
    assert chat_app.push_screen.call_count == 0
    assert any("Vault is locked" in msg for msg in logs)

    logs.clear()
    await chat_app._cmd_trust_detail("some-id")
    assert chat_app.push_screen.call_count == 0
    assert any("Vault is locked" in msg for msg in logs)


@pytest.mark.asyncio
async def test_unknown_id(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    _create_sample_devices(store)

    chat_app = ChatApp()
    chat_app.trust_store = store
    chat_app.push_screen = MagicMock()
    logs = []
    chat_app._log = lambda text: logs.append(text)

    # Empty arg
    await chat_app._cmd_trust_detail("")
    assert any("Usage:" in msg for msg in logs)
    assert chat_app.push_screen.call_count == 0

    # Nonexistent device id
    logs.clear()
    await chat_app._cmd_trust_detail("nonexistent-prefix")
    assert any("not found" in msg for msg in logs)
    assert chat_app.push_screen.call_count == 0


@pytest.mark.asyncio
async def test_trust_detail_success(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    p, t, r = _create_sample_devices(store)

    chat_app = ChatApp()
    chat_app.trust_store = store
    pushed = []
    chat_app.push_screen = lambda s: pushed.append(s)

    # Match by prefix
    prefix = p.device_id[:8]
    await chat_app._cmd_trust_detail(prefix)
    assert len(pushed) == 1
    assert isinstance(pushed[0], TrustDeviceDetailModal)
    assert pushed[0]._device.device_id == p.device_id


@pytest.mark.asyncio
async def test_detail_copy_fingerprint(tmp_path):
    kp = generate_keypair()
    now = time.time()
    dev = TrustedDevice(
        device_id=kp.device_id,
        public_key=_b64(kp),
        name="Device-To-Copy",
        first_seen=now,
        last_seen=now,
        status=TrustStatus.TRUSTED,
    )

    app = ModalHostApp()
    async with app.run_test() as pilot:
        detail_modal = TrustDeviceDetailModal(dev)
        await app.push_screen(detail_modal)
        await pilot.pause()

        await pilot.click("#td-copy-fp")
        await pilot.pause()

        expected_fp = format_fingerprint(dev.device_id)
        assert app.clipboard_content == expected_fp


@pytest.mark.asyncio
async def test_pairs_alias(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    chat_app = ChatApp()
    chat_app.trust_store = store
    pushed = []
    chat_app.push_screen = lambda s: pushed.append(s)

    await chat_app._handle_command("/pairs")
    assert len(pushed) == 1
    assert isinstance(pushed[0], TrustCenterModal)
    assert pushed[0]._filter is None

    pushed.clear()
    await chat_app._handle_command("/devices pending")
    assert len(pushed) == 1
    assert isinstance(pushed[0], TrustCenterModal)
    assert pushed[0]._filter == TrustStatus.PENDING
