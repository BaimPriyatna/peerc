"""tests/test_trust_center_4.py — Phase 37.2: Security-event review + rotation history.

Tests covering:
- test_security_events_grouping: two events for same type+device → one row, latest ts
- test_security_events_empty: empty buffer → empty state
- test_event_links_to_device: click event with known device_id → TrustDeviceDetailModal
- test_mismatch_not_approval: identity_changed shown; no approve/trust-new-key in Events modal
- test_rotation_history_shown: rotation chain → section visible on detail
- test_rotation_revoked_ancestor: REVOKED ancestor → tainted marker
- test_rotation_no_history: singleton chain → rotation section omitted
"""

import base64
import time

import pytest
from textual import work
from textual.app import App
from textual.widgets import Button, Label, ListView

from core.identity.device_identity import generate_keypair
from core.identity.rotation import create_transition_certificate
from core.security.events import (
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
)
from core.trust.revocation import revoke_device
from core.trust.store import TrustStore
from ui import (
    ChatApp,
    SecurityEventsModal,
    TrustDeviceDetailModal,
    _group_security_events,
)

pytestmark = pytest.mark.ui



class ModalHostApp(App):
    """Minimal Textual app to host modals during pilot tests."""

    def __init__(self, trust_store=None, security_event_log=None):
        super().__init__()
        self.trust_store = trust_store
        self._security_event_log = list(security_event_log or [])

    def copy_to_clipboard(self, text: str) -> None:
        pass


def _b64(kp) -> str:
    return base64.b64encode(kp.public_key_bytes()).decode("ascii")


def _setup_app(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    app = ChatApp()
    app.trust_store = store
    app.display_name = "LocalTester"
    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs
    app._security_event_log = []

    @work
    async def fake_setup(self):
        pass

    app._setup = fake_setup.__get__(app, ChatApp)
    return app, store


@pytest.mark.asyncio
async def test_security_events_grouping(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Bob")

    older = SecurityEvent(
        event_type=SecurityEventType.IDENTITY_CHANGED,
        severity=SecuritySeverity.WARNING,
        description="older mismatch",
        device_id=kp.device_id,
        timestamp=1000.0,
    )
    newer = SecurityEvent(
        event_type=SecurityEventType.IDENTITY_CHANGED,
        severity=SecuritySeverity.WARNING,
        description="newer mismatch",
        device_id=kp.device_id,
        timestamp=2000.0,
    )
    # Different type should remain a separate row
    other = SecurityEvent(
        event_type=SecurityEventType.KEY_ROTATION,
        severity=SecuritySeverity.INFO,
        description="rotation",
        device_id=kp.device_id,
        timestamp=1500.0,
    )

    grouped = _group_security_events([older, newer, other])
    assert len(grouped) == 2
    by_type = {e.event_type: e for e in grouped}
    assert by_type["identity_changed"].timestamp == 2000.0
    assert by_type["identity_changed"].description == "newer mismatch"

    app = ModalHostApp(trust_store=store, security_event_log=[older, newer, other])
    async with app.run_test() as pilot:
        modal = SecurityEventsModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#security-events-list", ListView)
        assert len(list_view.children) == 2
        labels = [str(item.query_one(Label).render()) for item in list_view.children]
        assert any("identity_changed" in lbl for lbl in labels)
        assert any("key_rotation" in lbl for lbl in labels)


@pytest.mark.asyncio
async def test_security_events_empty(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    app = ModalHostApp(trust_store=store, security_event_log=[])

    async with app.run_test() as pilot:
        modal = SecurityEventsModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#security-events-list", ListView)
        empty_label = modal.query_one("#security-events-empty", Label)
        assert len(list_view.children) == 0
        assert "No security events" in str(empty_label.render())


@pytest.mark.asyncio
async def test_event_links_to_device(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Bob-Phone")

    evt = SecurityEvent(
        event_type=SecurityEventType.UNKNOWN_DEVICE,
        severity=SecuritySeverity.WARNING,
        description="first seen",
        device_id=kp.device_id,
        timestamp=time.time(),
    )
    app = ModalHostApp(trust_store=store, security_event_log=[evt])

    async with app.run_test() as pilot:
        modal = SecurityEventsModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#security-events-list", ListView)
        assert len(list_view.children) == 1
        item = list_view.children[0]
        modal.on_list_view_selected(ListView.Selected(list_view, item, 0))
        await pilot.pause()

        assert isinstance(app.screen, TrustDeviceDetailModal)
        assert app.screen._device.device_id == kp.device_id


@pytest.mark.asyncio
async def test_mismatch_not_approval(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Eve")

    evt = SecurityEvent(
        event_type=SecurityEventType.IDENTITY_CHANGED,
        severity=SecuritySeverity.WARNING,
        description="key mismatch — rejected",
        device_id=kp.device_id,
        timestamp=time.time(),
    )
    app = ModalHostApp(trust_store=store, security_event_log=[evt])

    async with app.run_test() as pilot:
        modal = SecurityEventsModal()
        await app.push_screen(modal)
        await pilot.pause()

        list_view = modal.query_one("#security-events-list", ListView)
        labels = [str(item.query_one(Label).render()) for item in list_view.children]
        assert any("identity_changed" in lbl for lbl in labels)
        assert any("WARN" in lbl for lbl in labels)

        # Events modal is informational — Close only, no approval actions
        buttons = {b.id for b in modal.query(Button)}
        assert buttons == {"se-close"}
        assert "td-trust" not in buttons
        assert len(modal.query("#tpm-trust")) == 0


@pytest.mark.asyncio
async def test_rotation_history_shown(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp_a = generate_keypair()
    kp_b = generate_keypair()
    store.record_first_seen(kp_a.device_id, _b64(kp_a), name="Alice")
    store.approve(kp_a.device_id)
    store.record_rotation(create_transition_certificate(kp_a, kp_b))

    chain = store.get_rotation_chain(kp_b.device_id)
    assert len(chain) > 1

    app = ModalHostApp(trust_store=store)
    async with app.run_test() as pilot:
        await app.push_screen(TrustDeviceDetailModal(store.get(kp_b.device_id)))
        await pilot.pause()

        chain_label = app.screen.query_one("#td-rotation-chain", Label)
        text = str(chain_label.render())
        assert kp_a.device_id[:8] in text
        assert kp_b.device_id[:8] in text
        assert "→" in text
        assert len(app.screen.query("#td-rotation-taint")) == 0


@pytest.mark.asyncio
async def test_rotation_revoked_ancestor(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp_a = generate_keypair()
    kp_b = generate_keypair()
    store.record_first_seen(kp_a.device_id, _b64(kp_a), name="Alice")
    store.approve(kp_a.device_id)
    store.record_rotation(create_transition_certificate(kp_a, kp_b))
    revoke_device(store, kp_a.device_id, revoked_by="Admin", reason="compromised")

    app = ModalHostApp(trust_store=store)
    async with app.run_test() as pilot:
        await app.push_screen(TrustDeviceDetailModal(store.get(kp_b.device_id)))
        await pilot.pause()

        taint = app.screen.query_one("#td-rotation-taint", Label)
        assert "tainted" in str(taint.render()).lower()
        chain_text = str(app.screen.query_one("#td-rotation-chain", Label).render())
        assert kp_a.device_id[:8] in chain_text


@pytest.mark.asyncio
async def test_rotation_no_history(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Solo")

    assert len(store.get_rotation_chain(kp.device_id)) <= 1

    app = ModalHostApp(trust_store=store)
    async with app.run_test() as pilot:
        await app.push_screen(TrustDeviceDetailModal(store.get(kp.device_id)))
        await pilot.pause()

        assert len(app.screen.query("#td-rotation-chain")) == 0
        assert len(app.screen.query("#td-rotation-label")) == 0
        assert len(app.screen.query("#td-rotation-taint")) == 0


@pytest.mark.asyncio
async def test_buffer_via_emit(tmp_path):
    """Smoke: ChatApp buffer receives emit() via the listener method."""
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Bob")

    app._on_security_event_buffered(
        SecurityEvent(
            event_type=SecurityEventType.AUTH_FAILED,
            severity=SecuritySeverity.WARNING,
            description="bad handshake",
            device_id=kp.device_id,
        )
    )
    assert len(app._security_event_log) == 1
    assert app._security_event_log[0].event_type == "auth_failed"
