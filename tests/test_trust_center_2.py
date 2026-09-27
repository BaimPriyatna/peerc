"""tests/test_trust_center_2.py — Phase 36.2: Trust decision controls.

Tests covering:
- Approve pending device (PENDING -> TRUSTED)
- Attempting to approve a revoked device is refused (stays REVOKED)
- Revoking a trusted device with reason (TRUSTED -> REVOKED)
- Rejecting a pending device without reason (PENDING -> REVOKED)
- Group policy denial surfaces policy error and prevents approval
- /revoke command parsing, device lookup, and execution
- Idempotence / error handling on duplicate or conflicting actions
- Modal buttons presence based on status (Pending vs Trusted vs Revoked)
"""

import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from textual.app import App
from textual.widgets import Button

from core.group.policy import ExternalTrustDeniedError
from core.identity.device_identity import generate_keypair
from core.trust.device import TrustedDevice, TrustStatus
from core.trust.revocation import revoke_device
from core.trust.store import TrustStore
from ui import ChatApp, TrustConfirmModal, TrustDeviceDetailModal

pytestmark = pytest.mark.ui



class ModalHostApp(App):
    """Minimal Textual app to host modals during pilot tests."""

    def __init__(self, trust_store=None):
        super().__init__()
        self.trust_store = trust_store
        self.copied_text = None

    def copy_to_clipboard(self, text: str) -> None:
        self.copied_text = text


def _b64(kp) -> str:
    return base64.b64encode(kp.public_key_bytes()).decode("ascii")


def _setup_app_with_store(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    app = ChatApp()
    app.trust_store = store
    app.display_name = "Alice-Local"
    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs
    return app, store


@pytest.mark.asyncio
async def test_approve_pending(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Bob-Phone")

    assert store.get(kp.device_id).status == TrustStatus.PENDING

    await app._do_trust_approve(kp.device_id)

    updated = store.get(kp.device_id)
    assert updated.status == TrustStatus.TRUSTED
    assert any("approved and marked TRUSTED" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_approve_revoked_refused(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Charlie-PC")
    revoke_device(store, kp.device_id, revoked_by="Admin", reason="Compromised")

    assert store.get(kp.device_id).status == TrustStatus.REVOKED

    await app._do_trust_approve(kp.device_id)

    # Status must NOT change to TRUSTED
    assert store.get(kp.device_id).status == TrustStatus.REVOKED
    assert any("Could not approve" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_revoke_trusted(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Dave-Tablet")
    store.approve(kp.device_id)

    assert store.get(kp.device_id).status == TrustStatus.TRUSTED

    await app._do_trust_revoke(kp.device_id, reason="Lost during travel")

    updated = store.get(kp.device_id)
    assert updated.status == TrustStatus.REVOKED
    assert updated.revoke_reason == "Lost during travel"
    assert updated.revoked_by == "Alice-Local"
    assert any("locally REVOKED" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_reject_pending(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Eve-Stranger")

    assert store.get(kp.device_id).status == TrustStatus.PENDING

    await app._do_trust_revoke(kp.device_id, reason=None)

    updated = store.get(kp.device_id)
    assert updated.status == TrustStatus.REVOKED
    assert updated.revoke_reason is None
    assert any("locally REVOKED" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_policy_denial(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Frank-External")

    # Mock policy enforcer raising ExternalTrustDeniedError
    mock_enforcer = MagicMock()
    mock_enforcer.check_external_trust.side_effect = ExternalTrustDeniedError("External trust forbidden by group policy")
    app.policy_enforcer = mock_enforcer

    await app._do_trust_approve(kp.device_id)

    # Must stay pending and log explanation
    assert store.get(kp.device_id).status == TrustStatus.PENDING
    assert any("Trust denied by group policy" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_revoke_command(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Grace-Laptop")
    store.approve(kp.device_id)

    # User confirms with modal returning reason
    app.push_screen_wait = AsyncMock(return_value="hardware stolen")

    # Execute /revoke with prefix
    prefix = kp.device_id[:8]
    await app._handle_command(f"/revoke {prefix} stolen key")

    updated = store.get(kp.device_id)
    assert updated.status == TrustStatus.REVOKED
    assert updated.revoke_reason == "hardware stolen"

    # Test cancellation
    app.logs.clear()
    kp2 = generate_keypair()
    store.record_first_seen(kp2.device_id, _b64(kp2), name="Heidi-Phone")
    store.approve(kp2.device_id)

    app.push_screen_wait = AsyncMock(return_value=None)
    await app._handle_command(f"/revoke {kp2.device_id[:8]}")

    assert store.get(kp2.device_id).status == TrustStatus.TRUSTED
    assert any("Revocation cancelled" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_duplicate_action_idempotent(tmp_path):
    app, store = _setup_app_with_store(tmp_path)
    kp = generate_keypair()
    store.record_first_seen(kp.device_id, _b64(kp), name="Ivan-Device")
    store.approve(kp.device_id)

    # Revoke once
    await app._do_trust_revoke(kp.device_id, reason="Reason 1")
    assert store.get(kp.device_id).status == TrustStatus.REVOKED

    # Revoke again (already revoked) -> must handle without crash
    app.logs.clear()
    await app._do_trust_revoke(kp.device_id, reason="Reason 2")
    assert any("Could not revoke" in msg for msg in app.logs)


@pytest.mark.asyncio
async def test_detail_modal_buttons_by_status(tmp_path):
    kp = generate_keypair()
    now = time.time()

    # 1. PENDING device -> Trust and Reject buttons
    dev_pending = TrustedDevice(
        device_id=kp.device_id,
        public_key=_b64(kp),
        name="Pending-Dev",
        first_seen=now,
        last_seen=now,
        status=TrustStatus.PENDING,
    )
    host_app = ModalHostApp()
    async with host_app.run_test() as pilot:
        modal = TrustDeviceDetailModal(dev_pending)
        await host_app.push_screen(modal)
        await pilot.pause()

        assert modal.query_one("#td-trust", Button) is not None
        assert modal.query_one("#td-reject", Button) is not None
        assert len(modal.query("#td-revoke")) == 0

    # 2. TRUSTED device -> Revoke button
    dev_trusted = TrustedDevice(
        device_id=kp.device_id,
        public_key=_b64(kp),
        name="Trusted-Dev",
        first_seen=now,
        last_seen=now,
        status=TrustStatus.TRUSTED,
    )
    host_app = ModalHostApp()
    async with host_app.run_test() as pilot:
        modal = TrustDeviceDetailModal(dev_trusted)
        await host_app.push_screen(modal)
        await pilot.pause()

        assert modal.query_one("#td-revoke", Button) is not None
        assert len(modal.query("#td-trust")) == 0
        assert len(modal.query("#td-reject")) == 0

    # 3. REVOKED device -> view only (Close button only)
    dev_revoked = TrustedDevice(
        device_id=kp.device_id,
        public_key=_b64(kp),
        name="Revoked-Dev",
        first_seen=now,
        last_seen=now,
        status=TrustStatus.REVOKED,
    )
    host_app = ModalHostApp()
    async with host_app.run_test() as pilot:
        modal = TrustDeviceDetailModal(dev_revoked)
        await host_app.push_screen(modal)
        await pilot.pause()

        assert modal.query_one("#td-close", Button) is not None
        assert len(modal.query("#td-trust")) == 0
        assert len(modal.query("#td-reject")) == 0
        assert len(modal.query("#td-revoke")) == 0
