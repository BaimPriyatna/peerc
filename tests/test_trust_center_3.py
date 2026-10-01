"""tests/test_trust_center_3.py — Phase 37.1: Event-driven pending prompt.

Tests covering:
- test_prompt_shows_on_trust_required: event -> modal opens with metadata and controls
- test_later_leaves_pending: click Later -> device remains PENDING
- test_trust_from_prompt: click Trust -> device becomes TRUSTED, modal dismisses
- test_reject_from_prompt: click Reject -> device becomes REVOKED, modal dismisses
- test_dedup_same_peer: two events for same (peer_id, pubkey) -> only one prompt
- test_queue_multiple_peers: two distinct peers -> second prompt shown after first is dismissed
- test_vault_lock_dismisses_prompt: vault lock -> prompt dismissed, queue cleared
- test_non_blocking_with_file_offer: file offer active -> trust prompt queued, does not interrupt
"""

import base64
from unittest.mock import MagicMock
import pytest
from textual import work
from textual.widgets import Button, Label

from core.events import EventBus, TrustRequired
from core.identity.device_identity import generate_keypair
from core.identity.fingerprint import format_fingerprint, short_fingerprint
from core.trust.device import TrustStatus
from core.trust.store import TrustStore
from app.ui.app import ChatApp
from app.ui.modals.transfer import FileOfferModal
from app.ui.modals.identity import TrustPromptModal

pytestmark = pytest.mark.ui



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
    app.event_bus = EventBus()
    app.event_bus.subscribe(TrustRequired, app._on_trust_required)

    # Minimal setup to avoid opening real network sockets during tests
    @work
    async def fake_setup(self):
        pass

    app._setup = fake_setup.__get__(app, ChatApp)
    return app, store


@pytest.mark.asyncio
async def test_prompt_shows_on_trust_required(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="Bob-Phone")

    async with app.run_test() as pilot:
        evt = TrustRequired(
            peer_id=kp.device_id,
            peer_name="Bob-Phone",
            public_key=pubkey,
            addr_key="192.168.1.100:7777",
        )
        await app.event_bus.publish(evt)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        modal = app.screen
        assert "Bob-Phone" in str(modal.query_one("#tpm-name", Label).render())
        assert kp.device_id[:8] in str(modal.query_one("#tpm-id", Label).render())
        assert short_fingerprint(kp.device_id) in str(modal.query_one("#tpm-short-fp", Label).render())
        assert "192.168.1.100:7777" in str(modal.query_one("#tpm-route", Label).render())
        assert "untrusted reachability info, not for identity verification" in str(
            modal.query_one("#tpm-route", Label).render()
        )
        assert modal.query_one("#tpm-trust", Button) is not None
        assert modal.query_one("#tpm-reject", Button) is not None
        assert modal.query_one("#tpm-later", Button) is not None
        assert any("Bob-Phone" in msg and "not yet trusted" in msg for msg in app.logs)

        # Test full fingerprint reveal button
        await pilot.click("#tpm-reveal-fp")
        await pilot.pause()
        fp_label = modal.query_one("#tpm-full-fp", Label)
        assert fp_label.styles.display == "block"

        # Test copy fingerprint button
        app.copy_to_clipboard = MagicMock()
        await pilot.click("#tpm-copy-fp")
        await pilot.pause()
        app.copy_to_clipboard.assert_called_once_with(format_fingerprint(kp.device_id))


@pytest.mark.asyncio
async def test_later_leaves_pending(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="Bob-Phone")

    async with app.run_test() as pilot:
        evt = TrustRequired(peer_id=kp.device_id, peer_name="Bob-Phone", public_key=pubkey)
        await app.event_bus.publish(evt)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        await pilot.click("#tpm-later")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert store.get(kp.device_id).status == TrustStatus.PENDING
        assert app._trust_prompt_open is False


@pytest.mark.asyncio
async def test_trust_from_prompt(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="Charlie-Phone")

    async with app.run_test() as pilot:
        evt = TrustRequired(peer_id=kp.device_id, peer_name="Charlie-Phone", public_key=pubkey)
        await app.event_bus.publish(evt)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        await pilot.click("#tpm-trust")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert store.get(kp.device_id).status == TrustStatus.TRUSTED
        assert app._trust_prompt_open is False


@pytest.mark.asyncio
async def test_reject_from_prompt(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="Dave-Stranger")

    async with app.run_test() as pilot:
        evt = TrustRequired(peer_id=kp.device_id, peer_name="Dave-Stranger", public_key=pubkey)
        await app.event_bus.publish(evt)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        await pilot.click("#tpm-reject")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert store.get(kp.device_id).status == TrustStatus.REVOKED
        assert app._trust_prompt_open is False


@pytest.mark.asyncio
async def test_dedup_same_peer(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="Eve-Device")

    async with app.run_test() as pilot:
        evt1 = TrustRequired(peer_id=kp.device_id, peer_name="Eve-Device", public_key=pubkey)
        evt2 = TrustRequired(peer_id=kp.device_id, peer_name="Eve-Device", public_key=pubkey)
        await app.event_bus.publish(evt1)
        await app.event_bus.publish(evt2)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        assert len(app._trust_prompt_queue) == 0

        # Dismiss prompt
        await pilot.click("#tpm-later")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert len(app._trust_prompt_queue) == 0


@pytest.mark.asyncio
async def test_queue_multiple_peers(tmp_path):
    app, store = _setup_app(tmp_path)
    kp1 = generate_keypair()
    pubkey1 = _b64(kp1)
    store.record_first_seen(kp1.device_id, pubkey1, name="Peer-1")

    kp2 = generate_keypair()
    pubkey2 = _b64(kp2)
    store.record_first_seen(kp2.device_id, pubkey2, name="Peer-2")

    async with app.run_test() as pilot:
        evt1 = TrustRequired(peer_id=kp1.device_id, peer_name="Peer-1", public_key=pubkey1)
        evt2 = TrustRequired(peer_id=kp2.device_id, peer_name="Peer-2", public_key=pubkey2)
        await app.event_bus.publish(evt1)
        await app.event_bus.publish(evt2)
        await pilot.pause()

        # First prompt is Peer-1
        assert isinstance(app.screen, TrustPromptModal)
        modal1 = app.screen
        assert "Peer-1" in str(modal1.query_one("#tpm-name", Label).render())
        assert len(app._trust_prompt_queue) == 1

        # Dismiss first prompt -> second prompt appears
        await pilot.click("#tpm-later")
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        modal2 = app.screen
        assert "Peer-2" in str(modal2.query_one("#tpm-name", Label).render())
        assert len(app._trust_prompt_queue) == 0

        # Dismiss second prompt
        await pilot.click("#tpm-later")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert len(app._trust_prompt_queue) == 0


@pytest.mark.asyncio
async def test_vault_lock_dismisses_prompt(tmp_path):
    app, store = _setup_app(tmp_path)
    kp1 = generate_keypair()
    pubkey1 = _b64(kp1)
    store.record_first_seen(kp1.device_id, pubkey1, name="Peer-1")

    kp2 = generate_keypair()
    pubkey2 = _b64(kp2)
    store.record_first_seen(kp2.device_id, pubkey2, name="Peer-2")

    async with app.run_test() as pilot:
        evt1 = TrustRequired(peer_id=kp1.device_id, peer_name="Peer-1", public_key=pubkey1)
        evt2 = TrustRequired(peer_id=kp2.device_id, peer_name="Peer-2", public_key=pubkey2)
        await app.event_bus.publish(evt1)
        await app.event_bus.publish(evt2)
        await pilot.pause()

        assert isinstance(app.screen, TrustPromptModal)
        assert len(app._trust_prompt_queue) == 1

        # Lock the vault
        await app._do_vault_lock()
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert len(app._trust_prompt_queue) == 0
        assert app._trust_prompt_open is False


@pytest.mark.asyncio
async def test_non_blocking_with_file_offer(tmp_path):
    app, store = _setup_app(tmp_path)
    kp = generate_keypair()
    pubkey = _b64(kp)
    store.record_first_seen(kp.device_id, pubkey, name="FileOfferPeer")

    async with app.run_test() as pilot:
        # File offer modal is currently open
        await app.push_screen(FileOfferModal("SenderAlice", "important.zip", 10240))
        await pilot.pause()

        assert isinstance(app.screen, FileOfferModal)

        # TrustRequired event arrives while file offer is active
        evt = TrustRequired(peer_id=kp.device_id, peer_name="FileOfferPeer", public_key=pubkey)
        await app.event_bus.publish(evt)
        await pilot.pause()

        # Top screen must still be FileOfferModal (not interrupted)
        assert isinstance(app.screen, FileOfferModal)
        assert app._trust_prompt_open is False
        assert len(app._trust_prompt_queue) == 1

        # Accept file offer (dismisses FileOfferModal)
        await pilot.click("#accept")
        await pilot.pause()

        # Now TrustPromptModal is opened from the queue
        assert isinstance(app.screen, TrustPromptModal)
        assert app._trust_prompt_open is True
        assert len(app._trust_prompt_queue) == 0

        # Dismiss trust prompt
        await pilot.click("#tpm-later")
        await pilot.pause()

        assert not isinstance(app.screen, TrustPromptModal)
        assert app._trust_prompt_open is False
