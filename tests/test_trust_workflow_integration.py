"""tests/test_trust_workflow_integration.py — Phase 37.3: Full workflow verification.

Round-trip integration coverage: a real localhost TCP handshake between two
ConnectionManagers drives the TrustRequired event through the shared EventBus
into the live TrustPromptModal (driven via a Textual pilot); the user's
decision is then verified against the TrustStore and exercised again on a
fresh reconnect.

Covers:
  1. test_first_connect_pending_approve_trusted_reconnect —
     handshake -> PENDING + prompt -> approve via modal -> TRUSTED in store
     -> reconnect with no prompt.
  2. test_first_connect_reject_rejected_reconnect —
     handshake -> prompt -> reject via modal -> REVOKED in store
     -> reconnect handshake fails.
  3. test_policy_denial_in_prompt —
     group policy allow_external_trust=False -> prompt appears for the
     external peer -> Trust click surfaces ExternalTrustDeniedError ->
     device stays PENDING.
"""

import asyncio
import inspect

import pytest
from textual import work

from core.crypto.handshake import HandshakeError
from core.events import EventBus, TrustRequired
from core.group.membership import create_group
from core.group.policy import GroupPolicy, PolicyEnforcer
from core.group.store import GroupStore
from core.identity.device_identity import generate_keypair
from core.security import SecurityEventType, capture_security_events
from core.trust.device import TrustStatus
from core.trust.store import TrustDecision, TrustStore
from peer import ConnectionManager
from ui import ChatApp, TrustPromptModal

pytestmark = pytest.mark.ui



def _pub_hex(kp) -> str:
    return kp.public_key_bytes().hex()


def _setup_app(tmp_path):
    store = TrustStore(db_path=str(tmp_path / "trust.db"))
    app = ChatApp()
    app.trust_store = store
    app.display_name = "LocalHost"
    logs = []
    app._log = lambda text: logs.append(text)
    app.logs = logs
    app.event_bus = EventBus()
    app.event_bus.subscribe(TrustRequired, app._on_trust_required)

    @work
    async def fake_setup(self):
        pass

    app._setup = fake_setup.__get__(app, ChatApp)
    return app, store


async def _start(manager) -> int:
    """Start a ConnectionManager's server on an ephemeral port; return it."""
    await manager.start_server()
    return manager._server.sockets[0].getsockname()[1]


async def _wait_until(pilot, predicate, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        result = predicate()
        if inspect.isawaitable(result):
            result = await result
        if result:
            await pilot.pause()
            return True
        await pilot.pause()
        await asyncio.sleep(0.01)
    final = predicate()
    if inspect.isawaitable(final):
        final = await final
    return bool(final)


async def _wait_prompt_modal(pilot, app) -> None:
    """Wait until TrustPromptModal is on top AND its Trust button has been
    laid out — clicking before layout silently misses the target."""
    async def ready():
        if not isinstance(app.screen, TrustPromptModal):
            return False
        try:
            button = app.screen.query_one("#tpm-trust")
        except Exception:
            return False
        return button.region.width > 0 and button.region.height > 0

    assert await _wait_until(pilot, ready), "TrustPromptModal did not open (or finish layout)"


async def _drop_all_sessions(pilot, *managers) -> None:
    """Close every live session (but keep the servers listening) and wait
    until both managers' connection tables have drained."""
    for mgr in managers:
        for session in list(mgr._connections.values()):
            await session.close()
    assert await _wait_until(
        pilot, lambda: all(not m._connections for m in managers)
    ), "sessions did not drain after close"


@pytest.mark.asyncio
async def test_first_connect_pending_approve_trusted_reconnect(tmp_path):
    app, store = _setup_app(tmp_path)
    local_kp = generate_keypair()
    peer_kp = generate_keypair()

    trust_events: list[TrustRequired] = []
    app.event_bus.subscribe(TrustRequired, trust_events.append)

    local_cm = ConnectionManager(
        listen_port=0, my_identity=local_kp, my_name="LocalHost",
        event_bus=app.event_bus, trust_store=store,
    )
    peer_cm = ConnectionManager(
        listen_port=0, my_identity=peer_kp, my_name="PeerA",
    )
    try:
        async with app.run_test() as pilot:
            local_port = await _start(local_cm)
            await _start(peer_cm)

            # 1. Peer A connects -> handshake records it PENDING, prompt fires.
            await peer_cm.connect_to("127.0.0.1", local_port)

            await _wait_prompt_modal(pilot, app)
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.PENDING
            assert len(trust_events) == 1
            assert trust_events[0].peer_id == peer_kp.device_id
            assert trust_events[0].peer_name == "PeerA"

            # 2. User approves through the live modal.
            await pilot.click("#tpm-trust")

            # 3. TrustStore now reports TRUSTED, modal dismissed.
            assert await _wait_until(
                pilot,
                lambda: store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.TRUSTED,
            ), "device not TRUSTED after approve"
            assert store.get(peer_kp.device_id).status == TrustStatus.TRUSTED
            assert not isinstance(app.screen, TrustPromptModal)
            assert app._trust_prompt_open is False

            # 4. Reconnect: same peer, already trusted -> no new prompt.
            await _drop_all_sessions(pilot, peer_cm, local_cm)
            await peer_cm.connect_to("127.0.0.1", local_port)
            assert await _wait_until(pilot, lambda: bool(local_cm._connections))

            await pilot.pause()
            assert len(trust_events) == 1, "reconnect must not raise a new TrustRequired"
            assert not isinstance(app.screen, TrustPromptModal)
            assert app._trust_prompt_open is False
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.TRUSTED
    finally:
        await local_cm.close_all()
        await peer_cm.close_all()
        store.close()


@pytest.mark.asyncio
async def test_first_connect_reject_rejected_reconnect(tmp_path):
    app, store = _setup_app(tmp_path)
    local_kp = generate_keypair()
    peer_kp = generate_keypair()

    local_cm = ConnectionManager(
        listen_port=0, my_identity=local_kp, my_name="LocalHost",
        event_bus=app.event_bus, trust_store=store,
    )
    peer_cm = ConnectionManager(
        listen_port=0, my_identity=peer_kp, my_name="PeerA",
    )
    try:
        async with app.run_test() as pilot:
            local_port = await _start(local_cm)
            await _start(peer_cm)

            # 1. Peer A connects -> prompt fires for the first-seen device.
            await peer_cm.connect_to("127.0.0.1", local_port)
            await _wait_prompt_modal(pilot, app)
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.PENDING

            # 2. User rejects through the live modal.
            await pilot.click("#tpm-reject")

            assert await _wait_until(
                pilot, lambda: store.get(peer_kp.device_id).status == TrustStatus.REVOKED
            ), "device not REVOKED after reject"
            assert not isinstance(app.screen, TrustPromptModal)
            assert app._trust_prompt_open is False

            # 3. Reconnect: handshake fails closed against the REVOKED entry.
            await _drop_all_sessions(pilot, peer_cm, local_cm)
            with pytest.raises((HandshakeError, ConnectionResetError, BrokenPipeError)):
                await peer_cm.connect_to("127.0.0.1", local_port)

            assert not peer_cm._connections
            assert not local_cm._connections
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.REVOKED
    finally:
        await local_cm.close_all()
        await peer_cm.close_all()
        store.close()


@pytest.mark.asyncio
async def test_policy_denial_in_prompt(tmp_path):
    app, store = _setup_app(tmp_path)
    local_kp = generate_keypair()
    peer_kp = generate_keypair()

    # StrictCorp forbids trusting non-members (§6). The TrustStore itself is
    # deliberately not group-wired, so first-seen recording succeeds and the
    # restriction surfaces at the approve decision in _do_trust_approve.
    group_store = GroupStore(str(tmp_path / "group.db"))
    admin = generate_keypair()
    group = create_group(admin, name="StrictCorp")
    group_store.create_group(group)
    group_store.set_policy(GroupPolicy(group_id=group.group_id, allow_external_trust=False))
    app.group_store = group_store
    app.policy_enforcer = PolicyEnforcer(group_store)

    local_cm = ConnectionManager(
        listen_port=0, my_identity=local_kp, my_name="LocalHost",
        event_bus=app.event_bus, trust_store=store,
    )
    peer_cm = ConnectionManager(
        listen_port=0, my_identity=peer_kp, my_name="PeerB-External",
    )
    try:
        async with app.run_test() as pilot:
            local_port = await _start(local_cm)
            await _start(peer_cm)

            # 1. Peer B (not in StrictCorp) connects -> TrustRequired prompt.
            await peer_cm.connect_to("127.0.0.1", local_port)
            await _wait_prompt_modal(pilot, app)
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.PENDING

            # 2. User attempts Trust -> ExternalTrustDeniedError surfaces.
            with capture_security_events() as sec_events:
                await pilot.click("#tpm-trust")
                assert await _wait_until(
                    pilot,
                    lambda: any("Trust denied by group policy" in msg for msg in app.logs),
                ), "policy denial was not surfaced to the user"

            assert any(
                e.event_type == SecurityEventType.POLICY_VIOLATION
                and e.device_id == peer_kp.device_id
                for e in sec_events
            ), "POLICY_VIOLATION security event not emitted"

            # 3. Device stays PENDING — approval never landed.
            assert store.get(peer_kp.device_id).status == TrustStatus.PENDING
            assert store.check(peer_kp.device_id, _pub_hex(peer_kp)) == TrustDecision.PENDING
            assert not isinstance(app.screen, TrustPromptModal)
            assert app._trust_prompt_open is False
    finally:
        await local_cm.close_all()
        await peer_cm.close_all()
        store.close()
        group_store.close()
