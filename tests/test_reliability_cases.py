"""tests/test_reliability_cases.py — Phase 29/30.1: Required reliability cases.

RELIABILITY_DESIGN.md §3 lists 7 required new reliability cases for this
sub-step. Two are deferred to later phases they depend on (noted at the
end of this file rather than tested with a weak stand-in, per Baim's
direction):

  - "no event-loop stall above a chosen budget" — no budget exists yet
    (Phase 31.1 Baselines).
  - "an invalid state transition never sends an application frame" — no
    formal state machine guard exists yet (Phase 33.1/34.1); transfer and
    connection status are still free-form strings.

A third — "error responses contain no peer-internal exception text" — is
also deferred: there is no wire-level error-response mechanism to test
yet (Phase 35, Application Error Protocol, not built). Existing
rejections (file_reject) are deliberate protocol messages, not exception
dumps, so there's nothing exception-shaped to assert against today.

The remaining 4 are covered here, against the real live code paths
(peer.ConnectionManager, chat.ChatSession, file_transfer.FileTransferSession,
ui.ChatApp), not a parallel/mock implementation:

  1. Cancellation at await points (connect_to, _send_chunks)
  2. Duplicate / late chat_ack
  3. Peer disconnect mid-transfer
  4. Task cleanup after vault lock and app shutdown (the concrete gap
     that pulled core/task_registry.py's TaskRegistry forward from
     Phase 32.1)
"""

import asyncio
import os
import tempfile

import pytest

from core.messaging.session import ChatSession, SentMessageState
from core.transfer.session import FileTransferSession
from core.identity.device_identity import generate_keypair
from core.task_registry import TaskRegistry
from core.transport.manager import ConnectionManager
from app.ui.app import ChatApp

pytestmark = pytest.mark.integration


def _free_port_pair():
    # Fixed-but-widely-spaced ports, consistent with the existing
    # test_stage*.py / test_event_bus.py style in this suite.
    import random
    base = random.randint(20000, 40000)
    return base, base + 1


# ---------------------------------------------------------------------
# 1. Cancellation at await points
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cancelling_connect_to_leaves_no_zombie_connection():
    """Cancelling the connect_to() task itself (e.g. the app shutting
    down mid-handshake) must not leave a half-registered session behind."""
    port_a, port_b = _free_port_pair()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    try:
        task = asyncio.ensure_future(manager_a.connect_to("127.0.0.1", port_b))
        # Cancel immediately — before the handshake has any chance to finish.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # No connection should have been left half-registered on either side.
        await asyncio.sleep(0.1)
        assert len(manager_a._connections) == 0
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_cancelling_send_chunks_task_stops_cleanly_and_cleans_up():
    """Cancelling an in-flight _send_chunks task (the task registry's
    "transfer" group — this is what vault-lock now does) must not raise
    into the caller, and must still remove the transfer from _outgoing."""
    port_a, port_b = _free_port_pair()
    registry_a = TaskRegistry()
    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A", task_registry=registry_a,
    )
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_dir_a = tempfile.mkdtemp(prefix="peerc_rel_a_")
    tmp_dir_b = tempfile.mkdtemp(prefix="peerc_rel_b_")
    ft_a = FileTransferSession(manager_a, downloads_dir=tmp_dir_a)
    ft_b = FileTransferSession(manager_b, downloads_dir=tmp_dir_b)

    src_path = os.path.join(tmp_dir_a, "payload.bin")
    with open(src_path, "wb") as f:
        f.write(os.urandom(500_000))  # a handful of 64 KB chunks

    # Slow each chunk down deterministically so the "transfer" task is
    # reliably still mid-flight when we check/cancel it below, regardless
    # of how fast loopback I/O happens to be on this machine.
    real_send_binary = manager_a.send_binary

    async def slow_send_binary(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await real_send_binary(*args, **kwargs)

    manager_a.send_binary = slow_send_binary

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        transfer_id = await ft_a.offer_file(addr_key, src_path)
        await asyncio.sleep(0.1)

        # ft_b auto-accepts (default on_offer_received behavior) — no
        # need to send a manual file_accept, and doing so as well would
        # double up the _send_chunks task this test is trying to isolate.
        await asyncio.sleep(0.08)  # let the auto-accept round-trip, one slow chunk in

        assert ft_a._task_registry.active_count("transfer") == 1

        # Simulate a hard lock mid-transfer.
        await ft_a._task_registry.cancel_group("transfer")

        assert ft_a._task_registry.active_count("transfer") == 0
        # The cancelled transfer's finally-block cleanup still ran.
        assert transfer_id not in ft_a._outgoing
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# 2. Duplicate / late chat_ack
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_duplicate_ack_is_a_noop():
    """A second chat_ack for a message_id already marked delivered must
    not raise, and must not fire a second status-change notification."""
    manager = ConnectionManager(listen_port=0, my_identity=generate_keypair(), my_name="A")
    statuses = []
    session = ChatSession(manager, on_status_change=lambda mid, s: statuses.append((mid, s)))

    session._pending["msg-1"] = SentMessageState(message_id="msg-1", addr_key="peer-x")

    session._handle_ack({"message_id": "msg-1"})
    session._handle_ack({"message_id": "msg-1"})  # duplicate — must be a no-op

    assert statuses == [("msg-1", "delivered")]  # only fired once
    assert "msg-1" not in session._pending


@pytest.mark.asyncio
async def test_late_ack_after_timeout_is_a_noop():
    """An ack that arrives after the timeout watcher already marked the
    message failed must not raise and must not resurrect the message."""
    manager = ConnectionManager(listen_port=0, my_identity=generate_keypair(), my_name="A")
    statuses = []
    session = ChatSession(manager, on_status_change=lambda mid, s: statuses.append((mid, s)))

    session._pending["msg-2"] = SentMessageState(message_id="msg-2", addr_key="peer-x")
    # Simulate the timeout watcher having already fired.
    session._pending.pop("msg-2", None)
    session._notify_status("msg-2", "failed", "peer-x")

    # The (late) ack now arrives.
    session._handle_ack({"message_id": "msg-2"})

    assert statuses == [("msg-2", "failed")]  # unchanged — no second entry


# ---------------------------------------------------------------------
# 3. Peer disconnect mid-transfer
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_disconnect_during_sending_does_not_hang_or_raise():
    """If the receiving peer vanishes mid-transfer, the sender's
    _send_chunks task must resolve (not hang forever) and must not raise
    an unhandled exception out of the task."""
    port_a, port_b = _free_port_pair()
    registry_a = TaskRegistry()
    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A", task_registry=registry_a,
    )
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_dir_a = tempfile.mkdtemp(prefix="peerc_rel_disc_a_")
    tmp_dir_b = tempfile.mkdtemp(prefix="peerc_rel_disc_b_")
    ft_a = FileTransferSession(manager_a, downloads_dir=tmp_dir_a)
    ft_b = FileTransferSession(manager_b, downloads_dir=tmp_dir_b)

    completions = []
    ft_a.on_complete = lambda tid, success, path: completions.append((tid, success))

    src_path = os.path.join(tmp_dir_a, "payload.bin")
    with open(src_path, "wb") as f:
        f.write(os.urandom(500_000))

    # Slow each chunk down deterministically so there's a real window in
    # which to disconnect B mid-transfer, rather than racing loopback I/O.
    real_send_binary = manager_a.send_binary

    async def slow_send_binary(*args, **kwargs):
        await asyncio.sleep(0.05)
        return await real_send_binary(*args, **kwargs)

    manager_a.send_binary = slow_send_binary

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        transfer_id = await ft_a.offer_file(addr_key, src_path)
        await asyncio.sleep(0.1)

        # ft_b auto-accepts — see the note in the cancellation test above.
        await asyncio.sleep(0.08)  # let sending start (one slow chunk in), then yank the rug

        await manager_b.close_all()  # peer B vanishes mid-transfer

        # The task must finish on its own (send starts failing, or the
        # post-transfer ack simply never arrives and times out) rather
        # than hang forever — give it a generous but bounded window.
        for _ in range(50):
            if ft_a._task_registry.active_count("transfer") == 0:
                break
            await asyncio.sleep(0.2)
        else:
            pytest.fail("_send_chunks task never finished after peer disconnect")

        # The specific outcome (failed vs. succeeded-before-noticing) isn't
        # deterministic over a fast loopback connection — what reliability
        # actually requires is that it resolves at all, exactly once, and
        # the transfer bookkeeping doesn't leak.
        assert transfer_id not in ft_a._outgoing
        assert completions and completions[0][0] == transfer_id
        assert len(completions) == 1
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# 4. Task cleanup after vault lock and app shutdown
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hard_lock_cancels_inflight_transfer_tasks():
    """The concrete gap this sub-step was built to close: a _send_chunks
    task left running against a just-detached (None) store after
    _perform_hard_lock(). It must now be cancelled and awaited first."""
    app = ChatApp()
    async with app.run_test():
        registry = app._task_registry

        async def fake_transfer_task():
            await asyncio.sleep(3600)

        task = registry.create_task(fake_transfer_task(), group="transfer", name="fake")
        assert registry.active_count("transfer") == 1

        await app._perform_hard_lock()

        assert task.cancelled()
        assert registry.active_count("transfer") == 0


@pytest.mark.asyncio
async def test_hard_lock_leaves_connection_tasks_running():
    """Deliberate scoping decision (see _perform_hard_lock's docstring):
    only the "transfer" group is cancelled on lock, not "connection" —
    an active peer connection doesn't itself touch vault-scoped stores."""
    app = ChatApp()
    async with app.run_test():
        registry = app._task_registry

        async def fake_read_loop():
            await asyncio.sleep(3600)

        task = registry.create_task(fake_read_loop(), group="connection", name="fake")

        await app._perform_hard_lock()

        assert not task.cancelled()
        assert registry.active_count("connection") == 1

        await registry.cancel_all()  # tidy up before the app tears down


@pytest.mark.asyncio
async def test_app_shutdown_cancels_every_task_group():
    """Full bounded shutdown: on_unmount() cancels and awaits connection,
    transfer, and app-owned tasks alike — nothing is left running once
    the app exits."""
    app = ChatApp()
    registry = app._task_registry

    async def fake():
        await asyncio.sleep(3600)

    async with app.run_test():
        registry.create_task(fake(), group="transfer", name="t")
        registry.create_task(fake(), group="connection", name="c")
        registry.create_task(fake(), group="app", name="a")
        assert registry.active_count() == 3

    # The run_test() context manager triggers app teardown (on_unmount)
    # on exit.
    assert registry.active_count() == 0
