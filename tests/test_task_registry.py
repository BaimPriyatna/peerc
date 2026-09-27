"""tests/test_task_registry.py — Phase 32.1: TaskRegistry unit tests.

Covers the primitive itself in isolation (no ConnectionManager/ChatApp
involved): task tracking by group, cancel_group()/cancel_all() actually
awaiting completion rather than just calling .cancel(), active_count()
bookkeeping as tasks finish on their own, and that an exception in a
tracked task is logged rather than silently swallowed or raised back into
the registry's caller.
"""

import asyncio
import logging

import pytest

from core.task_registry import TaskRegistry

pytestmark = pytest.mark.unit


async def _sleep_forever() -> None:
    await asyncio.sleep(3600)


async def _quick_done(value: int = 1) -> int:
    await asyncio.sleep(0)
    return value


async def _ignores_cancellation_once() -> None:
    """Simulates a task that doesn't react to the *first* cancellation
    within the bound — e.g. one slow retry in a try/except that swallows
    CancelledError — but does stop on a second one, so the test can
    still clean it up afterward instead of leaking an immortal task."""
    try:
        await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass  # swallow the first one — deliberately misbehaving
    await asyncio.sleep(3600)  # second cancel() will land here normally


async def _boom() -> None:
    await asyncio.sleep(0)
    raise ValueError("boom")


@pytest.mark.asyncio
async def test_create_task_tracks_by_group():
    reg = TaskRegistry()
    reg.create_task(_sleep_forever(), group="transfer", name="t1")
    reg.create_task(_sleep_forever(), group="transfer", name="t2")
    reg.create_task(_sleep_forever(), group="connection", name="c1")

    assert reg.active_count("transfer") == 2
    assert reg.active_count("connection") == 1
    assert reg.active_count() == 3
    assert set(reg.groups()) == {"transfer", "connection"}

    await reg.cancel_all()


@pytest.mark.asyncio
async def test_finished_task_is_removed_automatically():
    reg = TaskRegistry()
    reg.create_task(_quick_done(), group="app", name="quick")
    await asyncio.sleep(0.05)  # let the done-callback run

    assert reg.active_count("app") == 0
    assert reg.groups() == []


@pytest.mark.asyncio
async def test_cancel_group_cancels_and_awaits_only_that_group():
    reg = TaskRegistry()
    t_transfer = reg.create_task(_sleep_forever(), group="transfer", name="t")
    t_connection = reg.create_task(_sleep_forever(), group="connection", name="c")

    await reg.cancel_group("transfer")

    assert t_transfer.cancelled()
    assert reg.active_count("transfer") == 0
    # The other group is untouched.
    assert reg.active_count("connection") == 1
    assert not t_connection.done()

    await reg.cancel_all()


@pytest.mark.asyncio
async def test_cancel_group_on_empty_group_is_a_noop():
    reg = TaskRegistry()
    await reg.cancel_group("nonexistent")  # must not raise


@pytest.mark.asyncio
async def test_cancel_all_cancels_and_awaits_every_group():
    reg = TaskRegistry()
    tasks = [
        reg.create_task(_sleep_forever(), group="transfer", name="t"),
        reg.create_task(_sleep_forever(), group="connection", name="c"),
        reg.create_task(_sleep_forever(), group="app", name="a"),
    ]

    await reg.cancel_all()

    assert all(t.cancelled() for t in tasks)
    assert reg.active_count() == 0
    assert reg.groups() == []


@pytest.mark.asyncio
async def test_task_exception_is_logged_not_raised(caplog):
    reg = TaskRegistry()
    with caplog.at_level(logging.WARNING, logger="peerc.tasks"):
        reg.create_task(_boom(), group="app", name="boom")
        await asyncio.sleep(0.05)  # let it run and the done-callback fire

    assert reg.active_count("app") == 0  # removed even though it raised
    assert any("boom" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_cancel_all_is_safe_with_no_tasks():
    reg = TaskRegistry()
    await reg.cancel_all()  # must not raise
    assert reg.active_count() == 0


@pytest.mark.asyncio
async def test_cancel_group_bounded_wait_logs_on_deadline_miss(caplog):
    """Phase 33.1: closes the deferred Phase 32.1 gap — a task that
    doesn't finish unwinding within the deadline gets a sanitized warning
    logged, and is dropped from tracking anyway rather than leaving
    cancel_group() waiting forever."""
    reg = TaskRegistry()
    task = reg.create_task(_ignores_cancellation_once(), group="transfer", name="stuck-task")
    # Let it actually start running (reach its try/except) before
    # cancelling — cancel()ing a task before its first step means the
    # CancelledError is thrown before the coroutine body (and its
    # except-and-swallow) ever runs, so it cancels cleanly instead of
    # exercising the "ignores cancellation" behavior this test needs.
    await asyncio.sleep(0)

    with caplog.at_level(logging.WARNING, logger="peerc.tasks"):
        await reg.cancel_group("transfer", timeout=0.1)

    assert reg.active_count("transfer") == 0  # dropped from tracking regardless
    assert any("missed its" in r.getMessage() and "stuck-task" in r.getMessage() for r in caplog.records)

    # Clean up the real, still-running task so it doesn't leak into
    # other tests / warn on interpreter shutdown.
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1.0)


@pytest.mark.asyncio
async def test_cancel_group_within_deadline_logs_nothing(caplog):
    reg = TaskRegistry()
    reg.create_task(_sleep_forever(), group="app", name="well-behaved")

    with caplog.at_level(logging.WARNING, logger="peerc.tasks"):
        await reg.cancel_group("app", timeout=1.0)  # well-behaved task cancels almost instantly

    assert not any("missed its" in r.getMessage() for r in caplog.records)
