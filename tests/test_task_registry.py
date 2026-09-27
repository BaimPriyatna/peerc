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
