"""core/task_registry.py — Phase 32.1: Task ownership (pulled forward).

RELIABILITY_DESIGN.md's Implementation Sequence places "task registries
for connection, transfer, and app-owned work" at 32.1, after baselines
(31.1). It was pulled forward into the 29/30.1 sub-step at Baim's explicit
direction, to close a real gap found while writing the "task cleanup
after vault lock and app shutdown" reliability case: `_perform_hard_lock()`
did not cancel in-flight transfer tasks, which could then touch a
just-detached (None) store.

This is a bounded, per-owner registry — NOT the "global unbounded task
supervisor" that RELIABILITY_DESIGN.md §9 explicitly puts out of scope.
Each `ChatApp` owns exactly one `TaskRegistry` instance, passed down to
the `ConnectionManager`, `ChatSession`, and `FileTransferSession` it
constructs; there is no process-wide singleton, and nothing here changes
handshake, transport, or trust semantics.
"""

import asyncio
import logging
from typing import Coroutine, Dict, List, Optional, Set

logger = logging.getLogger("peerc.tasks")

# Phase 33.1 (closing the deferred Phase 32.1 gap): "Cleanup uses
# cancellation followed by a bounded wait, and logs a sanitized warning
# if a task misses the deadline." Five seconds is generous for a task
# that's genuinely just unwinding (closing files, flushing a socket) —
# a task that needs longer than this to react to cancellation is the
# scenario this bound exists to surface, not silently wait out forever.
DEFAULT_CANCEL_TIMEOUT = 5.0


class TaskRegistry:
    """Tracks background tasks by named group so a caller can cancel and
    await a whole group in bulk (vault lock, app shutdown) instead of
    leaking them as untracked fire-and-forget `asyncio.create_task()`
    calls with no way to know if they're still running."""

    def __init__(self) -> None:
        self._tasks: Dict[str, Set[asyncio.Task]] = {}

    def create_task(
        self, coro: Coroutine, *, group: str, name: Optional[str] = None
    ) -> asyncio.Task:
        task = asyncio.create_task(coro, name=name)
        self._tasks.setdefault(group, set()).add(task)

        def _on_done(t: asyncio.Task, _group: str = group) -> None:
            self._tasks.get(_group, set()).discard(t)
            if not t.cancelled() and t.exception() is not None:
                logger.warning(
                    "task %r in group %r ended with an exception: %r",
                    t.get_name(), _group, t.exception(),
                )

        task.add_done_callback(_on_done)
        return task

    def active_count(self, group: Optional[str] = None) -> int:
        """Number of currently-tracked (not-yet-done) tasks, optionally
        scoped to one group."""
        if group is not None:
            return len(self._tasks.get(group, ()))
        return sum(len(tasks) for tasks in self._tasks.values())

    def groups(self) -> List[str]:
        """Names of groups with at least one currently-tracked task."""
        return [g for g, tasks in self._tasks.items() if tasks]

    async def cancel_group(self, group: str, timeout: float = DEFAULT_CANCEL_TIMEOUT) -> None:
        """Cancel every task in `group` and wait, up to `timeout` seconds,
        for them to actually finish unwinding before returning — a caller
        relying on this can assume no task from that group touches shared
        state afterward.

        A task that is still running once the deadline passes gets a
        sanitized warning logged (group, count, and the task's own name
        — never its exception content or any application data) rather
        than an unbounded wait; it's dropped from tracking either way, so
        a stuck task can't leave this group permanently "active"."""
        tasks = list(self._tasks.get(group, ()))
        if not tasks:
            return
        for t in tasks:
            t.cancel()
        _done, pending = await asyncio.wait(tasks, timeout=timeout)
        if pending:
            logger.warning(
                "task cleanup in group %r missed its %.1fs deadline: "
                "%d task(s) still running (%s)",
                group, timeout, len(pending),
                ", ".join(t.get_name() for t in pending),
            )
        self._tasks.pop(group, None)

    async def cancel_all(self, timeout: float = DEFAULT_CANCEL_TIMEOUT) -> None:
        """Bounded shutdown: cancel and await every group, each against
        its own `timeout` (not a shared budget across all groups)."""
        for group in list(self._tasks.keys()):
            await self.cancel_group(group, timeout=timeout)
