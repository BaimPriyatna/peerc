"""core/benchmarking.py — Phase 31.1: Performance measurement helpers.

Deterministic, local/loopback-only instrumentation used by
tests/test_benchmarks.py to record baseline numbers per
RELIABILITY_DESIGN.md §4 (transfer throughput, peak memory, event-loop
lag, handshake latency, shutdown time).

Non-gating by design: these helpers measure and record a number, they do
not assert a pass/fail threshold. There is nothing to regress against
until a baseline exists — that comparison is Phase 31/32.2's regression
gate, once this sub-step has produced docs/benchmarks/baseline.json.
"""

import asyncio
import json
import resource
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_BASELINE_PATH = Path("docs/benchmarks/baseline.json")


def peak_rss_mb() -> float:
    """Process peak resident set size observed so far, in MB.

    ru_maxrss is kilobytes on Linux but bytes on macOS — normalize by
    platform rather than assuming Linux (CI matrix isn't macOS today,
    but a contributor's laptop might be)."""
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return raw / (1024 * 1024)
    return raw / 1024


class EventLoopLagSampler:
    """Samples event-loop scheduling delay at a fixed interval while a
    concurrent workload (e.g. a file transfer) runs, tracking the worst
    (max) lag observed — how late a simple asyncio.sleep(interval) woke
    up relative to when it should have, which is what "is the UI still
    responsive while a transfer is running" actually measures."""

    def __init__(self, interval: float = 0.01) -> None:
        self.interval = interval
        self.max_lag = 0.0
        self._task: Optional[asyncio.Task] = None

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        next_tick = loop.time() + self.interval
        while True:
            await asyncio.sleep(self.interval)
            now = loop.time()
            lag = now - next_tick
            if lag > self.max_lag:
                self.max_lag = lag
            next_tick = now + self.interval

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> float:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        return self.max_lag


def load_baseline(path: Path = DEFAULT_BASELINE_PATH) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def record_metric(name: str, value: Any, path: Path = DEFAULT_BASELINE_PATH, **extra) -> None:
    """Merge one metric's result into the baseline JSON file.

    Reads-modifies-writes rather than overwriting the whole file, so
    running a subset of benchmark tests (or running them out of order)
    never clobbers other metrics already on record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = load_baseline(path)
    data[name] = {"value": value, "recorded_at": time.time(), **extra}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
