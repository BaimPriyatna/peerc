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
import enum
import json
import resource
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Phase 31.1: the committed, historical reference point.
BASELINE_PATH = Path("docs/benchmarks/baseline.json")
# Kept as an alias — some callers (and 31.1's own tests) still say
# "the baseline path" meaning "where record_metric writes by default".
DEFAULT_BASELINE_PATH = BASELINE_PATH

# Phase 31/32.2: where a fresh benchmark run lands by default going
# forward. Comparing against BASELINE_PATH is the whole point of the
# regression gate — a routine run must not silently overwrite the
# reference it's meant to be compared against. Gitignored; not committed.
CURRENT_RUN_PATH = Path("docs/benchmarks/latest.json")


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


def load_baseline(path: Path = BASELINE_PATH) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def record_metric(name: str, value: Any, path: Path = CURRENT_RUN_PATH, **extra) -> None:
    """Merge one metric's result into a run's JSON file — CURRENT_RUN_PATH
    by default (Phase 31/32.2: a routine benchmark run must not silently
    overwrite BASELINE_PATH, the committed reference the regression gate
    compares against). Pass path=BASELINE_PATH explicitly to deliberately
    re-baseline.

    Reads-modifies-writes rather than overwriting the whole file, so
    running a subset of benchmark tests (or running them out of order)
    never clobbers other metrics already on record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = load_baseline(path)
    data[name] = {"value": value, "recorded_at": time.time(), **extra}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


# ---------------------------------------------------------------------
# Phase 31/32.2: Regression gate
# ---------------------------------------------------------------------
#
# "Compare benchmarks, loop lag, and shutdown behavior against the
# baseline before declaring the program complete" (RELIABILITY_DESIGN.md
# §8, item 9) — explicitly NOT a per-push CI gate (§9's Out of Scope).
# This is pure comparison logic: no I/O, so it's cheap to unit test
# directly; scripts/regression_gate.py is the thing a human actually runs.


class Direction(enum.Enum):
    HIGHER_IS_BETTER = "higher_is_better"  # throughput
    LOWER_IS_BETTER = "lower_is_better"    # memory, lag, latency, shutdown time


# Matched by prefix against the metric name recorded via record_metric().
_METRIC_DIRECTIONS = (
    ("transfer_throughput_", Direction.HIGHER_IS_BETTER),
    ("peak_memory_", Direction.LOWER_IS_BETTER),
    ("event_loop_max_lag_", Direction.LOWER_IS_BETTER),
    ("handshake_latency_", Direction.LOWER_IS_BETTER),
    ("shutdown_time_", Direction.LOWER_IS_BETTER),
)

DEFAULT_THRESHOLD_PCT = 20.0  # a change past this, in the bad direction, is flagged


def metric_direction(name: str) -> Optional[Direction]:
    for prefix, direction in _METRIC_DIRECTIONS:
        if name.startswith(prefix):
            return direction
    return None


@dataclass(frozen=True)
class RegressionFinding:
    metric: str
    baseline_value: float
    current_value: float
    pct_change: float          # signed: positive means the value increased
    direction: Direction
    regressed: bool            # pct_change was past the threshold in the bad direction


def compare_to_baseline(
    current: Dict[str, Any],
    baseline: Dict[str, Any],
    threshold_pct: float = DEFAULT_THRESHOLD_PCT,
) -> List[RegressionFinding]:
    """Compare a fresh run's metrics against the baseline. Pure function —
    both arguments are already-loaded dicts (load_baseline()'s shape:
    {metric_name: {"value": ..., ...}}), so this has no I/O and no
    knowledge of *how* either run was produced.

    A metric present in only one of the two is skipped, not an error —
    a newer benchmark added since the baseline was recorded has nothing
    to compare against yet. A metric with no recognized direction
    (doesn't match a known prefix) is likewise skipped rather than
    guessed at."""
    findings: List[RegressionFinding] = []
    for name, cur_entry in current.items():
        base_entry = baseline.get(name)
        if base_entry is None:
            continue
        direction = metric_direction(name)
        if direction is None:
            continue
        try:
            cur_val = float(cur_entry["value"])
            base_val = float(base_entry["value"])
        except (KeyError, TypeError, ValueError):
            continue
        if base_val == 0:
            continue  # can't compute a percentage change against zero

        pct_change = (cur_val - base_val) / abs(base_val) * 100.0
        if direction is Direction.HIGHER_IS_BETTER:
            bad_pct = -pct_change   # a drop is bad
        else:
            bad_pct = pct_change    # a rise is bad
        regressed = bad_pct > threshold_pct

        findings.append(RegressionFinding(
            metric=name, baseline_value=base_val, current_value=cur_val,
            pct_change=pct_change, direction=direction, regressed=regressed,
        ))
    return findings
