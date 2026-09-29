#!/usr/bin/env python3
"""scripts/regression_gate.py — Phase 31/32.2: Regression gate.

Runs the benchmark suite fresh (writing to docs/benchmarks/latest.json,
never touching the committed baseline), then compares it against
docs/benchmarks/baseline.json and prints a report.

Deliberately NOT wired into per-push CI (RELIABILITY_DESIGN.md §9's Out
of Scope: "making benchmark timing a per-push CI gate") — run this by
hand, or from the manual/workflow_dispatch-only "regression-gate" CI job,
before declaring a reliability milestone done or cutting a release.
Always exits 0: a regression is reported for a human to judge (loopback
timing on a shared CI runner is noisy), never used to fail a build.
"""

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.benchmarking import (  # noqa: E402
    BASELINE_PATH,
    CURRENT_RUN_PATH,
    DEFAULT_THRESHOLD_PCT,
    compare_to_baseline,
    load_baseline,
)


def run_benchmarks(current_path: Path) -> int:
    if current_path.exists():
        current_path.unlink()  # start clean so a stale prior run can't hide a metric that failed to record this time
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-m", "benchmark"],
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    return result.returncode


def format_report(findings, threshold_pct: float) -> str:
    if not findings:
        return "No comparable metrics found between the current run and the baseline."
    lines = [f"Regression gate — threshold {threshold_pct:.0f}%\n"]
    any_regressed = False
    for f in sorted(findings, key=lambda f: f.metric):
        marker = "⚠ REGRESSED" if f.regressed else "OK"
        if f.regressed:
            any_regressed = True
        lines.append(
            f"  [{marker:12}] {f.metric}: baseline={f.baseline_value:.6g}  "
            f"current={f.current_value:.6g}  change={f.pct_change:+.1f}%"
        )
    lines.append("")
    lines.append(
        "One or more metrics regressed past the threshold — investigate before "
        "declaring this milestone done."
        if any_regressed else
        "All comparable metrics are within threshold."
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-path", type=Path, default=BASELINE_PATH)
    parser.add_argument("--current-path", type=Path, default=CURRENT_RUN_PATH)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD_PCT,
                         help="Percent change, in the bad direction, that counts as a regression.")
    parser.add_argument("--skip-run", action="store_true",
                         help="Compare an already-recorded --current-path instead of running the suite again.")
    args = parser.parse_args()

    if not args.baseline_path.exists():
        print(f"No baseline at {args.baseline_path} — nothing to compare against.", file=sys.stderr)
        return 0

    if not args.skip_run:
        print("Running the benchmark suite...")
        rc = run_benchmarks(args.current_path)
        if rc != 0:
            print(f"Benchmark suite exited {rc} — comparing whatever metrics it did record.", file=sys.stderr)

    if not args.current_path.exists():
        print(f"No results at {args.current_path} to compare.", file=sys.stderr)
        return 0

    baseline = load_baseline(args.baseline_path)
    current = load_baseline(args.current_path)
    findings = compare_to_baseline(current, baseline, threshold_pct=args.threshold)
    print()
    print(format_report(findings, args.threshold))
    return 0  # non-gating, always


if __name__ == "__main__":
    raise SystemExit(main())
