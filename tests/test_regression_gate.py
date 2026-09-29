"""tests/test_regression_gate.py — Phase 31/32.2: Regression gate.

Unit tests for core.benchmarking.compare_to_baseline() in isolation —
no I/O, no benchmark suite invocation (that's scripts/regression_gate.py,
which is what a human runs by hand; RELIABILITY_DESIGN.md §9 explicitly
keeps this out of per-push CI).
"""

import pytest

from core.benchmarking import Direction, compare_to_baseline, metric_direction

pytestmark = pytest.mark.unit


def _entry(value):
    return {"value": value, "recorded_at": 0}


def test_metric_direction_by_known_prefix():
    assert metric_direction("transfer_throughput_direct_bytes_per_sec") is Direction.HIGHER_IS_BETTER
    assert metric_direction("transfer_throughput_relay_bytes_per_sec") is Direction.HIGHER_IS_BETTER
    assert metric_direction("peak_memory_during_transfer_mb") is Direction.LOWER_IS_BETTER
    assert metric_direction("event_loop_max_lag_sec_during_transfer") is Direction.LOWER_IS_BETTER
    assert metric_direction("handshake_latency_direct_sec") is Direction.LOWER_IS_BETTER
    assert metric_direction("shutdown_time_sec_11_tasks") is Direction.LOWER_IS_BETTER


def test_unrecognized_metric_name_has_no_direction_and_is_skipped():
    assert metric_direction("some_future_metric") is None
    findings = compare_to_baseline(
        {"some_future_metric": _entry(10)}, {"some_future_metric": _entry(5)},
    )
    assert findings == []


def test_throughput_drop_is_flagged_rise_is_not():
    baseline = {"transfer_throughput_direct_bytes_per_sec": _entry(1000)}

    dropped = compare_to_baseline(
        {"transfer_throughput_direct_bytes_per_sec": _entry(700)}, baseline, threshold_pct=20,
    )
    assert dropped[0].regressed is True
    assert dropped[0].pct_change == pytest.approx(-30.0)

    risen = compare_to_baseline(
        {"transfer_throughput_direct_bytes_per_sec": _entry(1500)}, baseline, threshold_pct=20,
    )
    assert risen[0].regressed is False


def test_memory_rise_is_flagged_drop_is_not():
    baseline = {"peak_memory_during_transfer_mb": _entry(100)}

    risen = compare_to_baseline({"peak_memory_during_transfer_mb": _entry(150)}, baseline, threshold_pct=20)
    assert risen[0].regressed is True
    assert risen[0].pct_change == pytest.approx(50.0)

    dropped = compare_to_baseline({"peak_memory_during_transfer_mb": _entry(60)}, baseline, threshold_pct=20)
    assert dropped[0].regressed is False


def test_within_threshold_is_not_flagged():
    baseline = {"shutdown_time_sec_11_tasks": _entry(1.0)}
    findings = compare_to_baseline({"shutdown_time_sec_11_tasks": _entry(1.15)}, baseline, threshold_pct=20)
    assert findings[0].regressed is False
    assert findings[0].pct_change == pytest.approx(15.0)


def test_metric_missing_from_either_side_is_skipped_not_an_error():
    baseline = {"handshake_latency_direct_sec": _entry(0.01)}
    current = {"handshake_latency_relay_sec": _entry(0.02)}  # different metric entirely
    assert compare_to_baseline(current, baseline) == []


def test_zero_baseline_is_skipped_not_a_division_error():
    baseline = {"shutdown_time_sec_11_tasks": _entry(0.0)}
    current = {"shutdown_time_sec_11_tasks": _entry(0.5)}
    assert compare_to_baseline(current, baseline) == []  # no ZeroDivisionError


def test_non_numeric_values_are_skipped_not_an_error():
    baseline = {"peak_memory_during_transfer_mb": _entry("not-a-number")}
    current = {"peak_memory_during_transfer_mb": _entry(100)}
    assert compare_to_baseline(current, baseline) == []


def test_multiple_metrics_report_independently():
    baseline = {
        "transfer_throughput_direct_bytes_per_sec": _entry(1000),
        "peak_memory_during_transfer_mb": _entry(100),
    }
    current = {
        "transfer_throughput_direct_bytes_per_sec": _entry(500),  # regressed
        "peak_memory_during_transfer_mb": _entry(105),            # fine
    }
    findings = {f.metric: f for f in compare_to_baseline(current, baseline, threshold_pct=20)}
    assert findings["transfer_throughput_direct_bytes_per_sec"].regressed is True
    assert findings["peak_memory_during_transfer_mb"].regressed is False
