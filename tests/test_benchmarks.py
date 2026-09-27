"""tests/test_benchmarks.py — Phase 31.1: Performance Baselines.

Non-gating by design (RELIABILITY_DESIGN.md §8, item 3: "add a
non-gating benchmark runner and record baseline measurements before
changing I/O behavior"). These tests measure and record numbers into
docs/benchmarks/baseline.json; they assert only loose sanity bounds (a
measurement came back positive/finite) to catch a broken measurement,
never a specific performance threshold — there is no prior baseline to
regress against yet. Phase 31/32.2's regression gate is what later
compares a run's numbers against this one.

All fixtures are deterministic local files and loopback connections per
§4 — no public-network results here. Each test is independent and can
be run alone; baseline.json accumulates whichever metrics were run.
"""

import asyncio
import os
import random
import tempfile
import time

import pytest

import file_transfer
from core.benchmarking import EventLoopLagSampler, peak_rss_mb, record_metric
from core.identity.device_identity import generate_keypair
from core.task_registry import TaskRegistry
from peer import ConnectionManager

pytestmark = pytest.mark.benchmark

FIXTURE_SIZE = 8_000_000  # 8 MB: enough for a meaningful number, still fast


def _ports(n: int):
    base = random.randint(40000, 60000)
    return [base + i for i in range(n)]


async def _connect(manager_from, manager_to, host, port):
    addr_key = await manager_from.connect_to(host, port)
    await asyncio.sleep(0.2)
    return addr_key


def _make_fixture(directory: str, size: int = FIXTURE_SIZE) -> str:
    path = os.path.join(directory, "fixture.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


# ---------------------------------------------------------------------
# Transfer throughput — direct and relayed
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transfer_throughput_direct():
    port_a, port_b = _ports(2)
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_a = tempfile.mkdtemp(prefix="peerc_bench_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_bench_b_")
    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir=tmp_a)
    file_transfer.FileTransferSession(manager_b, downloads_dir=tmp_b)  # auto-accepts

    completed = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, success, path: (result.update(success=success), completed.set())

    src_path = _make_fixture(tmp_a)

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        start = time.monotonic()
        await ft_a.offer_file(addr_key, src_path)
        await asyncio.wait_for(completed.wait(), timeout=30.0)
        elapsed = time.monotonic() - start

        assert result.get("success") is True
        throughput = FIXTURE_SIZE / elapsed
        assert throughput > 0
        record_metric(
            "transfer_throughput_direct_bytes_per_sec", throughput,
            fixture_bytes=FIXTURE_SIZE, elapsed_sec=elapsed,
        )
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_transfer_throughput_relay():
    port_r, port_a, port_b = _ports(3)
    manager_r = ConnectionManager(listen_port=port_r, my_identity=generate_keypair(), my_name="R")
    a_identity = generate_keypair()
    b_identity = generate_keypair()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=a_identity, my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=b_identity, my_name="B")

    await manager_r.start_server()
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_a = tempfile.mkdtemp(prefix="peerc_bench_relay_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_bench_relay_b_")
    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir=tmp_a)
    file_transfer.FileTransferSession(manager_b, downloads_dir=tmp_b)  # auto-accepts

    completed = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, success, path: (result.update(success=success), completed.set())

    src_path = _make_fixture(tmp_a)

    try:
        addr_key_a_to_r = await _connect(manager_a, manager_r, "127.0.0.1", port_r)
        r_keys_after_a = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_a = next(iter(r_keys_after_a))

        await _connect(manager_b, manager_r, "127.0.0.1", port_r)
        r_keys_after_b = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_b = next(iter(r_keys_after_b - r_keys_after_a))

        manager_r.open_relay_pipe(addr_key_r_to_a, addr_key_r_to_b)

        tunneled_addr_a = await manager_a.connect_via_relay_tunnel(
            addr_key_a_to_r, b_identity.device_id, timeout=5.0,
        )

        start = time.monotonic()
        await ft_a.offer_file(tunneled_addr_a, src_path)
        await asyncio.wait_for(completed.wait(), timeout=30.0)
        elapsed = time.monotonic() - start

        assert result.get("success") is True
        throughput = FIXTURE_SIZE / elapsed
        assert throughput > 0
        record_metric(
            "transfer_throughput_relay_bytes_per_sec", throughput,
            fixture_bytes=FIXTURE_SIZE, elapsed_sec=elapsed,
        )
    finally:
        await manager_a.close_all()
        await manager_b.close_all()
        await manager_r.close_all()


# ---------------------------------------------------------------------
# Peak memory during a large-fixture transfer
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peak_memory_during_transfer():
    port_a, port_b = _ports(2)
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_a = tempfile.mkdtemp(prefix="peerc_bench_mem_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_bench_mem_b_")
    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir=tmp_a)
    file_transfer.FileTransferSession(manager_b, downloads_dir=tmp_b)

    completed = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, success, path: (result.update(success=success), completed.set())

    src_path = _make_fixture(tmp_a, size=32_000_000)  # larger fixture — memory should NOT scale with this

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        before_mb = peak_rss_mb()
        await ft_a.offer_file(addr_key, src_path)
        await asyncio.wait_for(completed.wait(), timeout=30.0)
        after_mb = peak_rss_mb()

        assert result.get("success") is True
        delta_mb = after_mb - before_mb
        assert after_mb > 0
        record_metric(
            "peak_memory_during_transfer_mb", after_mb,
            delta_mb=delta_mb, fixture_bytes=32_000_000,
        )
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# Event-loop lag during a transfer
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_loop_lag_during_transfer():
    port_a, port_b = _ports(2)
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    tmp_a = tempfile.mkdtemp(prefix="peerc_bench_lag_a_")
    tmp_b = tempfile.mkdtemp(prefix="peerc_bench_lag_b_")
    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir=tmp_a)
    file_transfer.FileTransferSession(manager_b, downloads_dir=tmp_b)

    completed = asyncio.Event()
    result = {}
    ft_a.on_complete = lambda tid, success, path: (result.update(success=success), completed.set())

    src_path = _make_fixture(tmp_a, size=16_000_000)

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        sampler = EventLoopLagSampler(interval=0.01)
        sampler.start()
        await ft_a.offer_file(addr_key, src_path)
        await asyncio.wait_for(completed.wait(), timeout=30.0)
        max_lag = await sampler.stop()

        assert result.get("success") is True
        assert max_lag >= 0
        record_metric("event_loop_max_lag_sec_during_transfer", max_lag, sample_interval_sec=0.01)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


# ---------------------------------------------------------------------
# Handshake latency — direct and relayed
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_handshake_latency_direct():
    port_a, port_b = _ports(2)
    manager_a = ConnectionManager(listen_port=port_a, my_identity=generate_keypair(), my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=generate_keypair(), my_name="B")
    await manager_a.start_server()
    await manager_b.start_server()

    try:
        start = time.monotonic()
        await manager_a.connect_to("127.0.0.1", port_b)
        elapsed = time.monotonic() - start

        assert elapsed > 0
        record_metric("handshake_latency_direct_sec", elapsed)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_handshake_latency_relay():
    port_r, port_a, port_b = _ports(3)
    manager_r = ConnectionManager(listen_port=port_r, my_identity=generate_keypair(), my_name="R")
    a_identity = generate_keypair()
    b_identity = generate_keypair()
    manager_a = ConnectionManager(listen_port=port_a, my_identity=a_identity, my_name="A")
    manager_b = ConnectionManager(listen_port=port_b, my_identity=b_identity, my_name="B")

    await manager_r.start_server()
    await manager_a.start_server()
    await manager_b.start_server()

    try:
        addr_key_a_to_r = await _connect(manager_a, manager_r, "127.0.0.1", port_r)
        r_keys_after_a = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_a = next(iter(r_keys_after_a))

        await _connect(manager_b, manager_r, "127.0.0.1", port_r)
        r_keys_after_b = set(manager_r.list_connected_addr_keys())
        addr_key_r_to_b = next(iter(r_keys_after_b - r_keys_after_a))

        manager_r.open_relay_pipe(addr_key_r_to_a, addr_key_r_to_b)

        start = time.monotonic()
        await manager_a.connect_via_relay_tunnel(addr_key_a_to_r, b_identity.device_id, timeout=5.0)
        elapsed = time.monotonic() - start

        assert elapsed > 0
        record_metric("handshake_latency_relay_sec", elapsed)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()
        await manager_r.close_all()


# ---------------------------------------------------------------------
# Shutdown time — cancel and await all owned tasks
# ---------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shutdown_time_cancel_all_tasks():
    """Now measurable thanks to Phase 32.1's TaskRegistry (pulled forward
    in 29/30.1): how long a bounded shutdown actually takes with a
    representative number of outstanding tasks across all groups."""
    registry = TaskRegistry()

    async def long_running():
        await asyncio.sleep(3600)

    for _ in range(5):
        registry.create_task(long_running(), group="connection", name="c")
    for _ in range(3):
        registry.create_task(long_running(), group="transfer", name="t")
    for _ in range(3):
        registry.create_task(long_running(), group="app", name="a")

    assert registry.active_count() == 11

    start = time.monotonic()
    await registry.cancel_all()
    elapsed = time.monotonic() - start

    assert registry.active_count() == 0
    assert elapsed >= 0
    record_metric("shutdown_time_sec_11_tasks", elapsed, task_count=11)
