"""tests/test_connectivity_locator.py — Phase 44.1: Locator (Endpoint/Locator
dataclasses + LocatorStore) tests.

Covers:
  1. Endpoint construction validation (bad kind, missing host, bad port).
  2. Endpoint.is_stale().
  3. Locator.sorted_endpoints(): direct before rendezvous, freshest first
     within each group.
  4. LocatorStore: upsert (insert + refresh-on-conflict), remove,
     list_endpoints (all / filtered by kind), get_locator for a device
     with zero endpoints (no error, just empty), prune_stale.
  5. adopt_conn detach — operations raise once detached.
"""

import time

import pytest

from core.connectivity.locator import (
    KIND_DIRECT_V4,
    KIND_DIRECT_V6,
    KIND_RENDEZVOUS,
    Endpoint,
    Locator,
    LocatorError,
)
from core.connectivity.store import LocatorStore


# ---------------------------------------------------------------------------
# 1-3. Endpoint / Locator (pure data)
# ---------------------------------------------------------------------------


def test_endpoint_rejects_invalid_kind():
    with pytest.raises(LocatorError):
        Endpoint(device_id="dev1", kind="carrier-pigeon", host="1.2.3.4", port=5656)


def test_endpoint_rejects_missing_host():
    with pytest.raises(LocatorError):
        Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="", port=5656)


def test_endpoint_rejects_invalid_port():
    with pytest.raises(LocatorError):
        Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=0)
    with pytest.raises(LocatorError):
        Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=70000)


def test_endpoint_is_stale():
    fresh = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656, updated_at=time.time())
    old = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656, updated_at=time.time() - 999999)

    assert fresh.is_stale(max_age_seconds=3600) is False
    assert old.is_stale(max_age_seconds=3600) is True


def test_locator_sorted_endpoints_direct_before_rendezvous():
    now = time.time()
    rendezvous = Endpoint(device_id="dev1", kind=KIND_RENDEZVOUS, host="rendez.example", port=443, updated_at=now)
    direct_older = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.1.1.1", port=5656, updated_at=now - 100)
    direct_newer = Endpoint(device_id="dev1", kind=KIND_DIRECT_V6, host="::1", port=5656, updated_at=now)

    locator = Locator(device_id="dev1", endpoints=[rendezvous, direct_older, direct_newer])
    ordered = locator.sorted_endpoints()

    assert ordered == [direct_newer, direct_older, rendezvous]


# ---------------------------------------------------------------------------
# 4. LocatorStore
# ---------------------------------------------------------------------------


def test_upsert_and_list_endpoints(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    ep = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656)

    store.upsert_endpoint(ep)

    endpoints = store.list_endpoints("dev1")
    assert len(endpoints) == 1
    assert endpoints[0].host == "1.2.3.4"


def test_upsert_refreshes_updated_at_on_conflict(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    ep_old = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656, updated_at=1000.0)
    ep_new = Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656, updated_at=2000.0)

    store.upsert_endpoint(ep_old)
    store.upsert_endpoint(ep_new)

    endpoints = store.list_endpoints("dev1")
    assert len(endpoints) == 1  # same (device_id, kind, host, port) — refreshed, not duplicated
    assert endpoints[0].updated_at == 2000.0


def test_list_endpoints_filtered_by_kind(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_RENDEZVOUS, host="rendez.example", port=443))

    direct_only = store.list_endpoints("dev1", kind=KIND_DIRECT_V4)
    assert len(direct_only) == 1
    assert direct_only[0].kind == KIND_DIRECT_V4


def test_remove_endpoint(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656))

    store.remove_endpoint("dev1", KIND_DIRECT_V4, "1.2.3.4", 5656)

    assert store.list_endpoints("dev1") == []


def test_get_locator_unknown_device_returns_empty(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))

    locator = store.get_locator("never-seen-device")

    assert locator.device_id == "never-seen-device"
    assert locator.endpoints == []


def test_multiple_endpoints_same_device_different_hosts(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="192.168.1.20", port=5656))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="10.10.0.20", port=5656))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V6, host="::1", port=5656))

    locator = store.get_locator("dev1")

    assert len(locator.endpoints) == 3


def test_prune_stale(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    now = time.time()
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.1.1.1", port=5656, updated_at=now - 999999))
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="2.2.2.2", port=5656, updated_at=now))

    removed = store.prune_stale(max_age_seconds=3600)

    assert removed == 1
    remaining = store.list_endpoints("dev1")
    assert len(remaining) == 1
    assert remaining[0].host == "2.2.2.2"


# ---------------------------------------------------------------------------
# 5. adopt_conn detach
# ---------------------------------------------------------------------------


def test_adopt_conn_detach_raises(tmp_path):
    store = LocatorStore(db_path=str(tmp_path / "locator.db"))
    store.adopt_conn(None)
    with pytest.raises(RuntimeError):
        store.list_endpoints("dev1")
