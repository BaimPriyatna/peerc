"""core.connectivity — Internet P2P Connectivity (Phase 44).

    locator.py — Endpoint/Locator dataclasses (pure data, no storage) —
                 deliberately separate from identity (device_id);
                 see docs/INTERNET_CONNECTIVITY_DESIGN.md §1-3
    store.py    — LocatorStore: SQLite-backed device_endpoints
                  (mirrors core/trust/store.py's shared-connection pattern)

Not yet present (later Phase 44 sub-steps, see the design doc and the
ROADMAP): endpoint_update.py (44.2, signed endpoint announcement +
verification), Add-by-Link (44.3, §3a Link Format).
"""

from .locator import (
    DEFAULT_STALE_SECONDS,
    KIND_DIRECT_V4,
    KIND_DIRECT_V6,
    KIND_RENDEZVOUS,
    VALID_KINDS,
    Endpoint,
    Locator,
    LocatorError,
)
from .store import DEFAULT_DB_PATH, LocatorStore, LocatorStoreError

__all__ = [
    "DEFAULT_STALE_SECONDS",
    "KIND_DIRECT_V4",
    "KIND_DIRECT_V6",
    "KIND_RENDEZVOUS",
    "VALID_KINDS",
    "Endpoint",
    "Locator",
    "LocatorError",
    "DEFAULT_DB_PATH",
    "LocatorStore",
    "LocatorStoreError",
]
