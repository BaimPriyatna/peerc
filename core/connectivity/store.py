"""core/connectivity/store.py — Phase 44.1: SQLite-backed locator storage.

Mirrors core/trust/store.py and core/group/store.py's shape exactly:
default to opening/owning its own db_path file, but accept an
already-open connection to share instead — the unified vault database
(Phase 39.2) is the real caller, same reasoning as TrustStore/GroupStore:
one encrypted file instead of running separate encrypt/flush lifecycles
in parallel.
"""

import os
import sqlite3
import time
from typing import List, Optional

from .locator import DEFAULT_STALE_SECONDS, Endpoint, Locator

DEFAULT_DB_PATH = os.path.expanduser("~/.peerc/locator.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_endpoints (
    device_id   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    updated_at  REAL NOT NULL,
    PRIMARY KEY (device_id, kind, host, port)
);
"""


class LocatorStoreError(Exception):
    """Base class for locator store errors."""


def _row_to_endpoint(row: sqlite3.Row) -> Endpoint:
    return Endpoint(
        device_id=row["device_id"],
        kind=row["kind"],
        host=row["host"],
        port=row["port"],
        updated_at=row["updated_at"],
    )


class LocatorStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, conn: Optional[sqlite3.Connection] = None):
        """conn, if given, is an already-open connection to share (the
        unified vault database) — db_path is ignored in that case, and
        this instance does NOT own/close that connection. When conn is
        None (the default), this store opens and owns its own db_path
        file — matches TrustStore/GroupStore exactly."""
        self.db_path = db_path
        if conn is not None:
            self._conn = conn
            self._owns_conn = False
        else:
            directory = os.path.dirname(db_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(db_path)
            self._owns_conn = True
        self._conn.row_factory = sqlite3.Row
        self._require_conn().executescript(_SCHEMA)
        self._require_conn().commit()

    def close(self) -> None:
        if self._owns_conn and self._conn is not None:
            self._conn.close()
            self._conn = None

    def adopt_conn(self, conn: Optional[sqlite3.Connection]) -> None:
        """Swap onto a new shared vault connection after a session
        re-unlock (or detach with conn=None while the vault is locked).
        Never closes a connection we don't own."""
        if self._owns_conn and self._conn is not None:
            self._conn.close()
        self._conn = conn
        self._owns_conn = False
        if conn is not None:
            self._conn.row_factory = sqlite3.Row

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("LocatorStore has no active connection (vault locked)")
        return self._conn

    def upsert_endpoint(self, endpoint: Endpoint) -> Endpoint:
        """Insert *endpoint*, or refresh updated_at if the same
        (device_id, kind, host, port) already exists — the primary key
        is the identity of an endpoint, updated_at is just "last
        confirmed current"."""
        self._require_conn().execute(
            "INSERT INTO device_endpoints (device_id, kind, host, port, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (device_id, kind, host, port) DO UPDATE SET updated_at = excluded.updated_at",
            (endpoint.device_id, endpoint.kind, endpoint.host, endpoint.port, endpoint.updated_at),
        )
        self._require_conn().commit()
        return endpoint

    def remove_endpoint(self, device_id: str, kind: str, host: str, port: int) -> None:
        self._require_conn().execute(
            "DELETE FROM device_endpoints WHERE device_id = ? AND kind = ? AND host = ? AND port = ?",
            (device_id, kind, host, port),
        )
        self._require_conn().commit()

    def list_endpoints(self, device_id: str, kind: Optional[str] = None) -> List[Endpoint]:
        if kind is None:
            rows = self._require_conn().execute(
                "SELECT * FROM device_endpoints WHERE device_id = ? ORDER BY updated_at DESC", (device_id,)
            ).fetchall()
        else:
            rows = self._require_conn().execute(
                "SELECT * FROM device_endpoints WHERE device_id = ? AND kind = ? ORDER BY updated_at DESC",
                (device_id, kind),
            ).fetchall()
        return [_row_to_endpoint(r) for r in rows]

    def get_locator(self, device_id: str) -> Locator:
        """Never raises for an unknown device_id — just returns an
        empty Locator (a device with zero known endpoints is a normal,
        unremarkable state, not an error)."""
        return Locator(device_id=device_id, endpoints=self.list_endpoints(device_id))

    def prune_stale(self, max_age_seconds: Optional[float] = None) -> int:
        """Delete every endpoint whose updated_at is older than
        max_age_seconds (defaults to locator.DEFAULT_STALE_SECONDS).
        Returns how many rows were removed."""
        threshold = time.time() - (max_age_seconds if max_age_seconds is not None else DEFAULT_STALE_SECONDS)
        cur = self._require_conn().execute("DELETE FROM device_endpoints WHERE updated_at < ?", (threshold,))
        self._require_conn().commit()
        return cur.rowcount
