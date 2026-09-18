"""tests/test_vault_locator_integration.py — Phase 44.1: LocatorStore
sharing the vault's connection, mirroring test_vault_group_integration.py's
coverage of GroupStore for the same pattern.
"""

import os

from core.connectivity.locator import KIND_DIRECT_V4, Endpoint
from core.connectivity.store import LocatorStore
from core.vault.database import VaultDatabase


def test_locator_store_shares_vault_connection(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = LocatorStore(conn=vdb.conn)
        store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656))

        row = vdb.conn.execute(
            "SELECT host FROM device_endpoints WHERE device_id = ?", ("dev1",)
        ).fetchone()
        assert row[0] == "1.2.3.4"
    finally:
        vdb.lock()


def test_endpoint_survives_flush_and_reunlock(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")

    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    store = LocatorStore(conn=vdb.conn)
    store.upsert_endpoint(Endpoint(device_id="dev1", kind=KIND_DIRECT_V4, host="1.2.3.4", port=5656))
    vdb.lock()

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        store2 = LocatorStore(conn=vdb2.conn)
        endpoints = store2.list_endpoints("dev1")
        assert len(endpoints) == 1
        assert endpoints[0].host == "1.2.3.4"
    finally:
        vdb2.lock()


def test_locator_store_close_on_shared_conn_does_not_close_it(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = LocatorStore(conn=vdb.conn)
        store.close()
        vdb.conn.execute("SELECT 1").fetchone()
    finally:
        vdb.lock()
