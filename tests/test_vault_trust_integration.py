"""tests/test_vault_trust_integration.py — Phase 39.2: TrustStore sharing
the vault's connection instead of its own separate plaintext file.

Covers:
  1. TrustStore(conn=vault_db.conn) writes into the vault's own
     trusted_devices table (not a separate file).
  2. A trust decision recorded this way survives flush() + lock() +
     re-unlock() with the same DEK, exactly like any other vault data.
  3. TrustStore.close() on a shared connection does NOT close the
     connection (the VaultDatabase still owns it) — legacy standalone
     usage (conn=None) still closes it as before.
"""

import os

from core.trust.store import TrustDecision, TrustStore
from core.vault.database import VaultDatabase


def test_trust_store_shares_vault_connection(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = TrustStore(conn=vdb.conn)
        store.record_first_seen("dev1", "pubkey1", "Alice")
        assert store.check("dev1", "pubkey1") == TrustDecision.PENDING

        # Same underlying connection — a direct query on vdb.conn sees it too.
        row = vdb.conn.execute(
            "SELECT status FROM trusted_devices WHERE device_id = 'dev1'"
        ).fetchone()
        assert row[0] == "PENDING"
    finally:
        vdb.lock()


def test_trust_decision_survives_flush_and_reunlock(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")

    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    store = TrustStore(conn=vdb.conn)
    store.record_first_seen("dev2", "pubkey2", "Bob")
    store.approve("dev2")
    vdb.lock()

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        store2 = TrustStore(conn=vdb2.conn)
        assert store2.check("dev2", "pubkey2") == TrustDecision.TRUSTED
    finally:
        vdb2.lock()


def test_shared_conn_close_does_not_close_connection(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = TrustStore(conn=vdb.conn)
        store.close()
        # Connection still usable — would raise ProgrammingError if closed.
        vdb.conn.execute("SELECT 1")
    finally:
        vdb.lock()


def test_standalone_trust_store_still_owns_and_closes_its_connection(tmp_path):
    db_path = str(tmp_path / "trust.db")
    store = TrustStore(db_path=db_path)
    store.close()
    try:
        store._conn.execute("SELECT 1")
        assert False, "expected the standalone connection to be closed"
    except Exception:
        pass  # sqlite3.ProgrammingError: Cannot operate on a closed database
