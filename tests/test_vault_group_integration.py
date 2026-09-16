"""tests/test_vault_group_integration.py — Phase 42.1: GroupStore sharing
the vault's connection, mirroring test_vault_trust_integration.py's
coverage of TrustStore for the same pattern.

Covers:
  1. GroupStore(conn=vault_db.conn) writes into the vault's own
     groups/group_memberships tables (not a separate file).
  2. A group + membership recorded this way survives flush() + lock() +
     re-unlock() with the same DEK, exactly like any other vault data.
  3. GroupStore.close() on a shared connection does NOT close the
     connection (the VaultDatabase still owns it).
"""

import os

from core.group.membership import create_group, issue_membership_certificate
from core.group.store import GroupStore, MembershipStatus
from core.identity.device_identity import generate_keypair
from core.vault.database import VaultDatabase


def test_group_store_shares_vault_connection(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = GroupStore(conn=vdb.conn)
        admin = generate_keypair()
        group = create_group(admin, name="Engineering")
        store.create_group(group)

        row = vdb.conn.execute(
            "SELECT name FROM groups WHERE group_id = ?", (group.group_id,)
        ).fetchone()
        assert row[0] == "Engineering"
    finally:
        vdb.lock()


def test_membership_survives_flush_and_reunlock(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")

    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    store = GroupStore(conn=vdb.conn)
    admin = generate_keypair()
    member = generate_keypair()
    group = create_group(admin, name="Engineering")
    store.create_group(group)
    cert = issue_membership_certificate(
        admin,
        device_id=member.device_id,
        device_public_key=member.public_key_bytes(),
        group_id=group.group_id,
    )
    store.record_membership(cert)
    vdb.lock()

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        store2 = GroupStore(conn=vdb2.conn)
        assert store2.get_membership_status(group.group_id, member.device_id) == MembershipStatus.ACTIVE
        assert store2.get_group(group.group_id).name == "Engineering"
    finally:
        vdb2.lock()


def test_group_store_close_on_shared_conn_does_not_close_it(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        store = GroupStore(conn=vdb.conn)
        store.close()
        # The vault's own connection is still usable.
        vdb.conn.execute("SELECT 1").fetchone()
    finally:
        vdb.lock()
