"""tests/test_vault_database.py — Phase 39.2: encrypted DB lifecycle tests.

Covers:
  1. unlock() on a fresh path creates all 5 tables (first run).
  2. Data written, flush()ed, then unlock()ed again with the same DEK
     round-trips correctly (the whole point of the lifecycle).
  3. Wrong DEK on unlock() raises VaultCorruptError.
  4. force_fallback=True uses the OS temp dir instead of /dev/shm.
  5. lock() destroys the plaintext working copy from disk.
  6. start_auto_flush() actually flushes periodically.
  7. migrate_plaintext_trust_db(): rows copied correctly, old file
     deleted, identity_transitions included, missing old file is a no-op,
     pre-Phase-40 trust.db (no identity_transitions table) still works.
"""

import asyncio
import os
import sqlite3
import time

import pytest

from core.vault.database import (
    RAM_BACKED_DIR,
    VaultCorruptError,
    VaultDatabase,
    _pick_working_dir,
)
from core.vault.migration import migrate_plaintext_trust_db


def test_unlock_fresh_creates_all_tables(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        tables = {
            row[0] for row in
            vdb.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"trusted_devices", "identity_transitions", "messages", "transfers", "settings"} <= tables
    finally:
        vdb.lock()


def test_flush_and_reunlock_roundtrip(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")

    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    vdb.conn.execute(
        "INSERT INTO messages (message_id, peer_device_id, direction, text, timestamp, status) "
        "VALUES ('m1', 'dev1', 'sent', 'hello vault', ?, 'delivered')",
        (time.time(),),
    )
    vdb.flush()
    vdb.lock()

    assert os.path.exists(vault_db_path)
    assert not os.path.exists(vdb.working_path)  # destroyed by lock()

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        row = vdb2.conn.execute("SELECT text FROM messages WHERE message_id = 'm1'").fetchone()
        assert row is not None
        assert row[0] == "hello vault"
    finally:
        vdb2.lock()


def test_wrong_dek_raises_corrupt_error(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    vdb.lock()

    with pytest.raises(VaultCorruptError):
        VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)


def test_force_fallback_uses_temp_dir_not_ram(tmp_path):
    directory, is_ram_backed = _pick_working_dir(force_fallback=True)
    assert not is_ram_backed
    assert directory != RAM_BACKED_DIR


def test_pick_working_dir_prefers_ram_when_available():
    if not (os.path.isdir(RAM_BACKED_DIR) and os.access(RAM_BACKED_DIR, os.W_OK)):
        pytest.skip("no /dev/shm on this system")
    directory, is_ram_backed = _pick_working_dir(force_fallback=False)
    assert is_ram_backed
    assert directory == RAM_BACKED_DIR


def test_lock_destroys_working_copy(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    working_path = vdb.working_path
    assert os.path.exists(working_path)
    vdb.lock()
    assert not os.path.exists(working_path)


@pytest.mark.asyncio
async def test_auto_flush_actually_flushes(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        vdb.conn.execute(
            "INSERT INTO settings (key, value) VALUES ('theme', '\"dark\"')"
        )
        vdb.conn.commit()
        assert not os.path.exists(vault_db_path)  # not flushed yet

        await vdb.start_auto_flush(interval=0.1)
        await asyncio.sleep(0.3)
        assert os.path.exists(vault_db_path)  # auto-flush wrote it
    finally:
        vdb.lock()


def test_migrate_plaintext_trust_db(tmp_path):
    old_path = str(tmp_path / "trust.db")
    old_conn = sqlite3.connect(old_path)
    old_conn.executescript("""
        CREATE TABLE trusted_devices (
            device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, name TEXT NOT NULL,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL, status TEXT NOT NULL,
            revoked_by TEXT, revoked_at REAL, revoke_reason TEXT
        );
        CREATE TABLE identity_transitions (
            old_device_id TEXT NOT NULL, new_device_id TEXT NOT NULL,
            old_public_key TEXT NOT NULL, new_public_key TEXT NOT NULL,
            timestamp REAL NOT NULL, signature TEXT NOT NULL, recorded_at REAL NOT NULL,
            PRIMARY KEY (old_device_id, new_device_id)
        );
    """)
    old_conn.execute(
        "INSERT INTO trusted_devices VALUES ('dev1', 'pubkey1', 'Alice', 1.0, 2.0, 'trusted', "
        "NULL, NULL, NULL)"
    )
    old_conn.execute(
        "INSERT INTO identity_transitions VALUES ('dev1', 'dev2', 'pubkey1', 'pubkey2', "
        "3.0, 'sig123', 4.0)"
    )
    old_conn.commit()
    old_conn.close()

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        migrated_count = migrate_plaintext_trust_db(vdb, old_path)
        assert migrated_count == 1
        assert not os.path.exists(old_path)  # retired, per project decision (no real users yet)

        device_row = vdb.conn.execute(
            "SELECT name, status FROM trusted_devices WHERE device_id = 'dev1'"
        ).fetchone()
        assert device_row == ("Alice", "trusted")

        transition_row = vdb.conn.execute(
            "SELECT new_device_id FROM identity_transitions WHERE old_device_id = 'dev1'"
        ).fetchone()
        assert transition_row == ("dev2",)
    finally:
        vdb.lock()


def test_migrate_missing_old_file_is_noop(tmp_path):
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        result = migrate_plaintext_trust_db(vdb, str(tmp_path / "does_not_exist.db"))
        assert result == 0
    finally:
        vdb.lock()


def test_migrate_pre_phase_40_trust_db_without_transitions_table(tmp_path):
    """An old trust.db from before Phase 40 won't have identity_transitions at all."""
    old_path = str(tmp_path / "trust.db")
    old_conn = sqlite3.connect(old_path)
    old_conn.executescript("""
        CREATE TABLE trusted_devices (
            device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, name TEXT NOT NULL,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL, status TEXT NOT NULL,
            revoked_by TEXT, revoked_at REAL, revoke_reason TEXT
        );
    """)
    old_conn.execute(
        "INSERT INTO trusted_devices VALUES ('dev1', 'pubkey1', 'Bob', 1.0, 2.0, 'trusted', "
        "NULL, NULL, NULL)"
    )
    old_conn.commit()
    old_conn.close()

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(os.urandom(32), vault_db_path=vault_db_path, force_fallback=True)
    try:
        migrated_count = migrate_plaintext_trust_db(vdb, old_path)
        assert migrated_count == 1
        assert not os.path.exists(old_path)
    finally:
        vdb.lock()
