"""tests/test_vault_session.py — Phase 39.3: session / auto-lock model.

Covers SECURE_STORAGE_DESIGN.md §4 / §11.4:
  1. Default auto-lock is 300s (sudo timestamp_timeout).
  2. unlock() seeds settings defaults into the vault `settings` table.
  3. Idle expiry → check_and_auto_lock() hard-locks (DEK wiped, DB locked).
  4. auto_lock_seconds=0 disables idle lock.
  5. File actions re-prompt by default; chat never does.
  6. "Don't ask again this session" skips file re-auth while unlocked,
     and is cleared on lock().
  7. Incoming transfer only re-prompts when the setting is on.
  8. verify_passphrase matches the live DEK; wrong passphrase is False.
  9. Persisted auto-lock timeout survives lock → re-unlock.
 10. TrustStore.adopt_conn(None) detaches cleanly; reattach restores reads.
 11. VaultPersistence.reattach(None) skips writes while locked.
"""

import os

import pytest

from core.trust.store import TrustDecision, TrustStore
from core.vault import (
    DEFAULT_AUTO_LOCK_SECONDS,
    FILE_ACTIONS_REQUIRING_AUTH,
    SETTING_AUTO_LOCK_SECONDS,
    SETTING_CRITICAL_KEY_VERIFIER,
    SessionLockedError,
    VaultDatabase,
    VaultPersistence,
    VaultSession,
    WrongSecretError,
    create_vault,
    load_vault_keyfile,
    save_vault_keyfile,
    unlock_with_passphrase,
)
from core.events import EventBus, ChatMessageSent


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _unlocked_session(tmp_path, clock=None, auto_lock_seconds=DEFAULT_AUTO_LOCK_SECONDS):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(
        auto_lock_seconds=auto_lock_seconds,
        monotonic=clock if clock is not None else FakeClock(),
    )
    session.unlock(dek, vdb)
    return session, dek, vault_db_path


def test_default_auto_lock_is_sudo_five_minutes():
    assert DEFAULT_AUTO_LOCK_SECONDS == 300.0


def test_unlock_seeds_default_settings(tmp_path):
    session, _, _ = _unlocked_session(tmp_path)
    try:
        assert session.is_unlocked
        row = session.vault_db.conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (SETTING_AUTO_LOCK_SECONDS,),
        ).fetchone()
        assert row is not None
        assert float(__import__("json").loads(row[0])) == DEFAULT_AUTO_LOCK_SECONDS
    finally:
        session.lock()


def test_idle_expiry_hard_locks_and_wipes_dek(tmp_path):
    clock = FakeClock()
    session, dek, vault_db_path = _unlocked_session(tmp_path, clock=clock, auto_lock_seconds=60.0)
    working_path = session.vault_db.working_path

    clock.advance(59.0)
    assert not session.idle_expired()
    assert session.check_and_auto_lock() is False
    assert session.is_unlocked

    clock.advance(1.0)
    assert session.idle_expired()
    assert session.check_and_auto_lock() is True
    assert not session.is_unlocked
    assert session.vault_db is None
    with pytest.raises(SessionLockedError):
        session.dek_bytes()
    assert not os.path.exists(working_path)
    assert os.path.exists(vault_db_path)

    # Original DEK still decrypts the on-disk vault (hard lock flushed it).
    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        assert vdb2.conn.execute("SELECT 1").fetchone()[0] == 1
    finally:
        vdb2.lock()


def test_auto_lock_zero_never_idles_out(tmp_path):
    clock = FakeClock()
    session, _, _ = _unlocked_session(tmp_path, clock=clock, auto_lock_seconds=0)
    try:
        clock.advance(10_000)
        assert not session.idle_expired()
        assert session.seconds_until_lock() is None
        assert session.check_and_auto_lock() is False
        assert session.is_unlocked
    finally:
        session.lock()


def test_file_actions_require_reauth_by_default(tmp_path):
    session, _, _ = _unlocked_session(tmp_path)
    try:
        assert session.requires_reauth("chat") is False
        for action in FILE_ACTIONS_REQUIRING_AUTH:
            assert session.requires_reauth(action) is True
        assert session.requires_reauth("incoming_transfer") is False
        assert session.requires_reauth("unknown_thing") is True  # fail closed
    finally:
        session.lock()


def test_dont_ask_again_files_cleared_on_lock(tmp_path):
    session, _, _ = _unlocked_session(tmp_path)
    try:
        session.set_dont_ask_again_files(True)
        assert session.dont_ask_again_files
        assert session.requires_reauth("open") is False
        assert session.requires_reauth("export") is False
    finally:
        session.lock()
    assert not session.dont_ask_again_files
    assert session.requires_reauth("open") is True


def test_incoming_transfer_opt_in_reauth(tmp_path):
    session, _, _ = _unlocked_session(tmp_path)
    try:
        assert session.requires_reauth("incoming_transfer") is False
        session.set_require_passphrase_for_incoming(True)
        assert session.requires_reauth("incoming_transfer") is True
    finally:
        session.lock()


def test_verify_passphrase_against_live_dek(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    try:
        assert session.verify_passphrase(keyfile, "correct horse battery") is True
        assert session.verify_passphrase(keyfile, "wrong passphrase here") is False
    finally:
        session.lock()
    with pytest.raises(SessionLockedError):
        session.verify_passphrase(keyfile, "correct horse battery")


def test_critical_action_key_unset_allows_export_with_unlocked_session(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    try:
        assert session.critical_action_key_configured(keyfile) is False
        assert session.authorize_export(keyfile) is True
        assert session.verify_critical_action_key(keyfile, "unused secret") is False
    finally:
        session.lock()


def test_critical_action_key_requires_session_and_fresh_secret(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    try:
        session.set_critical_action_key(keyfile, "critical export secret")
        assert keyfile.critical_key_salt is not None
        assert keyfile.critical_key_verifier_salt is not None
        assert session.critical_action_key_configured(keyfile) is True
        assert session.authorize_export(keyfile) is False  # live DEK alone is not enough
        assert session.authorize_export(keyfile, "wrong export secret") is False
        assert session.authorize_export(keyfile, "critical export secret") is True
        verifier_record = session.vault_db.conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (SETTING_CRITICAL_KEY_VERIFIER,),
        ).fetchone()
        assert verifier_record is not None
    finally:
        session.lock()

    with pytest.raises(SessionLockedError):
        session.authorize_export(keyfile, "critical export secret")


def test_critical_action_secret_alone_is_not_enough(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    try:
        session.set_critical_action_key(keyfile, "critical export secret")
        verifier_json = session.vault_db.conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (SETTING_CRITICAL_KEY_VERIFIER,),
        ).fetchone()[0]
    finally:
        session.lock()

    other_dek = os.urandom(32)
    other_vdb = VaultDatabase.unlock(
        other_dek,
        vault_db_path=str(tmp_path / "other_vault.db"),
        force_fallback=True,
    )
    other_session = VaultSession(monotonic=FakeClock())
    other_session.unlock(other_dek, other_vdb)
    try:
        other_session.vault_db.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (SETTING_CRITICAL_KEY_VERIFIER, verifier_json),
        )
        other_session.vault_db.conn.commit()
        assert other_session.authorize_export(keyfile, "critical export secret") is False
    finally:
        other_session.lock()


def test_change_and_clear_critical_action_key(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    try:
        session.set_critical_action_key(keyfile, "old critical secret")
        with pytest.raises(WrongSecretError):
            session.change_critical_action_key(
                keyfile,
                "wrong critical secret",
                "new critical secret",
            )
        session.change_critical_action_key(
            keyfile,
            "old critical secret",
            "new critical secret",
        )
        assert session.authorize_export(keyfile, "old critical secret") is False
        assert session.authorize_export(keyfile, "new critical secret") is True

        with pytest.raises(WrongSecretError):
            session.clear_critical_action_key(keyfile, "old critical secret")
        session.clear_critical_action_key(keyfile, "new critical secret")
        assert session.critical_action_key_configured(keyfile) is False
        assert session.authorize_export(keyfile) is True
        row = session.vault_db.conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (SETTING_CRITICAL_KEY_VERIFIER,),
        ).fetchone()
        assert row is None
    finally:
        session.lock()


def test_critical_action_key_persists_across_reunlock(tmp_path):
    keyfile_path = str(tmp_path / "vault_keyfile.json")
    keyfile, _ = create_vault("correct horse battery", path=keyfile_path)
    dek = unlock_with_passphrase(keyfile, "correct horse battery")

    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session = VaultSession(monotonic=FakeClock())
    session.unlock(dek, vdb)
    session.set_critical_action_key(keyfile, "critical export secret")
    save_vault_keyfile(keyfile, keyfile_path)
    session.lock()

    loaded = load_vault_keyfile(keyfile_path)
    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session2 = VaultSession(monotonic=FakeClock())
    session2.unlock(dek, vdb2)
    try:
        assert session2.critical_action_key_configured(loaded) is True
        assert session2.authorize_export(loaded, "critical export secret") is True
    finally:
        session2.lock()


def test_persisted_autolock_survives_relock(tmp_path):
    clock = FakeClock()
    session, dek, vault_db_path = _unlocked_session(tmp_path, clock=clock)
    session.set_auto_lock_seconds(120.0)
    session.lock()

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    session2 = VaultSession(auto_lock_seconds=DEFAULT_AUTO_LOCK_SECONDS, monotonic=FakeClock())
    session2.unlock(dek, vdb2)
    try:
        assert session2.auto_lock_seconds == 120.0
    finally:
        session2.lock()


def test_trust_store_adopt_conn_detach_and_reattach(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    store = TrustStore(conn=vdb.conn)
    store.record_first_seen("dev1", "pubkey1", "Alice")

    store.adopt_conn(None)
    with pytest.raises(RuntimeError, match="vault locked"):
        store.get("dev1")

    vdb.lock()
    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        store.adopt_conn(vdb2.conn)
        assert store.check("dev1", "pubkey1") == TrustDecision.PENDING
    finally:
        vdb2.lock()


def test_persistence_skips_writes_while_detached(tmp_path):
    dek = os.urandom(32)
    vault_db_path = str(tmp_path / "vault.db")
    vdb = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    bus = EventBus()
    persistence = VaultPersistence(vdb, bus)

    persistence.reattach(None)
    # Should not raise even though the vault is "locked" from persistence's POV.
    bus.post(
        ChatMessageSent(
            message_id="m-lock",
            peer_device_id="dev1",
            text="during lock",
            timestamp=1.0,
        )
    )
    vdb.lock()  # flush empty vault + destroy working copy

    vdb2 = VaultDatabase.unlock(dek, vault_db_path=vault_db_path, force_fallback=True)
    try:
        persistence.reattach(vdb2)
        row = vdb2.conn.execute(
            "SELECT text FROM messages WHERE message_id = 'm-lock'"
        ).fetchone()
        assert row is None  # skipped, not queued
    finally:
        persistence.reattach(None)
        vdb2.lock()
