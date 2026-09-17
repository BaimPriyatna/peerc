"""
test_stage5.py — headless smoke test for ui.py using Textual's test harness.

Runs the app in memory (no real terminal needed), types a /help command,
and checks it renders without crashing. This isn't a full integration test
of networking + UI together — it verifies the UI itself mounts, wires up
discovery/chat/file_transfer sessions, and responds to input.

Note: the vault-unlock flow (Phase 39.2+) is deliberately bypassed below
rather than driven through its modal — that interactive flow has its own
dedicated tests elsewhere; this file only needs a DEK in hand so _setup()
can get past it and wire up the rest of the app. Same reasoning applies
to the first-run NameSetupModal (Phase 3.4): _isolated_load always
creates a brand-new identity in an empty temp dir, so is_new is True on
every run, and pilot.pause(0.5) never answers that modal either.
"""

import asyncio
import os
import shutil
import tempfile

import core.identity as identity
import core.identity.key_storage as ks
import discovery
from core.vault.crypto import new_dek
from core.vault.database import VaultDatabase
from ui import ChatApp


async def main() -> None:
    tmpdir = tempfile.mkdtemp(prefix="peerc_stage5_")
    tmp_id = os.path.join(tmpdir, "identity.json")
    tmp_key = os.path.join(tmpdir, "key.pem")
    tmp_vault_db = os.path.join(tmpdir, "vault.db")
    keystore = ks.KeyStore(plaintext_fallback_path=tmp_key)

    saved_load_identity = identity.load_or_create_identity
    saved_disc_load = discovery.load_or_create_identity
    saved_unlock_vault = ChatApp._unlock_vault
    saved_setup_name = ChatApp._maybe_setup_name
    saved_db_unlock = VaultDatabase.unlock.__func__

    def _isolated_load(name="peer", identity_file=tmp_id, key_store=None):
        return saved_load_identity(name=name, identity_file=tmp_id, key_store=keystore)

    def _isolated_disc_load(config_path=tmp_id):
        dev = _isolated_load(name="TestUser", identity_file=tmp_id)
        return dev.device_id, dev.name

    async def _isolated_unlock_vault(self):
        # Skip VaultCreateModal/VaultUnlockModal entirely (no ~/.peerc on
        # a fresh CI runner would otherwise hang _setup() forever waiting
        # for interactive passphrase input) — just hand back a fresh DEK.
        return new_dek()

    async def _isolated_setup_name(self):
        # Skip NameSetupModal — keep the "peer" default, same as a real
        # user just not answering it.
        return ""

    def _isolated_db_unlock(cls, dek, vault_db_path=tmp_vault_db, force_fallback=False):
        # Same idea: keep this off the real ~/.peerc/vault.db.
        return saved_db_unlock(cls, dek, vault_db_path=vault_db_path, force_fallback=force_fallback)

    identity.load_or_create_identity = _isolated_load
    discovery.load_or_create_identity = _isolated_disc_load
    ChatApp._unlock_vault = _isolated_unlock_vault
    ChatApp._maybe_setup_name = _isolated_setup_name
    VaultDatabase.unlock = classmethod(_isolated_db_unlock)

    try:
        app = ChatApp()
        async with app.run_test() as pilot:
            await pilot.pause(0.5)  # let on_mount finish (starts discovery, server)

            assert app.peer_id, "peer_id should be set after mount"
            assert app.event_bus is not None, "EventBus should be created"
            assert app.manager is not None, "ConnectionManager should be created"
            assert app.chat_session is not None, "ChatSession should be created"
            assert app.file_session is not None, "FileTransferSession should be created"
            assert app.device_model, "device_model should be auto-detected"

            # Type a command and submit it
            await pilot.click("#input-box")
            await pilot.press(*"/help")
            await pilot.press("enter")
            await pilot.pause(0.2)

            log_widget = app.query_one("#chat-log")
            log_text = "\n".join(str(line) for line in log_widget.lines)
            assert "Commands" in log_text or "/msg" in log_text, f"expected help text in log, got: {log_text!r}"

            print("UI mounted, sessions wired, EventBus active, /help command handled correctly.")

        await app.manager.close_all()
        print("\nSTAGE 5 TEST: PASSED")
    finally:
        identity.load_or_create_identity = saved_load_identity
        discovery.load_or_create_identity = saved_disc_load
        ChatApp._unlock_vault = saved_unlock_vault
        ChatApp._maybe_setup_name = saved_setup_name
        VaultDatabase.unlock = classmethod(saved_db_unlock)
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
