"""tests/test_vault_persistence.py — Phase 39.2: EventBus -> vault DB wiring.

Covers:
  1. ChatReceived with a peer_device_id persists a 'received' message row.
  2. ChatReceived with no peer_device_id (unauthenticated) is skipped.
  3. ChatMessageSent persists a 'sent' message row.
  4. ChatMessageStatusChanged updates that row's status.
  5. TransferCompleted (success) persists a 'completed' transfer row.
  6. TransferCompleted (rejected) persists a 'rejected' transfer row.
  7. TransferCompleted with no peer_device_id is skipped.
"""

import os

from core.events import (
    ChatMessageSent,
    ChatMessageStatusChanged,
    ChatReceived,
    EventBus,
    TransferCompleted,
)
from core.vault.database import VaultDatabase
from core.vault.persistence import VaultPersistence


def _make_vault(tmp_path):
    return VaultDatabase.unlock(
        os.urandom(32), vault_db_path=str(tmp_path / "vault.db"), force_fallback=True,
    )


async def test_chat_received_persisted_with_device_id(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        await bus.publish(ChatReceived(
            addr_key="1.2.3.4:5656", sender_id="claimed", sender_name="Alice",
            text="hi there", message_id="m1", peer_device_id="dev_alice",
        ))
        row = vdb.conn.execute(
            "SELECT peer_device_id, direction, text, status FROM messages WHERE message_id = 'm1'"
        ).fetchone()
        assert row == ("dev_alice", "received", "hi there", "delivered")
    finally:
        vdb.lock()


async def test_chat_received_without_authenticated_id_skipped(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        await bus.publish(ChatReceived(
            addr_key="1.2.3.4:5656", sender_id="claimed", sender_name="Alice",
            text="hi there", message_id="m2", peer_device_id=None,
        ))
        row = vdb.conn.execute("SELECT * FROM messages WHERE message_id = 'm2'").fetchone()
        assert row is None
    finally:
        vdb.lock()


def test_chat_sent_persisted(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        bus.post(ChatMessageSent(
            message_id="m3", addr_key="1.2.3.4:5656", peer_device_id="dev_bob",
            text="outgoing text", timestamp=123.0,
        ))
        row = vdb.conn.execute(
            "SELECT peer_device_id, direction, text, status FROM messages WHERE message_id = 'm3'"
        ).fetchone()
        assert row == ("dev_bob", "sent", "outgoing text", "pending")
    finally:
        vdb.lock()


def test_chat_status_changed_updates_row(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        bus.post(ChatMessageSent(
            message_id="m4", addr_key="1.2.3.4:5656", peer_device_id="dev_bob",
            text="text", timestamp=123.0,
        ))
        bus.post(ChatMessageStatusChanged(message_id="m4", status="delivered", addr_key="1.2.3.4:5656"))
        row = vdb.conn.execute("SELECT status FROM messages WHERE message_id = 'm4'").fetchone()
        assert row == ("delivered",)
    finally:
        vdb.lock()


def test_transfer_completed_success_persisted(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        bus.post(TransferCompleted(
            transfer_id="t1", success=True, filepath="/downloads/photo.png",
            addr_key="1.2.3.4:5656", peer_device_id="dev_carol", direction="received",
            filename="photo.png", size=1024, checksum="abc123", timestamp=99.0,
        ))
        row = vdb.conn.execute(
            "SELECT peer_device_id, direction, filename, size, checksum, storage_mode, status "
            "FROM transfers WHERE transfer_id = 't1'"
        ).fetchone()
        assert row == ("dev_carol", "received", "photo.png", 1024, "abc123", "normal", "completed")
    finally:
        vdb.lock()


def test_transfer_completed_rejected_persisted(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        bus.post(TransferCompleted(
            transfer_id="t2", success=False, error="rejected",
            addr_key="1.2.3.4:5656", peer_device_id="dev_carol", direction="sent",
            filename="doc.pdf", size=500, checksum="def456", timestamp=100.0,
        ))
        row = vdb.conn.execute(
            "SELECT status FROM transfers WHERE transfer_id = 't2'"
        ).fetchone()
        assert row == ("rejected",)
    finally:
        vdb.lock()


def test_transfer_completed_without_authenticated_id_skipped(tmp_path):
    vdb = _make_vault(tmp_path)
    bus = EventBus()
    VaultPersistence(vdb, bus)
    try:
        bus.post(TransferCompleted(
            transfer_id="t3", success=True, peer_device_id=None,
            direction="sent", filename="x.txt", size=1, checksum="x",
        ))
        row = vdb.conn.execute("SELECT * FROM transfers WHERE transfer_id = 't3'").fetchone()
        assert row is None
    finally:
        vdb.lock()
