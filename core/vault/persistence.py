"""core/vault/persistence.py — Phase 39.2: wiring chat/transfer events
into the encrypted vault database.

This is the piece that actually makes Phase 39 "absorb Phase 27" real:
instead of chat.py/file_transfer.py reaching into a database directly,
they already publish typed events on the EventBus (Phase 26) — this
module just subscribes to the ones that represent something worth
persisting and writes a row.

Deliberately keyed on the *authenticated* peer_device_id
(ConnectionManager.get_peer_device_id(), verified by BUG-004's
handshake) carried on each event, not any self-reported field — a
message/transfer with no authenticated device_id available (e.g. the
connection dropped before the event was fully populated) is skipped
rather than persisted under a guessed identity.
"""

from typing import Optional

from .database import VaultDatabase


class VaultPersistence:
    """Subscribes to chat/transfer events and writes them into a
    VaultDatabase. One instance per running app (or per test) — hold a
    reference for as long as the vault stays unlocked.

    Phase 39.3: vault_db may be set to None while the session is
    locked; writes are skipped until reattach() after re-unlock rather
    than crashing on a closed connection. Events that arrive during the
    lock window are not queued (acceptable — the lock gap is the unlock
    modal, typically seconds).
    """

    def __init__(self, vault_db: Optional[VaultDatabase], event_bus: object):
        self.vault_db = vault_db
        self.event_bus = event_bus

        from core.events import (
            ChatMessageSent,
            ChatMessageStatusChanged,
            ChatReceived,
            TransferCompleted,
        )

        event_bus.subscribe(ChatReceived, self._on_chat_received)
        event_bus.subscribe(ChatMessageSent, self._on_chat_sent)
        event_bus.subscribe(ChatMessageStatusChanged, self._on_chat_status_changed)
        event_bus.subscribe(TransferCompleted, self._on_transfer_completed)

    def reattach(self, vault_db: Optional[VaultDatabase]) -> None:
        """Phase 39.3: point at a freshly unlocked VaultDatabase (or
        None while locked)."""
        self.vault_db = vault_db

    def _on_chat_received(self, evt) -> None:
        if self.vault_db is None or not evt.peer_device_id:
            return  # locked, or no authenticated identity — don't guess
        self.vault_db.conn.execute(
            "INSERT OR REPLACE INTO messages "
            "(message_id, peer_device_id, direction, text, timestamp, status) "
            "VALUES (?, ?, 'received', ?, ?, 'delivered')",
            (evt.message_id, evt.peer_device_id, evt.text, _now()),
        )
        self.vault_db.conn.commit()

    def _on_chat_sent(self, evt) -> None:
        if self.vault_db is None:
            return
        if not evt.peer_device_id:
            return
        self.vault_db.conn.execute(
            "INSERT OR REPLACE INTO messages "
            "(message_id, peer_device_id, direction, text, timestamp, status) "
            "VALUES (?, ?, 'sent', ?, ?, 'pending')",
            (evt.message_id, evt.peer_device_id, evt.text, evt.timestamp or _now()),
        )
        self.vault_db.conn.commit()

    def _on_chat_status_changed(self, evt) -> None:
        # Only updates a row that _on_chat_sent already inserted — a
        # status change for a message this listener never saw sent
        # (e.g. persistence was wired up after the message was already
        # in flight) has nothing to update, which is fine.
        if self.vault_db is None:
            return
        self.vault_db.conn.execute(
            "UPDATE messages SET status = ? WHERE message_id = ?",
            (evt.status, evt.message_id),
        )
        self.vault_db.conn.commit()

    def _on_transfer_completed(self, evt) -> None:
        if self.vault_db is None:
            return
        if not evt.peer_device_id:
            return
        status = "completed" if evt.success else ("rejected" if evt.error == "rejected" else "failed")
        
        # Phase 39.5: handle secure storage mode
        # evt.storage_mode and evt.secure_id are set by the receiver/sender
        storage_mode = getattr(evt, "storage_mode", "normal")
        
        if storage_mode == "secure":
            # For secure files, storage_path is the secure_id (opaque identifier)
            storage_path = getattr(evt, "secure_id", "")
        else:
            # For normal files, storage_path is the actual filesystem path
            storage_path = evt.filepath or ""
        
        self.vault_db.conn.execute(
            "INSERT OR REPLACE INTO transfers "
            "(transfer_id, peer_device_id, direction, filename, size, checksum, "
            "storage_mode, storage_path, status, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evt.transfer_id, evt.peer_device_id, evt.direction, evt.filename,
                evt.size, evt.checksum, storage_mode, storage_path, status,
                evt.timestamp or _now(),
            ),
        )
        self.vault_db.conn.commit()


def _now() -> float:
    import time
    return time.time()
