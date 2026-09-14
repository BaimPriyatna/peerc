"""
chat.py — chat message sending with delivery acknowledgment.

Sits on top of peer.ConnectionManager. Adds:
  - status tracking per outgoing message_id: "sent" -> "delivered" | "failed"
  - automatic chat_ack reply whenever an incoming "chat" message is received
  - a timeout that marks a message "failed" if no ack arrives in time

No retry/resend on failure — by design (see project notes): a peer's IP may
have changed since the message was sent, so blind retry isn't reliable.
The caller decides whether to resend manually.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import protocol
from peer import ConnectionManager

ACK_TIMEOUT = 5.0  # seconds to wait for chat_ack before marking a message failed

OnChatReceived = Callable[[str, dict], Awaitable[None]]  # (addr_key, message) -> None
OnStatusChange = Callable[[str, str], None]  # (message_id, new_status) -> None


@dataclass
class SentMessageState:
    message_id: str
    addr_key: str
    status: str = "sent"  # sent -> delivered | failed
    sent_at: float = field(default_factory=time.time)
    timeout_task: Optional[asyncio.Task] = None


class ChatSession:
    def __init__(
        self,
        manager: ConnectionManager,
        on_chat_received: Optional[OnChatReceived] = None,
        on_status_change: Optional[OnStatusChange] = None,
        event_bus: Optional[object] = None,
    ):
        self.manager = manager
        self.on_chat_received = on_chat_received
        self.on_status_change = on_status_change
        self.event_bus = event_bus or getattr(manager, "event_bus", None)
        self._pending: dict[str, SentMessageState] = {}

        if self.event_bus:
            from core.events import NetworkMessageReceived
            self.event_bus.subscribe(NetworkMessageReceived, self._on_network_message)
        else:
            # Wrap the manager's message dispatch so we intercept chat/chat_ack
            # before/alongside whatever the caller already wired up (legacy fallback).
            self._user_on_message = manager.on_message
            manager.on_message = self._dispatch

    async def _on_network_message(self, evt: Any) -> None:
        msg_type = evt.message.get("type")
        if msg_type == "chat":
            await self._handle_incoming_chat(evt.addr_key, evt.message)
        elif msg_type == "chat_ack":
            self._handle_ack(evt.message)

    async def _dispatch(self, addr_key: str, message: dict) -> None:
        msg_type = message.get("type")

        if msg_type == "chat":
            await self._handle_incoming_chat(addr_key, message)
        elif msg_type == "chat_ack":
            self._handle_ack(message)
        else:
            # not ours — pass through to whatever the caller originally set
            if getattr(self, "_user_on_message", None):
                await self._user_on_message(addr_key, message)

    async def _handle_incoming_chat(self, addr_key: str, message: dict) -> None:
        # Auto-acknowledge receipt immediately.
        ack = protocol.make_chat_ack(message["message_id"])
        await self.manager.send(addr_key, ack)

        if self.event_bus:
            from core.events import ChatReceived
            await self.event_bus.publish(
                ChatReceived(
                    addr_key=addr_key,
                    sender_id=message.get("sender_id", ""),
                    sender_name=message.get("sender_name", ""),
                    text=message.get("text", ""),
                    message_id=message.get("message_id", ""),
                    raw_message=message,
                )
            )

        if self.on_chat_received:
            await self.on_chat_received(addr_key, message)

    def _notify_status(self, message_id: str, status: str, addr_key: str = "") -> None:
        if self.event_bus:
            from core.events import ChatMessageStatusChanged
            self.event_bus.post(
                ChatMessageStatusChanged(
                    message_id=message_id,
                    status=status,
                    addr_key=addr_key,
                )
            )
        if self.on_status_change:
            self.on_status_change(message_id, status)

    def _handle_ack(self, message: dict) -> None:
        message_id = message.get("message_id")
        state = self._pending.get(message_id)
        if state is None:
            return  # ack for something we no longer track (e.g. already timed out)

        state.status = "delivered"
        addr_key = state.addr_key
        if state.timeout_task:
            state.timeout_task.cancel()
        self._pending.pop(message_id, None)

        self._notify_status(message_id, "delivered", addr_key)

    async def _timeout_watcher(self, message_id: str) -> None:
        try:
            await asyncio.sleep(ACK_TIMEOUT)
        except asyncio.CancelledError:
            return  # ack arrived in time, nothing to do

        state = self._pending.pop(message_id, None)
        if state is None:
            return  # already resolved
        state.status = "failed"
        self._notify_status(message_id, "failed", state.addr_key)

    async def send_chat(self, addr_key: str, sender_id: str, sender_name: str, text: str) -> str:
        """Send a chat message and start tracking it for delivery ack.

        Returns the message_id so the caller can correlate later status
        changes (via on_status_change) back to this send.
        """
        message = protocol.make_chat_message(sender_id, sender_name, text)
        message_id = message["message_id"]

        if len(text.encode("utf-8", errors="replace")) > protocol.MAX_CHAT_TEXT_SIZE:
            # BUG-021: don't even attempt to send something the receiver's
            # own validate_message() would just reject and disconnect over.
            self._notify_status(message_id, "failed", addr_key)
            return message_id

        # BUG-022: register the pending/timeout state BEFORE sending, not
        # after. On a fast local connection the ack can theoretically race
        # back before `_pending[message_id]` existed, so `_handle_ack`
        # would silently drop a legitimate ack.
        state = SentMessageState(message_id=message_id, addr_key=addr_key)
        self._pending[message_id] = state

        ok = await self.manager.send(addr_key, message)
        if not ok:
            # Not even connected — report as failed immediately, don't track.
            self._pending.pop(message_id, None)
            self._notify_status(message_id, "failed", addr_key)
            return message_id

        if message_id not in self._pending:
            # Already resolved (e.g. an ack raced in while send() was still
            # awaiting) — nothing left to time out.
            return message_id

        state.timeout_task = asyncio.create_task(self._timeout_watcher(message_id))
        return message_id

    def get_status(self, message_id: str) -> Optional[str]:
        state = self._pending.get(message_id)
        return state.status if state else None


if __name__ == "__main__":
    # Manual interactive test, same usage pattern as peer.py:
    #   python3 chat.py server 5555
    #   python3 chat.py client 5555 <server-ip>
    import sys

    import core.identity as identity

    async def _main() -> None:
        role = sys.argv[1]
        port = int(sys.argv[2])
        dev_identity = identity.load_or_create_identity()
        peer_id, name = dev_identity.device_id, dev_identity.name

        async def on_received(addr_key: str, message: dict) -> None:
            print(f"\n<{message['sender_name']}> {message['text']}")

        def on_status(message_id: str, status: str) -> None:
            mark = "\u2713\u2713" if status == "delivered" else "\u2717"
            print(f"  [{mark} {status}] {message_id[:8]}")

        manager = ConnectionManager(
            listen_port=port, my_identity=dev_identity.keypair, my_name=name,
            on_message=None,
        )
        chat = ChatSession(manager, on_chat_received=on_received, on_status_change=on_status)
        await manager.start_server()
        print(f"Listening on port {port} as {name} ({peer_id[:8]})")

        addr_key = None
        if role == "client":
            target_ip = sys.argv[3]
            addr_key = await manager.connect_to(target_ip, port)
            print(f"Connected to {addr_key}")

        loop = asyncio.get_event_loop()
        while True:
            text = await loop.run_in_executor(None, input, "")
            keys = list(manager._connections.keys()) or ([addr_key] if addr_key else [])
            if not keys:
                print("(no connection yet)")
                continue
            for k in keys:
                await chat.send_chat(k, peer_id, name, text)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass