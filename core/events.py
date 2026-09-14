"""core/events.py — Phase 26: Event Architecture.

Provides a decoupled EventBus and typed event dataclasses resolving ARCH-001
(elimination of on_message handler chaining across ConnectionManager, ChatSession,
FileTransferSession, and UI).

Architecture:
    Network (TCP/Encrypted)
           ↓
        EventBus
     ├── Security (SecurityWarning, TrustRequired)
     ├── Chat (ChatReceived, ChatMessageStatusChanged)
     ├── Transfer (FileOffered, FileProgress, TransferCompleted)
     ├── Connection (PeerConnected, PeerDisconnected)
     └── UI (Subscribes to high-level typed events)
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Type,
    TypeVar,
    Union,
)

logger = logging.getLogger("peerc.events")


# ============================================================================
# Base Event
# ============================================================================


@dataclass
class Event:
    """Base class for all peerc system events."""

    timestamp: float = field(default_factory=time.time)

    @property
    def event_name(self) -> str:
        return self.__class__.__name__


E = TypeVar("E", bound=Event)
EventHandler = Union[Callable[[Any], Any], Callable[[Any], Awaitable[Any]]]


# ============================================================================
# Phase 26 Standard Event Types
# ============================================================================


@dataclass
class ChatReceived(Event):
    """Fired when an incoming chat message is received and decrypted."""

    addr_key: str = ""
    sender_id: str = ""       # self-reported, from the message payload — display only
    sender_name: str = ""
    text: str = ""
    message_id: str = ""
    raw_message: dict = field(default_factory=dict)
    # Phase 39.2: the sender's device_id as verified by the transport's
    # own handshake (BUG-004), NOT the message's self-reported sender_id
    # above. This is what persistence should key rows on.
    peer_device_id: Optional[str] = None


@dataclass
class ChatMessageSent(Event):
    """Fired when an outgoing chat message is successfully handed to the
    transport (Phase 39.2 — persistence needs the message's own text,
    which ChatMessageStatusChanged below deliberately doesn't carry)."""

    message_id: str = ""
    addr_key: str = ""
    peer_device_id: Optional[str] = None  # authenticated, via ConnectionManager.get_peer_device_id
    text: str = ""
    timestamp: float = 0.0


@dataclass
class ChatMessageStatusChanged(Event):
    """Fired when an outgoing chat message status updates (e.g. sent, delivered, failed)."""

    message_id: str = ""
    status: str = ""  # "sent" | "delivered" | "failed"
    addr_key: str = ""


@dataclass
class FileOffered(Event):
    """Fired when a peer offers a file for transfer."""

    transfer_id: str = ""
    addr_key: str = ""
    filename: str = ""
    size: int = 0
    checksum: str = ""
    sender_name: str = ""
    sender_id: str = ""


@dataclass
class FileProgress(Event):
    """Fired during active file chunk upload or download."""

    transfer_id: str = ""
    bytes_transferred: int = 0
    total_bytes: int = 0
    is_upload: bool = False

    @property
    def percent(self) -> float:
        if self.total_bytes <= 0:
            return 100.0
        return min(100.0, (self.bytes_transferred / self.total_bytes) * 100.0)


@dataclass
class TransferCompleted(Event):
    """Fired when a file transfer finishes (successfully or with an error)."""

    transfer_id: str = ""
    success: bool = False
    filepath: Optional[str] = None
    error: Optional[str] = None
    # Phase 39.2: enough to write a `transfers` row without a second
    # lookup — filled in from the OutgoingTransfer/IncomingTransfer
    # record that's already in hand wherever this is published.
    addr_key: str = ""
    peer_device_id: Optional[str] = None  # authenticated, via ConnectionManager.get_peer_device_id
    direction: str = ""    # "sent" | "received"
    filename: str = ""
    size: int = 0
    checksum: str = ""
    timestamp: float = 0.0


@dataclass
class PeerConnected(Event):
    """Fired when a transport connection to/from a peer is established."""

    addr_key: str = ""
    peer_id: Optional[str] = None
    incoming: bool = False


@dataclass
class PeerDisconnected(Event):
    """Fired when a connection to a peer terminates."""

    addr_key: str = ""
    peer_id: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class TrustRequired(Event):
    """Fired when peer authentication requires user or policy trust decision."""

    peer_id: str = ""
    peer_name: str = ""
    public_key: str = ""
    addr_key: Optional[str] = None
    reason: str = "first_seen"  # "first_seen" | "key_changed" | "untrusted"


@dataclass
class SecurityWarning(Event):
    """Fired when a security event of WARNING or higher severity occurs."""

    event_type: str = ""
    severity: str = "WARNING"  # "WARNING" | "HIGH" | "CRITICAL"
    details: dict = field(default_factory=dict)
    peer_id: Optional[str] = None


@dataclass
class NetworkMessageReceived(Event):
    """Fired by transport when any raw wire frame arrives and is parsed."""

    addr_key: str = ""
    message: dict = field(default_factory=dict)
    kind: str = "json"  # "json" | "binary"


# ============================================================================
# EventBus
# ============================================================================


class EventBus:
    """Central decoupled asynchronous event dispatcher.

    Supports:
      - Type-specific subscriptions (including inheritance polymorphism)
      - Wildcard subscriptions (receive all events)
      - Both synchronous and asynchronous subscriber callbacks
      - Exception isolation: a failing subscriber will not crash other subscribers
      - Synchronous post() and async publish()
    """

    def __init__(self) -> None:
        self._subscribers: Dict[Type[Event], List[EventHandler]] = {}
        self._wildcard_subscribers: List[EventHandler] = []

    def subscribe(self, event_type: Type[E], handler: EventHandler) -> None:
        """Subscribe a callable to receive instances of event_type or its subclasses."""
        handlers = self._subscribers.setdefault(event_type, [])
        if handler not in handlers:
            handlers.append(handler)

    def unsubscribe(self, event_type: Type[E], handler: EventHandler) -> bool:
        """Unsubscribe a callable from event_type. Returns True if removed."""
        handlers = self._subscribers.get(event_type)
        if handlers and handler in handlers:
            handlers.remove(handler)
            if not handlers:
                self._subscribers.pop(event_type, None)
            return True
        return False

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe a callable to receive all events dispatched through the bus."""
        if handler not in self._wildcard_subscribers:
            self._wildcard_subscribers.append(handler)

    def unsubscribe_all(self, handler: EventHandler) -> bool:
        """Unsubscribe a wildcard callable. Returns True if removed."""
        if handler in self._wildcard_subscribers:
            self._wildcard_subscribers.remove(handler)
            return True
        return False

    def clear(self) -> None:
        """Clear all registered event subscribers."""
        self._subscribers.clear()
        self._wildcard_subscribers.clear()

    def _collect_handlers(self, event: Event) -> List[EventHandler]:
        """Collect all matching handlers for event, deduplicated in registration order."""
        seen: Set[EventHandler] = set()
        matched: List[EventHandler] = []

        # 1. Matching by class hierarchy (exact type and base classes)
        event_cls = type(event)
        for registered_type, handlers in list(self._subscribers.items()):
            if issubclass(event_cls, registered_type):
                for h in handlers:
                    if h not in seen:
                        seen.add(h)
                        matched.append(h)

        # 2. Wildcard subscribers
        for h in self._wildcard_subscribers:
            if h not in seen:
                seen.add(h)
                matched.append(h)

        return matched

    async def publish(self, event: Event) -> None:
        """Publish an event to all registered subscribers asynchronously.

        Catches and logs exceptions raised by individual subscribers to guarantee
        isolation.
        """
        handlers = self._collect_handlers(event)
        for handler in handlers:
            try:
                res = handler(event)
                if inspect.isawaitable(res):
                    await res
            except Exception as exc:
                logger.exception(
                    "Error executing event subscriber %r for %s: %s",
                    handler,
                    event.event_name,
                    exc,
                )

    def post(self, event: Event) -> None:
        """Post an event synchronously.

        If an event loop is currently running, schedules publish() as a background
        task. Otherwise, executes synchronous handlers immediately and logs a warning
        if any asynchronous handler cannot be awaited without a loop.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.publish(event))
        except RuntimeError:
            # No running loop in this thread: invoke synchronous handlers directly.
            handlers = self._collect_handlers(event)
            for handler in handlers:
                try:
                    res = handler(event)
                    if inspect.isawaitable(res):
                        logger.warning(
                            "Cannot await async subscriber %r from sync post() without running event loop",
                            handler,
                        )
                except Exception as exc:
                    logger.exception(
                        "Error executing sync event subscriber %r for %s: %s",
                        handler,
                        event.event_name,
                        exc,
                    )

    @asynccontextmanager
    async def capture(self, *event_types: Type[Event]) -> AsyncIterator[List[Event]]:
        """Context manager to capture emitted events for testing and assertions.

        Usage:
            async with bus.capture(ChatReceived) as captured:
                await session.send_chat(...)
            assert len(captured) == 1
        """
        captured: List[Event] = []

        def _collector(evt: Event) -> None:
            if not event_types or any(isinstance(evt, t) for t in event_types):
                captured.append(evt)

        self.subscribe_all(_collector)
        try:
            yield captured
        finally:
            self.unsubscribe_all(_collector)


# ============================================================================
# Security Events Bridge (Phase 41 -> Phase 26)
# ============================================================================


def bridge_security_events(
    event_bus: EventBus,
    min_severity_name: str = "WARNING",
) -> Callable[[], None]:
    """Bridge security events from core.security.events into EventBus.

    Converts SecurityEvent instances with severity >= min_severity_name into
    SecurityWarning events and dispatches them onto the provided EventBus.

    Returns an unhook callable that unregisters the bridge listener.
    """
    from core.security.events import (
        SecurityEvent,
        SecuritySeverity,
        add_listener,
        remove_listener,
    )

    target_sev = SecuritySeverity(min_severity_name)

    def _on_security_event(sec_evt: SecurityEvent) -> None:
        if sec_evt.severity >= target_sev:
            evt_type_val = (
                sec_evt.event_type
                if isinstance(sec_evt.event_type, str)
                else sec_evt.event_type.value
            )
            warning_evt = SecurityWarning(
                event_type=evt_type_val,
                severity=sec_evt.severity.value,
                details=sec_evt.details,
                peer_id=sec_evt.device_id,
                timestamp=sec_evt.timestamp,
            )
            event_bus.post(warning_evt)

    add_listener(_on_security_event)

    def unhook() -> None:
        remove_listener(_on_security_event)

    return unhook
