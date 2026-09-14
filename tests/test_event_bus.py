"""tests/test_event_bus.py — Tests for Phase 26 EventBus and event architecture.

Covers:
  - EventBus sync and async subscriber dispatch
  - Polymorphic inheritance dispatch (subscribing to Event matches all events)
  - Wildcard subscribers (subscribe_all / unsubscribe_all)
  - Unsubscribe functionality
  - Exception isolation among subscribers
  - Async context manager event capture (bus.capture)
  - All 8 Phase 26 event types
  - Security event logging bridge (bridge_security_events)
  - Integration with ConnectionManager, ChatSession, and FileTransferSession without on_message chaining
"""

import asyncio
import os
import shutil
import tempfile
import pytest

from core.events import (
    ChatMessageStatusChanged,
    ChatReceived,
    Event,
    EventBus,
    FileOffered,
    FileProgress,
    NetworkMessageReceived,
    PeerConnected,
    PeerDisconnected,
    SecurityWarning,
    TransferCompleted,
    TrustRequired,
    bridge_security_events,
)
from core.security.events import (
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    emit as emit_security_event,
)
import chat
import file_transfer
from core.identity.device_identity import generate_keypair
from peer import ConnectionManager


@pytest.mark.asyncio
async def test_event_bus_sync_and_async_dispatch():
    """Verify both synchronous and asynchronous handlers receive events."""
    bus = EventBus()
    sync_received = []
    async_received = []

    def sync_handler(evt: ChatReceived):
        sync_received.append(evt)

    async def async_handler(evt: ChatReceived):
        await asyncio.sleep(0.01)
        async_received.append(evt)

    bus.subscribe(ChatReceived, sync_handler)
    bus.subscribe(ChatReceived, async_handler)

    test_evt = ChatReceived(
        addr_key="127.0.0.1:5000",
        sender_id="dev-1",
        sender_name="Alice",
        text="Hello",
        message_id="msg-1",
    )
    await bus.publish(test_evt)

    assert len(sync_received) == 1
    assert sync_received[0].text == "Hello"
    assert len(async_received) == 1
    assert async_received[0].sender_id == "dev-1"


@pytest.mark.asyncio
async def test_event_bus_polymorphic_dispatch():
    """Verify subscribing to Event base class receives all subclass events."""
    bus = EventBus()
    all_events = []

    def handle_any(evt: Event):
        all_events.append(evt)

    bus.subscribe(Event, handle_any)

    chat_evt = ChatReceived(text="hi")
    connected_evt = PeerConnected(addr_key="127.0.0.1:5555")

    await bus.publish(chat_evt)
    await bus.publish(connected_evt)

    assert len(all_events) == 2
    assert isinstance(all_events[0], ChatReceived)
    assert isinstance(all_events[1], PeerConnected)


@pytest.mark.asyncio
async def test_event_bus_wildcard_and_unsubscribe():
    """Verify wildcard subscribers and unsubscribing."""
    bus = EventBus()
    collected = []

    def wildcard(evt: Event):
        collected.append(evt)

    bus.subscribe_all(wildcard)
    await bus.publish(PeerDisconnected(addr_key="127.0.0.1:5555"))
    assert len(collected) == 1

    # Unsubscribe wildcard
    assert bus.unsubscribe_all(wildcard) is True
    await bus.publish(PeerDisconnected(addr_key="127.0.0.1:5555"))
    assert len(collected) == 1  # No increase

    # Type-specific unsubscribe
    type_collected = []
    def specific_handler(evt: TrustRequired):
        type_collected.append(evt)

    bus.subscribe(TrustRequired, specific_handler)
    await bus.publish(TrustRequired(peer_id="p1", peer_name="Peer 1", public_key="abc"))
    assert len(type_collected) == 1

    assert bus.unsubscribe(TrustRequired, specific_handler) is True
    await bus.publish(TrustRequired(peer_id="p1", peer_name="Peer 1", public_key="abc"))
    assert len(type_collected) == 1


@pytest.mark.asyncio
async def test_event_bus_exception_isolation():
    """A failing subscriber does not halt or crash other subscribers."""
    bus = EventBus()
    received_after_fault = []

    def faulty_handler(evt: ChatReceived):
        raise ValueError("Intentional subscriber explosion")

    def safe_handler(evt: ChatReceived):
        received_after_fault.append(evt)

    bus.subscribe(ChatReceived, faulty_handler)
    bus.subscribe(ChatReceived, safe_handler)

    # Should not raise
    await bus.publish(ChatReceived(text="Survives"))

    assert len(received_after_fault) == 1
    assert received_after_fault[0].text == "Survives"


@pytest.mark.asyncio
async def test_event_bus_capture_context_manager():
    """Verify bus.capture() collects emitted events during a block."""
    bus = EventBus()

    async with bus.capture(ChatReceived, PeerConnected) as captured:
        await bus.publish(ChatReceived(text="A"))
        await bus.publish(PeerDisconnected(addr_key="127.0.0.1:1111"))  # Not captured
        await bus.publish(PeerConnected(addr_key="127.0.0.1:2222"))    # Captured

    assert len(captured) == 2
    assert isinstance(captured[0], ChatReceived)
    assert isinstance(captured[1], PeerConnected)


@pytest.mark.asyncio
async def test_all_phase_26_events():
    """Instantiate and verify properties of all 8 Phase 26 events."""
    bus = EventBus()
    dispatched = []

    bus.subscribe_all(lambda e: dispatched.append(e))

    events = [
        ChatReceived(addr_key="1.2.3.4:5", sender_id="s1", sender_name="A", text="t", message_id="m1"),
        FileOffered(transfer_id="t1", addr_key="1.2.3.4:5", filename="f.txt", size=1024, checksum="h", sender_name="A"),
        FileProgress(transfer_id="t1", bytes_transferred=512, total_bytes=1024, is_upload=True),
        TransferCompleted(transfer_id="t1", success=True, filepath="/tmp/f.txt"),
        PeerConnected(addr_key="1.2.3.4:5", incoming=True),
        PeerDisconnected(addr_key="1.2.3.4:5", reason="eof"),
        TrustRequired(peer_id="p1", peer_name="Bob", public_key="pk_hex", reason="first_seen"),
        SecurityWarning(event_type="AUTH_FAILED", severity="WARNING", details={"ip": "1.2.3.4"}),
    ]

    for e in events:
        await bus.publish(e)

    assert len(dispatched) == 8
    # Test progress percent helper
    progress = dispatched[2]
    assert isinstance(progress, FileProgress)
    assert progress.percent == 50.0


@pytest.mark.asyncio
async def test_bridge_security_events():
    """Verify security events with WARNING+ severity are bridged into EventBus as SecurityWarning."""
    bus = EventBus()
    warnings = []

    bus.subscribe(SecurityWarning, lambda w: warnings.append(w))
    unhook = bridge_security_events(bus, min_severity_name="WARNING")

    try:
        # INFO severity: should NOT be bridged
        emit_security_event(
            SecurityEvent(
                event_type=SecurityEventType.ENDPOINT_CHANGED,
                severity=SecuritySeverity.INFO,
                description="Endpoint updated",
                device_id="peer-info",
            )
        )
        await asyncio.sleep(0.02)
        assert len(warnings) == 0

        # WARNING severity: should be bridged
        emit_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description="Auth signature failed",
                device_id="peer-warn",
                details={"reason": "bad_signature"},
            )
        )
        await asyncio.sleep(0.02)
        assert len(warnings) == 1
        assert warnings[0].event_type == "auth_failed"
        assert warnings[0].severity == "WARNING"
        assert warnings[0].peer_id == "peer-warn"

        # HIGH severity: should be bridged
        emit_security_event(
            SecurityEvent(
                event_type=SecurityEventType.REPLAY_DETECTED,
                severity=SecuritySeverity.HIGH,
                description="Replay nonce detected",
                device_id="peer-high",
            )
        )
        await asyncio.sleep(0.02)
        assert len(warnings) == 2
        assert warnings[1].event_type == "replay_detected"
        assert warnings[1].severity == "HIGH"
    finally:
        unhook()


@pytest.mark.asyncio
async def test_event_bus_chat_and_connection_manager_integration():
    """Verify ConnectionManager + ChatSession work over EventBus without on_message chaining."""
    port_a = 9181
    port_b = 9182

    bus_a = EventBus()
    bus_b = EventBus()

    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A", event_bus=bus_a,
    )
    manager_b = ConnectionManager(
        listen_port=port_b, my_identity=generate_keypair(), my_name="B", event_bus=bus_b,
    )

    chat_a = chat.ChatSession(manager_a, event_bus=bus_a)
    chat_b = chat.ChatSession(manager_b, event_bus=bus_b)

    # Verify ARCH-001 fix: neither ChatSession touched manager.on_message!
    assert manager_a.on_message is None
    assert manager_b.on_message is None

    b_received_events = []
    bus_b.subscribe(ChatReceived, lambda e: b_received_events.append(e))

    a_status_events = []
    bus_a.subscribe(ChatMessageStatusChanged, lambda e: a_status_events.append(e))

    await manager_a.start_server()
    await manager_b.start_server()

    try:
        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        msg_id = await chat_a.send_chat(addr_key, "alice", "Alice", "Testing EventBus Chat!")
        await asyncio.sleep(0.3)

        assert len(b_received_events) == 1
        assert b_received_events[0].text == "Testing EventBus Chat!"
        assert b_received_events[0].sender_name == "Alice"

        # Check delivery ack reached A via ChatMessageStatusChanged event
        delivered = [e for e in a_status_events if e.status == "delivered"]
        assert len(delivered) >= 1
        assert delivered[0].message_id == msg_id
    finally:
        await manager_a.close_all()
        await manager_b.close_all()


@pytest.mark.asyncio
async def test_event_bus_file_transfer_integration():
    """Verify FileTransferSession works over EventBus without on_message chaining."""
    port_a = 9281
    port_b = 9282

    bus_a = EventBus()
    bus_b = EventBus()

    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=generate_keypair(), my_name="A", event_bus=bus_a,
    )
    manager_b = ConnectionManager(
        listen_port=port_b, my_identity=generate_keypair(), my_name="B", event_bus=bus_b,
    )

    temp_dir_a = tempfile.mkdtemp(prefix="peerc_bus_ft_a_")
    temp_dir_b = tempfile.mkdtemp(prefix="peerc_bus_ft_b_")

    try:
        ft_a = file_transfer.FileTransferSession(
            manager_a, downloads_dir=temp_dir_a, event_bus=bus_a
        )
        ft_b = file_transfer.FileTransferSession(
            manager_b, downloads_dir=temp_dir_b, event_bus=bus_b
        )

        # Neither session mutated on_message
        assert manager_a.on_message is None
        assert manager_b.on_message is None

        b_offers = []
        b_completes = []
        bus_b.subscribe(FileOffered, lambda e: b_offers.append(e))
        bus_b.subscribe(TransferCompleted, lambda e: b_completes.append(e))

        await manager_a.start_server()
        await manager_b.start_server()

        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        # Create a small file to offer
        src_file = os.path.join(temp_dir_a, "sample.txt")
        with open(src_file, "wb") as f:
            f.write(b"EventBus file transfer content 12345")

        tid = await ft_a.offer_file(addr_key, src_file)
        await asyncio.sleep(0.5)

        assert len(b_offers) == 1
        assert b_offers[0].transfer_id == tid
        assert b_offers[0].filename == "sample.txt"

        assert len(b_completes) == 1
        assert b_completes[0].transfer_id == tid
        assert b_completes[0].success is True
        assert b_completes[0].filepath is not None
        assert os.path.exists(b_completes[0].filepath)
    finally:
        await manager_a.close_all()
        await manager_b.close_all()
        shutil.rmtree(temp_dir_a, ignore_errors=True)
        shutil.rmtree(temp_dir_b, ignore_errors=True)
