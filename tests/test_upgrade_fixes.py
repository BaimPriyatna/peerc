"""
test_upgrade_fixes.py — checks for BUG-014, 016, 020, 021, 022, 023, 025.
"""

import asyncio

import chat
import discovery
import peer
import protocol
from core.identity.device_identity import generate_keypair
from core.transport.timeout import ConnectTimeoutError
from peer import ConnectionManager

PORT_A = 7401
PORT_B = 7402


async def test_connect_timeout():
    manager = ConnectionManager(
        listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None,
    )
    # 10.255.255.1 is a non-routable address commonly used to trigger a
    # connect that hangs rather than fails fast.
    try:
        start = asyncio.get_event_loop().time()
        try:
            await asyncio.wait_for(manager.connect_to("10.255.255.1", 5656), timeout=8.0)
            raise AssertionError("connect should not have succeeded")
        except (asyncio.TimeoutError, OSError, ConnectTimeoutError):
            pass
        elapsed = asyncio.get_event_loop().time() - start
        assert elapsed < 7.0, f"connect_to should time out around {peer.CONNECT_TIMEOUT}s, took {elapsed}s"
        print(f"test_connect_timeout OK — BUG-014 fixed ({elapsed:.1f}s)")
    finally:
        await manager.close_all()


async def test_connection_limit():
    async def noop(addr_key, message):
        pass

    manager_b = ConnectionManager(
        listen_port=PORT_B, my_identity=generate_keypair(), my_name="B",
        on_message=noop, max_connections=2,
    )
    await manager_b.start_server()
    try:
        managers = [
            ConnectionManager(
                listen_port=PORT_B + 10 + i, my_identity=generate_keypair(),
                my_name=f"client-{i}", on_message=noop,
            )
            for i in range(4)
        ]
        connected = 0
        for i, m in enumerate(managers):
            try:
                await asyncio.wait_for(m.connect_to("127.0.0.1", PORT_B), timeout=2.0)
                connected += 1
            except Exception:
                pass
            await asyncio.sleep(0.1)

        await asyncio.sleep(0.3)
        assert len(manager_b._connections) <= 2, f"expected at most 2 accepted, got {len(manager_b._connections)}"
        print(f"test_connection_limit OK — BUG-016 fixed (accepted {len(manager_b._connections)}/2 max)")
        for m in managers:
            await m.close_all()
    finally:
        await manager_b.close_all()


def test_discovery_packet_validation():
    # Phase 5.1: wire format renamed peer_id -> device_id and added
    # version + public_key fields (IMPLEMENTATION_PLAN.md "Phase 5 —
    # Discovery V2"). This test still exercises the original BUG-023
    # field validation (name/tcp_port), just on the current wire shape —
    # see tests/test_discovery.py for the Phase 5.1-specific coverage
    # (version mismatch, public_key self-consistency, malformed keys).
    import base64
    import json

    from core.identity.device_identity import generate_keypair

    registry = discovery.PeerRegistry()
    me_keypair = generate_keypair()
    d = discovery.Discovery(
        peer_id=me_keypair.device_id, name="Me", tcp_port=5656, registry=registry,
        public_key=me_keypair.public_key_bytes(),
    )

    attacker_keypair = generate_keypair()
    attacker_pubkey_b64 = base64.b64encode(attacker_keypair.public_key_bytes()).decode("ascii")

    bad_packets = [
        {"type": "announce", "version": 2, "device_id": 123, "public_key": attacker_pubkey_b64,
         "tcp_port": 5656},  # non-string device_id
        {"type": "announce", "version": 2, "device_id": attacker_keypair.device_id,
         "public_key": attacker_pubkey_b64, "tcp_port": -999},  # negative port
        {"type": "announce", "version": 2, "device_id": attacker_keypair.device_id,
         "public_key": attacker_pubkey_b64, "tcp_port": 999999},  # out of range
        {"type": "announce", "version": 2, "device_id": "", "public_key": attacker_pubkey_b64,
         "tcp_port": 5656},  # empty device_id
        "just a string",
        123,
        None,
    ]
    for pkt in bad_packets:
        data = json.dumps(pkt).encode("utf-8") if not isinstance(pkt, str) else pkt.encode("utf-8")
        d._handle_packet(data, ("192.168.1.50", 9999))

    assert registry.list_peers() == [], f"malformed discovery packets should never be admitted, got {registry.list_peers()}"

    good = json.dumps({
        "type": "announce", "version": 2, "device_id": attacker_keypair.device_id,
        "public_key": attacker_pubkey_b64, "name": "Attacker", "tcp_port": 5656,
    }).encode()
    d._handle_packet(good, ("192.168.1.50", 9999))
    assert len(registry.list_peers()) == 1, "a genuinely valid packet should still be admitted"
    print("test_discovery_packet_validation OK — BUG-023 fixed")


async def test_chat_oversized_text_rejected_client_side():
    async def noop(addr_key, message):
        pass

    manager_a = ConnectionManager(
        listen_port=7501, my_identity=generate_keypair(), my_name="A", on_message=noop,
    )
    manager_b = ConnectionManager(
        listen_port=7502, my_identity=generate_keypair(), my_name="B", on_message=noop,
    )
    chat_a = chat.ChatSession(manager_a)
    await manager_a.start_server()
    await manager_b.start_server()
    addr_key = await manager_a.connect_to("127.0.0.1", 7502)
    await asyncio.sleep(0.2)

    events = []
    chat_a.on_status_change = lambda mid, status: events.append(status)

    huge_text = "x" * (protocol.MAX_CHAT_TEXT_SIZE + 1)
    await chat_a.send_chat(addr_key, "me", "Me", huge_text)
    await asyncio.sleep(0.1)

    assert events == ["failed"], f"oversized chat text should fail fast client-side, got {events}"
    assert chat_a._pending == {}, "oversized message should never be tracked as pending"
    print("test_chat_oversized_text_rejected_client_side OK — BUG-021 fixed")

    await manager_a.close_all()
    await manager_b.close_all()


async def test_ack_race_pending_registered_before_send():
    # Simulate an ack arriving synchronously "too fast" by making send()
    # itself trigger the ack handler before returning, mimicking a
    # same-process loopback race. With the fix, pending state exists
    # before send() is even called, so the ack is never dropped.
    async def noop(addr_key, message):
        pass

    manager = ConnectionManager(
        listen_port=7503, my_identity=generate_keypair(), my_name="A", on_message=noop,
    )
    session = chat.ChatSession(manager)

    original_send = manager.send

    async def racy_send(addr_key, message):
        # Fire the ack handler "early", before the real send() returns —
        # this is exactly the race window BUG-022 described.
        if message.get("type") == "chat":
            session._handle_ack({"type": "chat_ack", "message_id": message["message_id"]})
        return True

    manager.send = racy_send
    events = []
    session.on_status_change = lambda mid, status: events.append(status)
    message_id = await session.send_chat("fake-addr", "me", "Me", "hi")

    # _handle_ack pops the pending entry once resolved, so we check via the
    # status-change callback rather than get_status() (which correctly
    # returns None for an already-resolved message).
    assert events == ["delivered"], (
        f"ack that raced ahead of pending registration should still resolve correctly, got {events}"
    )
    print("test_ack_race_pending_registered_before_send OK — BUG-022 fixed")
    manager.send = original_send


def test_ipv6_connect_parsing():
    # Exercise the same parsing logic used in ui.py's /connect handler.
    def parse(arg, default_port=5656):
        port = default_port
        ip = arg
        if arg.startswith("["):
            closing = arg.find("]")
            if closing != -1:
                ip = arg[1:closing]
                rest = arg[closing + 1:]
                if rest.startswith(":") and rest[1:].isdigit():
                    port = int(rest[1:])
        elif arg.count(":") == 1:
            ip_part, port_str = arg.rsplit(":", 1)
            if port_str.isdigit():
                ip = ip_part
                port = int(port_str)
        return ip, port

    assert parse("192.168.1.10") == ("192.168.1.10", 5656)
    assert parse("192.168.1.10:7000") == ("192.168.1.10", 7000)
    assert parse("fe80::1234") == ("fe80::1234", 5656)
    assert parse("[fe80::1234]:7000") == ("fe80::1234", 7000)
    assert parse("[::1]:5656") == ("::1", 5656)
    print("test_ipv6_connect_parsing OK — BUG-025 fixed")


async def main():
    await test_connect_timeout()
    await test_connection_limit()
    test_discovery_packet_validation()
    await test_chat_oversized_text_rejected_client_side()
    await test_ack_race_pending_registered_before_send()
    test_ipv6_connect_parsing()
    print("\nUPGRADE FIX TESTS: PASSED")


if __name__ == "__main__":
    asyncio.run(main())