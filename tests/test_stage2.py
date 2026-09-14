"""
test_stage2.py — automated sanity check for protocol.py + peer.py.

Starts two ConnectionManagers on localhost, connects one to the other,
sends a chat message each way, and asserts both sides receive it correctly.
Not a full test suite — just a manual verification script for Stage 2.
"""

import asyncio

import protocol
from core.identity.device_identity import generate_keypair
from peer import ConnectionManager

PORT_A = 7001
PORT_B = 7002

received: list[tuple[str, dict]] = []


async def main() -> None:
    async def on_message_a(addr_key: str, message: dict) -> None:
        received.append(("A", message))

    async def on_message_b(addr_key: str, message: dict) -> None:
        received.append(("B", message))

    manager_a = ConnectionManager(
        listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=on_message_a,
    )
    manager_b = ConnectionManager(
        listen_port=PORT_B, my_identity=generate_keypair(), my_name="B", on_message=on_message_b,
    )

    await manager_a.start_server()
    await manager_b.start_server()

    addr_key_from_a = await manager_a.connect_to("127.0.0.1", PORT_B)
    await asyncio.sleep(0.2)  # let B's server register the incoming connection

    msg1 = protocol.make_chat_message("id-a", "Alice", "Halo dari A")
    ok = await manager_a.send(addr_key_from_a, msg1)
    assert ok, "send A->B should succeed"

    await asyncio.sleep(0.3)

    b_addr_keys = list(manager_b._connections.keys())
    assert b_addr_keys, "B should have an incoming connection registered"
    msg2 = protocol.make_chat_message("id-b", "Bob", "Halo balik dari B")
    ok = await manager_b.send(b_addr_keys[0], msg2)
    assert ok, "send B->A should succeed"

    await asyncio.sleep(0.3)

    await manager_a.close_all()
    await manager_b.close_all()

    print("Received messages:")
    for who, msg in received:
        print(f"  [{who}] type={msg['type']} sender={msg['sender_name']} text={msg['text']!r}")

    assert len(received) == 2, f"expected 2 messages, got {len(received)}"
    texts = {msg["text"] for _, msg in received}
    assert texts == {"Halo dari A", "Halo balik dari B"}, f"unexpected texts: {texts}"

    print("\nSTAGE 2 TEST: PASSED")


if __name__ == "__main__":
    asyncio.run(main())
