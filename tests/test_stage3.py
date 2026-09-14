"""
test_stage3.py — automated check for chat.py delivery acknowledgment.

Verifies:
  1. A sent chat message ends up "delivered" once the receiver's auto-ack
     comes back.
  2. A message sent to a peer that never responds (simulated by sending to
     a dead address) is marked "failed" after the ack timeout.
"""

import asyncio

import chat
from core.identity.device_identity import generate_keypair
from peer import ConnectionManager

PORT_A = 7101
PORT_B = 7102

received_by_b: list[dict] = []
status_events: list[tuple[str, str]] = []


async def main() -> None:
    async def on_received_b(addr_key: str, message: dict) -> None:
        received_by_b.append(message)

    def on_status_a(message_id: str, status: str) -> None:
        status_events.append((message_id, status))

    manager_a = ConnectionManager(
        listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None,
    )
    manager_b = ConnectionManager(
        listen_port=PORT_B, my_identity=generate_keypair(), my_name="B", on_message=None,
    )

    chat_a = chat.ChatSession(manager_a, on_status_change=on_status_a)
    chat_b = chat.ChatSession(manager_b, on_chat_received=on_received_b)

    await manager_a.start_server()
    await manager_b.start_server()

    addr_key = await manager_a.connect_to("127.0.0.1", PORT_B)
    await asyncio.sleep(0.2)

    # --- Case 1: normal send, expect "delivered" ---
    message_id = await chat_a.send_chat(addr_key, "id-a", "Alice", "Halo, apa kabar?")
    await asyncio.sleep(0.5)

    assert len(received_by_b) == 1, "B should have received exactly 1 chat message"
    assert received_by_b[0]["text"] == "Halo, apa kabar?"
    assert chat_a.get_status(message_id) is None, "resolved messages are popped from pending"
    assert ("delivered" in [s for _, s in status_events]), f"expected delivered, got {status_events}"
    print(f"Case 1 OK — message {message_id[:8]} delivered. Events: {status_events}")

    # --- Case 2: send to a connection that isn't actually open -> immediate failure ---
    status_events.clear()
    fake_addr_key = "127.0.0.1:9999"  # nothing listening here
    message_id_2 = await chat_a.send_chat(fake_addr_key, "id-a", "Alice", "Ke mana ya ini?")
    await asyncio.sleep(0.1)

    assert status_events == [(message_id_2, "failed")], f"expected immediate failed, got {status_events}"
    print(f"Case 2 OK — message {message_id_2[:8]} failed immediately (not connected). Events: {status_events}")

    # --- Case 3: connected, but receiver never acks (simulate by disabling B's dispatch) ---
    status_events.clear()
    chat.ACK_TIMEOUT = 0.5  # speed up the test instead of waiting the real 5s

    addr_key_2 = await manager_a.connect_to("127.0.0.1", PORT_B)
    # Silence B's auto-ack by swapping its handler to a no-op after this point
    manager_b.on_message = lambda addr_key, message: asyncio.sleep(0)  # drop everything

    message_id_3 = await chat_a.send_chat(addr_key_2, "id-a", "Alice", "Halo? Ada orang?")
    await asyncio.sleep(0.8)  # wait past the shortened ACK_TIMEOUT

    assert status_events == [(message_id_3, "failed")], f"expected timeout failed, got {status_events}"
    print(f"Case 3 OK — message {message_id_3[:8]} timed out (no ack) -> failed. Events: {status_events}")

    await manager_a.close_all()
    await manager_b.close_all()

    print("\nSTAGE 3 TEST: PASSED")


if __name__ == "__main__":
    asyncio.run(main())
