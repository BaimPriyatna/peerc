"""
test_stage4.py — automated check for file_transfer.py.

Case 1: A offers a file to B, B accepts, file arrives at B intact
        (checksum matches).
Case 2: A offers a file to B, B rejects, A is notified and no file
        appears on B's side.
"""

import asyncio
import hashlib
import os
import shutil

import file_transfer
from core.identity.device_identity import generate_keypair
from peer import ConnectionManager

PORT_A = 7201
PORT_B = 7202

DOWNLOADS_B = "/tmp/peerc_test_downloads_b"

progress_events: list[tuple[str, int, int]] = []
complete_events: list[tuple[str, bool, str]] = []


def make_test_file(path: str, size_bytes: int) -> str:
    with open(path, "wb") as f:
        f.write(os.urandom(size_bytes))
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


async def main() -> None:
    shutil.rmtree(DOWNLOADS_B, ignore_errors=True)

    manager_a = ConnectionManager(
        listen_port=PORT_A, my_identity=generate_keypair(), my_name="A", on_message=None,
    )
    manager_b = ConnectionManager(
        listen_port=PORT_B, my_identity=generate_keypair(), my_name="B", on_message=None,
    )

    # --- Case 1: accept, expect successful transfer ---
    async def accept_offer(transfer_id, filename, size, sender_name):
        return True

    def on_progress(transfer_id, done, total):
        progress_events.append((transfer_id, done, total))

    def on_complete(transfer_id, success, filepath):
        complete_events.append((transfer_id, success, filepath))

    ft_a = file_transfer.FileTransferSession(manager_a, downloads_dir="/tmp/peerc_test_downloads_a")
    ft_b = file_transfer.FileTransferSession(
        manager_b, downloads_dir=DOWNLOADS_B,
        on_offer_received=accept_offer, on_progress=on_progress, on_complete=on_complete,
    )

    await manager_a.start_server()
    await manager_b.start_server()

    addr_key = await manager_a.connect_to("127.0.0.1", PORT_B)
    await asyncio.sleep(0.2)

    test_file_path = "/tmp/peerc_test_source.bin"
    expected_checksum = make_test_file(test_file_path, size_bytes=300 * 1024)  # 300 KB, multiple chunks

    transfer_id = await ft_a.offer_file(addr_key, test_file_path)
    await asyncio.sleep(1.0)  # allow chunked transfer to complete

    assert len(complete_events) == 1, f"expected 1 complete event, got {complete_events}"
    tid, success, filepath = complete_events[0]
    assert success, "transfer should have succeeded"
    assert tid == transfer_id

    actual_checksum = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
    assert actual_checksum == expected_checksum, "received file checksum mismatch!"
    assert len(progress_events) > 1, "expected multiple progress events for a multi-chunk file"

    print(f"Case 1 OK — file transferred, checksum verified, {len(progress_events)} progress events")

    # --- Case 2: reject ---
    complete_events.clear()

    async def reject_offer(transfer_id, filename, size, sender_name):
        return False

    ft_b.on_offer_received = reject_offer

    reject_complete: list[tuple] = []
    ft_a.on_complete = lambda tid, ok, path: reject_complete.append((tid, ok, path))

    test_file_path_2 = "/tmp/peerc_test_source2.bin"
    make_test_file(test_file_path_2, size_bytes=1024)
    transfer_id_2 = await ft_a.offer_file(addr_key, test_file_path_2)
    await asyncio.sleep(0.3)

    assert reject_complete == [(transfer_id_2, False, None)], f"expected reject notice, got {reject_complete}"
    assert not os.path.exists(os.path.join(DOWNLOADS_B, "peerc_test_source2.bin"))
    print(f"Case 2 OK — offer rejected, sender notified, no file written on receiver side")

    await manager_a.close_all()
    await manager_b.close_all()

    print("\nSTAGE 4 TEST: PASSED")


if __name__ == "__main__":
    asyncio.run(main())
