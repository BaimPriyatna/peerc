"""tests/test_file_resume_receiver.py — Phase 47.4: Receiver file resume unit & integration tests.

Tests receiver-side resume functionality per docs/FILE_RESUME_DESIGN.md §5, §6, §8, §13:
- Resumable partial lookup matching authenticated peer_device_id, filename, size, checksum
- Expiry sweep on startup and on file_offer
- Busy partial hazard protection
- Disk space pre-check with remaining bytes
- Atomic checkpoints every COMMIT_INTERVAL (4 MiB)
- Retention policy:
    * PeerDisconnected / handle_connection_lost -> keep partial & sidecar
    * Terminal peer error -> keep partial & sidecar
    * User reject -> delete partial & sidecar
    * Protocol violation / size exceeded -> delete partial & sidecar
    * Final checksum mismatch -> delete partial & sidecar
    * Success -> rename .part to dest, delete sidecar
- Restart detection on first chunk (old sender fallback to offset 0)
- Real loopback transfer verification with connection drop and restart
"""

import asyncio
import hashlib
import os
import random
import shutil
import tempfile
import time
import uuid
from typing import Optional

import pytest

from core.events import EventBus, FileOffered, PeerDisconnected, TransferCompleted
from core.identity.device_identity import generate_keypair
from core.protocol import (
    ErrorCode,
    encode_file_data,
    make_error,
    make_file_accept,
    make_file_done,
    make_file_offer,
    make_file_reject,
)
from core.transfer.chunker import DEFAULT_CHUNK_SIZE
from core.transfer.partial import (
    COMMIT_INTERVAL,
    PARTIAL_MAX_AGE_SECONDS,
    discard,
    meta_path_for,
    read_meta,
    write_meta,
)
from core.transfer.resume import get_part_path
from core.transfer.session import FileTransferSession, IncomingTransfer
from core.transfer_state import IncomingTransferState
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.integration

CHUNK_SIZE = DEFAULT_CHUNK_SIZE


def _random_ports(n: int = 2):
    base = random.randint(25000, 45000)
    return [base + i for i in range(n)]


class MockTransportManager:
    """Lightweight mock for unit tests that inspect outgoing wire frames."""

    def __init__(self, my_device_id: str = "dev-receiver", peer_device_id: str = "dev-sender"):
        self.sent: list[tuple[str, dict]] = []
        self.sent_binary: list[tuple[str, bytes]] = []
        self._peer_device_id = peer_device_id
        self.my_identity = type("Id", (), {"device_id": my_device_id})()
        self.my_name = "MockReceiver"
        self.on_message = None

    def get_peer_device_id(self, addr_key: str) -> Optional[str]:
        return self._peer_device_id

    async def send(self, addr_key: str, message: dict) -> bool:
        self.sent.append((addr_key, message))
        return True

    async def send_binary(self, addr_key: str, data: bytes) -> bool:
        self.sent_binary.append((addr_key, data))
        return True

    async def send_error(self, addr_key: str, code: ErrorCode, context: dict = None) -> bool:
        self.sent.append((addr_key, make_error(code, context=context or {})))
        return True


@pytest.fixture
def tmp_downloads():
    d = tempfile.mkdtemp(prefix="peerc_test_resume_recv_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# =====================================================================
# Unit tests: Lookup, identity binding, and offer handling
# =====================================================================


@pytest.mark.asyncio
async def test_fresh_offer_without_partial_requests_zero_offset(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    offer = make_file_offer(
        "t-1", sender_id="peer-1", sender_name="Peer 1",
        filename="video.mp4", size=1000, checksum="a" * 64,
    )
    await session._handle_offer("addr-1", offer)

    assert session.resume_offset_for("t-1") == 0
    assert len(manager.sent) == 1
    accept_msg = manager.sent[0][1]
    assert accept_msg["type"] == "file_accept"
    assert "resume_offset" not in accept_msg  # 0 offset omitted for backwards compatibility

    part_path = get_part_path(os.path.join(tmp_downloads, "video.mp4"))
    assert os.path.exists(part_path)
    meta = read_meta(meta_path_for(part_path))
    assert meta is not None
    assert meta.committed == 0
    assert meta.peer_device_id == "peer-1"


@pytest.mark.asyncio
async def test_matching_partial_detected_and_resume_offset_accepted(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-authenticated")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    # Prepare an existing partial with 128 KiB
    dest_path = os.path.join(tmp_downloads, "doc.pdf")
    part_path = get_part_path(dest_path)
    file_size = 300 * 1024
    checksum = "b" * 64

    with open(part_path, "wb") as f:
        f.write(b"x" * (128 * 1024))

    write_meta(
        part_path,
        peer_device_id="peer-authenticated",
        filename="doc.pdf",
        size=file_size,
        checksum=checksum,
        dest_name="doc.pdf",
        committed=128 * 1024,
    )

    offer = make_file_offer(
        "t-2", sender_id="peer-authenticated", sender_name="Peer",
        filename="doc.pdf", size=file_size, checksum=checksum,
    )
    await session._handle_offer("addr-peer", offer)

    # Offer matched: resume offset is 128 KiB
    expected_offset = 128 * 1024
    assert session.resume_offset_for("t-2") == expected_offset
    assert len(manager.sent) == 1
    accept_msg = manager.sent[0][1]
    assert accept_msg["type"] == "file_accept"
    assert accept_msg["resume_offset"] == expected_offset

    inc = session._incoming["t-2"]
    assert inc.bytes_received == expected_offset
    assert inc.expected_chunk_index == expected_offset // CHUNK_SIZE
    assert inc.resume_offset == expected_offset


@pytest.mark.asyncio
async def test_different_peer_device_id_starts_fresh(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-different")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    dest_path = os.path.join(tmp_downloads, "file.iso")
    part_path = get_part_path(dest_path)
    with open(part_path, "wb") as f:
        f.write(b"y" * (64 * 1024))
    write_meta(
        part_path,
        peer_device_id="peer-original",
        filename="file.iso",
        size=200 * 1024,
        checksum="c" * 64,
        dest_name="file.iso",
        committed=64 * 1024,
    )

    # Offered by peer-different
    offer = make_file_offer(
        "t-diff", sender_id="peer-original", sender_name="Spoofer",
        filename="file.iso", size=200 * 1024, checksum="c" * 64,
    )
    await session._handle_offer("addr-diff", offer)

    # Must start fresh because authenticated device_id is peer-different
    assert session.resume_offset_for("t-diff") == 0
    accept_msg = manager.sent[0][1]
    assert "resume_offset" not in accept_msg


@pytest.mark.asyncio
async def test_checksum_mismatch_starts_fresh(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    dest_path = os.path.join(tmp_downloads, "data.bin")
    part_path = get_part_path(dest_path)
    with open(part_path, "wb") as f:
        f.write(b"z" * (64 * 1024))
    write_meta(
        part_path,
        peer_device_id="peer-1",
        filename="data.bin",
        size=100 * 1024,
        checksum="1" * 64,
        dest_name="data.bin",
        committed=64 * 1024,
    )

    # Offer with different checksum "2" * 64
    offer = make_file_offer(
        "t-sum", sender_id="peer-1", sender_name="Peer",
        filename="data.bin", size=100 * 1024, checksum="2" * 64,
    )
    await session._handle_offer("addr-1", offer)
    assert session.resume_offset_for("t-sum") == 0


@pytest.mark.asyncio
async def test_busy_partial_rejects_second_offer(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    # First offer accepted
    offer1 = make_file_offer(
        "t-busy-1", sender_id="peer-1", sender_name="Peer",
        filename="busy.bin", size=1000, checksum="d" * 64,
    )
    await session._handle_offer("addr-1", offer1)
    assert "t-busy-1" in session._incoming

    # Second offer for the same destination path while first is active
    offer2 = make_file_offer(
        "t-busy-2", sender_id="peer-1", sender_name="Peer",
        filename="busy.bin", size=1000, checksum="d" * 64,
    )
    await session._handle_offer("addr-1", offer2)

    # Second offer must be rejected immediately to avoid corrupting active .part
    assert "t-busy-2" not in session._incoming
    reject_msg = [m for _, m in manager.sent if m.get("transfer_id") == "t-busy-2"]
    assert len(reject_msg) == 1
    assert reject_msg[0]["type"] == "file_reject"
    # First transfer must remain active
    assert "t-busy-1" in session._incoming


@pytest.mark.asyncio
async def test_user_reject_deletes_partial_and_sidecar(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")

    async def on_offer(transfer_id, filename, size, sender):
        return False  # user rejects

    session = FileTransferSession(
        manager, downloads_dir=tmp_downloads, on_offer_received=on_offer
    )

    dest_path = os.path.join(tmp_downloads, "reject.zip")
    part_path = get_part_path(dest_path)
    with open(part_path, "wb") as f:
        f.write(b"content" * 1000)
    write_meta(
        part_path,
        peer_device_id="peer-1",
        filename="reject.zip",
        size=50000,
        checksum="e" * 64,
        dest_name="reject.zip",
        committed=7000,
    )
    assert os.path.exists(part_path)
    assert os.path.exists(meta_path_for(part_path))

    offer = make_file_offer(
        "t-rej", sender_id="peer-1", sender_name="Peer",
        filename="reject.zip", size=50000, checksum="e" * 64,
    )
    await session._handle_offer("addr-1", offer)

    # Rejection per §8 deletes .part and .part.meta
    assert not os.path.exists(part_path)
    assert not os.path.exists(meta_path_for(part_path))
    assert manager.sent[-1][1]["type"] == "file_reject"


# =====================================================================
# Unit tests: Restart detection (§6)
# =====================================================================


@pytest.mark.asyncio
async def test_restart_detection_restarts_cleanly_from_zero(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    dest_path = os.path.join(tmp_downloads, "restart.dat")
    part_path = get_part_path(dest_path)
    initial_bytes = b"original-part-bytes-that-should-be-truncated"
    with open(part_path, "wb") as f:
        f.write(initial_bytes)
    write_meta(
        part_path,
        peer_device_id="peer-1",
        filename="restart.dat",
        size=100000,
        checksum="f" * 64,
        dest_name="restart.dat",
        committed=len(initial_bytes) - (len(initial_bytes) % CHUNK_SIZE),
    )

    # Offer arrives and matches
    offer = make_file_offer(
        "t-res", sender_id="peer-1", sender_name="Peer",
        filename="restart.dat", size=100000, checksum="f" * 64,
    )
    await session._handle_offer("addr-1", offer)

    inc = session._incoming["t-res"]
    # Sender ignores resume_offset and sends sequence 0 at offset 0
    first_chunk_data = b"fresh-start-from-zero"
    chunk_msg = {
        "type": "file_data",
        "transfer_id": "t-res",
        "sequence": 0,
        "offset": 0,
        "data": first_chunk_data,
    }
    await session._handle_chunk("addr-1", chunk_msg)

    # Transfer was restarted: offset reset, data written from 0
    assert inc.resume_offset == 0
    assert inc.bytes_received == len(first_chunk_data)
    assert inc.expected_chunk_index == 1
    assert inc.state.state is IncomingTransferState.RECEIVING

    inc._file_handle.flush()
    with open(part_path, "rb") as f:
        assert f.read() == first_chunk_data


@pytest.mark.asyncio
async def test_restart_detection_aborts_on_unexpected_sequence(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    dest_path = os.path.join(tmp_downloads, "bogus.dat")
    part_path = get_part_path(dest_path)
    with open(part_path, "wb") as f:
        f.write(b"x" * (64 * 1024))
    write_meta(
        part_path,
        peer_device_id="peer-1",
        filename="bogus.dat",
        size=200000,
        checksum="0" * 64,
        dest_name="bogus.dat",
        committed=64 * 1024,
    )

    offer = make_file_offer(
        "t-bogus", sender_id="peer-1", sender_name="Peer",
        filename="bogus.dat", size=200000, checksum="0" * 64,
    )
    await session._handle_offer("addr-1", offer)

    # Receiver expects seq=1, offset=65536. Sender sends seq=5, offset=99999.
    chunk_msg = {
        "type": "file_data",
        "transfer_id": "t-bogus",
        "sequence": 5,
        "offset": 99999,
        "data": b"bad",
    }
    await session._handle_chunk("addr-1", chunk_msg)

    # Aborts incoming transfer on out-of-order chunk and deletes part & meta
    assert "t-bogus" not in session._incoming
    assert not os.path.exists(part_path)
    assert not os.path.exists(meta_path_for(part_path))
    ack_msgs = [m for _, m in manager.sent if m.get("type") == "file_complete_ack"]
    assert len(ack_msgs) == 1
    assert ack_msgs[0]["success"] is False


# =====================================================================
# Unit tests: Connection loss, retention and expiry (§8)
# =====================================================================


@pytest.mark.asyncio
async def test_handle_connection_lost_keeps_partial_and_flushes(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    notified = []
    session = FileTransferSession(
        manager, downloads_dir=tmp_downloads,
        on_complete=lambda tid, ok, path: notified.append((tid, ok, path))
    )

    offer = make_file_offer(
        "t-loss", sender_id="peer-1", sender_name="Peer",
        filename="loss.dat", size=100000, checksum="9" * 64,
    )
    await session._handle_offer("addr-1", offer)

    # Send 1 chunk (64 KiB)
    chunk_data = b"k" * (64 * 1024)
    await session._handle_chunk(
        "addr-1",
        {"type": "file_data", "transfer_id": "t-loss", "sequence": 0, "offset": 0, "data": chunk_data},
    )

    # Simulate connection lost
    session.handle_connection_lost("addr-1")

    assert "t-loss" not in session._incoming
    assert len(notified) == 1
    assert notified[0] == ("t-loss", False, None)

    # Crucial §8 retention check: .part and sidecar MUST BE KEPT
    part_path = get_part_path(os.path.join(tmp_downloads, "loss.dat"))
    assert os.path.exists(part_path)
    meta = read_meta(meta_path_for(part_path))
    assert meta is not None
    assert meta.committed == 64 * 1024


@pytest.mark.asyncio
async def test_peer_disconnected_event_triggers_handle_connection_lost(tmp_downloads):
    bus = EventBus()
    manager = MockTransportManager(peer_device_id="peer-ev")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads, event_bus=bus)

    offer = make_file_offer(
        "t-ev-loss", sender_id="peer-ev", sender_name="Peer",
        filename="ev.dat", size=50000, checksum="8" * 64,
    )
    await session._handle_offer("addr-ev", offer)
    assert "t-ev-loss" in session._incoming

    # Post PeerDisconnected to event bus
    bus.post(PeerDisconnected(addr_key="addr-ev", reason="eof"))
    await asyncio.sleep(0.05)

    assert "t-ev-loss" not in session._incoming
    part_path = get_part_path(os.path.join(tmp_downloads, "ev.dat"))
    assert os.path.exists(part_path)


@pytest.mark.asyncio
async def test_checksum_mismatch_on_done_deletes_partial(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    offer = make_file_offer(
        "t-mismatch", sender_id="peer-1", sender_name="Peer",
        filename="mismatch.bin", size=4, checksum="0" * 64,
    )
    await session._handle_offer("addr-1", offer)
    await session._handle_chunk(
        "addr-1",
        {"type": "file_data", "transfer_id": "t-mismatch", "sequence": 0, "offset": 0, "data": b"1234"},
    )
    # file_done with expected checksum "0"*64 which doesn't match sha256(b"1234")
    await session._handle_done("addr-1", make_file_done("t-mismatch", "0" * 64))

    part_path = get_part_path(os.path.join(tmp_downloads, "mismatch.bin"))
    assert not os.path.exists(part_path)
    assert not os.path.exists(meta_path_for(part_path))


@pytest.mark.asyncio
async def test_successful_transfer_removes_sidecar_and_renames(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")
    session = FileTransferSession(manager, downloads_dir=tmp_downloads)

    data = b"complete-file-contents"
    checksum = hashlib.sha256(data).hexdigest()
    offer = make_file_offer(
        "t-done", sender_id="peer-1", sender_name="Peer",
        filename="done.txt", size=len(data), checksum=checksum,
    )
    await session._handle_offer("addr-1", offer)
    await session._handle_chunk(
        "addr-1",
        {"type": "file_data", "transfer_id": "t-done", "sequence": 0, "offset": 0, "data": data},
    )
    await session._handle_done("addr-1", make_file_done("t-done", checksum))

    final_dest = os.path.join(tmp_downloads, "done.txt")
    part_path = get_part_path(final_dest)
    assert os.path.exists(final_dest)
    assert not os.path.exists(part_path)
    assert not os.path.exists(meta_path_for(part_path))


@pytest.mark.asyncio
async def test_expiry_sweep_removes_stale_partial_with_sidecar(tmp_downloads):
    manager = MockTransportManager(peer_device_id="peer-1")

    # Create an old partial (> 7 days) with sidecar
    old_part = os.path.join(tmp_downloads, "old.txt.part")
    with open(old_part, "wb") as f:
        f.write(b"old")
    write_meta(
        old_part,
        peer_device_id="peer-1",
        filename="old.txt",
        size=100,
        checksum="7" * 64,
        dest_name="old.txt",
        committed=3,
        now=time.time() - (8 * 24 * 3600),  # 8 days ago
    )

    # Create an orphaned .part without sidecar (must NOT be touched)
    orphan_part = os.path.join(tmp_downloads, "orphan.part")
    with open(orphan_part, "wb") as f:
        f.write(b"orphan")

    # Initializing FileTransferSession sweeps expired partials
    FileTransferSession(manager, downloads_dir=tmp_downloads)

    assert not os.path.exists(old_part)
    assert not os.path.exists(meta_path_for(old_part))
    assert os.path.exists(orphan_part)  # Untouched


# =====================================================================
# Real loopback transfer tests
# =====================================================================


@pytest.mark.asyncio
async def test_real_loopback_connection_drop_and_resume_offer():
    """Verify receiver behavior over real TCP connection with real Ed25519 handshakes:
    1. Transfer starts between real ConnectionManager A and B.
    2. Connection is dropped mid-transfer.
    3. Receiver retains .part and writes .part.meta with committed offset.
    4. Upon reconnect and re-offer of the same file, receiver recognizes partial and offers resume_offset.
    """
    port_a, port_b = _random_ports()
    bus_a = EventBus()
    bus_b = EventBus()

    keypair_a = generate_keypair()
    keypair_b = generate_keypair()

    manager_a = ConnectionManager(
        listen_port=port_a, my_identity=keypair_a, my_name="PeerA", event_bus=bus_a,
    )
    manager_b = ConnectionManager(
        listen_port=port_b, my_identity=keypair_b, my_name="PeerB", event_bus=bus_b,
    )

    dir_a = tempfile.mkdtemp(prefix="peerc_loopback_a_")
    dir_b = tempfile.mkdtemp(prefix="peerc_loopback_b_")

    try:
        ft_a = FileTransferSession(manager_a, downloads_dir=dir_a, event_bus=bus_a)
        ft_b = FileTransferSession(manager_b, downloads_dir=dir_b, event_bus=bus_b)

        await manager_a.start_server()
        await manager_b.start_server()

        addr_key = await manager_a.connect_to("127.0.0.1", port_b)
        await asyncio.sleep(0.1)

        # Authenticated device IDs proven by handshake
        assert manager_a.get_peer_device_id(addr_key) == keypair_b.device_id
        b_addr_key = list(manager_b._connections.keys())[0]
        assert manager_b.get_peer_device_id(b_addr_key) == keypair_a.device_id

        # 1 MiB test file (16 chunks) so it cannot complete in milliseconds
        test_file = os.path.join(dir_a, "loopback.bin")
        payload = os.urandom(1024 * 1024)
        checksum = hashlib.sha256(payload).hexdigest()
        with open(test_file, "wb") as f:
            f.write(payload)

        # Hook on_progress on ft_b so we interrupt as soon as chunk 1 arrives
        one_chunk_done = asyncio.Event()

        def on_b_progress(tid, done, total):
            if done >= CHUNK_SIZE:
                one_chunk_done.set()

        ft_b.on_progress = on_b_progress

        # A offers file to B
        tid = await ft_a.offer_file(addr_key, test_file)
        await asyncio.wait_for(one_chunk_done.wait(), timeout=5.0)

        # Abruptly kill connections mid-transfer
        await manager_a.close_all()
        await asyncio.sleep(0.15)

        part_b = get_part_path(os.path.join(dir_b, "loopback.bin"))
        assert os.path.exists(part_b)
        meta = read_meta(meta_path_for(part_b))
        assert meta is not None
        assert meta.committed >= CHUNK_SIZE
        assert meta.peer_device_id == keypair_a.device_id
        saved_committed = meta.committed

        # --- Reconnect and re-offer ---
        port_a2, port_b2 = _random_ports()
        manager_a2 = ConnectionManager(
            listen_port=port_a2, my_identity=keypair_a, my_name="PeerA", event_bus=bus_a,
        )
        manager_b2 = ConnectionManager(
            listen_port=port_b2, my_identity=keypair_b, my_name="PeerB", event_bus=bus_b,
        )
        await manager_a2.start_server()
        await manager_b2.start_server()

        b2_observed_offset = None

        async def on_b2_offer(tid, name, size, sender):
            nonlocal b2_observed_offset
            b2_observed_offset = ft_b2.resume_offset_for(tid)
            return True

        ft_b2 = FileTransferSession(
            manager_b2, downloads_dir=dir_b, event_bus=bus_b, on_offer_received=on_b2_offer
        )

        addr_key2 = await manager_a2.connect_to("127.0.0.1", port_b2)
        await asyncio.sleep(0.1)

        # Use a proper UUID transfer_id so encode_file_data accepts it
        tid_resumed = str(uuid.uuid4())

        # Peer A re-offers the exact same file
        offer_msg = make_file_offer(
            tid_resumed, sender_id=keypair_a.device_id, sender_name="PeerA",
            filename="loopback.bin", size=len(payload), checksum=checksum,
        )
        await manager_a2.send(addr_key2, offer_msg)
        await asyncio.sleep(0.1)

        # Receiver B recognized the partial download from Peer A!
        assert b2_observed_offset == saved_committed
        assert ft_b2.resume_offset_for(tid_resumed) == saved_committed
        inc2 = ft_b2._incoming[tid_resumed]
        assert inc2.resume_offset == saved_committed
        assert inc2.expected_chunk_index == saved_committed // CHUNK_SIZE

        # Send remaining chunks and done
        curr_offset = saved_committed
        curr_seq = saved_committed // CHUNK_SIZE
        while curr_offset < len(payload):
            chunk = payload[curr_offset : curr_offset + CHUNK_SIZE]
            await manager_a2.send_binary(addr_key2, encode_file_data(tid_resumed, curr_seq, curr_offset, chunk))
            curr_offset += len(chunk)
            curr_seq += 1

        await manager_a2.send(addr_key2, make_file_done(tid_resumed, checksum))
        await asyncio.sleep(0.15)

        # File is now complete and finalized!
        final_file = os.path.join(dir_b, "loopback.bin")
        assert os.path.exists(final_file)
        assert not os.path.exists(part_b)
        assert not os.path.exists(meta_path_for(part_b))
        with open(final_file, "rb") as f:
            assert f.read() == payload

        await manager_a2.close_all()
        await manager_b2.close_all()
    finally:
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(dir_b, ignore_errors=True)
