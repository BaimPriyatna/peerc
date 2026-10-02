"""tests/test_file_resume_sender.py — Phase 47.5: Sender file resume unit tests.

Tests sender-side resume functionality per docs/FILE_RESUME_DESIGN.md §7:
- Read resume_offset from file_accept message (default 0)
- Validation: must be int, 0 <= offset <= size, offset % CHUNK_SIZE == 0
- Invalid offset is logged and ignored (send from 0), not a protocol error
- Valid offset: stream from start_offset via read_chunks
- Progress starts from resume_offset
- file_done sends whole-file checksum (unchanged)
- Special case: offset == size sends only file_done, no chunks
"""

import asyncio
import hashlib
import os
import tempfile
import uuid
from typing import Optional
from unittest.mock import AsyncMock

import pytest

from core.protocol import make_file_accept, make_file_offer
from core.transfer.chunker import DEFAULT_CHUNK_SIZE
from core.transfer.hashing import sha256_file
from core.transfer.session import FileTransferSession, OutgoingTransfer
from core.transfer_state import OutgoingTransferState
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.asyncio

CHUNK_SIZE = DEFAULT_CHUNK_SIZE


class MockTransportManager:
    """Minimal mock for sender tests."""

    def __init__(self, my_device_id: str = "dev-sender", peer_device_id: str = "dev-receiver"):
        self.sent: list[tuple[str, dict]] = []
        self.sent_binary: list[tuple[str, bytes]] = []
        self._peer_device_id = peer_device_id
        self.my_identity = type("Id", (), {"device_id": my_device_id})()
        self.my_name = "MockSender"
        self.on_message = None

    def get_peer_device_id(self, addr_key: str) -> Optional[str]:
        return self._peer_device_id

    async def send(self, addr_key: str, message: dict) -> bool:
        self.sent.append((addr_key, message))
        return True

    async def send_binary(self, addr_key: str, data: bytes) -> bool:
        self.sent_binary.append((addr_key, data))
        return True


def _make_test_file(path: str, size: int) -> str:
    """Create a test file with predictable content and return its SHA-256."""
    with open(path, "wb") as f:
        f.write(b"X" * size)
    return sha256_file(path)


async def test_fresh_accept_without_offset_sends_from_zero(tmp_path):
    """A file_accept without resume_offset streams from byte 0."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    checksum = _make_test_file(str(test_file), 3 * CHUNK_SIZE)

    transfer_id = await ft.offer_file("peer1", str(test_file))
    transfer = ft._outgoing[transfer_id]

    # Simulate receiver accepts without resume_offset
    accept = make_file_accept(transfer_id)
    assert "resume_offset" not in accept

    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)  # let _send_chunks run

    assert transfer.resume_offset == 0
    assert len(manager.sent_binary) == 3  # 3 chunks
    # First chunk at offset 0
    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["sequence"] == 0
    assert first_frame["offset"] == 0


async def test_valid_resume_offset_honored(tmp_path):
    """A valid resume_offset in file_accept causes streaming from that offset."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    checksum = _make_test_file(str(test_file), 5 * CHUNK_SIZE)

    transfer_id = await ft.offer_file("peer1", str(test_file))
    transfer = ft._outgoing[transfer_id]

    # Receiver requests resume from 2 * CHUNK_SIZE
    resume_offset = 2 * CHUNK_SIZE
    accept = make_file_accept(transfer_id, resume_offset=resume_offset)
    assert accept["resume_offset"] == resume_offset

    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    assert transfer.resume_offset == resume_offset
    # Should send 3 chunks (from offset 2*CHUNK to end)
    assert len(manager.sent_binary) == 3

    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["sequence"] == 2  # sequence = offset // CHUNK_SIZE
    assert first_frame["offset"] == resume_offset


async def test_invalid_offset_type_ignored(tmp_path):
    """resume_offset that is not an int (e.g., bool, str) is ignored and sender streams from 0."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    checksum = _make_test_file(str(test_file), 2 * CHUNK_SIZE)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    # Malformed accept: resume_offset is a string
    accept = {"type": "file_accept", "transfer_id": transfer_id, "resume_offset": "not_an_int"}
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    transfer = ft._outgoing.get(transfer_id)
    # Transfer might be popped if completed, check if it was created with offset 0
    # Easier: check first chunk
    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["offset"] == 0  # ignored, sent from 0


async def test_invalid_offset_negative_ignored(tmp_path):
    """Negative resume_offset is ignored."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    checksum = _make_test_file(str(test_file), 2 * CHUNK_SIZE)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    accept = {"type": "file_accept", "transfer_id": transfer_id, "resume_offset": -1}
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["offset"] == 0


async def test_invalid_offset_exceeds_size_ignored(tmp_path):
    """resume_offset > file size is ignored."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    size = 2 * CHUNK_SIZE
    checksum = _make_test_file(str(test_file), size)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    accept = {"type": "file_accept", "transfer_id": transfer_id, "resume_offset": size + 1}
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["offset"] == 0


async def test_invalid_offset_not_chunk_aligned_ignored(tmp_path):
    """resume_offset not aligned to CHUNK_SIZE is ignored."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    checksum = _make_test_file(str(test_file), 3 * CHUNK_SIZE)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    # Offset not aligned to CHUNK_SIZE
    accept = {"type": "file_accept", "transfer_id": transfer_id, "resume_offset": CHUNK_SIZE + 1}
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    from core.protocol.binary import decode_file_data
    first_frame = decode_file_data(manager.sent_binary[0][1])
    assert first_frame["offset"] == 0


async def test_offset_equal_to_size_sends_only_file_done(tmp_path):
    """resume_offset == file size sends no chunks, only file_done."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    size = 2 * CHUNK_SIZE
    checksum = _make_test_file(str(test_file), size)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    accept = make_file_accept(transfer_id, resume_offset=size)
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    # No binary frames (chunks)
    assert len(manager.sent_binary) == 0
    # But file_done was sent
    done_msgs = [msg for addr, msg in manager.sent if msg.get("type") == "file_done"]
    assert len(done_msgs) == 1
    assert done_msgs[0]["checksum"] == checksum


async def test_progress_starts_from_resume_offset(tmp_path):
    """Progress notification starts counting from resume_offset, not 0."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)

    progress_calls = []

    def on_progress(transfer_id, bytes_so_far, total):
        progress_calls.append((transfer_id, bytes_so_far, total))

    ft = FileTransferSession(manager, downloads_dir=downloads, on_progress=on_progress)

    test_file = tmp_path / "send.txt"
    size = 4 * CHUNK_SIZE
    checksum = _make_test_file(str(test_file), size)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    resume_offset = 2 * CHUNK_SIZE
    accept = make_file_accept(transfer_id, resume_offset=resume_offset)
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    # Progress should start from 2*CHUNK_SIZE and go to 4*CHUNK_SIZE
    assert len(progress_calls) >= 2
    # First progress call after sending first resumed chunk
    first_call = progress_calls[0]
    assert first_call[1] == resume_offset + CHUNK_SIZE  # 2*CHUNK + CHUNK


async def test_whole_file_checksum_sent_regardless_of_offset(tmp_path):
    """file_done always sends the whole-file checksum, even when resumed."""
    manager = MockTransportManager()
    downloads = str(tmp_path / "downloads")
    os.makedirs(downloads, exist_ok=True)
    ft = FileTransferSession(manager, downloads_dir=downloads)

    test_file = tmp_path / "send.txt"
    size = 3 * CHUNK_SIZE
    expected_checksum = _make_test_file(str(test_file), size)

    transfer_id = await ft.offer_file("peer1", str(test_file))

    resume_offset = CHUNK_SIZE
    accept = make_file_accept(transfer_id, resume_offset=resume_offset)
    await ft._handle_accept("peer1", accept)
    await asyncio.sleep(0.05)

    # file_done sent
    done_msgs = [msg for addr, msg in manager.sent if msg.get("type") == "file_done"]
    assert len(done_msgs) == 1
    # Checksum is of the whole file
    assert done_msgs[0]["checksum"] == expected_checksum


async def test_validation_helper_correctness():
    """Unit test for _is_valid_resume_offset helper."""
    manager = MockTransportManager()
    ft = FileTransferSession(manager, downloads_dir="/tmp")

    file_size = 10 * CHUNK_SIZE

    # Valid cases
    assert ft._is_valid_resume_offset(0, file_size) is True
    assert ft._is_valid_resume_offset(CHUNK_SIZE, file_size) is True
    assert ft._is_valid_resume_offset(5 * CHUNK_SIZE, file_size) is True
    assert ft._is_valid_resume_offset(file_size, file_size) is True

    # Invalid: not int
    assert ft._is_valid_resume_offset("123", file_size) is False
    assert ft._is_valid_resume_offset(1.5, file_size) is False
    assert ft._is_valid_resume_offset(True, file_size) is False  # bool is int subclass, but we reject it

    # Invalid: negative
    assert ft._is_valid_resume_offset(-1, file_size) is False

    # Invalid: exceeds size
    assert ft._is_valid_resume_offset(file_size + 1, file_size) is False

    # Invalid: not chunk-aligned
    assert ft._is_valid_resume_offset(CHUNK_SIZE + 1, file_size) is False
    assert ft._is_valid_resume_offset(CHUNK_SIZE - 1, file_size) is False
