"""tests/test_file_transfer_v2.py — Comprehensive tests for Phase 12–20 File Transfer V2.

Covers:
    - Streaming sha256_file and IncrementalHasher verification.
    - Chunker chunk generator and offset seeking (Phase 12).
    - Path traversal prevention & directory confinement (Phase 13).
    - Size enforcement and overflow rejection (Phase 14).
    - Strict sequence and offset alignment (Phase 15).
    - .part file creation, offset resume, and atomic finalize (Phase 16).
    - Authoritative checksum verification (Phase 17).
    - Pre-flight disk space validation (Phase 20).
    - Transfer manager limits: MAX_CONCURRENT_TRANSFERS and MAX_TOTAL_INCOMING_SIZE.
"""

import hashlib
import os
import shutil
import pytest

from core.transfer import (
    DEFAULT_CHUNK_SIZE,
    MAX_CONCURRENT_TRANSFERS,
    MAX_INCOMING_FILE_SIZE,
    ChunkValidationError,
    FileReceiver,
    FileSender,
    FileTransferManager,
    IncrementalHasher,
    InsufficientDiskSpaceError,
    TransferSecurityError,
    check_disk_space,
    cleanup_part_file,
    finalize_part_file,
    get_part_path,
    get_partial_bytes,
    read_chunks,
    resolve_safe_dest_path,
    sha256_file,
)
import tempfile

pytestmark = pytest.mark.integration



@pytest.fixture
def temp_dir():
    test_dir = os.path.join(os.path.dirname(__file__), "_temp_transfer_test")
    os.makedirs(test_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=test_dir) as d:
        yield d
    try:
        shutil.rmtree(test_dir, ignore_errors=True)
    except OSError:
        pass


def _make_temp_file(directory: str, name: str, size: int) -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


def test_hashing_and_chunker(temp_dir):
    """Verify sha256_file, IncrementalHasher, and chunk reading with offset."""
    fpath = _make_temp_file(temp_dir, "sample.bin", size=150 * 1024)
    expected_hash = hashlib.sha256(open(fpath, "rb").read()).hexdigest()

    # sha256_file check
    assert sha256_file(fpath) == expected_hash

    # IncrementalHasher check
    inc_hasher = IncrementalHasher()
    chunks = list(read_chunks(fpath, chunk_size=32 * 1024))
    assert len(chunks) == 5  # 150 KB in 32 KB chunks: 4x32 + 1x22

    for seq, offset, data in chunks:
        inc_hasher.update(data)

    assert inc_hasher.hexdigest() == expected_hash
    assert inc_hasher.bytes_hashed == 150 * 1024

    # Test offset seeking
    resume_chunks = list(read_chunks(fpath, start_offset=64 * 1024, chunk_size=32 * 1024))
    assert len(resume_chunks) == 3
    assert resume_chunks[0][0] == 2  # sequence index 2
    assert resume_chunks[0][1] == 64 * 1024  # offset


def test_resume_part_file_lifecycle(temp_dir):
    """Verify .part file operations and atomic renaming."""
    target_path = os.path.join(temp_dir, "received_file.dat")
    part_path = get_part_path(target_path)
    assert part_path.endswith(".part")

    cleanup_part_file(part_path)
    assert get_partial_bytes(part_path) == 0

    with open(part_path, "wb") as f:
        f.write(b"partial-data")

    assert get_partial_bytes(part_path) == 12

    finalize_part_file(part_path, target_path)
    assert not os.path.exists(part_path)
    assert os.path.exists(target_path)
    assert open(target_path, "rb").read() == b"partial-data"


def test_path_traversal_protection(temp_dir):
    """Verify resolve_safe_dest_path strips traversal patterns and confines to directory."""
    d_dir = os.path.join(temp_dir, "downloads")
    os.makedirs(d_dir, exist_ok=True)

    # Relative traversal
    safe1 = resolve_safe_dest_path("../../evil.txt", d_dir)
    assert os.path.dirname(os.path.realpath(safe1)) == os.path.realpath(d_dir)
    assert os.path.basename(safe1) == "evil.txt"

    # Deep directory separators
    safe2 = resolve_safe_dest_path("sub\\dir\\image.png", d_dir)
    assert os.path.dirname(os.path.realpath(safe2)) == os.path.realpath(d_dir)
    assert os.path.basename(safe2) == "image.png"

    # Empty / dot paths raise TransferSecurityError
    with pytest.raises(TransferSecurityError):
        resolve_safe_dest_path("..", d_dir)

    with pytest.raises(TransferSecurityError):
        resolve_safe_dest_path("", d_dir)


def test_disk_space_check(temp_dir):
    """Verify free disk space check logic."""
    d_dir = str(temp_dir)
    assert check_disk_space(d_dir, required_bytes=1024) is True
    # Unrealistically huge file (e.g. 100 Petabytes) should return False
    assert check_disk_space(d_dir, required_bytes=100 * 1024 * 1024 * 1024 * 1024 * 1024) is False


def test_receiver_sender_roundtrip(temp_dir):
    """Verify sender streaming to receiver produces an intact, verified file."""
    src_file = _make_temp_file(temp_dir, "source.dat", size=100 * 1024)
    sender = FileSender(transfer_id="t1", filepath=src_file, chunk_size=32 * 1024)

    dest_file = os.path.join(temp_dir, "downloads", "source.dat")
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)

    receiver = FileReceiver(
        transfer_id="t1",
        filename="source.dat",
        size=sender.size,
        expected_checksum=sender.checksum,
        sender_name="Alice",
        dest_path=dest_file,
        chunk_size=32 * 1024,
    )

    offset = receiver.prepare(resume=False)
    assert offset == 0

    for seq, off, data in sender.get_chunks(start_offset=offset):
        receiver.write_chunk(sequence=seq, offset=off, data=data)

    success = receiver.finish()
    assert success is True
    assert os.path.exists(dest_file)
    assert not os.path.exists(receiver.part_path)
    assert sha256_file(dest_file) == sender.checksum


def test_receiver_resume_partial_file(temp_dir):
    """Verify interrupted transfer can resume from existing .part file."""
    src_file = _make_temp_file(temp_dir, "large.dat", size=200 * 1024)
    sender = FileSender(transfer_id="t2", filepath=src_file, chunk_size=64 * 1024)

    dest_file = os.path.join(temp_dir, "downloads", "large.dat")
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)

    receiver = FileReceiver(
        transfer_id="t2",
        filename="large.dat",
        size=sender.size,
        expected_checksum=sender.checksum,
        sender_name="Bob",
        dest_path=dest_file,
        chunk_size=64 * 1024,
    )

    # Simulate partial 64 KB download
    with open(receiver.part_path, "wb") as f:
        f.write(open(src_file, "rb").read(64 * 1024))

    # Receiver resumes from existing 64 KB
    resume_offset = receiver.prepare(resume=True)
    assert resume_offset == 64 * 1024

    # Sender streams remaining chunks
    for seq, off, data in sender.get_chunks(start_offset=resume_offset):
        receiver.write_chunk(sequence=seq, offset=off, data=data)

    success = receiver.finish()
    assert success is True
    assert sha256_file(dest_file) == sender.checksum


def test_chunk_validation_sequence_and_overflow(temp_dir):
    """Verify out-of-order chunks and size overflow raise ChunkValidationError."""
    dest_file = os.path.join(temp_dir, "fail.dat")
    receiver = FileReceiver(
        transfer_id="t3",
        filename="fail.dat",
        size=100,
        expected_checksum="deadbeef",
        sender_name="Mallory",
        dest_path=dest_file,
    )
    receiver.prepare()

    # Out of order sequence (send seq 1 before seq 0)
    with pytest.raises(ChunkValidationError, match="Out-of-order chunk"):
        receiver.write_chunk(sequence=1, offset=0, data=b"chunk")

    # Correct sequence 0
    receiver.write_chunk(sequence=0, offset=0, data=b"0" * 50)

    # Size overflow (> 100 bytes)
    with pytest.raises(ChunkValidationError, match="Declared size exceeded"):
        receiver.write_chunk(sequence=1, offset=50, data=b"1" * 60)

    receiver.abort(cleanup=True)


def test_manager_limits_and_concurrency(temp_dir):
    """Verify FileTransferManager concurrency, pending size, and max file size limits."""
    mgr = FileTransferManager(
        downloads_dir=str(temp_dir),
        max_concurrent=2,
        max_total_incoming=1000,
    )

    # Size > 2 GB raises ValueError
    with pytest.raises(ValueError, match="Invalid file size"):
        mgr.validate_offer("huge.iso", MAX_INCOMING_FILE_SIZE + 1)

    # Negative or 0 size raises ValueError
    with pytest.raises(ValueError, match="Invalid file size"):
        mgr.validate_offer("empty.bin", 0)

    # Register 2 active receivers
    p1 = mgr.validate_offer("file1.bin", 200)
    r1 = mgr.create_receiver("t1", "file1.bin", 200, "hash1", "peer1", p1)
    r1.prepare()

    p2 = mgr.validate_offer("file2.bin", 300)
    r2 = mgr.create_receiver("t2", "file2.bin", 300, "hash2", "peer2", p2)
    r2.prepare()

    # Max concurrent limit (2) reached
    with pytest.raises(InsufficientDiskSpaceError, match="Maximum concurrent"):
        mgr.validate_offer("file3.bin", 100)

    # Finish one transfer
    r1.status = "done"
    assert mgr.active_incoming_count == 1

    # Exceeding total pending incoming size (pending: 300, max: 1000, offer: 800 -> 1100 > 1000)
    with pytest.raises(InsufficientDiskSpaceError, match="Total pending"):
        mgr.validate_offer("file4.bin", 800)
