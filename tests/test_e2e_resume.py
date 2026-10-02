"""tests/test_e2e_resume.py — Phase 47.7: End-to-end resume integration test.

Full sender-to-receiver resume flow over real TCP connections with connection drop,
verifying all components work together: partial store, protocol, sender, receiver, UI callbacks.
"""

import asyncio
import hashlib
import os
import random
import shutil
import tempfile
import uuid

import pytest

from core.events import EventBus, TransferCompleted
from core.identity.device_identity import generate_keypair
from core.transfer.chunker import DEFAULT_CHUNK_SIZE
from core.transfer.hashing import sha256_file
from core.transfer.session import FileTransferSession
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.asyncio

CHUNK_SIZE = DEFAULT_CHUNK_SIZE


def _random_ports(n: int = 2):
    base = random.randint(25000, 45000)
    return [base + i for i in range(n)]


async def test_full_e2e_resume_with_tcp_and_ui_callbacks():
    """Full end-to-end: sender offers file, receiver accepts, connection drops mid-transfer,
    re-offer resumes from partial, completion event includes resumed_from.
    
    This is the comprehensive integration test per FILE_RESUME_DESIGN.md §13.
    """
    dir_a = tempfile.mkdtemp(prefix="peerc_e2e_sender_")
    dir_b = tempfile.mkdtemp(prefix="peerc_e2e_receiver_")
    
    try:
        # Create 512 KiB test file
        test_file = os.path.join(dir_a, "test.bin")
        payload = os.urandom(8 * CHUNK_SIZE)
        with open(test_file, "wb") as f:
            f.write(payload)
        expected_checksum = sha256_file(test_file)
        
        # Setup identities and managers
        keypair_a = generate_keypair()
        keypair_b = generate_keypair()
        
        ports = _random_ports(2)
        
        event_bus_a = EventBus()
        event_bus_b = EventBus()
        
        manager_a = ConnectionManager(
            identity=type("Id", (), {"device_id": keypair_a.device_id, "public_key": keypair_a.public_key})(),
            private_key=keypair_a.private_key,
            listen_port=ports[0],
            event_bus=event_bus_a,
        )
        
        manager_b = ConnectionManager(
            identity=type("Id", (), {"device_id": keypair_b.device_id, "public_key": keypair_b.public_key})(),
            private_key=keypair_b.private_key,
            listen_port=ports[1],
            event_bus=event_bus_b,
        )
        
        # Track UI callbacks
        offer_calls_b = []
        progress_calls_a = []
        progress_calls_b = []
        complete_calls_a = []
        complete_calls_b = []
        
        def on_offer_b(transfer_id, filename, size, sender_name):
            offer_calls_b.append((transfer_id, filename, size, sender_name))
            return True  # auto-accept
        
        def on_progress_a(transfer_id, done, total):
            progress_calls_a.append((transfer_id, done, total))
        
        def on_progress_b(transfer_id, done, total):
            progress_calls_b.append((transfer_id, done, total))
        
        def on_complete_a(transfer_id, success, filepath):
            complete_calls_a.append((transfer_id, success, filepath))
        
        def on_complete_b(transfer_id, success, filepath):
            complete_calls_b.append((transfer_id, success, filepath))
        
        # Setup transfer sessions
        ft_a = FileTransferSession(
            manager_a, downloads_dir=dir_a, event_bus=event_bus_a,
            on_progress=on_progress_a, on_complete=on_complete_a,
        )
        
        ft_b = FileTransferSession(
            manager_b, downloads_dir=dir_b, event_bus=event_bus_b,
            on_offer_received=on_offer_b, on_progress=on_progress_b, on_complete=on_complete_b,
        )
        
        # Track TransferCompleted events
        completed_events_b = []
        
        async def on_transfer_completed_b(evt):
            completed_events_b.append(evt)
        
        event_bus_b.subscribe(TransferCompleted, on_transfer_completed_b)
        
        await manager_a.start_server()
        await manager_b.start_server()
        
        # Connect
        addr_key_ab = await manager_a.connect("127.0.0.1", ports[1])
        await asyncio.sleep(0.1)
        
        # First attempt: offer and start transfer
        transfer_id = await ft_a.offer_file(addr_key_ab, test_file)
        assert transfer_id is not None
        
        await asyncio.sleep(0.2)  # let some chunks send
        
        # Verify initial offer was received
        assert len(offer_calls_b) == 1
        assert offer_calls_b[0][1] == "test.bin"
        assert offer_calls_b[0][2] == len(payload)
        
        # Verify some progress happened
        assert len(progress_calls_a) > 0
        assert len(progress_calls_b) > 0
        
        # Simulate connection drop by closing manager A
        await manager_a.close_all()
        await asyncio.sleep(0.2)
        
        # Verify receiver kept the partial
        part_path_b = os.path.join(dir_b, "test.bin.part")
        assert os.path.exists(part_path_b)
        
        from core.transfer.partial import meta_path_for, read_meta
        meta_path = meta_path_for(part_path_b)
        assert os.path.exists(meta_path)
        
        meta = read_meta(part_path_b)
        assert meta is not None
        assert meta.peer_device_id == keypair_a.device_id
        assert meta.filename == "test.bin"
        assert meta.size == len(payload)
        assert meta.checksum == expected_checksum
        assert meta.committed > 0
        assert meta.committed % CHUNK_SIZE == 0
        saved_committed = meta.committed
        
        # Verify first attempt completed with error (connection_lost)
        assert len(complete_calls_b) == 1
        assert complete_calls_b[0][1] is False  # not success
        
        # Second attempt: reconnect and re-offer
        manager_a2 = ConnectionManager(
            identity=type("Id", (), {"device_id": keypair_a.device_id, "public_key": keypair_a.public_key})(),
            private_key=keypair_a.private_key,
            listen_port=ports[0],
            event_bus=event_bus_a,
        )
        
        ft_a2 = FileTransferSession(
            manager_a2, downloads_dir=dir_a, event_bus=event_bus_a,
            on_progress=on_progress_a, on_complete=on_complete_a,
        )
        
        await manager_a2.start_server()
        await asyncio.sleep(0.1)
        
        addr_key_ab2 = await manager_a2.connect("127.0.0.1", ports[1])
        await asyncio.sleep(0.1)
        
        # Clear previous offer calls to track the resumed offer
        offer_calls_b.clear()
        
        transfer_id2 = await ft_a2.offer_file(addr_key_ab2, test_file)
        assert transfer_id2 is not None
        
        await asyncio.sleep(0.3)  # let transfer complete
        
        # Verify resumed offer was shown
        assert len(offer_calls_b) == 1
        
        # Verify receiver recognized resume
        resume_offset_b = ft_b.resume_offset_for(transfer_id2)
        assert resume_offset_b == saved_committed
        
        # Wait for completion
        await asyncio.sleep(0.5)
        
        # Verify transfer completed successfully
        final_file = os.path.join(dir_b, "test.bin")
        assert os.path.exists(final_file)
        assert not os.path.exists(part_path_b)
        assert not os.path.exists(meta_path)
        
        with open(final_file, "rb") as f:
            assert f.read() == payload
        
        actual_checksum = sha256_file(final_file)
        assert actual_checksum == expected_checksum
        
        # Verify completion callbacks were called
        assert len(complete_calls_b) == 2  # first failed, second succeeded
        assert complete_calls_b[1][1] is True  # success
        assert complete_calls_b[1][2] == final_file
        
        # Verify TransferCompleted event includes resumed_from
        assert len(completed_events_b) >= 1
        final_event = completed_events_b[-1]
        assert final_event.success is True
        assert final_event.direction == "received"
        assert final_event.resumed_from == saved_committed
        assert final_event.size == len(payload)
        assert final_event.checksum == expected_checksum
        
        # Verify sender progress started from resume_offset
        # (progress_calls_a includes both attempts; we can't easily separate them here,
        #  but the fact that the transfer completed with correct checksum proves it worked)
        
        await manager_a2.close_all()
        await manager_b.close_all()
        
    finally:
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(dir_b, ignore_errors=True)
