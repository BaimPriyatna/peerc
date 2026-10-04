"""tests/test_e2e_resume.py — Phase 47: end-to-end resume over real TCP.

Every scenario runs two (or three) real ConnectionManagers with real Ed25519
handshakes on loopback. Nothing here races the transfer against a timer: the
sender is *frozen* after exactly N data frames (its send_binary blocks), the
receiver is waited on until it has stored those N chunks, and only then is the
connection killed. That makes "interrupted mid-transfer" a fact instead of a
hope, independent of how fast the machine is.

The scenarios follow docs/FILE_RESUME_DESIGN.md: resume after an interruption,
fallback to a restart for a sender that ignores the offset, a corrupted
partial, rejecting an offer, a crash that left a zero-filled tail, an offer for
a file that was already fully received, a busy partial, and a different peer
offering a file with the same name.
"""

import asyncio
import hashlib
import os
import shutil
import socket
import tempfile

import pytest

from core.events import EventBus, TransferCompleted
from core.identity.device_identity import generate_keypair
from core.transfer import partial
from core.transfer.chunker import DEFAULT_CHUNK_SIZE
from core.transfer.session import FileTransferSession
from core.transport.manager import ConnectionManager

pytestmark = pytest.mark.integration

CHUNK = DEFAULT_CHUNK_SIZE
CHUNKS = 8


def free_port():
    """A port the OS has just confirmed is free (random picks collide with ephemeral ports)."""
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 0))
        return probe.getsockname()[1]


async def wait_until(predicate, timeout=10.0, what="condition"):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


class Peer:
    """One side of a transfer: manager + session + recorded callbacks."""

    def __init__(self, name, kp=None):
        self.name = name
        self.kp = kp or generate_keypair()
        self.bus = EventBus()
        self.dir = tempfile.mkdtemp(prefix=f"peerc_e2e_{name}_")
        self.accept = True
        self.offers = []          # (transfer_id, filename, size, resume_offset)
        self.completions = []     # (transfer_id, success, filepath)
        self.progress = []        # (transfer_id, done, total)
        self.events = []          # TransferCompleted events
        self.manager = None
        self.session = None
        self.port = None

    async def start(self, session_cls=FileTransferSession):
        last_error = None
        for _ in range(5):                       # another process can still grab the port in between
            self.port = free_port()
            self.manager = ConnectionManager(
                listen_port=self.port, my_identity=self.kp, my_name=self.name, event_bus=self.bus,
            )
            try:
                await self.manager.start_server()
            except OSError as exc:
                last_error = exc
                continue
            break
        else:
            raise last_error
        self.session = session_cls(
            self.manager, downloads_dir=self.dir, event_bus=self.bus,
            on_offer_received=self._on_offer, on_progress=self._on_progress, on_complete=self._on_complete,
        )

        async def on_completed(evt):
            self.events.append(evt)

        self.bus.subscribe(TransferCompleted, on_completed)
        return self

    async def _on_offer(self, transfer_id, filename, size, sender_name):
        self.offers.append((transfer_id, filename, size, self.session.resume_offset_for(transfer_id)))
        return self.accept

    def _on_progress(self, transfer_id, done, total):
        self.progress.append((transfer_id, done, total))

    def _on_complete(self, transfer_id, success, filepath):
        self.completions.append((transfer_id, success, filepath))

    async def stop(self):
        try:
            await self.manager.close_all()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
async def world():
    peers = []

    async def make(name, kp=None, session_cls=FileTransferSession):
        peer = Peer(name, kp)
        peers.append(peer)
        return await peer.start(session_cls)

    yield make
    for peer in peers:
        await peer.stop()


class Gate:
    """Blocks the sender's (frames+1)-th data frame until released."""

    def __init__(self, manager, frames):
        self.frames, self.sent = frames, 0
        self.reached, self.release = asyncio.Event(), asyncio.Event()
        original = manager.send_binary

        async def gated(addr_key, payload):
            self.sent += 1
            if self.sent > self.frames:
                self.reached.set()
                await self.release.wait()
            return await original(addr_key, payload)

        manager.send_binary = gated


def count_frames(manager):
    frames = []
    original = manager.send_binary

    async def counting(addr_key, payload):
        frames.append(len(payload))
        return await original(addr_key, payload)

    manager.send_binary = counting
    return frames


def hold_file_done(manager):
    """Freeze the sender right before it announces file_done."""
    reached, release = asyncio.Event(), asyncio.Event()
    original = manager.send

    async def gated(addr_key, message):
        if isinstance(message, dict) and message.get("type") == "file_done":
            reached.set()
            await release.wait()
        return await original(addr_key, message)

    manager.send = gated
    return reached, release


def make_file(directory, name="data.bin", size=CHUNKS * CHUNK):
    path = os.path.join(directory, name)
    payload = os.urandom(size)
    with open(path, "wb") as fh:
        fh.write(payload)
    return path, payload


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


async def interrupt(sender, receiver, filepath, frames):
    """Start a transfer, freeze the sender after `frames` chunks, kill the link."""
    gate = Gate(sender.manager, frames)
    addr = await sender.manager.connect_to("127.0.0.1", receiver.port)
    await sender.session.offer_file(addr, filepath)
    await wait_until(gate.reached.is_set, what="sender to reach the freeze point")
    await wait_until(
        lambda: any(t.bytes_received >= frames * CHUNK for t in receiver.session._incoming.values()),
        what="receiver to store the chunks",
    )
    await sender.manager.close_all()
    await wait_until(lambda: not receiver.session._incoming, what="receiver to notice the lost connection")
    gate.release.set()


async def retry(world, sender_kp, receiver, filepath, session_cls=FileTransferSession, wait_for=None):
    """A brand-new sender process (same identity) offers the file again."""
    sender2 = await world("sender2", kp=sender_kp, session_cls=session_cls)
    frames = count_frames(sender2.manager)
    n_before = len(receiver.completions)
    addr = await sender2.manager.connect_to("127.0.0.1", receiver.port)
    tid = await sender2.session.offer_file(addr, filepath)
    await wait_until(lambda: len(receiver.completions) > n_before or sender2.completions,
                     what="the second attempt to finish")
    return sender2, frames, tid


def part_files(directory):
    return sorted(n for n in os.listdir(directory) if n.endswith((".part", ".part.meta")))


# ---------------------------------------------------------------------------

async def test_interrupted_transfer_resumes_and_sends_only_the_rest(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)

    await interrupt(sender, receiver, path, frames=3)

    assert part_files(receiver.dir) == ["data.bin.part", "data.bin.part.meta"], "partial must be kept"
    info = partial.read_meta(os.path.join(receiver.dir, "data.bin.part.meta"))
    assert info.peer_device_id == sender.kp.device_id and info.checksum == sha(payload)
    assert info.committed == 3 * CHUNK
    assert receiver.completions[-1][1] is False and receiver.events[-1].error == "connection_lost"

    sender2, frames, _ = await retry(world, sender.kp, receiver, path)

    assert receiver.offers[-1][3] == 3 * CHUNK, "the offer dialog must know where it will resume"
    assert len(frames) == CHUNKS - 3, "only the remaining chunks may be sent"
    assert receiver.completions[-1][1] is True
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload
    assert part_files(receiver.dir) == []
    assert receiver.events[-1].success and receiver.events[-1].resumed_from == 3 * CHUNK
    assert min(done for _, done, _ in sender2.progress) >= 3 * CHUNK, "sender progress starts at the offset"


async def test_a_sender_that_ignores_the_offset_makes_the_receiver_restart_cleanly(world):
    class OldSender(FileTransferSession):
        async def _handle_accept(self, addr_key, message):
            message = {k: v for k, v in message.items() if k != "resume_offset"}
            return await super()._handle_accept(addr_key, message)

    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)

    _, frames, _ = await retry(world, sender.kp, receiver, path, session_cls=OldSender)

    assert receiver.offers[-1][3] == 3 * CHUNK
    assert len(frames) == CHUNKS, "an old sender streams everything"
    assert receiver.completions[-1][1] is True
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload
    assert receiver.events[-1].resumed_from == 0, "a restart is not reported as a resume"
    assert part_files(receiver.dir) == []


async def test_a_corrupted_partial_is_discarded_and_the_next_attempt_starts_fresh(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)
    with open(os.path.join(receiver.dir, "data.bin.part"), "r+b") as fh:
        fh.seek(10)
        original = fh.read(4)
        fh.seek(10)
        fh.write(bytes(b ^ 0xFF for b in original))          # flip bits inside the committed region

    await retry(world, sender.kp, receiver, path)

    assert receiver.completions[-1][1] is False, "end-to-end SHA-256 must catch the bad prefix"
    assert not os.path.exists(os.path.join(receiver.dir, "data.bin")), "no corrupt file may be delivered"
    assert part_files(receiver.dir) == [], "a failed hash discards the partial"

    _, frames, _ = await retry(world, sender.kp, receiver, path)
    assert len(frames) == CHUNKS and receiver.completions[-1][1] is True
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload


async def test_rejecting_an_offer_that_has_a_partial_deletes_the_partial(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, _ = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)
    assert part_files(receiver.dir)

    receiver.accept = False
    sender2 = await world("sender2", kp=sender.kp)
    addr = await sender2.manager.connect_to("127.0.0.1", receiver.port)
    await sender2.session.offer_file(addr, path)
    await wait_until(lambda: receiver.offers[-1:] and not part_files(receiver.dir), what="the partial to be deleted")

    assert receiver.offers[-1][3] == 3 * CHUNK
    assert part_files(receiver.dir) == []


async def test_bytes_after_the_committed_offset_are_never_trusted(world):
    """A crash can leave a zero-filled tail beyond what was fsynced."""
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)
    with open(os.path.join(receiver.dir, "data.bin.part"), "ab") as fh:
        fh.write(b"\x00" * (2 * CHUNK + 123))

    _, frames, _ = await retry(world, sender.kp, receiver, path)

    assert receiver.offers[-1][3] == 3 * CHUNK
    assert len(frames) == CHUNKS - 3
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload


async def test_a_sidecar_that_lags_behind_the_data_resumes_from_what_it_records(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)
    part = os.path.join(receiver.dir, "data.bin.part")
    info = partial.read_meta(partial.meta_path_for(part))
    partial.write_meta(part, peer_device_id=info.peer_device_id, filename=info.filename, size=info.size,
                       checksum=info.checksum, dest_name=info.dest_name, committed=2 * CHUNK)

    _, frames, _ = await retry(world, sender.kp, receiver, path)

    assert receiver.offers[-1][3] == 2 * CHUNK and len(frames) == CHUNKS - 2
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload


async def test_a_file_that_was_fully_received_but_not_finalized_needs_no_chunks(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir, size=4 * CHUNK)        # exact multiple of the chunk size
    reached, release = hold_file_done(sender.manager)
    addr = await sender.manager.connect_to("127.0.0.1", receiver.port)
    await sender.session.offer_file(addr, path)
    await wait_until(reached.is_set, what="sender to hold file_done")
    await wait_until(lambda: any(t.bytes_received == 4 * CHUNK for t in receiver.session._incoming.values()),
                     what="receiver to hold every chunk")
    await sender.manager.close_all()
    await wait_until(lambda: not receiver.session._incoming, what="connection loss")
    release.set()
    assert partial.read_meta(os.path.join(receiver.dir, "data.bin.part.meta")).committed == 4 * CHUNK

    _, frames, _ = await retry(world, sender.kp, receiver, path)

    assert receiver.offers[-1][3] == 4 * CHUNK
    assert frames == [], "nothing is left to send"
    assert receiver.completions[-1][1] is True
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload


async def test_a_second_offer_for_a_partial_in_use_is_rejected_and_the_first_transfer_survives(world):
    sender = await world("sender")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    gate = Gate(sender.manager, 3)
    addr = await sender.manager.connect_to("127.0.0.1", receiver.port)
    await sender.session.offer_file(addr, path)
    await wait_until(gate.reached.is_set, what="sender to freeze")
    await wait_until(lambda: any(t.bytes_received >= 3 * CHUNK for t in receiver.session._incoming.values()),
                     what="receiver to store 3 chunks")

    second = await sender.session.offer_file(addr, path)             # same peer, same file, first still live
    await wait_until(lambda: any(not ok for _, ok, _ in sender.completions) or second not in sender.session._outgoing,
                     what="the second offer to be refused")
    assert len(receiver.session._incoming) == 1, "the live transfer must not be touched"

    gate.release.set()
    await wait_until(lambda: any(ok for _, ok, _ in receiver.completions), what="the first transfer to finish")
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload
    assert part_files(receiver.dir) == []


async def test_another_peers_offer_with_the_same_name_does_not_destroy_a_partial(world):
    sender = await world("sender")
    other = await world("other")
    receiver = await world("receiver")
    path, payload = make_file(sender.dir)
    await interrupt(sender, receiver, path, frames=3)
    kept = partial.read_meta(os.path.join(receiver.dir, "data.bin.part.meta"))

    other_path, other_payload = make_file(other.dir, name="data.bin")      # different content, same name
    addr = await other.manager.connect_to("127.0.0.1", receiver.port)
    await other.session.offer_file(addr, other_path)
    await wait_until(lambda: any(ok for _, ok, _ in receiver.completions), what="the other peer's transfer")

    delivered = sorted(n for n in os.listdir(receiver.dir) if not n.startswith("data.bin.part"))
    assert len(delivered) == 1 and delivered[0] != "data.bin", f"must not overwrite or reuse the partial: {delivered}"
    assert partial.read_meta(os.path.join(receiver.dir, "data.bin.part.meta")) == kept, "the partial is untouched"

    _, frames, _ = await retry(world, sender.kp, receiver, path)
    assert len(frames) == CHUNKS - 3, "the original sender can still resume"
    with open(os.path.join(receiver.dir, "data.bin"), "rb") as fh:
        assert fh.read() == payload
