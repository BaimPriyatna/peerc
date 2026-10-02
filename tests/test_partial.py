"""tests/test_partial.py — Phase 47.2: sidecar store for resumable partial downloads."""

import json
import os
import time

import pytest

from core.transfer import partial
from core.transfer.chunker import DEFAULT_CHUNK_SIZE

pytestmark = pytest.mark.unit

CHUNK = DEFAULT_CHUNK_SIZE
SUM = "ab" * 32
PEER = "d" * 64


def _make(directory, name="report.pdf", *, committed=0, size=10 * CHUNK, part_bytes=None,
          peer=PEER, filename=None, checksum=SUM, now=None, created_at=None):
    """Create <name>.part (+ sidecar) and return the PartialInfo."""
    part = os.path.join(directory, name + ".part")
    with open(part, "wb") as fh:
        fh.write(b"x" * (committed if part_bytes is None else part_bytes))
    return partial.write_meta(
        part, peer_device_id=peer, filename=filename or name, size=size, checksum=checksum,
        dest_name=name, committed=committed, now=now, created_at=created_at,
    )


def _raw_meta(directory, name="report.pdf", **overrides):
    """Write a sidecar by hand so tests can corrupt individual fields."""
    record = {"version": 1, "peer_device_id": PEER, "filename": name, "size": 100, "checksum": SUM,
              "dest_name": name, "committed": 0, "created_at": 1.0, "updated_at": 2.0}
    record.update(overrides)
    part = os.path.join(directory, name + ".part")
    open(part, "wb").close()
    meta = partial.meta_path_for(part)
    with open(meta, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    return meta


# --- write / read -----------------------------------------------------------

def test_write_then_read_roundtrip(tmp_path):
    info = _make(str(tmp_path), committed=3 * CHUNK, now=1000.0, created_at=900.0)
    again = partial.read_meta(info.meta_path)
    assert again == info
    assert (info.peer_device_id, info.filename, info.size, info.checksum) == (PEER, "report.pdf", 10 * CHUNK, SUM)
    assert (info.committed, info.created_at, info.updated_at) == (3 * CHUNK, 900.0, 1000.0)
    assert info.part_path.endswith("report.pdf.part") and info.meta_path == info.part_path + ".meta"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_sidecar_is_private_to_the_user(tmp_path):
    info = _make(str(tmp_path))
    assert (os.stat(info.meta_path).st_mode & 0o777) == 0o600


def test_writes_leave_no_temporary_files_and_replace_atomically(tmp_path):
    d = str(tmp_path)
    _make(d, committed=0, now=1.0)
    info = _make(d, committed=CHUNK, now=2.0, created_at=1.0)
    assert partial.read_meta(info.meta_path).committed == CHUNK
    assert sorted(os.listdir(d)) == ["report.pdf.part", "report.pdf.part.meta"]


def test_write_meta_refuses_values_the_validator_would_reject(tmp_path):
    part = os.path.join(str(tmp_path), "a.bin.part")
    open(part, "wb").close()
    with pytest.raises(ValueError):
        partial.write_meta(part, peer_device_id=PEER, filename="a.bin", size=10, checksum="not-a-hash",
                           dest_name="a.bin", committed=0)
    assert not os.path.exists(part) and not os.path.exists(part + ".meta")


# --- hostile / malformed sidecars -------------------------------------------

@pytest.mark.parametrize("override", [
    {"version": 2}, {"version": "1"}, {"peer_device_id": ""}, {"peer_device_id": 5},
    {"peer_device_id": "x" * 129}, {"filename": ""}, {"filename": None},
    {"checksum": "short"}, {"checksum": "G" * 64}, {"checksum": "AB" * 32},
    {"size": -1}, {"size": "100"}, {"size": True}, {"size": 1.5},
    {"committed": -1}, {"committed": 101}, {"committed": "0"}, {"committed": False},
    {"created_at": "now"}, {"updated_at": None},
])
def test_malformed_fields_are_rejected(tmp_path, override):
    meta = _raw_meta(str(tmp_path), **override)
    assert partial.read_meta(meta) is None


@pytest.mark.parametrize("dest_name", ["../evil", "a/b", "a\\b", "..", ".", "", "x\x00y", "/etc/passwd"])
def test_dest_name_must_be_a_plain_file_name(tmp_path, dest_name):
    meta = _raw_meta(str(tmp_path), dest_name=dest_name)
    assert partial.read_meta(meta) is None


@pytest.mark.parametrize("name, ok", [
    ("report.pdf", True), ("a b (1).txt", True), ("\u00e9t\u00e9.txt", True),
    ("..", False), (".", False), ("", False), ("../x", False), ("a/b", False), ("a\\b", False),
    ("x\x00y", False), ("x" * 1025, False), (None, False), (5, False),
])
def test_plain_name_rule(name, ok):
    """The name rule on its own, not shadowed by the part-file consistency check."""
    assert partial._is_plain_name(name) is ok


@pytest.mark.skipif(os.name == "nt", reason="a backslash is a path separator on Windows")
def test_backslash_name_is_rejected_even_when_the_part_file_matches_it(tmp_path):
    """On POSIX 'a\\b.part' is a legal file name, so the consistency check alone
    would accept this sidecar; only the plain-name rule rejects it."""
    d = str(tmp_path)
    part = os.path.join(d, "a\\b.part")
    open(part, "wb").close()
    record = {"version": 1, "peer_device_id": PEER, "filename": "a", "size": 10, "checksum": SUM,
              "dest_name": "a\\b", "committed": 0, "created_at": 1.0, "updated_at": 2.0}
    with open(part + ".meta", "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    assert partial.read_meta(part + ".meta") is None


def test_sidecar_must_describe_the_part_file_it_sits_next_to(tmp_path):
    meta = _raw_meta(str(tmp_path), "real.bin", dest_name="other.bin")
    assert partial.read_meta(meta) is None


def test_oversized_not_json_and_non_object_sidecars_are_rejected(tmp_path):
    d = str(tmp_path)
    meta = _raw_meta(d)
    with open(meta, "w") as fh:
        fh.write(" " * (partial.MAX_META_BYTES + 1))
    assert partial.read_meta(meta) is None
    with open(meta, "w") as fh:
        fh.write("{not json")
    assert partial.read_meta(meta) is None
    with open(meta, "w") as fh:
        fh.write("[1, 2, 3]")
    assert partial.read_meta(meta) is None
    assert partial.read_meta(os.path.join(d, "missing.part.meta")) is None


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinked_sidecar_and_part_are_ignored(tmp_path):
    d = str(tmp_path)
    real = _make(d, "real.bin", committed=CHUNK)
    link_meta = os.path.join(d, "link.bin.part.meta")
    os.symlink(real.meta_path, link_meta)
    assert partial.read_meta(link_meta) is None

    target = os.path.join(d, "secret.txt")
    open(target, "wb").write(b"s" * CHUNK)
    info = _make(d, "swap.bin", committed=CHUNK)
    os.remove(info.part_path)
    os.symlink(target, info.part_path)
    assert partial.find_resumable(d, peer_device_id=PEER, filename="swap.bin", size=10 * CHUNK, checksum=SUM) is None


# --- finding a resumable partial ---------------------------------------------

def _find(d, **kw):
    args = dict(peer_device_id=PEER, filename="report.pdf", size=10 * CHUNK, checksum=SUM)
    args.update(kw)
    return partial.find_resumable(d, **args)


def test_find_matches_the_exact_offer(tmp_path):
    d = str(tmp_path)
    info = _make(d, committed=2 * CHUNK)
    assert _find(d) == info


@pytest.mark.parametrize("change", [
    {"peer_device_id": "e" * 64}, {"filename": "other.pdf"}, {"size": 10 * CHUNK + 1}, {"checksum": "cd" * 32},
])
def test_find_requires_all_four_identity_fields_to_match(tmp_path, change):
    d = str(tmp_path)
    _make(d, committed=2 * CHUNK)
    assert _find(d, **change) is None


def test_find_needs_the_part_file_to_still_exist(tmp_path):
    d = str(tmp_path)
    info = _make(d, committed=CHUNK)
    os.remove(info.part_path)
    assert _find(d) is None


def test_find_prefers_the_most_recently_updated_match(tmp_path):
    d = str(tmp_path)
    _make(d, "a.pdf", committed=CHUNK, filename="report.pdf", now=100.0)
    newer = _make(d, "b.pdf", committed=2 * CHUNK, filename="report.pdf", now=200.0)
    assert _find(d) == newer


def test_find_ignores_unrelated_files_and_missing_directories(tmp_path):
    d = str(tmp_path)
    open(os.path.join(d, "browser.download.part"), "wb").write(b"z")
    open(os.path.join(d, "notes.meta"), "w").write("{}")
    assert _find(d) is None
    assert _find(os.path.join(d, "does-not-exist")) is None


# --- resume offset --------------------------------------------------------------

@pytest.mark.parametrize("committed, part_bytes, expected", [
    (3 * CHUNK, 3 * CHUNK, 3 * CHUNK),                     # exact multiple
    (3 * CHUNK + 5, 3 * CHUNK + 5, 3 * CHUNK),             # rounded down to a chunk boundary
    (CHUNK - 1, CHUNK - 1, 0),                             # less than one chunk: start over
    (0, 0, 0),
    (5 * CHUNK, 2 * CHUNK + 7, 2 * CHUNK),                 # sidecar claims more than the file holds
    (2 * CHUNK, 9 * CHUNK, 2 * CHUNK),                     # file has bytes beyond `committed`: not trusted
])
def test_resume_offset_trusts_only_committed_bytes_aligned_to_a_chunk(tmp_path, committed, part_bytes, expected):
    info = _make(str(tmp_path), committed=committed, part_bytes=part_bytes)
    assert partial.resume_offset_for(info) == expected


def test_resume_offset_is_zero_when_the_part_file_is_gone(tmp_path):
    info = _make(str(tmp_path), committed=4 * CHUNK)
    os.remove(info.part_path)
    assert partial.resume_offset_for(info) == 0


def test_resume_offset_never_exceeds_the_file_size(tmp_path):
    info = _make(str(tmp_path), "small.bin", size=2 * CHUNK, committed=2 * CHUNK, part_bytes=2 * CHUNK)
    assert partial.resume_offset_for(info) == 2 * CHUNK


# --- discard and expiry -----------------------------------------------------------

def test_discard_removes_both_files_and_tolerates_missing_ones(tmp_path):
    d = str(tmp_path)
    info = _make(d, committed=CHUNK)
    partial.discard(info.part_path)
    assert os.listdir(d) == []
    partial.discard(info.part_path)  # already gone: no error


def test_sweep_removes_only_expired_partials_that_have_a_sidecar(tmp_path):
    d = str(tmp_path)
    now = 10_000_000.0
    old = _make(d, "old.bin", filename="old.bin", now=now - partial.PARTIAL_MAX_AGE_SECONDS - 1)
    fresh = _make(d, "fresh.bin", filename="fresh.bin", now=now - 60)
    edge = _make(d, "edge.bin", filename="edge.bin", now=now - partial.PARTIAL_MAX_AGE_SECONDS)
    orphan = os.path.join(d, "orphan.bin.part")
    open(orphan, "wb").write(b"o")
    bad_meta = _raw_meta(d, "broken.bin", committed=999)         # invalid: committed > size
    ahead = _make(d, "future.bin", filename="future.bin", now=now + 3600)  # clock skew: not expired

    removed = partial.sweep_expired(d, now=now)

    assert removed == [old.part_path]
    remaining = set(os.listdir(d))
    assert "old.bin.part" not in remaining and "old.bin.part.meta" not in remaining
    for kept in (fresh, edge, ahead):
        assert os.path.exists(kept.part_path) and os.path.exists(kept.meta_path)
    assert os.path.exists(orphan), "a .part without a sidecar must never be deleted"
    assert os.path.exists(bad_meta) and os.path.exists(bad_meta[:-5]), "unreadable sidecars are left alone"


def test_sweep_uses_the_real_clock_by_default(tmp_path):
    d = str(tmp_path)
    info = _make(d, now=time.time() - partial.PARTIAL_MAX_AGE_SECONDS - 60)
    assert partial.sweep_expired(d) == [info.part_path]
    assert partial.sweep_expired(os.path.join(d, "nope")) == []
