"""core/transfer/partial.py — sidecar metadata for resumable partial downloads (Phase 47.2).

A `.part` file on its own says nothing about which transfer it belongs to, so
each partial download gets a small JSON sidecar next to it:

    <dest>.part        the bytes received so far
    <dest>.part.meta   who sent it, what it is, and how much is safely on disk

The sidecar is what lets a receiver recognize "the same file, offered again by
the same peer" (docs/FILE_RESUME_DESIGN.md sections 5 and 8). This module only
stores, finds, validates and expires sidecars; it does not touch the transfer
session. Sidecars are local but treated as untrusted input: they are size
capped, schema checked, and may only name a plain file inside their own
directory.

`committed` is the number of bytes known to have been flushed to disk. After a
crash a `.part` can hold more bytes than that (or a zero-filled tail), so
nothing beyond `committed` is ever trusted.
"""

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

from core.transfer.chunker import DEFAULT_CHUNK_SIZE

META_SUFFIX = ".meta"
PART_SUFFIX = ".part"
META_VERSION = 1
MAX_META_BYTES = 4096                      # a real sidecar is a few hundred bytes
COMMIT_INTERVAL = 4 * 1024 * 1024          # fsync + record progress every 4 MiB
PARTIAL_MAX_AGE_SECONDS = 7 * 24 * 3600    # partials expire after 7 days

_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 1024


@dataclass(frozen=True)
class PartialInfo:
    """A validated sidecar plus the paths it describes."""

    meta_path: str
    part_path: str
    dest_name: str
    peer_device_id: str
    filename: str
    size: int
    checksum: str
    committed: int
    created_at: float
    updated_at: float


def meta_path_for(part_path: str) -> str:
    """Path of the sidecar belonging to `part_path`."""
    return part_path + META_SUFFIX


def write_meta(
    part_path: str,
    *,
    peer_device_id: str,
    filename: str,
    size: int,
    checksum: str,
    dest_name: str,
    committed: int,
    created_at: Optional[float] = None,
    now: Optional[float] = None,
) -> PartialInfo:
    """Write (or atomically replace) the sidecar for `part_path`.

    The JSON is written to a temporary file in the same directory and moved
    into place with os.replace(), so a crash never leaves a half-written
    sidecar. The file is private to the user (0600).
    """
    now = time.time() if now is None else now
    created = now if created_at is None else created_at
    meta_path = meta_path_for(part_path)
    record = {
        "version": META_VERSION,
        "peer_device_id": peer_device_id,
        "filename": filename,
        "size": size,
        "checksum": checksum,
        "dest_name": dest_name,
        "committed": committed,
        "created_at": created,
        "updated_at": now,
    }
    directory = os.path.dirname(meta_path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-partial-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass  # best effort (e.g. filesystems without POSIX modes)
        os.replace(tmp, meta_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    info = read_meta(meta_path)
    if info is None:  # the caller passed values the validator rejects
        discard(part_path)
        raise ValueError("refusing to write an invalid partial-download record")
    return info


def _is_plain_name(name: object) -> bool:
    return (
        isinstance(name, str)
        and 0 < len(name) <= _MAX_TEXT
        and name not in (".", "..")
        and os.path.basename(name) == name
        and "/" not in name
        and "\\" not in name
        and "\x00" not in name
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def read_meta(meta_path: str) -> Optional[PartialInfo]:
    """Parse and validate a sidecar; return None if it is missing or unusable."""
    try:
        if os.path.islink(meta_path) or os.path.getsize(meta_path) > MAX_META_BYTES:
            return None
        with open(meta_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != META_VERSION:
        return None

    peer = data.get("peer_device_id")
    filename = data.get("filename")
    dest_name = data.get("dest_name")
    checksum = data.get("checksum")
    size, committed = data.get("size"), data.get("committed")
    created, updated = data.get("created_at"), data.get("updated_at")

    if not (isinstance(peer, str) and 0 < len(peer) <= 128):
        return None
    if not (isinstance(filename, str) and 0 < len(filename) <= _MAX_TEXT):
        return None
    if not _is_plain_name(dest_name):
        return None
    if not (isinstance(checksum, str) and _CHECKSUM_RE.match(checksum)):
        return None
    if not (_is_int(size) and _is_int(committed) and 0 <= committed <= size):
        return None
    if not (_is_number(created) and _is_number(updated)):
        return None

    if not meta_path.endswith(PART_SUFFIX + META_SUFFIX):
        return None
    part_path = meta_path[: -len(META_SUFFIX)]
    if os.path.basename(part_path) != dest_name + PART_SUFFIX:
        return None  # the sidecar must describe the part file it sits next to

    return PartialInfo(
        meta_path=meta_path, part_path=part_path, dest_name=dest_name,
        peer_device_id=peer, filename=filename, size=size, checksum=checksum,
        committed=committed, created_at=float(created), updated_at=float(updated),
    )


def _part_is_usable(part_path: str) -> bool:
    return os.path.isfile(part_path) and not os.path.islink(part_path)


def find_resumable(
    directory: str,
    *,
    peer_device_id: str,
    filename: str,
    size: int,
    checksum: str,
) -> Optional[PartialInfo]:
    """The partial in `directory` that belongs to this exact offer, if any.

    All four of the authenticated peer, filename, size and checksum must match,
    and the `.part` file must still exist as a regular file. If several match,
    the most recently updated one wins.
    """
    best: Optional[PartialInfo] = None
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return None
    for entry in entries:
        if not entry.name.endswith(PART_SUFFIX + META_SUFFIX):
            continue
        info = read_meta(entry.path)
        if info is None:
            continue
        if (info.peer_device_id, info.filename, info.size, info.checksum) != (peer_device_id, filename, size, checksum):
            continue
        if not _part_is_usable(info.part_path):
            continue
        if best is None or info.updated_at > best.updated_at:
            best = info
    return best


def resume_offset_for(info: PartialInfo, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Byte offset at which a resumed transfer may safely continue.

    The smaller of what the sidecar says is committed and what the `.part`
    really holds, rounded down to a chunk boundary (the sender derives the
    first sequence number as offset // chunk_size). 0 means "start over".
    """
    try:
        actual = os.path.getsize(info.part_path)
    except OSError:
        return 0
    trusted = min(info.committed, actual, info.size)
    return trusted - (trusted % chunk_size)


def discard(part_path: str) -> None:
    """Delete a partial download and its sidecar; missing files are fine."""
    for path in (part_path, meta_path_for(part_path)):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def sweep_expired(
    directory: str,
    *,
    now: Optional[float] = None,
    max_age: float = PARTIAL_MAX_AGE_SECONDS,
) -> List[str]:
    """Delete partials older than `max_age`; return the `.part` paths removed.

    Only a `.part` that has a valid sidecar is ever removed. A `.part` without
    one, or with an unreadable sidecar, is left alone: it may be unrelated to
    peerc, and removing it is not this function's call.
    """
    now = time.time() if now is None else now
    removed: List[str] = []
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return removed
    for entry in entries:
        if not entry.name.endswith(PART_SUFFIX + META_SUFFIX):
            continue
        info = read_meta(entry.path)
        if info is None:
            continue
        if now - info.updated_at > max_age:
            discard(info.part_path)
            removed.append(info.part_path)
    return removed
