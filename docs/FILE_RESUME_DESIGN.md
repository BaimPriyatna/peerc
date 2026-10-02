# File Transfer Resume (Phase 47)

Status: **design resolved, not yet implemented.** Written before any code, per
the project rule for large features (see `ROADMAP.md`, "Phase 45/46 design
(resolved)"). The owner's three product decisions are in section 1; the
remaining choices are mine and are listed in section 12 for review before
sub-step 47.2 starts.

## 1. Decisions

Resolved with the owner:

| # | Question | Decision |
|---|----------|----------|
| 1 | What triggers a resume? | **Automatically when the same file is offered again.** The receiver recognizes the offer (same authenticated sender, filename, size and checksum) and continues; the offer dialog says "resume from X%". No automatic reconnect, no manual `/resume` command. |
| 2 | Older peers? | **Backward compatible.** The resume offset is an optional field. A peer that ignores it sends from byte 0 and the receiver restarts cleanly from zero. Nothing breaks; the saving is simply not realized. |
| 3 | When is a `.part` kept? | **Kept** on connection loss and on transfer failure. **Deleted** when the user rejects/cancels, when the final hash does not match, and **after 7 days**. |

## 2. Current behavior (verified against the code)

- A fresh `transfer_id` is generated per offer. `file_offer` carries
  `filename`, `size`, `checksum` (whole-file SHA-256, computed by the sender
  before offering) and a self-reported `sender_id`.
- `file_accept` carries only `transfer_id`. The validator checks required
  fields only, so an extra optional field is accepted by older peers.
- The receiver writes `<dest>.part`; on `file_done` it re-hashes the **entire**
  `.part` (`sha256_file`) and only then renames it atomically. This means the
  integrity of a resumed file is already covered by the existing end-to-end
  check.
- When an offer is accepted the receiver **deletes any existing `.part`**
  (`cleanup_part_file`) and opens a new one with `"wb"`. The sender always
  streams from offset 0 (`read_chunks` without `start_offset`), and the
  receiver requires `sequence == expected_chunk_index` and
  `offset == bytes_received` starting from 0.
- Every failure path (`_fail_incoming`, `_abort_incoming`) deletes the `.part`.
- **There is no handling of connection loss in `FileTransferSession`.** If the
  TCP connection dies mid-transfer, the incoming transfer stays in
  `_incoming` with an open file handle; the `.part` is only deleted by
  accident when a later offer for the same name is accepted. The manager does
  publish `PeerDisconnected(addr_key, peer_id, reason)` on the event bus.
- There is no way for the user to cancel a transfer in progress; the only user
  decision is Accept/Reject on the offer.
- Building blocks that exist and are unit-tested but unused by the session:
  `core/transfer/resume.py` (`get_part_path`, `get_partial_bytes`,
  `cleanup_part_file`, `finalize_part_file`) and
  `chunker.read_chunks(filepath, start_offset, chunk_size)`, which derives the
  first sequence index as `start_offset // chunk_size`.
- Chunk size is the constant `CHUNK_SIZE = 64 KiB`; the data frame carries both
  a `uint32` sequence and a `uint64` byte offset.

## 3. Goals and non-goals

Goals: continue an interrupted receive without re-sending bytes that were
safely stored; never accept corrupted data silently; keep old peers working;
bound disk usage by partial files.

Non-goals (not in Phase 47): automatic reconnect and re-offer; pause/resume
controls inside a live connection (the FSM states `PAUSED`/`RESUMING` model
that and stay unused); resuming an *outgoing* transfer from the sender's side
without the receiver's cooperation; verifying a prefix hash before resuming
(possible later extension, see section 11); multi-file or parallel transfers.

## 4. Protocol

`file_accept` gains one **optional** field:

```json
{"type": "file_accept", "transfer_id": "...", "resume_offset": 1048576}
```

- Omitted or `0` means "send from the beginning". `make_file_accept(transfer_id,
  resume_offset=0)` adds the field only when it is greater than zero, so the
  message for a fresh transfer is byte-identical to today's.
- Validation: if present it must be an `int` (not `bool`) and `>= 0`.
  `PROTOCOL_VERSION` is unchanged: the field is optional and ignorable.
- The offset is always a multiple of `CHUNK_SIZE` (the receiver aligns it, see
  section 5). The first resumed chunk therefore has
  `sequence == resume_offset // CHUNK_SIZE` and `offset == resume_offset`,
  exactly what `read_chunks(start_offset=resume_offset)` yields.
- Nothing else changes: `file_offer`, `file_done` and `file_complete_ack` are
  untouched.

Compatibility matrix:

| Sender | Receiver | Result |
|--------|----------|--------|
| old | old | unchanged |
| new | old | accept has no offset, sender streams from 0 (unchanged) |
| old | new | receiver asks for an offset, the old sender ignores it and streams from 0; the receiver sees the first chunk at offset 0, **truncates its `.part` to zero and continues from scratch** (section 6) |
| new | new | resume |

## 5. Receiver: remembering and finding a partial

A `.part` file alone has no identity, so each one gets a sidecar
`<dest>.part.meta` (JSON, mode 0600, written atomically via a temp file and
`os.replace`, at most 4 KiB):

```json
{"version": 1, "peer_device_id": "<hex>", "filename": "...", "size": 123,
 "checksum": "<sha256 hex>", "dest_name": "...", "committed": 1048576,
 "created_at": 0.0, "updated_at": 0.0}
```

**Identity.** A partial is reusable only if the **authenticated** device id of
the current peer (`ConnectionManager.get_peer_device_id(addr_key)`, proven by
the handshake) equals `peer_device_id` **and** `filename`, `size` and
`checksum` match. The offer's own `sender_id` is self-reported and is never
used for this. If the authenticated id is unavailable, the transfer is simply
fresh. Binding to the same peer also means a resume offset is only ever
revealed to the peer that already sent those bytes.

**Lookup.** On `file_offer`, after the existing size and disk checks, the
receiver scans `*.part.meta` in the downloads directory (non-recursive; a
handful of small files) for a match. The recorded `dest_name` is used as the
destination (it may differ from `filename` because of collision renaming) after
passing the same `resolve_safe_dest_path` check as any destination. Sidecars
are parsed defensively: size cap, schema and type checks, basenames only,
unknown `version` ignored.

**Durability.** Data is flushed and `fsync`ed, and only then is `committed`
advanced in the sidecar, every `COMMIT_INTERVAL = 4 MiB` received and at every
stop (completion, failure, connection loss). After a crash the file may
contain bytes beyond `committed` (or a zero-filled tail), so they are never
trusted.

**Resume offset.** `resume_offset = committed - (committed % CHUNK_SIZE)`,
also clamped to the real `.part` size. If it is `0`, the partial is discarded
and the transfer is fresh. Otherwise the `.part` is opened `r+b`, truncated to
`resume_offset`, and `bytes_received = resume_offset`,
`expected_chunk_index = resume_offset // CHUNK_SIZE`. The disk-space check
uses the **remaining** bytes (`size - resume_offset`).

**Busy partial.** If a live incoming transfer already holds the partial's
path, a second offer for it is rejected rather than touching it. (Today a
second offer for the same name would delete the live transfer's `.part`; this
removes that hazard.)

## 6. Restart detection (old sender, or invalid offset)

The receiver does not need to be told whether the sender honored the offset; it
sees it on the first chunk. While `resume_offset > 0` and no chunk has arrived:

- first chunk at `offset == resume_offset` (and the matching sequence): resumed;
- first chunk at `sequence == 0` and `offset == 0`: the sender did not resume.
  Truncate the `.part` to zero, set `bytes_received = 0` and
  `expected_chunk_index = 0`, mark the transfer as restarted, tell the user,
  and process the chunk normally;
- anything else: the existing "out-of-order chunk" abort.

## 7. Sender

On `file_accept` the sender reads `resume_offset` (default `0`). It is honored
only if it is an `int`, `0 <= offset <= size` and `offset % CHUNK_SIZE == 0`.
Anything else is logged and **ignored** (the file is sent from 0), which the
receiver handles through section 6. The sender then streams with
`read_chunks(filepath, start_offset=offset, chunk_size=CHUNK_SIZE)`, starts its
progress at `offset`, and sends `file_done` and the whole-file checksum as
today. If `offset == size` no chunk is sent, only `file_done`. If the file on
disk changed since the offer, the final checksum fails exactly as it does for
any transfer.

## 8. Retention policy

| Event | `.part` and sidecar |
|-------|---------------------|
| Connection lost (`PeerDisconnected`) | **keep**, `committed` set to what was fsynced |
| Peer-reported terminal error (`_fail_incoming`) | **keep** |
| Process exit or crash | **keep** (`committed` may lag by up to 4 MiB) |
| User rejects an offer that has a resumable partial | **delete** |
| Mid-transfer user cancel (none exists today; applies if one is added) | **delete** |
| Final SHA-256 does not match | **delete** |
| Protocol violation by the sender (`_abort_incoming`: out-of-order chunk, declared size exceeded) | **delete** |
| Older than 7 days (`PARTIAL_MAX_AGE_SECONDS`, by sidecar `updated_at`) | **delete** |

The expiry sweep removes only a `.part` that has a sidecar, so unrelated or
legacy `.part` files are never touched. It runs on each `file_offer` and once
at application start.

To make the "connection lost" row real, `FileTransferSession` gains
`handle_connection_lost(addr_key)`: for each incoming transfer of that peer it
flushes and fsyncs, records `committed`, closes the handle, moves the
transfer to `FAILED` with error `connection_lost`, and keeps the files; for
each outgoing transfer it calls `_fail_outgoing(..., "connection_lost")`. When
the session has an event bus it subscribes to `PeerDisconnected` and calls
this; the method is public so it can be driven directly in tests.

## 9. User experience

- Offer dialog: when a resumable partial exists, it shows "Resume from X%
  (done of total)" and the accept button reads "Resume"; Reject discards the
  partial and says so. Wording is otherwise unchanged. The
  `on_offer_received(transfer_id, filename, size, sender_name)` callback
  signature does **not** change; the session exposes
  `resume_offset_for(transfer_id)` and `ChatApp` passes the value to
  `FileOfferModal(..., resume_offset=0)`.
- Progress starts at the resumed percentage on both sides.
- If the sender did not resume (section 6) the log says the transfer is
  restarting from the beginning.
- The completion message notes that the transfer was resumed; `TransferCompleted`
  gains an optional `resumed_from: int = 0`.
- There is no separate "restart from zero" button in this phase: rejecting
  discards the partial and the sender re-offers.

## 10. Security and privacy

- **Integrity** is unchanged and end to end: the whole `.part` is SHA-256
  verified before the atomic rename. A corrupted or wrong prefix costs time
  (the file is discarded and must be re-sent) but can never produce a bad file.
- **Binding** to the authenticated device id prevents a different peer from
  probing which files this device holds, and from steering a resume.
- **Sidecars** are local, untrusted input: bounded, schema-checked, basename
  only, never allowed to escape the downloads directory.
- **Disk use** by retained partials is bounded in time (7 days) and by the
  existing size and free-space checks. A hostile peer could still leave many
  partials; a total-size cap is out of scope and noted as a possible follow-up.
- **No new trust**: the sender trusts the receiver's offset only for its own
  transfer; an invalid value is ignored.

## 11. Out of scope, possible later

Prefix-hash verification (the receiver sends the SHA-256 of its first
`resume_offset` bytes and the sender checks it, to detect a corrupt partial
before re-sending the rest); automatic reconnect and re-offer; a "restart from
zero" button; a cap on total retained partial bytes.

## 12. Choices to review (made by me, not the owner)

1. Sidecar file plus 4 MiB `fsync` checkpoints, rather than trusting the raw
   `.part` size.
2. Resume is bound to the authenticated device id, not the self-reported
   `sender_id`.
3. Rejecting an offer that has a resumable partial deletes the partial.
4. Protocol violations by the sender delete the partial; peer-reported terminal
   errors keep it.
5. A second offer for a partial held by a live transfer is rejected.
6. An invalid `resume_offset` is ignored by the sender (full send) instead of
   being a protocol error.
7. No prefix-hash verification in this phase.
8. 64 KiB alignment of the resume offset.
9. Expiry sweep on each offer and at startup, only for `.part` files that have a
   sidecar.
10. No "restart from zero" button.

## 13. Tests and verification

Unit: sidecar store (create/load/match/commit/expire/delete, malformed and
oversized sidecars, path-escape attempts); `make_file_accept` and its
validation; offset alignment and clamping. Integration over real loopback
transfers: interrupt mid-file, re-offer, assert only the remainder is sent and
the checksum matches; old-sender simulation (accept offset ignored) restarts
cleanly; sender ignores invalid offsets; reject deletes the partial; hash
mismatch deletes it; connection loss keeps it; expiry removes it only with a
sidecar; zero-filled tail beyond `committed` is not trusted; busy-partial
rejection; resume of an exact-multiple size and of a zero-length file. Plus the
manual `stage4` script, the Textual flows, benchmarks (A/B on one machine), and
`scripts/verify_wheel.py`.

## 14. Sub-steps

Each sub-step is one commit with its own version (the first of a new phase
raises the minor), and the full suite stays green before every commit.

| Step | Version | Content |
|------|---------|---------|
| 47.1 | `1.23.0` | This design and the roadmap entry (documentation only). |
| 47.2 | `1.23.1` | `core/transfer/partial.py`: the sidecar store, with unit tests. No session change. |
| 47.3 | `1.23.2` | Optional `resume_offset` in `file_accept` plus validation. No session change. |
| 47.4 | `1.23.3` | Receiver: lookup, checkpoints, restart detection, `handle_connection_lost`, retention and expiry. |
| 47.5 | `1.23.4` | Sender: honor and validate the offset, progress from the offset. |
| 47.6 | `1.23.5` | UI: offer dialog, progress, notices, `TransferCompleted.resumed_from`. |
| 47.7 | `1.23.6` | End-to-end tests, wheel check, benchmark A/B, README and design status. |
