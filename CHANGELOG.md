# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.23.1] — Phase 47.2: Partial download store

### Added
- **`core/transfer/partial.py`** [NEW]: the sidecar store from `FILE_RESUME_DESIGN.md` sections 5 and 8. `write_meta` writes `<dest>.part.meta` atomically (temp file + `os.replace`, mode 0600); `read_meta` validates it defensively (4 KiB cap, schema and type checks, SHA-256 shape, plain file names only, the sidecar must describe the `.part` beside it, symlinks refused); `find_resumable` matches an offer on authenticated peer, filename, size **and** checksum and needs a real regular `.part`; `resume_offset_for` trusts only `min(committed, real size)` rounded down to a 64 KiB chunk, so bytes beyond `committed` after a crash are never trusted; `discard`; and `sweep_expired`, which removes only partials that have a valid sidecar and are older than 7 days. Constants: `COMMIT_INTERVAL` 4 MiB, `PARTIAL_MAX_AGE_SECONDS` 7 days. Not connected to the transfer session yet, so there is no behavior change.
- **`tests/test_partial.py`** [NEW] (68, unit): round trip, 0600 permissions, atomic replace with no temp files left, rejection of malformed and hostile sidecars (wrong types, bad checksums, `committed > size`, path-escaping names, oversized, non-JSON, symlinks), exact four-field matching, newest-wins, resume-offset alignment and clamping, and expiry (including that an orphan `.part` or an unreadable sidecar is never deleted and that a clock-skewed future timestamp does not expire).
- **Mutation checks**: four deliberate breakages of `partial.py` (a loosened name rule, trusting the sidecar without comparing the real file size, a sweep that deletes orphan `.part` files, matching without the checksum) were each caught. The first one initially survived: the hostile-name tests were being rejected by the part-file consistency check, so the name rule itself was untested. It now has direct tests, including a POSIX case where only the name rule can reject the sidecar.
- **Full suite**: 914 passed, 1 skipped, 7 deselected (was 846).

## [1.23.0] — Phase 47.1: File transfer resume design

### Added
- **`docs/FILE_RESUME_DESIGN.md`** [NEW]: the resolved design for resuming interrupted file transfers, written before any code. Owner decisions: resume is **automatic when the same file is offered again**; it is **backward compatible** (an optional `resume_offset` in `file_accept`, and a peer that ignores it makes the receiver restart cleanly from zero); a `.part` is **kept** on connection loss or failure and **deleted** on reject, on a final-hash mismatch, and after 7 days. The document also records the remaining design (authenticated-peer binding, a `.part.meta` sidecar with `fsync` checkpoints, restart detection on the first chunk, a retention table, UX, security analysis, test plan and the seven implementation sub-steps 47.2-47.7) and lists ten choices made without the owner for review.
- **`docs/ROADMAP.md`**: a *Phase 47 design (resolved)* section, the version-table row and the entry in the recommended order.

### Found while reading the code (not changed here)
- `FileTransferSession` has **no handling of connection loss**: a transfer that loses its TCP connection stays in `_incoming` with an open file handle, and its `.part` is only removed by accident when a later offer for the same name is accepted. The design adds `handle_connection_lost`.
- A second offer for a name whose `.part` belongs to a live transfer deletes that transfer's `.part` (`cleanup_part_file` at accept time). The design rejects such an offer instead.
- There is no way to cancel a transfer in progress; the only user decision is Accept/Reject on the offer.

Documentation only; suite unchanged (846 passed).

## [1.22.13] — Phase 38.14: README resume claim

### Changed
- **Fixed (docs)**: the README said transfers resume from an existing `.part` offset. The code does the opposite: an accepted offer deletes any existing `.part` file (`cleanup_part_file` at accept time), the sender always streams from offset 0 (`read_chunks` without a start offset) and the receiver requires `offset == bytes_received` from 0. The Architecture text and the feature list now say that transfers are not resumable yet; the resume building blocks (`get_partial_bytes` in `core/transfer/resume.py`, the chunker's start-offset support) exist and are unit-tested but are not used by `FileTransferSession`. Implementing resume would be separate feature work.
- **Phase 38 closed out**: `ROADMAP.md` and section 9 of `PROJECT_STRUCTURE_DESIGN.md` record the owner's decisions (the benchmark baseline is deliberately left as is; the README claim is corrected) and mark the phase complete.
- **Full suite**: unchanged (846 passed); documentation only.

## [1.22.12] — Phase 38.13: mDNS receive-side fix

### Changed
- **Fixed (pre-existing bug, the only functional change on the Phase 38 branch)**: mDNS advertised this device but never produced a peer. `_PeercServiceListener` resolved discovered services with the blocking `ServiceInfo.request()`, called from `AsyncServiceBrowser`'s callback on the event loop, and zeroconf refuses that (`RuntimeError: Use AsyncServiceInfo.async_request from the event loop`; identical on `zeroconf` 0.131.0 and 0.151.5). The listener now only schedules a task per service that resolves it with `AsyncServiceInfo.async_request()`; the TXT decoding and packet building are unchanged, so the same `Discovery._handle_packet` validation runs. In-flight tasks are held by strong reference, failures are logged (`mDNS: could not resolve peer: ...`) instead of vanishing, and `MDNSDiscovery.run()` cancels pending resolutions on shutdown. This closes the known issue recorded in 1.22.2.
- **Verified over real mDNS**: two `MDNSDiscovery` instances in one process each discovered the other through the real `Discovery._handle_packet` validation (name and TCP port correct), with no event-loop errors and no tasks left after shutdown, on both `zeroconf` 0.131.0 and 0.151.5. Previously the same run produced four `RuntimeError`s and no packets.
- **`tests/test_mdns_listener.py`** [NEW] (8, unit): deterministic, using a fake `AsyncServiceInfo`, so no network and no `zeroconf` install is needed. Covers non-blocking `add_service`, packet delivery, the full path into `PeerRegistry`, `update_service`, unresolved services, logged failures that do not stop later ones, cancellation on shutdown, and `remove_service`. All 8 fail against the previous code, and the main ones fail against a mutation that reintroduces the blocking call.
- **User-visible effect**: on networks where mDNS works, peers announced over mDNS now appear in the peer list; before, only UDP broadcast could find them. **Docs**: the Phase 38 status in `ROADMAP.md` and section 9 of `PROJECT_STRUCTURE_DESIGN.md` now reflect that the cleanup is done; what remains is the benchmark baseline and the merge.
- **Full suite**: 846 passed, 1 skipped, 7 deselected (was 838).

## [1.22.11] — Phase 38.12: Old-file mentions

### Changed
- **Comments, docstrings and living docs** that pointed at a file that has since moved now name its new home (42 targeted replacements in 28 files): e.g. `ui.py` -> `app/ui/app.py`, `peer.ConnectionManager` -> `core.transport.manager.ConnectionManager`, `discovery.py's PEER_TIMEOUT` -> `core/discovery/registry.py's PEER_TIMEOUT`, `file_transfer.py` -> `core/transfer/session.py`; in tests, module docstrings of the stage scripts and the relay/rendezvous UI tests; in docs, `GROUP_AUTHORITY_DESIGN.md` and `INTERNET_CONNECTIVITY_DESIGN.md`.
- **Kept on purpose**: the Phase 38 move notes and shim descriptions, one historical aside in `core/transport/manager.py` (now written "the chat and file-transfer sessions (then `chat.py` and `file_transfer.py`)"), `core/group/protocol.py` and the file viewer's own `protocol.py` (different files that merely share a name), and the historical documents (`CHANGELOG.md`, `BUG_REPORT.md`, `IMPLEMENTATION_PLAN.md`, the `ROADMAP.md` version table), which record what was true when they were written.
- **Verification**: for all 26 changed `.py` files the AST with docstrings removed is identical to the previous commit, so only comments and docstrings changed; full suite 838 passed.

## [1.22.10] — Phase 38.11: Test import migration

### Changed
- **29 test files migrated** from root-shim imports to the canonical `app.*` / `core.*` paths with an AST codemod driven by the same name table that `tests/test_shims.py` pins (62 import statements; `from peer import ConnectionManager` -> `from core.transport.manager import ConnectionManager`, `chat.ChatSession` -> `ChatSession`, `protocol.write_message` -> `protocol.write_frame`, ...). A dry run first listed every ambiguous case (bare uses of a shim module, attribute assignment, name clashes) and found none besides `tests/test_stage5.py`, which was migrated by hand because it reassigns `load_or_create_identity`; it now patches `core.discovery.identity_loader`.
- **Only `tests/test_shims.py` still imports a root shim.** `tests/test_import_boundaries.py` gains a rule that keeps it that way (28 tests); injecting `from peer import ...` into a test made it fail with `file:line` before being reverted.
- **Verification**: full suite 838 passed (was 837, +1 for the new rule); `tests/test_stage2-5.py` PASSED; the 7 benchmarks pass; the only new pyflakes messages are three pre-existing unused imports whose path text changed. No production code changed.

## [1.22.9] — Phase 38.10: Documentation

### Changed
- **README**: the Transport Stack diagram names the canonical modules; Usage runs `python3 -m app.main` (noting that `python3 ui.py` still works); Project Structure is rewritten from the filesystem (it listed 6 of the 12 `core/` subpackages and had no `app/` layer at all) and now states the layering rules, the shim contract and where to patch a name; Running Tests lists the boundary and shim suites and `scripts/verify_wheel.py`, and notes that the benchmark baseline is machine-specific.
- **`docs/PROJECT_STRUCTURE_DESIGN.md`**: the target tree matches the as-built layout (adds `constants.py`) and a new section 9, *As Built*, records every deviation from the design and what is still open.
- **`docs/ROADMAP.md`**: the obsolete *Why Phase 38 Is Deferred* section is replaced by the Phase 38 status.
- **Verification**: a check confirmed that all 33 README and 43 design-doc tree paths exist, relative links resolve, and the documented commands run (`python3 -m app.main --help`, `python3 ui.py --help`). Documentation only; suite unchanged (837 passed).
- **Noticed, not changed (pre-dates Phase 38)**: the README (Architecture > File Transfer) says transfers resume from an existing `.part` offset, but `FileTransferSession` always sends from offset 0 and deletes the `.part` on failure; the resume helpers in `core/transfer/` (`resume.py`, chunker offsets, receiver `prepare`) are not wired into the session. Needs an owner decision: correct the text or implement resume.

## [1.22.8] — Phase 38.9: Shim suite and installed-wheel test

### Changed
- **`tests/test_shims.py`** [NEW] (101): the dedicated shim suite. Every legacy name in all six shims is the *same object* as its canonical home; each shim's `__all__` equals the documented legacy surface; importing a non-UI shim starts no thread and does not import `app`/`textual`; `python -m ui` (the `python3 ui.py` path) and `python -m app.main` still start the app. Mutating a shim (a look-alike subclass, a dropped `__all__` name, a UI import) made the suite fail each time.
- **`scripts/verify_wheel.py`** [NEW]: builds the wheel, checks its contents (six shims, every `app`/`core` package, nothing from tests/docs/scripts, only `peerc = app.main:main`), installs it into a fresh virtualenv, and from an empty directory with no `PYTHONPATH` confirms `peerc --help`, that all 99 modules import, that the shims resolve inside `site-packages`, and runs a slice of the suite (shims, handshake, connection FSM, relay tunnel, discovery, Textual pilot flows: 192 tests) against the installed package. CI uses `pip install -e .`, so packaging was never exercised before; deliberately excluding `core.discovery` from `packages.find` now makes the script fail. Run by hand before a release; needs network.
- **Full verification**: suite 837 passed (was 736), including 124 UI and 226 integration tests; `tests/test_stage2-5.py` PASSED; the 7 benchmark tests (deselected by default, so not covered by earlier steps) pass on both the baseline and this tree.
- **Regression gate**: against the committed `baseline.json` it flags transfer throughput (direct -55%, relay -44%) and event-loop lag, but an A/B on one machine (baseline tag vs this tree, 5 alternating runs each) shows no regression (direct -0.2%, relay +4.0%, lag lower). `baseline.json` was recorded on a faster machine, so the gate's absolute numbers are not comparable across machines; it was not re-baselined.
- **Deferred by the owner to the end of Phase 38**: migrating test imports to canonical paths (30 of 63 test files still import a shim), the mDNS receive-side bug, and stale mentions of the old files in docs.

## [1.22.7] — Phase 38.8: Import boundary guard

### Changed
- **Import audit** (AST-based, 100 production files, including imports nested in functions and literal `importlib.import_module()`/`__import__()` calls): zero imports of `peer`, `discovery`, `chat`, `file_transfer`, `protocol` or `ui` outside the six shims, and no `core` -> `app` imports. Nothing needed rewriting; earlier steps had already migrated every production import.
- **`tests/test_import_boundaries.py`** [NEW] (27, unit): turns the audit into a permanent static guard -- production code must not import root shims, `core` must not import `app`, the repo root holds exactly the six shims and `pyproject.toml` `py-modules` matches them, no console script targets a root shim, and each shim contains only a docstring, imports from `app`/`core`, `__all__` (plus `ui.py`'s documented `__main__` launch guard). Files are parsed, never imported.
- **Negative controls**: parametrized synthetic cases prove the scanner flags lazy, aliased and dynamic imports while allowing `from core import protocol` and relative imports; injecting a real violation into `core/`, a shim and a `core` -> `app` import each made the guard fail with `file:line` before being reverted.
- **Full suite**: 736 passed, 1 skipped, 7 deselected (was 709).

## [1.22.6] — Phase 38.7: Console script switch

### Changed
- **Console script**: `peerc` now targets `app.main:main` instead of the root shim `ui:main`; no entry point targets a root shim any more.
- **Removed: the `pchat` console script** (owner decision) -- only `peerc` remains. `python -m app.main` and `python3 ui.py` still launch the app. `PROJECT_STRUCTURE_DESIGN.md` and `IMPLEMENTATION_PLAN.md` are updated to match (no more `pchat --help` checks); the README install note now lists only `peerc`.
- **Verification**: full suite and the manual `tests/test_stage2-5.py` scripts green; wheel built and installed into a fresh virtualenv (not editable) -- `entry_points.txt` lists only `peerc`, and `peerc --help` runs.

## [1.22.5] — Phase 38.6b: ChatApp and main move

### Changed
- **`ChatApp` -> `app/ui/app.py`, `main()` -> `app/main.py`** (`python -m app.main` works); `ui.py` is now a re-export shim of the legacy UI API and keeps only the `__main__` guard so `python3 ui.py` still launches. `ChatApp` uses canonical imports (`core.discovery.*`, `core.messaging.session`, `core.transfer.session`, `core.protocol`).
- **Verification**: the 18 rewritten references are the only code change, checked by applying the same substitutions to the original `ChatApp` AST; full suite 709 passed; `tests/test_stage2-5.py` PASSED. Four test files that patched `discovery.get_network_info` through the shim now patch `core.discovery.broadcast` (8 sites, no assertion changed). Console scripts still target `ui:main` until step 7.

## [1.22.4] — Phase 38.6a: UI config, widget, and modals

### Changed
- **`app/config.py`** (UI port, IP-change/auto-lock intervals, relay orchestration timeouts), **`app/ui/widgets/rich_log.py`** (`SelectableRichLog`, clipboard helper), and **`app/ui/modals/{identity,vault,transfer,link}.py`** (trust/security-event/name-setup modals in `identity`; the critical-action-key modal in `vault`).
- **Verification**: all 32 top-level definitions AST-identical to the previous `ui.py`; `ChatApp` still lives in `ui.py` and imports the moved names from `app.*`. Modals reference `ChatApp` only in local annotations, so `identity.py` imports it under `TYPE_CHECKING`. Full suite 709 passed; `test_stage5` PASSED.

## [1.22.3] — Phase 38.5: Chat and transfer sessions

### Changed
- **`chat.py` -> `core/messaging/session.py`** (`ChatSession`) and **`file_transfer.py` -> `core/transfer/session.py`** (`FileTransferSession`), both via `git mv`; the root modules are re-export shims with identical objects. Both now use `core.protocol`.
- **Verification**: top-level definitions AST-identical; full suite 709 passed; the manual scripts `tests/test_stage2-5.py` (not collected by pytest) all PASSED, same as the `pre-phase38-refactor` baseline. `tests/test_stage3.py` now sets `ACK_TIMEOUT` on `core.messaging.session`, where `ChatSession` reads it.
- Session-level resume is not implemented (the FSM only models PAUSED/RESUMING); `.part`/resume handling stays in `core/transfer/`, untouched.

## [1.22.2] — Phase 38.4: Discovery split

### Changed
- **`discovery.py` -> `core/discovery/`**: `registry.py` (`Peer`, `PeerRegistry`), `broadcast.py` (`Discovery`, UDP, the single packet-validation path), `mdns.py` (optional zeroconf adapter), `identity_loader.py`, and `constants.py` (`BROADCAST_PORT`, `PROTOCOL_VERSION`; added to break the `broadcast` <-> `mdns` import cycle). `discovery.py` is now a re-export shim.
- **Verification**: top-level definitions AST-identical to the previous `discovery.py`; logger name `peerc.discovery` unchanged; UDP path exercised over real sockets (valid peer registered, forged `device_id` and bad version/port rejected); full suite 709 passed with and without `zeroconf` installed. `tests/test_discovery.py` patch targets moved to `core.discovery.broadcast`.
- **Known issue (pre-existing, unchanged)**: the mDNS receive side raises `RuntimeError: Use AsyncServiceInfo.async_request from the event loop` (blocking `ServiceInfo.request` inside the event loop), so mDNS never yields peers; identical on `zeroconf` 0.131.0 and later. Deferred to the end of Phase 38.

## [1.22.1] — Phase 38.3: Transport manager move

### Changed
- **`peer.py` -> `core/transport/manager.py`** (`git mv`, history kept): `ConnectionManager`, `ConnectionLimitError`, `OnMessage`, `CONNECT_TIMEOUT`, `MAX_CONNECTIONS`. `peer.py` is now a re-export shim with identical objects.
- **Production imports** in `chat.py`, `file_transfer.py` and `ui.py` use `core.transport.manager`; the moved module uses `core.protocol` instead of the root `protocol` shim and drops an unused `discovery` import from its manual harness (now `python -m core.transport.manager`).
- **Verification**: full suite 709 passed, unchanged. No behavior change.

## [1.22.0] — Phase 38.2: Packaging scaffold

### Changed
- **`pyproject.toml`**: the hand-maintained `packages` list is replaced by `[tool.setuptools.packages.find]` (`app*`, `core*`); root shim modules stay in `py-modules`. Console scripts unchanged.
- **Empty target packages**: `app`, `app.ui`, `app.ui.widgets`, `app.ui.modals`, `core.discovery`, `core.messaging` (`widgets/` and `modals/` carry an `__init__.py` so auto-discovery includes them).
- **Verification**: wheel contents compared with the previous build -- nothing removed, six packages added. No behavior change.

## [1.21.7] — Phase 31/32.2: Regression gate (Phase 28-35 fully complete)

### Added
- **`core/benchmarking.py`**: `compare_to_baseline(current, baseline, threshold_pct=20.0)` — pure, no I/O: per-metric percent change, direction-aware (`transfer_throughput_*` higher-is-better; `peak_memory_*`/`event_loop_max_lag_*`/`handshake_latency_*`/`shutdown_time_*` lower-is-better via `metric_direction()`'s prefix table), flags a `RegressionFinding` past `threshold_pct` in the bad direction. A metric missing from either side, with no recognized direction, non-numeric, or with a zero baseline is skipped rather than erroring.
- **Baseline vs. current run split**: `BASELINE_PATH` (`docs/benchmarks/baseline.json`, committed, fixed reference) vs. `CURRENT_RUN_PATH` (`docs/benchmarks/latest.json`, gitignored) — `record_metric()`'s default target changed from the former to the latter, so a routine `pytest -m benchmark` run no longer silently overwrites the committed baseline it's meant to be compared against.
- **`scripts/regression_gate.py`** [NEW]: runs the benchmark suite fresh into `latest.json`, loads both files, prints a per-metric report. Always exits 0 — a regression is reported for a human to judge (loopback timing on a shared runner is noisy — the standing baseline itself showed a 31.6% swing on `handshake_latency_relay_sec`, a 1.3ms→1.7ms difference, pure measurement noise) — never used to fail a build, per RELIABILITY_DESIGN.md §9's explicit "not a per-push CI gate."
- **`.github/workflows/tests.yml`**: added `workflow_dispatch` as a manual trigger and a `regression-gate` job that only runs on it (`if: github.event_name == 'workflow_dispatch'`), uploading the fresh run as an artifact. The existing `benchmark` job's comments/artifact name updated to match the `latest.json` rename.
- **`README.md`**: the "Running Tests" section was still describing the pre-Phase-31.1 8-hardcoded-file `pytest` invocation the CI fix already moved past — corrected to the marker-based commands, plus the new benchmark/regression-gate ones.
- **Test Coverage**: `tests/test_regression_gate.py` (9, unit): direction lookup, flagged vs. not-flagged in both directions for both metric kinds, threshold boundary, and every skip-not-error case (unrecognized metric, missing from either side, zero baseline, non-numeric value).
- **Full suite**: 709 passed, 1 skipped, 7 deselected (was 700); benchmark suite (7) still green.

**Phase 28-35 (the reliability program) is now fully complete, including its optional final gate**: 28.1 logging, 29/30.1 taxonomy + task registry, 31.1 baselines, 32.1 task ownership (folded into 29/30.1 and 33.1), 33.1 connection FSM, 34.1 transfer FSM, 35.1/35.2 application error protocol, 31/32.2 regression gate.

## [1.21.6] — Phase 35.2: Error integration (Phase 28-35 reliability program complete)

### Added
- **`core/app_errors.py`** [NEW]: `parse_or_log()` (validate a received `error`, log-and-drop a malformed one) and `log_not_applied()` (a valid error that changed nothing — unsolicited, duplicate, late, wrong peer, or a non-terminal code — logged at debug level). Nothing that handles an `error` ever sends one back, by construction.
- **`peer.py`**: `ConnectionManager.send_error()` — best-effort `error` to a connected peer, never raises. `_report_invalid_frame()` produces `INVALID_FRAME` from the read loop right before a malformed authenticated frame drops the connection as it always has (skipped for a malformed `error` itself — no ping-pong; decode/decryption failures stay local-log-only per §7, unchanged).
- **`file_transfer.py`**: `_handle_error()` correlates a received `error`'s `context.transfer_id` to an active outgoing/incoming transfer *with that same peer*; only a terminal code resolves it, via new `_fail_outgoing()`/`_fail_incoming()` (idempotent — a duplicate/late signal can't notify twice). `_send_chunks()` now checks its transfer's state before each chunk and before/after `file_done`, so an externally-resolved transfer (peer error, peer abort) actually stops streaming instead of finishing the file first. New producers, each only where no existing response already covers the outcome: `TRANSFER_NOT_FOUND` (accept/chunk/done for an unknown transfer), `INVALID_STATE` (chunk or done after a terminal/paused state) — both deduplicated to once per (peer, code, transfer) via a capped `_reported_errors` set. A negative `file_complete_ack` mid-`SENDING` (receiver aborted mid-stream) now stops the sender immediately via the same path.
- **`chat.py`**: `ChatSession._handle_error()` — the same correlate-by-peer, terminal-only pattern for a pending chat message's `context.message_id`; cancels its timeout watcher and reports `"failed"` immediately rather than waiting out the timeout.
- **`ui.py`**: `_show_peer_error()` displays the local canonical text for the code — never the peer's own `message` — plus a retry hint when the code allows one.
- **Test Coverage**: `tests/test_error_integration.py` (21, integration): `INVALID_FRAME` over a real socket pair (and confirms a malformed `error` itself is never answered with one), a real streaming transfer stopped promptly by a real `TRANSFER_NOT_FOUND` (one error for the whole stream, not one per chunk), and handler-level coverage of every "changes nothing" case (wrong peer, non-terminal code, unknown transfer/message, missing context, malformed) for both `FileTransferSession` and `ChatSession`.
- **Full suite**: 700 passed, 1 skipped, 7 deselected (was 679); benchmark suite (7) still green.

**Phase 28-35 (the reliability program) is now complete**: 28.1 logging, 29/30.1 taxonomy + task registry, 31.1 baselines, 32.1 task ownership (folded into 29/30.1 and 33.1), 33.1 connection FSM, 34.1 transfer FSM, 35.1/35.2 application error protocol.

## [1.21.5] — Phase 35.1: Application error schema

### Added
- **`core/protocol/error_codes.py`** [NEW] per RELIABILITY_DESIGN.md §7: the closed 12-code `ErrorCode` set and an `ErrorContract` for each (canonical plain-language text, whether the UI may offer a retry action, whether the code marks a correlated operation terminal, and a retry hint). Only `INVALID_STATE` and `RATE_LIMITED` are non-terminal; only `INVALID_STATE`, `DISK_FULL`, `TRANSFER_EXPIRED` and `RATE_LIMITED` allow a retry action. A module-level assert fails at import if a code is added without a contract.
- **Safe `context`**: allowlisted to `message_id`/`transfer_id`/`group_id` (each must look like a plain identifier: 1-128 chars of `A-Za-z0-9_.:-`) and a bounded numeric `retry_after` (0 < n <= 3600 seconds). Anything else — a traceback, local path, peer address, key material, raw exception text, or any unknown key — is dropped. `filter_context()` never raises, since it runs on both the sending side (a caller's bug must not leak) and the receiving side (the payload is untrusted).
- **Sender**: `build_error()` (and `protocol.make_error()`, now routed through it, with `message`/`context` optional) uses the code's canonical text by default; a custom `message` that looks like a traceback, path, IP address, long hex/base64 run, or raw exception text — or contains control characters or exceeds 200 characters — is replaced by the canonical text. An unknown code is a programming error and raises `ValueError`; a bad `message`/`context` never raises, because this runs in failure paths.
- **Receiver**: `parse_error_message()` validates the schema strictly (`ProtocolError`, never `KeyError`/`TypeError`) and returns a sanitized `ErrorInfo`. An unknown `code` is *not* malformed — a newer peer may have added one — it is displayed as `INTERNAL_ERROR` and its raw value kept for a sanitized log line. **The receiver never displays the peer's `message`**: `display_text` comes from the local contract, so a hostile peer can't put its own words (or terminal escape sequences) in front of the user; the peer's text is only kept, defanged and truncated, for logs. `validate_message()` now enforces this parser for `error`.
- **Scoping note**: this sub-step is schema only. Nothing sends or handles `error` yet — that is 35.2, which will add errors only where an existing negative response (`file_reject`, `file_complete_ack(success=false)`, `relay_response(accepted=false)`) doesn't already cover the outcome.
- **Test Coverage**: `tests/test_error_schema.py` (63, marker `security`): the code set, contracts, context filtering (including bad ids and out-of-range/NaN/bool `retry_after`), unsafe-message fallback, strict parsing of malformed input, unknown codes, the local-text-only display rule, and log sanitizing.
- **Full suite**: 679 passed, 1 skipped, 7 deselected (was 616).

## [1.21.4] — Phase 34.1: Transfer lifecycle FSMs

### Added
- **`core/transfer_state.py`** [NEW]: `OutgoingTransferStateMachine` (`OFFERED → WAITING_FOR_ACCEPT → SENDING → WAITING_FOR_COMPLETE_ACK → COMPLETED`, plus `FAILED`/`REJECTED`/`CANCELLED`) and `IncomingTransferStateMachine` (`OFFERED → ACCEPTED → RECEIVING → VERIFYING → COMPLETED`, plus `REJECTED`/`CANCELLED`/`FAILED`/`EXPIRED` and the `PAUSED → RESUMING → RECEIVING` cycle) per RELIABILITY_DESIGN.md §6.2. `transition_to()` is the only mutator; illegal transitions raise `InvalidTransferTransition`; terminal states are idempotent. `RECEIVING → RECEIVING` is allowed so each further chunk doesn't raise.
- **`file_transfer.py`**: `OutgoingTransfer`/`IncomingTransfer` replace their `status: str` field — which every one of its 9 assignments only ever *wrote* and nothing ever read, so there was no protection at all — with a `state` machine. New behavior this buys: a duplicate `file_accept` no longer re-runs `_handle_accept` and spawns a second `_send_chunks` task (found while writing the 29/30.1 reliability tests); a `file_reject` after the transfer already resolved, a duplicate/late `file_complete_ack`, and a chunk arriving after a terminal or paused state are all dropped rather than acted on. A zero-byte file (no chunks, so still `ACCEPTED` when `file_done` arrives) steps through `RECEIVING` to `VERIFYING` so the table stays strict.
- **Scoping notes**: `PAUSED`/`RESUMING` are modeled per the diagram but nothing drives them yet — no pause/resume feature is wired into the live transfer path (`core/transfer/resume.py` exists but is unused there). `CANCELLED`/`REJECTED`(incoming)/`EXPIRED` are likewise legal-but-currently-untriggered targets. `core/transfer/{sender,receiver,manager}.py` (`FileSender`/`FileReceiver`/`TransferManager`) were deliberately not touched: `ui.py` and `file_transfer.py` never use them (only the chunker/hashing/disk-space/path-safety helpers), so adding state guards there would change nothing in production.
- **Test Coverage**: `tests/test_transfer_fsm.py` (20, unit): both tables — happy paths, illegal skips, duplicate accept, chunk after terminal, resume cycle, idempotent terminals. `tests/test_transfer_fsm_integration.py` (7, integration): a real transfer reaches `COMPLETED` on both sides, duplicate accept doesn't spawn a second send task, reject lands in `REJECTED`, zero-byte file completes, late/duplicate complete-ack dropped, chunk after `FAILED`/`PAUSED` dropped.
- **Full suite**: 616 passed, 1 skipped, 7 deselected (was 589 before this sub-step).

## [1.21.3] — Phase 33.1: Connection lifecycle FSM (+ closed deferred Phase 32.1 gap)

### Added
- **`core/connection_state.py`** [NEW]: `ConnectionState` (`NEW`/`TCP_CONNECTED`/`HANDSHAKING`/`AUTHENTICATED`/`ESTABLISHED`/`CLOSING`/`CLOSED`) and `ConnectionStateMachine` per RELIABILITY_DESIGN.md §6.1 — an internal safety contract, not a wire message. `transition_to()` is the only mutator; illegal transitions raise `InvalidConnectionTransition`, but `CLOSING`/`CLOSED` are idempotent (a late frame, timeout, or duplicate close can't revive a connection or raise). `require_established()` guards application-frame dispatch.
- **`peer.py`**: `ConnectionManager` now keeps one `ConnectionStateMachine` per addr_key. Scoping note: `accept_secure_session()`/`initiate_secure_session()` already run the whole handshake atomically before `ConnectionManager` ever sees a session, so there's no hook into `TCP_CONNECTED`/`HANDSHAKING` as separately-observable steps without instrumenting `core.crypto` itself (out of scope here) — `_register_session()` fast-forwards through them (each still individually validated). `_read_loop()` now calls `require_established()` before dispatching each frame (catches a real race: a send-path failure elsewhere can move a connection to `CLOSING` while `_read_loop` is still returning one more already-buffered frame). `send()`/`send_binary()`/`send_relay_data()` mark `CLOSING` defensively on failure; `close_all()` does the same before closing each session. `get_connection_state(addr_key)` added for introspection/tests.
- **Closed the deferred Phase 32.1 gap**: `core/task_registry.py`'s `cancel_group()`/`cancel_all()` now take a `timeout` (default 5s) — `asyncio.wait(..., timeout=...)` instead of an unbounded `gather()`, with a sanitized warning logged (group, count, task names — never exception content) if a task misses the deadline. A stuck task is still dropped from tracking either way, so it can't leave a group permanently "active."
- **Test Coverage**: `tests/test_connection_fsm.py` (14, unit): the transition table itself — happy paths, illegal skips/backwards moves, idempotent terminal states, the guard. `tests/test_connection_fsm_integration.py` (4, integration): wired into real `ConnectionManager` pairs — reaches `ESTABLISHED` after a real handshake, reaches `CLOSED` after disconnect, a duplicate/racing close doesn't raise or resurrect, a late frame after `CLOSING` is dropped before `on_message`. `tests/test_task_registry.py`: +2 for the bounded-wait/deadline-miss logging.
- **Full suite**: 589 passed, 1 skipped, 7 deselected (was 583 before this sub-step).

## [1.21.2] — Phase 31.1: Performance baselines

### Added
- **`core/benchmarking.py`** [NEW]: `EventLoopLagSampler` (periodic loop-lag sampling while a workload runs), `peak_rss_mb()` (platform-normalized peak RSS), `record_metric()`/`load_baseline()` (merge-not-overwrite JSON recorder).
- **`tests/test_benchmarks.py`** [NEW] (marker `benchmark`): non-gating — measures and records, never asserts a regression threshold (nothing to regress against yet). Covers all 5 metrics from RELIABILITY_DESIGN.md §4: transfer throughput (direct + relayed), peak memory during a 32 MB transfer, event-loop max lag during a transfer, handshake latency (direct + relayed), and shutdown time cancelling 11 tasks across all three `TaskRegistry` groups (now measurable thanks to 29/30.1's registry).
- **`docs/benchmarks/baseline.json`** [NEW]: first recorded baseline — 7 metrics, deterministic local fixtures and loopback connections only, no public-network numbers.
- **`pyproject.toml`**: `addopts = "-m 'not benchmark'"` — benchmark tests excluded from a plain `pytest` run by default; `pytest -m benchmark` opts in explicitly.
- **`.github/workflows/tests.yml`**: fixed a real gap found while wiring this in — the `test` job was only ever running 8 explicitly-named test files (`test_security_fixes.py`, `test_upgrade_fixes.py`, `test_handshake.py`, `test_kdf.py`, `test_encryption.py`, `test_transport.py`, `test_file_transfer_v2.py`, `test_security_events.py`) plus 4 standalone stage-sanity scripts, never the full suite. Now runs plain `pytest` (all 569 non-benchmark tests via the Phase 29/30.1 markers). Added a separate `benchmark` job (`continue-on-error: true`, uploads `docs/benchmarks/baseline.json` as an artifact) so slow/timing-sensitive benchmark runs never gate merges.
- **Test Coverage**: 7 new benchmark tests (marker `benchmark`, excluded from the `569 passed` default count). Full default suite unchanged at 569 passed, 1 skipped, 7 deselected.

## [1.21.1] — Phase 29/30.1: Reliability taxonomy + task ownership (pulled forward)

### Added
- **Pytest markers** (`pyproject.toml`): registered `unit`, `integration`, `ui`, `security`, `benchmark` (reserved for Phase 31+); applied `pytestmark` to all 52 existing test files by actual content (real-socket/two-peer tests → `integration`, crypto/handshake/trust/vault/group-policy/relay-authorization → `security`, anything driving `ChatApp` → `ui`, the rest → `unit`). Flat `tests/` layout unchanged, per RELIABILITY_DESIGN.md §3.
- **`core/task_registry.py`** [NEW] — `TaskRegistry`: bounded, per-owner task tracking by group (`connection`/`transfer`/`app`), `create_task()`, `active_count()`, `groups()`, `cancel_group()`/`cancel_all()` (cancel + await, not fire-and-forget). Not a global task supervisor — each `ChatApp` owns exactly one instance, passed down to `ConnectionManager`/`ChatSession`/`FileTransferSession`.
  - **Pulled forward from Phase 32.1** at Baim's explicit direction, to fully close a gap found while writing the "task cleanup after vault lock" reliability case: `_perform_hard_lock()` didn't cancel in-flight transfer tasks, which could then touch a just-detached (`None`) store.
  - `peer.py`/`chat.py`/`file_transfer.py`: `ConnectionManager`/`ChatSession`/`FileTransferSession` all take an optional registry (falls back to bare `asyncio.create_task()` when none is supplied, so existing direct-construction tests are unaffected); read-loop, relay-incoming, chat-ack-timeout, and `_send_chunks` tasks now flow through it.
  - `ui.py`: `_perform_hard_lock()` is now `async` and cancels+awaits the `"transfer"` group first (the concrete fix); `on_unmount()` is now `async` and cancels+awaits every group (full bounded shutdown). Connection tasks are deliberately left running on vault lock (see the method's docstring) — only on app shutdown are all three groups torn down.
  - Incidental fix found in the same code path: `/lock` called `action_lock_vault()` (a coroutine function) without `await`, so the command silently did nothing.
- **Required reliability cases** (`tests/test_reliability_cases.py`, `tests/test_task_registry.py`): cancellation at await points (`connect_to`, `_send_chunks`), duplicate/late `chat_ack` are no-ops, peer disconnect mid-transfer resolves without hanging or raising, and the task-cleanup fix above — all tested against the real live code paths.
  - **Deferred** (documented in the test file's module docstring, not weak stand-ins): "no event-loop stall above a budget" (Phase 31.1, no budget chosen yet), "an invalid state transition never sends a frame" (Phase 33.1/34.1, no formal state machine yet), and "error responses contain no peer-internal exception text" (Phase 35, no wire-level error-response mechanism exists yet to test against).
- **Test Coverage**: `tests/test_task_registry.py`: 7 tests; `tests/test_reliability_cases.py`: 8 tests. Full suite: 569 passed, 1 skipped.

## [1.21.0] — Phase 28.1: Operational logging foundation

### Added
- **`core/logging_setup.py`** [NEW]: single startup configuration point for the `peerc` logger tree (`peerc.transport`, `peerc.protocol`, `peerc.transfer`, `peerc.vault`, `peerc.ui`, `peerc.security`, `peerc.discovery`, ...), resolving RELIABILITY_DESIGN.md §2.
  - `configure_logging(diagnostic_mode=False, debug=False, log_path=None)`: rotating file handler (`~/.peerc/diagnostics.log`, 5 MB × 3 backups, same dotfolder convention as `TrustStore`/vault paths) at `WARNING`+ by default, `INFO`+ in diagnostic mode, `DEBUG`+ in single-run debug mode (visibly marked with a log line). Idempotent — re-configuring replaces the previously-installed handler rather than stacking duplicates.
  - `_RedactingFilter`: installed once at the root `peerc` logger; strips a forbidden-field allowlist (`passphrase`, `private_key`, `session_key`, `dek`, `recovery_code`, `link_pin`, `pin`, `endpoint_link`, `vault_plaintext`, `chat_content`, `file_content`, ...) from any record's structured `extra` fields, regardless of which child logger emitted it. `core.security.events` is untouched — no competing security-event path.
  - Root `peerc` logger does not propagate to the library root logger, keeping diagnostics out of the Textual UI.
- **`ui.py`**: `main()` gains `--diagnostic` / `--debug` CLI flags wired to `configure_logging()`; a startup log line visibly marks diagnostic mode when active.
- **`discovery.py`**: logger renamed from bare `__name__` to `peerc.discovery`, joining the `peerc` tree instead of sitting outside it.
- **Test Coverage**: `tests/test_logging_setup.py`: 9 focused tests covering rotating-file creation, default `WARNING` policy, diagnostic/debug level escalation with visible markers, forbidden-field redaction (including a full sweep of the forbidden-field set), allowed-field passthrough, idempotent re-configuration, non-propagation, and the `discovery.py` logger rename.

## [1.20.4] — Phase 37.3: Full workflow verification

### Added
- **Test Coverage**: `tests/test_trust_workflow_integration.py` — 3 end-to-end Textual pilot scenarios chaining the full trust lifecycle: first connection → `TrustRequired` → pending prompt → `Trust` → reconnect as `TRUSTED`; first connection → `Reject` → reconnect as `REVOKED`; and a pending prompt where group policy denies external trust, leaving the device `PENDING` with no state change.
- Confirms the existing handshake, trust, rotation, group-policy, and vault integration suites still pass unmodified alongside the new Phase 36/37 UI work.

**Phase 37 is now complete**: 37.1 (`1.20.2`), 37.2 (`1.20.3`), and 37.3 (`1.20.4`).

## [1.20.3] — Phase 37.2: Security-event review + rotation history

### Added
- **Security Events View (`SecurityEventsModal`)**:
  - Read-only, groups buffered `SecurityEvent` entries by `(event_type, device_id)`, keeping only the latest timestamp per group.
  - Selecting a row with a known `device_id` opens `TrustDeviceDetailModal` for that device; a key mismatch is shown strictly as a rejected security event, never as an approval choice.
  - `_on_security_event_buffered()` appends every emitted `SecurityEvent` to an in-memory, capped (`_SECURITY_EVENT_LOG_CAP = 200`) review buffer.
- **Rotation history in device detail** (`TrustDeviceDetailModal._render_rotation_section()`): reads `TrustStore.get_rotation_chain()` and renders a read-only chain of device IDs, omitted entirely when there's no history; a revoked ancestor anywhere in the chain is highlighted and the whole chain is flagged "tainted."
- **Command**: `/events` opens the Security Events view.
- **Test Coverage**: `tests/test_trust_center_4.py`: 8 focused tests covering event grouping, empty state, device-detail linking, mismatch-not-approval, rotation history display, revoked-ancestor tainting, no-history omission, and buffer-via-emit.

## [1.20.2] — Phase 37.1: Event-driven pending prompt

### Added
- **Trust Prompt (`TrustPromptModal`)**: replaces log-only `TrustRequired` handling with a non-blocking modal — device name, short ID, abbreviated + revealable/copyable full fingerprint, and the observed connection route labelled as untrusted reachability info (not identity evidence). `Trust`, `Reject`, and `Later` actions; `Later` leaves the device `PENDING` and does not touch the connection.
- **Queueing & dedup**: `_on_trust_required()` deduplicates by `(peer_id, public_key)`, queues behind any blocking modal (file offer, vault unlock/create, recovery-code, critical-action-key) or an already-open prompt, and `_dequeue_next_trust_prompt()` drains the queue once unblocked — but never while the vault is locked. The log entry is retained as an audit-friendly signal alongside the modal.
- **Vault-lock safety**: `_perform_hard_lock()` clears the queue and dismisses any open `TrustPromptModal` rather than leaving a decision prompt live against a now-locked vault.
- **Test Coverage**: `tests/test_trust_center_3.py`: 8 focused tests covering prompt display on `TrustRequired`, `Later` leaving `PENDING`, trust/reject from the prompt, same-peer dedup, multi-peer queueing, vault-lock dismissal, and non-blocking behavior alongside a file offer.

## [1.20.1] — Phase 36.2: Trust decision controls

### Added
- **Interactive Trust Decisions (`TrustDeviceDetailModal`)**:
  - Contextual action buttons based on device status: `Trust` (variant `success`) and `Reject` (variant `error`) for `PENDING` devices; `Revoke` (variant `error`) for `TRUSTED` devices; view-only `Close` for `REVOKED` devices.
  - In-place view refresh (`_refresh()`) re-rendering the device state upon decision confirmation.
- **Confirmation Gate (`TrustConfirmModal`)**:
  - Pre-write modal preventing accidental changes. Displays device name and formatted fingerprint for `trust`, and an explanation with optional reason input for `revoke` / `reject`.
- **Backend Handlers & Policy Enforcer**:
  - `_do_trust_approve(device_id)`: Enforces group policy restrictions via `PolicyEnforcer.check_external_trust()` (denials surface descriptive error without state changes) and marks device `TRUSTED` via `TrustStore.approve()`.
  - `_do_trust_revoke(device_id, reason)`: Locally revokes devices via `revoke_device()` with user attribution and optional reason.
  - Idempotence guards preventing crashes on duplicate or disallowed actions (e.g. attempting to approve a revoked device).
- **Command**:
  - `/revoke <device_id> [reason]`: Direct command to revoke or reject a device by prefix or exact ID with interactive confirmation modal and optional pre-filled reason.
- **Test Coverage**:
  - `tests/test_trust_center_36_2.py`: 8 focused tests covering pending approval, refusal to approve revoked devices, trusted revocation, pending rejection, group policy denial, command dispatch/cancellation, idempotence, and dynamic button layout.

## [1.20.0] — Phase 36.1: Read-only device inventory

### Added
- **Trust Center UI (`TrustCenterModal`)**:
  - Read-only device inventory listing all known devices from `TrustStore.list_all()`.
  - Filter toggle tabs: All, ⏳ Pending, ✓ Trusted, and ✗ Revoked.
  - Informative row labels showing status icon, device name, truncated device ID, status name, and relative last seen time.
  - Safe empty states for all filters and a vault-locked state if opened without an unlocked vault session.
- **Device Detail View (`TrustDeviceDetailModal`)**:
  - Full inspect view for any device showing full device ID, formatted public-key fingerprint (`format_fingerprint`), first/last seen relative timestamps, and revocation metadata (revoked by, reason) if revoked.
  - "Copy Fingerprint" action button copying the formatted fingerprint to the clipboard.
- **Commands**:
  - `/devices [pending]`: Opens the Trust Center dialog (defaulting to all, or filtering to pending only).
  - `/pairs`: Direct alias for `/devices`.
  - `/trust <device_id>`: Opens the device detail modal by exact device ID or prefix match.
- **Auditing & Notification**:
  - `_on_trust_required` now points users to `/devices pending` when a new device connects for the first time.
- **Test Coverage**:
  - `tests/test_trust_center_36_1.py`: 8 focused tests covering empty list, multi-status inventory, filter switching, vault-locked safeguards, unknown device lookup, prefix resolution, clipboard copy, and command alias handling.

## [1.19.3] — Phase 46.4: relay-mode toggle

### Added
- **`ui.py`**: `/group relay <group_id> on|off` enables or disables this device as a relay host for an active group. The setting is in-memory only, requires active membership to enable, and remains independent from Rendezvous mode.
- Four focused tests cover unknown groups, non-members, on/off behavior, invalid input, and Rendezvous independence.

### Changed
- **Relay candidate discovery** is explicitly broadcast-based: A sends `relay_candidate_query` to already-connected peers and collects live `relay_candidate_response` messages. It does not reuse `rendezvous_lookup`, so Relay hosting does not depend on any group member enabling Rendezvous.

**Phase 46 is now complete**: 46.1 (`1.19.0`), 46.2 (`1.19.1`), 46.3 (`1.19.2`), and 46.4 (`1.19.3`).

## [1.19.2] — Phase 46.3: A-side direct-then-relay orchestration

### Added
- **`core/protocol/messages.py`**: `make_relay_candidate_query(group_id)` (A broadcasts to all connected peers) and `make_relay_candidate_response(group_id, available)` (R responds if relay mode is on and authorized), plus `REQUIRED_FIELDS` and `validate_message()` coverage for both. Exported in `core/protocol/__init__.py` and root `protocol.py`.
- **`core/connectivity/relay.py`**: `authorize_relay_candidate_query()` — pure authorization logic checking relay mode status (`RelayNotHostingError`) and active group membership (`RelayAuthError`). Exported in `core/connectivity/__init__.py`.
- **`core/transport/session.py`**: `initiate_secure_session_on_connection(tcp_conn, ...)` — runs Phase 6 handshake over an existing `TCPConnection` (real socket or relayed tunnel) and wraps it in a `SecureSession`. `initiate_secure_session` now acts as a clean wrapper over this function. Exported in `core/transport/__init__.py`.
- **`peer.py`**:
  - `ConnectionManager.connect_via_relay_tunnel(r_addr_key, target_device_id, timeout)`: establishes an outgoing tunneled `SecureSession` to `target_device_id` through relay R (`r_addr_key`), verifies peer identity against expected target, registers the session under a collision-free `relay-<short_id>` key, and starts the background read loop.
  - Incoming passive relayed connection handling: when an incoming `relay` chunk arrives with no pre-registered tunnel or pipe and connection limit is not exceeded, `ConnectionManager._read_loop` automatically accepts the incoming virtual connection via `accept_secure_session` in the background (passive B model — B is unprompted and needs no prior registration on R).
  - `_tunnel_r_keys` mapping to automatically unregister underlying relay tunnels on session teardown.
- **`ui.py`**:
  - `_relay_candidate_queues` and `_relay_response_futures` for asynchronous candidate collection and response correlation.
  - `_on_relay_candidate_query`: host-side silent gate (replies with `available=True` only if relay mode is active and requester is authorized).
  - `_on_relay_candidate_response`: requester-side feeder into group-specific candidate queue.
  - `_on_relay_response`: updated to resolve pending response futures for `_try_relay_connect` orchestration.
  - `_try_relay_connect(target_device_id, group_id)`: full direct-then-relay orchestration:
    1. Direct TCP connection attempt with `RELAY_DIRECT_TIMEOUT` (3s).
    2. Relay candidate discovery: broadcasts `relay_candidate_query` to connected peers and gathers candidates within `RELAY_CANDIDATE_WINDOW` (0.5s).
    3. Sequential trial: queries candidates with `relay_request` with `RELAY_RESPONSE_TIMEOUT` (3s) and opens a tunnel via `connect_via_relay_tunnel()` on accept.
- 21 new tests across `tests/test_relay_pipe.py` (passive Bob e2e handshake and message passing), `tests/test_relay_authorization.py` (candidate query authorization and message validation), and `tests/test_relay_ui.py` (candidate queries, response queue feeding, direct and relay fallback connect orchestration) — total 40 relay tests passing.

## [1.19.1] — Phase 46.2: relay_request wire protocol + R-side authorization

### Added
- **`core/protocol/messages.py`**: `make_relay_request(group_id, target_device_id)` (A → R) and `make_relay_response(group_id, target_device_id, accepted)` (R → A), plus `REQUIRED_FIELDS`/`validate_message()` coverage for both. One response type with a boolean `accepted` field, mirroring `rendezvous_lookup_response`'s nullable-field shape, rather than two separate accept/reject message types.
- **`core/connectivity/relay.py`** [NEW]: `authorize_relay_request()` — pure authorization logic, no network I/O, same shape as `core/connectivity/rendezvous.py`. Checks, in order: relay mode is on for the group on this device (`RelayNotHostingError`), the requester is an active member (`RelayAuthError`), and this device is already connected to the target (`RelayTargetUnreachableError`). The first two stay silent at the ui.py layer — same posture as `_on_rendezvous_lookup`'s auth-failure gate — while the third gets an explicit `relay_response(accepted=False)`, since "not currently connected to the target" is the ordinary, non-sensitive "legitimate query, negative answer" case (mirrors `rendezvous_lookup_response`'s `endpoint_update=None`), and an explicit fast reply matters for 46.3's sequential candidate trial.
- **`peer.py`**: `ConnectionManager.find_addr_key_for_device(device_id)` — reverse of `get_peer_device_id()`, needed for R to check "am I already connected to the relay target?".
- **`ui.py`**: `self._relay_active_groups` state (separate from `_rendezvous_active_groups`, per the Phase 46 design's separate-toggle decision — the toggle command itself is 46.4); `_on_relay_request`/`_on_relay_response` handlers wired into the message dispatch. `_on_relay_request`'s happy path calls 46.1's `ConnectionManager.open_relay_pipe()` directly. `_on_relay_response` currently just surfaces the outcome — actually opening a tunnel and running the handshake with the target is 46.3.
- 19 new tests: `tests/test_relay_authorization.py` (pure `authorize_relay_request()` logic + wire message validation, including check-ordering) and `tests/test_relay_ui.py` (ui.py plumbing: silent gates, the explicit decline reply, `open_relay_pipe()` wiring on the happy path).

### Not yet done (46.3-46.4)
- No A-side direct-then-relay orchestration — nothing sends a `relay_request` yet, and `_on_relay_response`'s accept path doesn't open a tunnel or start a handshake.
- No `/group relay <id> on|off` command — `_relay_active_groups` has to be populated directly (as the tests do) until 46.4 adds it.

## [1.19.0] — Phase 46.1: relay-tunnel primitive

### Added
- **Phase 46 design resolved with Baim** before any code — `INTERNET_CONNECTIVITY_DESIGN.md` §11 "Optional Relay" was 6 lines, architecture-only. Landed: no active hole-punching (try direct via `ConnectionManager.connect_to` with a short timeout, fall straight back to relay), relay authorization opt-in per-group via a separate toggle from Rendezvous (`/group relay <id> on|off`, Phase 46.4), live relay-candidate discovery by broadcast to connected peers, and a pure-byte relay protocol where B is passive and the pipe at R lives exactly as long as both its legs do. Full writeup: `docs/ROADMAP.md`'s new "Phase 46 design (resolved)" section.
- **`core/transport/secure.py`**: a third inner payload marker, `TYPE_RELAY` (`b"R"`), alongside the existing `TYPE_JSON`/`TYPE_BINARY` — `EncryptedTransport.send_relay()`/`receive_frame()`'s `"relay"` kind. Kept fully separate from `TYPE_BINARY` (file_data) so a relayed chunk can never collide with `decode_file_data`'s fixed-header framing; zero base64 tax, since it rides the same raw-bytes wire path file_data already uses.
- **`core/transport/session.py`**: `SecureSession.send_relay()`, mirroring `send_binary()`.
- **`core/transport/relay_stream.py`** [NEW]: `RelayedStreamReader`/`RelayedStreamWriter` — a duck-typed `asyncio.StreamReader`/`StreamWriter` pair (just the `readexactly()` / `write()`+`drain()`+`get_extra_info()`+`is_closing()`+`close()`+`wait_closed()` surface `core/protocol/frame.py`, `core/transport/tcp.py`, and `core/crypto/handshake.py` actually use) backed by `relay` chunks instead of a real socket. Wrapped in a plain `TCPConnection`, this lets `perform_handshake_initiator`/`_responder` and `SecureSession`/`EncryptedTransport` run completely unmodified over a relayed connection — see the new tests for a full Phase 6 handshake proving it end-to-end.
- **`peer.py`**: `ConnectionManager.send_relay_data()`; R-side `open_relay_pipe()`/`close_relay_pipe()`/`is_relay_pipe_open()` (bidirectional forwarding table between two already-connected sessions — R never parses a relayed chunk, just re-sends it on the paired session); A/B-side `register_relay_tunnel()`/`unregister_relay_tunnel()`/`open_relay_tunnel()` (builds a ready-to-use tunneled `TCPConnection`). `_read_loop` dispatches `"relay"` frames to whichever applies (forward if I'm R, feed a registered tunnel reader if I'm A/B, else drop) — never through `on_message`/`NetworkMessageReceived`, since the content is opaque at this layer. Pipe and tunnel-reader entries are cleaned up automatically in `_read_loop`'s `finally` when either leg's session closes (pipe lifecycle decision: closes the moment either A↔R or B↔R disconnects).
- 7 new tests (`tests/test_relay_pipe.py`): the shim in isolation (multi-chunk `readexactly()`, blocking-until-fed, EOF → `IncompleteReadError`, writer `get_extra_info`/close); the wire-level `relay` channel between two handshaked managers; R-side forwarding with an explicit assertion that R's own `on_message` is never called; pipe teardown on leg disconnect; and the full payoff — a real Phase 6 handshake plus one encrypted chat message between two peers, running entirely through a relay tunnel.

### Not yet done (46.2-46.4)
- No `relay_request`/accept/reject negotiation or R-side authorization check yet — `open_relay_pipe()` has to be called directly; nothing decides when it's safe to.
- No A-side direct-then-relay orchestration (46.3) or `/group relay on|off` toggle (46.4) yet.
- No explicit "far leg died mid-tunnel" signal forwarded through R — if R's pipe drops out from under a live tunnel (as opposed to A's or B's own leg dying, which the tunnel notices directly), the stalled side currently only recovers via existing handshake/idle timeouts. Revisit in 46.2 if that proves insufficient.

## [1.18.8] — Phase 45.3: rendezvous wired into ui.py — Phase 45 complete

### Added
- **`ui.py`**: `/group rendezvous <group_id> on|off|find <device_id>` — `on`/`off` toggle this device as a rendezvous host for a group (checked against real active membership via `GroupStore`; `off` also evicts that group's cached entries via `RendezvousCache.evict_all_for_group()`); `find` broadcasts a `rendezvous_lookup` to every currently-connected peer (`ConnectionManager.list_connected_addr_keys()`).
- Host-side `_on_rendezvous_register()`/`_on_rendezvous_lookup()`: both gate on `group_id in self._rendezvous_active_groups` — a device that hasn't opted in for a group stays completely silent for it (no response at all for `lookup`, not even an empty one), so the toggle is a real opt-in rather than every connected device passively accumulating cache entries nobody asked it to hold.
- Requester-side `_on_rendezvous_lookup_response()`: re-verifies the returned `EndpointUpdate` against the target's public key from the requester's OWN `MembershipCertificate` copy (`GroupStore.get_membership()`) — never trusts the host, matching the design's "mail carrier, never a vouched-for party" principle — cross-checks the claimed `target_device_id` against `EndpointUpdate.device_id` too, then upserts to `locator_store` and attempts a connection (reuses 44.3's `_connect_to_link_endpoint()`).
- `_register_with_rendezvous_hosts()`: fires alongside `_send_self_endpoint_update()` on every `hello`/`hello_ack` and on 45.1's `_reannounce_endpoint_to_connected_peers()` (IP change) — sends a `rendezvous_register` for every group this device is an active member of, to whichever peer it just connected to. This is the "push my new IP to rendezvous when the receiver isn't connected" behavior Baim asked for: a group-mate hosting rendezvous who happens to be connected will cache it; one who isn't hosting silently ignores it.
- 19 new tests (`tests/test_rendezvous_ui.py`): the on/off/find command (unknown group, non-member, happy path, cache eviction, no-connected-peers), host-side register/lookup (not-hosting gate, happy path, device_id mismatch, found/not-found responses), requester-side lookup_response (no endpoint, unknown target, device_id mismatch, invalid signature, happy path), and self-registration fan-out.

### Fixed
- **`core/protocol/__init__.py` / `protocol.py`**: Phase 45.2 added `make_rendezvous_register`/`make_rendezvous_lookup`/`make_rendezvous_lookup_response` to `core/protocol/messages.py` but never exported them through the package `__init__.py` or the root compatibility shim — `protocol.make_rendezvous_lookup(...)` raised `AttributeError` from any caller outside `messages.py` itself. Caught immediately by this sub-step's own tests failing on first run.

**Phase 45 (Rendezvous) is now complete**: 45.1 (`1.18.6`), 45.2 (`1.18.7`), 45.3 (`1.18.8`).

## [1.18.7] — Phase 45.2: RendezvousCache + three wire messages

### Added
- **`core/connectivity/rendezvous.py`** [NEW]: `RendezvousCache` — in-memory (never persisted) cache of `EndpointUpdate` blobs, indexed by `(group_id, device_id)`. Implements the two host-side operations: `register()` (a device publishes its current endpoint for group-mates to look up) and `lookup()` (a group member retrieves a cached update for a target peer). `evict()`/`evict_all_for_group()` clean up on disconnect or when rendezvous mode is disabled for a group (45.3 wires the on/off toggle). `RendezvousAuthError` (non-member requester/target), `RendezvousSignatureError` (bad EndpointUpdate sig), `RendezvousDeviceIdMismatchError` (EndpointUpdate.device_id ≠ authenticated peer) cover the three distinct refusal cases.
- **Authorization shape** (same as every other `group_*` message): the host checks ONLY that both parties hold an active, non-revoked `MembershipCertificate` for `group_id`. No new crypto — `register()` re-verifies the `EndpointUpdate`'s existing Ed25519 signature (Phase 44.2) before caching; `lookup()` returns the blob verbatim for the requester to re-verify against the target's public key from the group `MembershipCertificate`. The host is a mail carrier, never a vouched-for party.
- **Three new wire messages** in `core/protocol/messages.py`:
  - `make_rendezvous_register(group_id, endpoint_update)` — sender publishes its signed update blob to the host
  - `make_rendezvous_lookup(group_id, target_device_id)` — requester asks the host for a cached update
  - `make_rendezvous_lookup_response(group_id, target_device_id, endpoint_update | None)` — host's reply (update dict or null on cache miss)
- `REQUIRED_FIELDS` entries and `validate_message()` checks for all three types, including nested validation of the embedded `endpoint_update` dict (required string fields, port range, recognized `kind`) — the same rigor as the standalone `endpoint_update` message.
- `core/connectivity/__init__.py` exports `RendezvousCache`, `RendezvousError`, `RendezvousAuthError`, `RendezvousSignatureError`, `RendezvousDeviceIdMismatchError`.
- 32 new tests (`tests/test_rendezvous_cache.py`): register happy-path, device_id mismatch, non-member sender, tampered signature, overwrite; lookup happy-path, cache miss, non-member requester, non-member target; evict/evict_all_for_group (including cross-group isolation); all four factories; validate_message() well-formed/missing-required/bad-nested-port/bad-nested-kind/non-dict/null-update for all three types.

`/group rendezvous on|off` command and wiring the IP-change trigger through rendezvous-mode peers are Phase 45.3.

## [1.18.6] — Phase 45.1: own-IP-change detection

### Added
- **Phase 45 design resolved with Baim** before any code — `INTERNET_CONNECTIVITY_DESIGN.md` §9/§10 were architecture diagrams only, no wire protocol. Landed: opt-in per-group Rendezvous (not a separate server — any active group member can relay other members' already-signed `EndpointUpdate`s), no new crypto (host relays, requester re-verifies), 3 wire messages (`rendezvous_register`/`rendezvous_lookup`/`rendezvous_lookup_response`), freshness reused from `EndpointUpdate`'s own window, in-memory-only cache. Full writeup: `docs/ROADMAP.md`'s new "Phase 45 design (resolved)" section.
- **`peer.py`**: `ConnectionManager.list_connected_addr_keys()` — a snapshot list of currently-connected addr_keys, safe to iterate even if a connection drops mid-loop.
- **`ui.py`**: `_check_ip_change()` — polled every `IP_CHANGE_CHECK_INTERVAL` (30s, `set_interval`) against `_last_known_local_ips` (in-memory only, never persisted — same reasoning as `device_info.py`'s model string). On a real change, `_reannounce_endpoint_to_connected_peers()` re-sends a signed self-announcement (reusing 44.4's `_send_self_endpoint_update()`) to every currently-connected peer, closing §7 "IP Change Problem" for the case where at least one path is still up. A transient empty reading (e.g. a brief interface blip) is deliberately ignored rather than treated as a change — it would otherwise clobber the baseline and make the next real reading always look "new".
- 8 new tests (`tests/test_ip_change_detection.py`): `list_connected_addr_keys()` empty/populated (real handshake), `_check_ip_change()` no-change/change/empty-reading/added-interface, `_reannounce_endpoint_to_connected_peers()` fan-out and no-op-when-nothing-connected.

The rendezvous-relay case (target peer NOT currently connected) is 45.2 (`RendezvousCache` + wire messages) and 45.3 (`/group rendezvous on|off` + wiring), not this sub-step.

## [1.18.5] — Phase 44.4: endpoint_update wired into the live connection protocol

### Added
- **`peer.py`**: `ConnectionManager.get_peer_public_key(addr_key)` — raw Ed25519 public key bytes for an authenticated connection, mirroring `get_peer_device_id()`'s existing shape (Phase 6 handshake-verified, not self-reported).
- **`core/protocol/messages.py`**: `make_endpoint_update()`, plus a `REQUIRED_FIELDS` entry and `validate_message()` checks (port range, `kind` must be one of the three recognized values — kept as literal strings rather than importing `core.connectivity`, since this module is deliberately dependency-free). Exported through `core/protocol/__init__.py` and the root `protocol.py` compatibility shim.
- **`ui.py`**: `_send_self_endpoint_update(addr_key)` — right after every `hello`/`hello_ack` handshake completes, sign and send one `endpoint_update` per detected local IP (`discovery.get_network_info()`) announcing how to reach this device. `_on_endpoint_update(addr_key, msg)` — verifies an incoming one against the connection's AUTHENTICATED public key (`get_peer_public_key()`), never anything the message self-reports, cross-checks the claimed `device_id` against the authenticated identity too (logs a `SECURITY:` warning and refuses on mismatch — the same defense-in-depth pattern `_verify_self_reported_id()` already uses for `hello`), then persists to `locator_store` via replay-guarded `verify_endpoint_update()` (Phase 44.2's `NonceCache`, one instance per running app, not vault-gated since it's in-memory-only regardless).
- Every successful connection — LAN discovery, `/connect`, or Add-by-Link — now leaves a cryptographically-confirmed, reusable `locator_store` entry behind, not just ones made through Add-by-Link.
- 14 new tests (`tests/test_endpoint_update_wire.py`): a real two-`ConnectionManager` handshake proving `get_peer_public_key()` returns the correct authenticated key on each side; message factory + schema validation (well-formed accepted, missing fields/bad port/unknown kind rejected); mocked `ChatApp` flow tests for the happy path, a device_id/authenticated-identity mismatch, a tampered/invalid signature, no authenticated session, a replay, and vault-locked no-op.

This closes the last "still unwired" item from Phase 44's original scope besides QR display, which stays deliberately deferred per Baim's direction to focus on the click UI first.

## [1.18.4] — Phase 44.3 UI: visible "+ Add by Link" button on the main screen

### Added
- **`ui.py`**: a real, always-visible `Button` ("+ Add by Link") above the peer list on the main screen — Ctrl+G and `/link` already opened the same flow, but neither is a persistent on-screen control; this is the third entry point Baim asked for. `compose()`'s peer list now lives inside a new `Vertical(id="sidebar")` alongside the button (same overall sidebar width as before). Clicking it calls the same `action_add_by_link()` the Ctrl+G binding already triggers — button, keybinding, and command all land on the identical `LinkMenuModal` flow, no behavior change to the flow itself.
- Manually verified in a real Textual `Pilot` session (`pilot.click("#add-link-btn")` → `LinkMenuModal` opens), same style of extra sanity check as `1.18.3`.

## [1.18.3] — Phase 44.3 UI: Add-by-Link click flow

### Added
- **`ui.py`**: click-based UI for Add-by-Link, per Baim's direction to focus on click+input over slash commands (QR display deliberately deferred — `generate_qr()` exists in `core/connectivity/link.py` but isn't wired into any modal yet). Reachable two ways, both landing on the same `LinkMenuModal`: the `/link` command, or the new **Ctrl+G** binding (shown in the Footer alongside the existing Lock/Clear/Quit shortcuts).
- `LinkMenuModal` → `LinkGenerateModal` (pre-fills detected local `host:port` lines from `discovery.get_network_info()` into an editable `TextArea`; "Random PIN" button fills a `secrets`-backed 6-digit PIN) → `LinkResultModal` (shows the generated link + PIN, "Copy Link" button reuses the app's existing `copy_to_clipboard()`).
- `LinkMenuModal` → `LinkAddModal` (paste a link + its PIN) → decodes with `decode_link()`, then tries each endpoint in `Locator.sorted_endpoints()` order (direct before rendezvous) via the same `ConnectionManager.connect_to()` + hello-handshake sequence `/connect` already uses. Successfully-decoded endpoints are persisted to `locator_store` regardless of whether the connection attempt succeeds. A decoded link is never automatic trust (§3a) — the existing TOFU/trust flow takes over exactly as it would for any freshly-discovered peer once the handshake completes.
- `_parse_endpoint_line()`: parses a `TextArea` line into an `Endpoint`, inferring `direct-v4`/`direct-v6`/`rendezvous` the same way `/connect`'s own argument parser already does (including BUG-025's IPv6 bracket-notation handling) — one shared mental model for "how do I type an address" across both features.
- 15 new tests (`tests/test_link_ui.py`: 7 `_parse_endpoint_line()` parsing cases, 8 flow-method tests with `push_screen_wait`/`manager`/`registry` mocked, same pattern as `test_group_ui.py`). Manually verified in a real Textual `Pilot` session too (Ctrl+G → menu → Generate/Add → each modal's Cancel button) as an extra sanity check beyond the mocked unit tests.

## [1.18.2] — Phase 44.3: Add-by-Link (PIN-protected connection links + QR)

### Added
- **`core/connectivity/link.py`** [NEW]: Add-by-Link (§3a Link Format) — `PEERC1:<base64url(salt‖nonce‖ciphertext)>`. Protected by a 6-digit PIN, not QR-only (QR is an additional render of the same string, never a separate encoding). Sign-then-Encrypt, deliberately in that order: the payload (sender's public key, tagged endpoints, `created_at`) is Ed25519-signed first, then the whole signed bundle is AES-256-GCM-encrypted under `Scrypt(PIN, salt)` — without the PIN, nothing is visible, not even the sender's device_id. Reuses `core/vault/crypto.py`'s exact Scrypt/AES-GCM primitives and RFC 7914 parameters rather than inventing new ones.
- `create_link()` / `decode_link()`: endpoints pack compactly — `direct-v4`/`direct-v6` as raw address bytes (4/16 bytes), `rendezvous` as a length-prefixed UTF-8 hostname — multiple endpoints per link supported (a link can carry a LAN IP, a VPN IP, an IPv6 address, and a public IP all at once, same as `Locator`).
- Three distinct failure modes, matching the design doc's own reasoning: `LinkFormatError` (malformed, independent of PIN — bad prefix, bad base64, truncated), `WrongPinError` (AES-GCM auth failed — deliberately doesn't distinguish "wrong PIN" from "tampered link", same reasoning as `core/vault/crypto.py`'s `WrongSecretError`), and `LinkSignatureError` (PIN was correct but the embedded Ed25519 signature didn't verify — the one scenario the signature exists to catch: a brute-forced PIN without the real sender's private key, surfaced distinctly from a simple wrong PIN since it's a materially different, more concerning situation).
- No expiry by design — a link stays valid until the sender's endpoint actually changes, at which point Endpoint Update (44.2) keeps a verifier's locator current without a new link. A successfully decoded link is never automatic trust — approval stays manual (§3a "Approval"): this module only proves "genuinely device X, reachable here."
- `generate_qr()`: renders a link as a terminal ASCII/ANSI QR code via the new optional `qrcode` dependency (`pip install peerc[qr]`, mirrors the existing `mdns` optional-dependency pattern) — raises a clear `QrCodeUnavailableError` with install instructions if not installed; the copy-paste string form works fully either way.
- 15 new tests (`tests/test_connectivity_link.py`): validation, single/multiple/mixed-kind endpoints round-trip, wrong PIN, tampered ciphertext, malformed links, the correct-PIN-forged-signature case, wire-prefix format, QR generation.

No `/link` UI commands, `endpoint_update` wire-protocol message, or logic to actually initiate a connection to a decoded link's endpoint yet — this sub-step is the crypto/format primitive only, same scope pattern as 44.1/44.2.

## [1.18.1] — Phase 44.2: signed endpoint announcement + verification

### Added
- **`core/connectivity/endpoint_update.py`** [NEW]: `EndpointUpdate` dataclass and `create_endpoint_update()`/`verify_endpoint_update()` (§4 Endpoint Update) — a device signs "I am now reachable at host:port" with its existing identity key (the same key it always signs with; an endpoint change alone never touches identity, see the design doc's "Endpoint Update and Key Rotation" comparison). Ed25519 over a domain-separated `device_id`+`kind`+`host`+`port`+`timestamp`+`nonce` payload. Reuses `core/crypto/handshake.py`'s `NonceCache` for replay protection rather than inventing a new primitive, per the design doc's explicit instruction.
- Verification order is deliberate: signature first, then timestamp freshness (±300s default, configurable), then nonce replay — a forged or unsigned update fails on signature before it ever gets to consume a `NonceCache` slot or have its timestamp judged.
- `endpoint_update_to_endpoint()` — shape conversion from a verified `EndpointUpdate` into `LocatorStore.upsert_endpoint()`'s `Endpoint` input. Storage-agnostic by design, same split as `membership.py`/`admin.py`: this module never touches `LocatorStore` itself, and the caller supplies its own `NonceCache` instance rather than one being created/persisted here.
- 13 new tests (`tests/test_connectivity_endpoint_update.py`): validation, happy path, wrong verifying key, tampered host/port/kind, stale/future timestamp, nonce replay (including that a forged update with a stolen nonce doesn't consume the cache slot a real update would need), shape conversion.

No wire-protocol message type or `ui.py` integration yet — this is the crypto/data primitive only. Wiring an `endpoint_update` message into `core/protocol/messages.py` and having `ui.py` apply it to `locator_store` on receipt is a later integration step, most naturally once there's an actual "connect over the Internet" flow (direct or via rendezvous, Phase 45) for a device to piggyback its announcement on.

## [1.18.0] — Phase 44.1: Locator (IP/port tracking, separate from identity)

### Added
- **`core/connectivity/locator.py`** [NEW]: `Endpoint` (`device_id`, `kind` — `direct-v4`/`direct-v6`/`rendezvous`, `host`, `port`, `updated_at`) and `Locator` (all currently-known endpoints for one device) dataclasses. Deliberately separate from identity — a device's `device_id` never changes, but it can have several endpoints at once (LAN IP, VPN IP, IPv6, public IP), and they change constantly. `Locator.sorted_endpoints()` orders direct endpoints (freshest first) ahead of rendezvous ones, per §11's "try direct, fall back to rendezvous" pattern applied to endpoint resolution.
- **`core/connectivity/store.py`** [NEW]: `LocatorStore`, mirroring `TrustStore`/`GroupStore`'s shared-connection pattern exactly. `upsert_endpoint()` (insert or refresh `updated_at` on conflict — the primary key `(device_id, kind, host, port)` is the endpoint's identity), `remove_endpoint()`, `list_endpoints()` (all or filtered by kind), `get_locator()` (never errors on an unknown device — empty `Locator` is a normal state), `prune_stale()` (30-day default, deliberately generous — Internet endpoints legitimately go quiet between sessions, unlike `discovery.py`'s short-lived `PEER_TIMEOUT`).
- **`core/vault/database.py`**: `device_endpoints` table added to `VaultDatabase`'s unified schema — same reasoning as every other subsystem so far (one encrypted file, not a separate DB).
- **`ui.py`**: `self.locator_store` wired through the same lock/unlock/hard-lock lifecycle as `self.trust_store`/`self.group_store`.
- 16 new tests (`tests/test_connectivity_locator.py`, `tests/test_vault_locator_integration.py`): `Endpoint` validation, staleness, sort order, `LocatorStore` CRUD + refusal paths, and vault-connection sharing/persistence across flush+lock+re-unlock.

Not to be confused with `discovery.py`'s `Peer`/`PeerRegistry`: that remains an in-memory, this-session-only cache of LAN broadcast/mDNS sightings. `LocatorStore` is the new persisted, cross-session layer for Internet endpoints, meant to be updated by a signed Endpoint Update rather than re-discovered fresh every run.

No signed endpoint announcement/verification or Add-by-Link yet — `endpoint_update.py` (44.2, reuses `core/crypto/handshake.py`'s `NonceCache` for replay protection) and Add-by-Link (44.3, §3a Link Format — PIN-protected `PEERC1:` links + QR) are later Phase 44 sub-steps.

## [1.17.0] — Phase 43: Group-Gated Export Authorization

### Added
- **`core/group/export_auth.py`** [NEW]: short-lived, admin-signed export capabilities and device export requests per `GROUP_AUTHORITY_DESIGN.md` §11 and §12.
  - `ExportRequest`: device-signed request binding `request_id`, `device_id`, `device_public_key`, `group_id`, `file_id`, `action="EXPORT"`, and optional `reason` using domain-separated Ed25519 signature (`peerc-group-export-request`).
  - `ExportCapability`: admin-signed authorization token binding `capability_id`, `request_id`, `device_id`, `group_id`, `file_id`, `action="EXPORT"`, `issued_at`, `expires_at` (default TTL 300 s / 5 minutes), `nonce`, and `admin_device_id` using domain-separated Ed25519 signature (`peerc-group-export-capability`).
  - `create_export_request()`, `verify_export_request()`, `issue_export_capability()`, and `verify_export_capability()` with active admin public key verification and automatic `POLICY_VIOLATION` event emission on expired tokens.
- **`core/group/policy.py`**: upgraded `PolicyEnforcer.check_export()` to the Phase 43 AND-gate (§11). When a group restricts export (`allow_export=False`), it looks up an unexpired, unused `ExportCapability` matching the device and file (or wildcard `*`), verifies it against the active admin keys, burns it (one-shot per §12), and emits a `POLICY_CHANGED` security event. If no valid capability is present, fails closed with `ExportDeniedError` and emits `POLICY_VIOLATION`.
- **`core/group/store.py`**: `export_capabilities` table added to SQLite schema with complete CRUD methods: `store_capability()`, `get_valid_capability()`, `mark_capability_used()` (one-shot burn), `list_capabilities()`, and `purge_expired_capabilities()`.
- **`core/vault/file_actions.py`**: `export_secure_file()` integrates the group capability gate before the personal critical-action key gate. Both gates must pass (AND-gate) when a device belongs to an export-restricted group. Backward-compatible when no policy enforcer is configured.
- **`core/vault/database.py`**: unified encrypted vault schema updated to include `export_capabilities`.
- **`core/protocol/messages.py`**: wire message factories `make_group_export_request` and `make_group_export_capability`, added to `_REQUIRED_FIELDS` and `validate_message`. Re-exported via `core/protocol/__init__.py` and `protocol.py`.
- **`ui.py`**:
  - Wired `PolicyEnforcer(self.group_store)` into the live unlocked session and `export_secure_file()`.
  - Added commands: `/group req-export <id> <fid> [reason]`, `/group authorize-export <id> <dev> [fid] [ttl]`, and `/group caps <id> [dev]`.
  - Network callbacks: `_on_group_export_request` (with rich admin prompt) and `_on_group_export_capability` (stores verified capability locally).
  - Updated `/help` with new group export commands.
- **`tests/test_group_export_auth.py`** [NEW]: 12 tests covering capability issuance, expiry rejection, signature verification, storage/retrieval, one-shot burn, PolicyEnforcer AND-gate, file_actions export integration, wire message validation, and UI command flows.

## [1.16.5] — Phase 42.5: Signed Audit Log (completes Phase 42: Group Authority System)

### Added
- **`core/group/audit.py`** [NEW]: signed audit logging for Group Authority actions (§13 `GROUP_AUTHORITY_DESIGN.md`). Integrates with Phase 41's `SecurityEvent` architecture using Ed25519 domain-separated signing (`_EVENT_DOMAIN`) over `event.canonical_payload()`. Functions: `sign_audit_event()`, `verify_audit_event()`, `create_group_audit_event()`, `verify_group_audit_event()` (verifies against current active admin public keys), and `format_audit_event()` (standardized formatting per §13).
- **`core/group/store.py`**: `group_audit_log` table added to SQLite schema; `record_audit_event()` (with optional active-admin signature verification), `list_audit_events()` (filtering by event_type, severity, timestamp since, and limit), and `get_audit_event()`. Automatically records structured audit entries and emits security events on group lifecycle actions (`create_group`, `record_membership`, `revoke_membership`, `set_policy`, `add_admin`, `remove_admin`).
- **`core/vault/database.py`**: unified encrypted vault database schema updated to include `group_audit_log`.
- **`core/security/events.py`**: added standard group event types to `SecurityEventType`: `GROUP_CREATED`, `MEMBERSHIP_ISSUED`, `ADMIN_ADDED`, `MEMBERSHIP_REVOKED`, `ADMIN_REMOVED`.
- **`ui.py`**: added `/group audit [group_id] [limit]` command allowing users and admins to view the group's chronological audit log with badge indicators for verified admin signatures, unsigned events, and invalid signatures. Updated `/help` with the audit command.
- **`tests/test_group_audit.py`** [NEW]: 10 tests covering audit event creation, Ed25519 signing/verification, tamper rejection, active admin validation, `GroupStore` record/list filtering, lifecycle auto-auditing, formatting, and Textual UI command execution.

## [1.16.4] — Phase 42.4: Join/Leave/Revoke protocol messages

### Added
- **`core/group/protocol.py`** [NEW]: signed Group Authority control-plane payloads for `GroupJoinRequest`/`GroupJoinResponse`, `GroupLeaveRequest`/`GroupLeaveResponse`, and `MembershipRevocation`. All signatures are Ed25519 over domain-separated canonical payloads and reuse the existing device identity key type: joining devices sign their join/leave requests, admins sign approvals and revocations. Join requests also check `device_id == sha256(device_public_key)` before verification.
- **`core/protocol/messages.py`**: wire factories and schema validation for `group_join_request`, `group_join_response`, `group_leave_request`, `group_leave_response`, and `group_membership_revoke`. The root `protocol.py` shim and `core.protocol` exports include the new factories.
- **`core/group/store.py`**: `process_join_response()` verifies an active admin's signed approval and records the included membership certificate; `process_leave_request()` verifies a member-signed self-leave and tombstones the membership only when `leave_requires_admin` is not active; `process_leave_response()` and `record_revocation()` verify admin-signed revocation messages before marking membership `REVOKED`. `get_membership_revocation()` exposes tombstone metadata (`revoked_by`, `revoked_at`, reason).
- **`core/vault/database.py`**: unified encrypted vault schema now includes `group_admins`, matching `GroupStore`'s Phase 42.3 admin table when group data lives inside the vault connection.
- 8 new tests (`tests/test_group_protocol.py`) covering join request self-consistency, signed join approvals, tamper rejection, self-leave policy handling, admin-approved leave, admin revocation, removed-admin refusal, and wire schema validation.

No UI commands yet — those are intentionally deferred until after this core layer. No audit log yet — that is 42.5.

## [1.16.3] — Phase 42.3: multi-admin + k-of-n threshold signatures

### Added
- **`core/group/admin.py`** [NEW]: `AdminRecord` (an admin is just a device whose public key is additionally recorded as a group authority — same identity, no new key type). `ThresholdApproval` — a generic k-of-n signature collector for any admin-gated action: `create_threshold_approval()`, `sign_approval()` (Ed25519, domain-separated payload binding `group_id`+`action_id`+`action_payload`, refuses a second signature from the same admin device), `verify_approval_signature()`, `count_valid_signatures()`/`is_approved()`. Storage-agnostic by design (mirrors `membership.py`'s split): the active-admin set is passed in by the caller rather than looked up here, so a signature from an admin removed after signing simply stops counting toward the threshold, no error needed.
- **`core/group/store.py`**: `group_admins` table + `add_admin()` (only a currently-active admin can add another, refuses a duplicate `device_id`), `remove_admin()` (refuses removing the last currently-active admin — a group must always have ≥1), `get_admin()`/`get_admin_status()`/`is_admin()`/`list_admins()`, `get_active_admin_public_keys()` (feeds straight into `admin.py`'s threshold functions). `create_group()` now auto-registers the founder as the first active admin row.
- **`core/group/store.py`**: `record_membership()` and `set_policy()` now check the certificate/policy's `admin_device_id` against ANY currently-active admin of the group (via `group_admins`), not just the group's founding `admin_device_id` — §14 Multiple Administrators is now actually functional end-to-end, not just a standalone module.
- 18 new tests (`tests/test_group_admin.py`): threshold-approval crypto (happy path, duplicate signer, wrong key, tampered payload, k-of-n math, non-active-admin signatures not counting), admin CRUD (add/remove/list, last-admin-refusal, non-active-adder-refusal, duplicate-refusal), and `record_membership()`/`set_policy()` accepting a second admin's signature and refusing a removed one's.

No Join/Leave/Revoke protocol wiring or audit log yet — those are 42.4/42.5.

## [1.16.2] — Phase 3.4: identity display metadata (device model, first-run name setup)

### Added
- **`core/device_info.py`** [NEW]: `detect_device_model()` — best-effort human-readable OS/platform string (macOS version, Linux with WSL/Termux special-cased, Windows release, generic fallback). Deliberately never persisted anywhere (not `identity.json`, not the vault) — recomputed fresh every app start, so restoring/importing an identity onto different hardware never shows a stale device's model. See §37 "Self-Reported Display Metadata" in `docs/SECURITY_MODEL.md`.
- **`core/identity/identity_file.py`**: `DeviceIdentity.is_new` — True only for the `load_or_create_identity()` call that generates a brand-new identity, letting `ui.py` show a first-run prompt exactly once.
- **`ui.py`**: `NameSetupModal` — first-run only, lets a new user pick a display name before the app proceeds (defaults to `"peer"` if left blank, same as never running `/name` at all). `validate_display_name()` factors out the BUG-020 rules (no control characters/newlines, max 32 chars) so both the modal and the `/name` command share one validator. `self.device_model` shown in the startup log, `/info`, and next to each peer in `/peers`.
- **`discovery.py`**: `model` threaded through both discovery transports (UDP broadcast + mDNS TXT records) the same way `name` already was — `Peer.model`, `PeerRegistry.upsert(model=...)` (never clears a previously-known model on an update announce with none), `_build_mdns_txt`/`_mdns_txt_to_packet` round-trip it (64-char cap, matching `name`). Legacy peers that don't send a `model` field are still accepted, same as before Phase 3.4.
- 19 new/updated tests (`tests/test_device_info.py`, `tests/test_identity_file.py`, additions to `tests/test_discovery.py` and `tests/test_stage5.py`).

### Changed
- **`ui.py`**: `/nick` renamed to `/name` (clearer — this changes a display label, not a network handle). `/help` and the self-info panel updated to match.

## [1.16.1] — Group Authority System — policy schema & core-level enforcement

### Added
- **`core/group/policy.py`** [NEW]: Group Authority policy schema and core-level enforcement (`GROUP_AUTHORITY_DESIGN.md` §5, §6, §7, §8, §10):
  - `GroupPolicy`: Schema defining `allow_external_trust`, `allow_export`, `leave_requires_admin`, `allow_inter_group`, and `communication_matrix`. Includes serialization (`to_dict`/`from_dict`) and deterministic `canonical_payload()` for Ed25519 signatures (`_POLICY_DOMAIN = b"peerc-group-policy\x00"`).
  - `CommunicationRule` & `PolicyAction` & `PolicyEffect`: Fine-grained Communication Policy Matrix (§7) supporting wildcard, role-based, device-based, and group-based access control across actions (`CHAT`, `FILE_SEND`, `FILE_RECEIVE`, `EXPORT`, `TRUST`, `GROUP_JOIN`, `GROUP_LEAVE`).
  - Exceptions: `PolicyViolationError`, `ExternalTrustDeniedError`, `ExportDeniedError`, `LeaveRequiresAdminError`, `InterGroupDeniedError`, `CommunicationDeniedError`.
  - `PolicyEnforcer`: Core-level policy evaluation ensuring decisions are enforced at storage and protocol boundaries, failing closed.
- **External Trust Restriction (§6)**:
  - Wired into `core/trust/store.py`'s `TrustStore.record_first_seen()`: When an active group policy enforces `allow_external_trust=False`, any device that is not an active, non-expired member (or admin) of the group is refused with `ExternalTrustDeniedError` before insertion into `trusted_devices`.
  - Emits high-severity `POLICY_VIOLATION` security event.
- **`core/security/events.py`**: Added `POLICY_VIOLATION` (severity HIGH) and `POLICY_CHANGED` (severity INFO) to `SecurityEventType`.
- **`core/group/store.py` & `core/vault/database.py`**:
  - `group_policies` table added to SQLite schema and unified encrypted vault schema.
  - `GroupStore.set_policy()`, `get_policy()`, and `list_policies()` added with group existence and admin validation.
- **`ui.py`**: Wired `self.trust_store.set_group_store(self.group_store)` across app lifecycle (on_mount and unlock).
- **Packaging**: Added `core.group` to `[tool.setuptools]` packages in `pyproject.toml`.
- 18 new tests (`tests/test_group_policy.py`, `tests/test_trust_group_policy.py`) covering policy defaults, serialization, communication matrix matching, core enforcements (external trust, export, leave, inter-group, communication rules), vault persistence, and `TrustStore.record_first_seen()` restriction.

## [1.16.0] — Group Authority System — membership certificates + storage

### Added
- **`core/group/membership.py`**: `Group` dataclass (a group's identity — just the trust anchor `admin_public_key`, membership lives elsewhere) and `MembershipCertificate` dataclass. `issue_membership_certificate()`/`verify_membership_certificate()` follow the same Ed25519 domain-separated-payload pattern as `core/identity/rotation.py`'s `TransitionCertificate` — an admin is just a device whose public key is additionally recorded as a group's authority, not a new key type. `is_membership_expired()` for optional TTL-based expiry (`expires_at=None` means never expires).
- **`core/group/store.py`**: `GroupStore`, mirroring `core/trust/store.py`'s `TrustStore` shared-connection pattern exactly (default owns its own `db_path`, or shares an already-open `conn`). `record_membership()` verifies the certificate's signature against the group's recorded admin public key before writing — refuses an unverifiable signature, an admin/group mismatch (a cert signed by someone other than the group's recorded admin), or a duplicate `(group_id, device_id)` membership.
- **`core/vault/database.py`**: `groups`/`group_memberships` tables added to `VaultDatabase`'s unified schema (§12) — per the Phase 42.1 discuss-before-build decision, group data lives in the same encrypted vault file as everything else, not a separate DB.
- **`ui.py`**: `self.group_store` wired through the exact same lock/unlock/hard-lock lifecycle as `self.trust_store` (`adopt_conn(None)` on lock, `adopt_conn(self.vault_db.conn)` on re-unlock).
- 18 new tests (`tests/test_group_membership.py`, `tests/test_vault_group_integration.py`) covering issue/verify (happy path, tampered cert, wrong verifying key), expiry, `GroupStore` CRUD + refusal paths, and vault-connection sharing/persistence across flush+lock+re-unlock.

No policy enforcement or UI commands yet — `policy.py` (schema + core-level enforcement, including the External Trust Restriction wiring into `TrustStore.record_first_seen()`), `admin.py` (multi-admin, k-of-n threshold signatures), and `audit.py` (signed audit log) are later Phase 42.x sub-steps.

## [1.15.7] — Fix stale vault isolation in the Stage 5 UI smoke test

### Fixed
- **`tests/test_stage5.py`**: the headless `ui.py` smoke test isolated `identity.load_or_create_identity` for a temp dir, but never isolated the vault path — `_unlock_vault()` always checked the real `~/.peerc/vault_keyfile.json`. On any environment without a pre-existing vault (every fresh CI runner), this triggered `VaultCreateModal`'s interactive passphrase prompt, which the test's `pilot.pause(0.5)` never answers, so `_setup()`'s worker hung indefinitely and `app.manager` was never assigned — `AssertionError: ConnectionManager should be created`. This test file predates the vault system (last touched at Phase 26 / v1.14.0; vault landed at Phase 39.1+ / v1.15.0+) and was never updated for it. Fixed by bypassing `ChatApp._unlock_vault` (returns an in-memory DEK directly, no modal) and isolating `VaultDatabase.unlock()` to a temp path — this file's stated scope is UI wiring, not the vault-unlock flow, which has its own dedicated tests.

## [1.15.6] — Bug fixes: executable detection & Open-block wiring

### Fixed
- **`core/vault/executable_detection.py`**: `is_executable()` fail-closed logic corrected. Previously, inconclusive content (`None`) in strict mode only blocked if the extension was *also* suspicious, letting genuinely unknown files with non-suspicious extensions through; strict mode now always fails closed on inconclusive content. Also, "safe" content (e.g. plain text) with a suspicious extension (e.g. `.exe`, `.py`) was previously never flagged; content/extension mismatches are now caught. Removed `.bin` from `EXECUTABLE_EXTENSIONS` (too ambiguous — used for arbitrary binary blobs, not typically directly executed).
- **`core/vault/file_actions.py`**: `open_secure_file()`'s executable-check `except` clause only caught `ExecutableBlockedError`, but the checker actually wired up in `ui.py` (`check_executable_for_open`) raises `ExecutableDetectionError` — a different, unrelated exception class. This meant blocked opens never cleaned up their decrypted temp file, and `ui.py`'s block-message handler never fired. Now catches both exception types and normalizes to `ExecutableBlockedError`. Detected file type is now computed and embedded in the exception message *before* the temp file is deleted (previously `ui.py` tried to inspect the file after deletion, which silently always reported "unknown").
- **`ui.py`**: removed the now-redundant post-deletion `describe_file_type()` call in the Open-blocked handler.
- **`tests/test_file_actions.py`**: two tests were missing `set_dont_ask_again_files(True)` before calling `open_secure_file()`, so they were unintentionally exercising the re-auth-required path (§4) instead of the decrypt/executable-check path they were meant to test.
- **`tests/test_transport.py`**: the connect-timeout test relied on `192.0.2.1` actually timing out, which isn't guaranteed across network environments (some sandboxes return `ConnectionRefusedError` immediately instead of hanging). Now mocks `asyncio.open_connection` to hang, making the test deterministic.

## [1.15.5] — Phase 39.5: File actions / secure storage

### Added
- **`core/vault/secure_file.py`** [NEW]: Per-file encryption/decryption with AES-256-GCM and HKDF-derived keys. `encrypt_file()` generates unique salt+nonce per file, opaque secure_id naming (64-char hex, not original filename). `decrypt_file()` verifies size/checksum, detects tampering via GCM auth tag. `delete_secure_file()` removes both ciphertext and metadata. `list_secure_files()` returns all encrypted files sorted by timestamp. Metadata (`.meta` JSON) stores original filename, size, checksum, salt, nonce separately from ciphertext (`.peercfile`).
- **`core/vault/file_actions.py`** [NEW]: Five distinct file operations integrating with `VaultSession.requires_reauth()`:
  - `open_secure_file()`: decrypt to ephemeral temp, strip executable bits, call executable_checker, hand to OS viewer. View-only, never execute. Re-auth by default.
  - `export_secure_file()`: decrypt to permanent plaintext copy. Requires `authorize_export()` (39.4 critical-action key gate). FileExistsError on existing destination.
  - `move_to_secure_storage()`: encrypt existing local file into secure storage. Re-auth required by default. Optional delete_source parameter.
  - `delete_secure_file_action()`: remove secure file + metadata permanently. Re-auth by default.
  - `handle_incoming_transfer()`: authorize accept/reject for incoming files. Passphrase-free unless require_passphrase_for_incoming enabled.
  All actions raise SessionLockedError when vault locked. Secure deletion (overwrite-then-unlink) for plaintext sources.
- **`core/vault/executable_detection.py`** [NEW]: Magic-byte content sniffing for executable detection (§6, §11.6). Checks PE (`MZ`), ELF (`\x7fELF`), Mach-O (6 variants), shebang (`#!`). Positive allowlist for safe formats (PDF, PNG, JPEG, GIF, plain text via printable-ASCII heuristic). Fails closed on inconclusive results in strict mode. Extension is secondary signal only — renamed executables still caught by content. `check_executable_for_open()` raises `ExecutableBlockedError` to prevent accidental execution via Open. `describe_file_type()` provides human-readable detection results for UI messages.
- **`core/transfer/receiver.py`**: secure storage mode support. `FileReceiver` accepts `storage_mode`, `secure_storage_dir`, `dek` parameters. When `storage_mode='secure'`, `_finalize_secure()` encrypts verified plaintext on-arrival, securely deletes temp `.part` file. `secure_id` attribute set after encryption. Import guard prevents circular dependency.
- **`core/transfer/manager.py`**: `create_receiver()` gains `storage_mode`, `secure_storage_dir`, `dek` parameters for Phase 39.5 integration.
- **`core/vault/persistence.py`**: handles `storage_mode='secure'` in `_on_transfer_completed()`. Stores `secure_id` in `storage_path` column for secure files (via `getattr(evt, 'secure_id', '')`), plaintext path for normal files.
- **`core/vault/__init__.py`**: exports Phase 39.5 APIs (`SecureFileError`, `SecureFileCorruptError`, `SecureFileMetadata`, `encrypt_file`, `decrypt_file`, `delete_secure_file`, `generate_secure_id`, `load_metadata`, `list_secure_files`, `FileActionError`, `AuthorizationError`, `ExecutableBlockedError`, `open_secure_file`, `export_secure_file`, `move_to_secure_storage`, `delete_secure_file_action`, `handle_incoming_transfer`, `ExecutableDetectionError`, `is_executable`, `check_executable_for_open`, `describe_file_type`).
- **`ui.py`**: file action commands and UI flows:
  - `/files`: list all secure files (12-char ID prefix, original filename, size in MB). Limit to 20 most recent.
  - `/open <file_id>`: decrypt to temp, open in default system viewer (Windows: `os.startfile`, macOS: `open`, Linux: `xdg-open`). Executable detection blocks dangerous files. Re-auth via `VaultUnlockModal` when `requires_reauth('open')` is True.
  - `/export <file_id>`: export to permanent plaintext copy in downloads_dir. Always goes through `_prompt_for_export_authorization()` (39.4 gate). Auto-renames if destination exists (append counter).
  - `/secure <filepath>`: encrypt local file into secure storage. Calculates SHA-256 checksum. Keeps original file by default (delete_source=False). Re-auth when required.
  - `/delete <file_id>`: delete secure file permanently. Re-auth when required. Shows original filename in confirmation message.
  All commands check `vault_session.is_unlocked`, raise appropriate errors, log results with Rich formatting. Prefix matching on secure_id for user convenience. Added `secure_storage_dir` (`~/.peerc/secure`) and `downloads_dir` (`downloads`) attributes. Updated `/help` with "File Actions" section between "Vault & Security" and quit command.
- **Tests**: 68 total test cases across 3 new test files:
  - `tests/test_secure_file.py` (18): encrypt/decrypt roundtrip, metadata preservation (all fields), unique salt/nonce per file, wrong DEK rejection (SecureFileCorruptError), corrupted ciphertext detection, size mismatch detection, delete operations (both files removed), list_secure_files sorting (descending timestamp), opaque secure_id naming (64 hex chars), generate_secure_id uniqueness, load_metadata error cases, auto-create secure_dir.
  - `tests/test_executable_detection.py` (28): PE/ELF/Mach-O/shebang detection (all 6 Mach-O variants), safe format allowlist (PDF/PNG/JPEG/GIF/text), executable extensions flagged, extension mismatch caught (PE content with .txt extension), fail-closed on unknown files (strict mode), check_executable_for_open raises ExecutableDetectionError, describe_file_type descriptions, empty file allowed, ZIP not flagged, renamed ELF still detected.
  - `tests/test_file_actions.py` (22): open_secure_file decrypts to temp, executable_checker integration, re-auth when required, "don't ask again" bypasses re-auth, export requires authorize_export, export with critical key (both success and rejection), export creates permanent copy, move_to_secure encrypts local file, move requires re-auth, delete removes both files, delete requires re-auth, handle_incoming_transfer authorization, all actions raise SessionLockedError when locked, open strips executable bits, export raises FileExistsError on existing destination.

### Changed
- **Phase 39 complete**: all five sub-steps (39.1 envelope encryption, 39.2 encrypted DB, 39.3 session/auto-lock, 39.4 critical-action Export key, 39.5 file actions/secure storage) now implemented and tested. Secure Storage design (`docs/SECURE_STORAGE_DESIGN.md`) fully realized. Chat history, transfer records, trusted devices, and secure files all encrypted at rest. Session-based unlock model with configurable auto-lock. File actions with executable detection and configurable re-auth policy. Export gated by optional critical-action key. Ready for Phase 42 (Group Authority System).

## [1.15.4] — Phase 39.4: Critical-action Export key primitive

### Added
- **`core/vault/session.py`**: critical-action Export auth primitive.
  `VaultSession` can now set/change/clear the optional Export-only
  critical-action key, verify it against the live unlocked session, and
  expose `authorize_export()` for Phase 39.5's actual Export call path.
  The gate is an AND, not an OR: HKDF combines the live session DEK
  material with a freshly entered critical-action secret, then uses an
  AES-GCM verifier so neither half authenticates alone.
- **Keyfile / vault DB integration**: the reserved
  `VaultKeyfile.critical_key_salt` and
  `critical_key_verifier_salt` fields now mark/configure the critical
  key. The AEAD verifier record is stored in the encrypted vault
  `settings` table as `critical_key_verifier`; callers still persist the
  mutated keyfile via `save_vault_keyfile()`.
- **Tests**: `tests/test_vault_session.py` covers unset-by-default
  behavior, live-session-only rejection, critical-secret-only rejection,
  wrong-key rejection, change/clear flows, lock-state rejection, and
  persistence across lock → re-unlock.
- **Not part of this sub-step:** actual Open/Export/Delete secure-file
  I/O, Export destination handling, settings UI, and Export prompt UI
  remain Phase 39.5.

## [1.15.3] — Phase 39.3: Session / auto-lock model

### Added
- **`core/vault/session.py`** [NEW]: `VaultSession` — the §4 / §11.4
  session model. Text chat is session-based (unlock once, read/send
  freely); auto-lock after **5 minutes idle by default** (sudo's own
  `timestamp_timeout`, user-configurable, `0` = never); hard lock wipes
  the in-memory DEK and flushes+destroys the vault working copy via
  `VaultDatabase.lock()`. File actions (`open` / `export` /
  `move_to_secure` / `delete`) re-prompt by default; per-session
  "don't ask again" opts into reusing the unlocked session until the
  next lock; Incoming Transfer stays passphrase-free unless the user
  turns that on. Settings (`auto_lock_timeout_seconds`,
  `require_passphrase_for_incoming`) live in the vault `settings` table
  and are loaded on every unlock. `verify_passphrase()` supports
  step-up re-auth against the live DEK without locking (critical-action
  Export AND-gate itself stays 39.4).
- **`ui.py`**: wires `VaultSession` around the live vault — idle poll
  loop (`_auto_lock_loop`), activity touch on input, mid-session
  re-unlock modal (same `VaultUnlockModal` as startup), `/lock` +
  `Ctrl+L` for manual hard lock, `/autolock [minutes]` to show/set the
  timeout, `/info` shows remaining idle time. Chat/commands while
  locked refuse with a re-prompt rather than writing into a closed DB.
- **`core/trust/store.py`**: `TrustStore.adopt_conn()` — swap onto a
  freshly unlocked vault connection (or detach with `None` while
  locked) without closing a connection we don't own.
- **`core/vault/persistence.py`**: `VaultPersistence.reattach()` —
  writes are skipped while detached (lock-window events are not
  queued; the gap is the unlock modal).
- **`peer.py`**: incoming handshakes during a hard-lock window catch
  `RuntimeError` from a detached TrustStore and fail closed cleanly
  instead of crashing the accept loop.
- **Tests**: `tests/test_vault_session.py` (11) — idle expiry, DEK wipe,
  settings persistence, file-action re-auth policy, passphrase
  step-up, TrustStore detach/reattach, persistence skip-while-locked.
- **Not part of this sub-step:** critical-action key for Export (39.4),
  file actions / secure-mode storage / magic-byte executable detection
  (39.5) — `requires_reauth()` is ready for those gates to call.

## [1.15.2] — Phase 39.2: Encrypted database lifecycle + persistence

### Added
- **`core/vault/database.py`** [NEW]: `VaultDatabase` — the encrypted
  database lifecycle from §5/§17. `unlock(dek, vault_db_path)` decrypts
  the vault file (AES-256-GCM, key HKDF-derived from the DEK with a
  domain-separation label distinct from the vault keyfile's own KEKs)
  into a plaintext working copy, `flush()` re-encrypts it back
  (write-temp-then-atomic-rename), `start_auto_flush(interval=30)` does
  this periodically, `lock()` flushes once more and destroys the working
  copy. Working copy lives on `/dev/shm` (RAM-backed) on Linux when
  available; falls back to the OS temp dir otherwise with a best-effort
  overwrite-before-delete on lock() — a real, documented gap versus the
  Linux path, exercised in tests via `force_fallback=True` since actual
  Windows/macOS hardware isn't available here.
- Unified schema (§12): `trusted_devices` (Phase 4, schema unchanged),
  `identity_transitions` (Phase 40, added after the design doc predates
  it), `messages`, `transfers`, `settings` — one encrypted file instead
  of running two separate encrypt/flush lifecycles in parallel.
- **`core/vault/migration.py`** [NEW]: `migrate_plaintext_trust_db()` —
  one-time copy of `trusted_devices`/`identity_transitions` rows from
  the old plaintext `trust.db` into the vault, then deletes the old file
  outright (no `.migrated` backup — no real users yet, per project
  decision). No-op if the old file doesn't exist; handles pre-Phase-40
  files that predate `identity_transitions` entirely.
- **`core/trust/store.py`**: `TrustStore.__init__` gained an optional
  `conn` parameter — when given an already-open connection (the vault's),
  `TrustStore` operates directly on it instead of opening its own file,
  and `close()` doesn't close a connection it doesn't own. Default
  behavior (`conn=None`) is unchanged for every pre-existing call site.
- **`core/vault/persistence.py`** [NEW]: `VaultPersistence` — subscribes
  to `ChatReceived`/`ChatMessageSent`/`ChatMessageStatusChanged`/
  `TransferCompleted` on the EventBus (Phase 26) and writes `messages`/
  `transfers` rows. This is what actually "absorbs Phase 27" — no direct
  DB calls from `chat.py`/`file_transfer.py` themselves. Rows are keyed
  on each event's authenticated `peer_device_id` (from BUG-004's
  handshake, via `ConnectionManager.get_peer_device_id()`), never a
  self-reported field; an event with no authenticated device_id
  available is skipped rather than persisted under a guess.
- **`core/events.py`**: new `ChatMessageSent` event (outgoing messages
  previously had no event carrying their own text). `ChatReceived` and
  `TransferCompleted` gained a `peer_device_id` field alongside their
  existing self-reported identity fields; `TransferCompleted` also
  gained `direction`/`filename`/`size`/`checksum`/`addr_key`/`timestamp`
  so persistence needs no second lookup.
- **`chat.py`**: `send_chat()` now publishes `ChatMessageSent` after a
  successful send; `_handle_incoming_chat()` populates the new
  `peer_device_id` field on `ChatReceived`.
- **`file_transfer.py`**: `_notify_complete()` now takes the transfer
  object itself (not just its id) so it can populate the new
  `TransferCompleted` fields; all 6 call sites updated.
- **`ui.py`**: full vault unlock flow wired in via three new
  `ModalScreen`s — `VaultCreateModal` (first run: passphrase + confirm,
  validated locally before dismissing), `VaultRecoveryCodeModal` (shown
  exactly once, right after creation), `VaultUnlockModal` (every run
  after: passphrase, with a "use recovery code instead" toggle; wrong
  attempts loop back with an inline error rather than crashing or
  retrying silently). `_setup()` — the former body of `on_mount()` — is
  now `@work`-decorated: Textual's `push_screen_wait()` (needed for
  these modals) must run inside a worker, not directly in `on_mount`,
  which headless testing (`App.run_test()` + `Pilot`) caught before it
  became a runtime bug. `on_unmount()` locks the vault on exit.
  `TrustStore` now shares the vault's own connection instead of opening
  its separate plaintext file, and `migrate_plaintext_trust_db()` runs
  once at startup before it's constructed.
- **Tests**: `tests/test_vault_database.py` (10), `test_vault_persistence.py`
  (7), `test_vault_trust_integration.py` (4) — 21 new automated tests.
  The full `ui.py` vault modal flow (first-run create → recovery code →
  main screen; second-run wrong-passphrase retry with inline error →
  toggle to recovery-code mode → successful unlock; correct-passphrase
  unlock on a subsequent run; vault data surviving a full lock/unlock
  cycle) was verified headlessly via `App.run_test()`/`Pilot` — not
  committed as a permanent test yet, since `ChatApp` doesn't currently
  accept injectable paths and a reload-based workaround risked leaking
  state into other tests; a proper version is a worthwhile follow-up,
  not folded into this sub-step.
- **Not part of this sub-step:** the session/auto-lock model (39.3),
  the critical-action key for Export (39.4), file actions and secure-mode
  storage — every transfer today persists with `storage_mode='normal'`
  (39.5).

## [1.15.1] — BUG-004: Live secure transport integration

### Fixed
- **BUG-004 (TCP plaintext)**: `peer.py`'s `ConnectionManager` — the code
  path every real connection in the running app goes through — was
  still 100% plaintext TCP with no handshake at all, despite Phase 6-9
  (`core/crypto/handshake.py`, `core/transport/`) being fully
  implemented and unit-tested since much earlier. Nothing in `ui.py`/
  `peer.py`/`chat.py`/`file_transfer.py` ever actually called them.
- Every connection, incoming or outgoing, now goes through
  `core/transport`'s mutual authenticated handshake and
  ChaCha20-Poly1305 session encryption (`initiate_secure_session`/
  `accept_secure_session`). `ConnectionManager`'s public API is
  unchanged (`send()`/`send_binary()`/`connect_to()`/`is_connected()`,
  still addr_key-keyed) so `chat.py`/`file_transfer.py` needed no
  changes beyond identity plumbing.
- New `ConnectionManager.get_peer_device_id(addr_key)` — the first place
  in the app where a peer's device_id is cryptographically verified
  rather than only self-reported inside an application-level message
  field.
- `TrustStore` (Phase 4) finally constructed and wired into the live app
  for the first time (`ui.py`) — still its own plaintext
  `~/.peerc/trust.db` for now; migrating it into the encrypted vault is
  Phase 39.2, not this fix. REVOKED/KEY_CHANGED devices are rejected at
  the handshake (connection closed); PENDING (first-seen) devices are
  allowed to proceed, matching `handshake.py`'s existing behavior, and
  now publish a `TrustRequired` event — `ui.py` logs a notification for
  it, but full approve/reject UX stays Phase 36/37 as already planned,
  not folded into this fix.
- `file_transfer.py`'s `offer_file()` no longer hardcodes
  `sender_id=""`/`sender_name=""` — it now uses the identity
  `ConnectionManager` already holds.
- `my_identity`/`my_name` are required constructor arguments on
  `ConnectionManager`, with no defaults — a silently-auto-generated
  throwaway identity would be easy to miss. Every call site (including
  all test fixtures) was made explicit.
- Found and fixed a Python 3.12-specific hang: `asyncio.Server.wait_closed()`
  waits for every accepted connection's handler task to finish, not just
  for `close()` itself — a just-closed session's background read loop
  can take a beat to notice its socket died. `ConnectionManager.close_all()`
  now bounds that wait with a 2s timeout instead of blocking indefinitely.
- **Tests**: `tests/test_security_fixes.py`, `test_upgrade_fixes.py`,
  `test_event_bus.py`, `test_stage2/3/4.py` updated for the new required
  constructor args. The two BUG-017/018 raw-socket-injection tests in
  `test_security_fixes.py` were rewritten: one now sends a malformed
  dict through the real encrypted channel (`manager.send()` itself does
  no schema validation, so this still reaches the receiver's
  `validate_message()` exactly as before); the other hand-crafts a raw
  encrypted non-dict-JSON frame via the session's own transport
  primitives, since `EncryptedTransport.send_message()` now refuses to
  put a non-dict on the wire at all through the normal send path — a
  real, permanent fix for that specific bug shape, not just a
  relocated test.
- **Not part of this fix (deliberately out of scope):** migrating
  `trust.db` into the encrypted vault (Phase 39.2, resuming next),
  full trust approve/reject UI (Phase 36/37), and the
  Rendezvous/"link add" endpoint model for internet (non-LAN) peers
  discussed but deferred to Phase 44/45 (`docs/INTERNET_CONNECTIVITY_DESIGN.md`
  §9-10) — today's fix only concerns the existing LAN ip:port model.

## [1.15.0] — Phase 39.1: Vault Envelope Encryption (Phase 39 begins)

### Added
- **`core/vault/`** [NEW] — envelope-encryption core for Secure Storage,
  per `docs/SECURE_STORAGE_DESIGN.md` §2/§3/§13–§16:
  - `crypto.py`: Scrypt KDF (`derive_kek`, N=131072/r=8/p=1 per RFC 7914's
    interactive-use recommendation) and AES-256-GCM `wrap_dek`/`unwrap_dek`
    (fresh random 12-byte nonce every call; GCM's own auth tag is the
    "wrong passphrase" verifier — no separate verifier hash stored).
  - `recovery_code.py`: Crockford Base32 recovery code (20 random bytes,
    grouped-with-dashes display, trailing checksum character; O/I/L
    transcription-mistake normalization on input).
  - `keyfile.py`: `VaultKeyfile` dataclass matching the documented
    `vault_keyfile.json` schema; `create_vault()` (first-time setup,
    returns the recovery code exactly once, never stored),
    `unlock_with_passphrase()`, `unlock_with_recovery_code()`,
    `change_passphrase()` (re-wraps the DEK only, nothing else touched),
    `save_vault_keyfile()`/`load_vault_keyfile()` (atomic write-temp-
    then-rename), `validate_passphrase()` (§14: 8-char minimum only, no
    forced complexity, rejects empty or same-as-device-name).
  - Default path `~/.peerc/vault_keyfile.json` — same convention as
    `core/identity/identity_file.py`'s `DEFAULT_IDENTITY_DIR`
    (`os.path.expanduser`, portable across Linux/macOS/Windows without a
    new dependency).
  - No new dependency — `cryptography` (already required since Phase 3)
    covers both Scrypt and AES-GCM.
  - **`tests/test_vault.py`** [NEW]: 17 tests — create/unlock roundtrip
    (passphrase and recovery code), wrong passphrase rejected, mistyped
    recovery-code checksum rejected before the KDF, a well-formed-but-
    wrong recovery code still rejected at unwrap, change-passphrase
    roundtrip (DEK unchanged, old passphrase stops working), passphrase
    validation rejections, duplicate `create_vault()` rejected,
    save/load roundtrip, atomic-write cleanup, recovery-code
    normalization (lowercase/dashes/ambiguous-character substitution).
  - **Not yet done (Phase 39.2, next sub-step):** encrypted database
    lifecycle (tmpfs unlock/flush/lock), unified schema absorbing Phase
    27 (`messages`/`transfers`/`settings`) plus migrating Phase 4's
    plaintext `trust.db` into it.

## [1.14.0] — Phase 26: Event Architecture

### Added
- **Phase 26 — Event Architecture** (`core/events.py`, `core/__init__.py`, `tests/test_event_bus.py`):
  - **`EventBus`**: Central decoupled asynchronous event dispatcher supporting typed subscriptions, subtype polymorphism (subscribing to `Event` receives all subtypes), wildcard subscriptions (`subscribe_all`), sync and async handler callbacks, subscriber exception isolation, and async context manager testing (`bus.capture()`).
  - **Typed Event Classes**:
    - `ChatReceived`: Incoming chat messages with parsed metadata and payload.
    - `ChatMessageStatusChanged`: Outgoing message status transitions (`sent`, `delivered`, `failed`).
    - `FileOffered`: Incoming file transfer offers.
    - `FileProgress`: Real-time upload and download progress with percentage calculation.
    - `TransferCompleted`: Final status of file transfers with error diagnostics.
    - `PeerConnected`: Transport connection establishment notifications.
    - `PeerDisconnected`: Connection drop notifications.
    - `TrustRequired`: Notifications when peer authentication requires trust confirmation.
    - `SecurityWarning`: Bridge event for security alerts at `WARNING` or higher severity.
    - `NetworkMessageReceived`: Raw framed transport messages parsed from the wire.
  - **Security Bridge** (`bridge_security_events`): Automatically hooks into `core.security.events`, filtering and projecting `SecurityEvent` instances of `WARNING`+ severity into `SecurityWarning` events on the bus.
  - **Comprehensive Test Suite** (`tests/test_event_bus.py`): 9 unit and integration tests covering pub/sub, error isolation, polymorphic dispatch, security bridging, and multi-session integration.

### Changed
- **Resolved ARCH-001 (`on_message` handler chaining)**:
  - `ConnectionManager` (`peer.py`) now accepts an optional `event_bus` and emits `PeerConnected`, `PeerDisconnected`, and `NetworkMessageReceived`. Legacy `on_message` callback remains supported for backward compatibility.
  - `ChatSession` (`chat.py`) subscribes to `NetworkMessageReceived` and dispatches `ChatReceived` and `ChatMessageStatusChanged` without modifying `manager.on_message`.
  - `FileTransferSession` (`file_transfer.py`) subscribes to `NetworkMessageReceived` and dispatches `FileOffered`, `FileProgress`, and `TransferCompleted` without modifying `manager.on_message`.
  - `ChatApp` (`ui.py`) uses `EventBus` to bind transport, chat, file transfer, and security warnings, completely removing `on_message` callback mutation.

## [1.13.1] — Phase 5.2: mDNS Discovery (Phase 5 complete)

### Added
- **Phase 5.2 — mDNS Discovery** (`discovery.py`, `pyproject.toml`,
  `tests/test_discovery.py`):
  - **`MDNSDiscovery`** class: advertises this device as
    `<device_id[:16]>._peerc._tcp.local.` and browses for peers using
    the `zeroconf` library.  TXT record carries key-value fields
    (`version`, `device_id`, `public_key`, `name`, `tcp_port`) — all
    inspectable with `avahi-browse`/`dns-sd`, unlike an opaque blob.
  - **`_PeercServiceListener`**: zeroconf `ServiceListener` that resolves
    discovered mDNS services and feeds them into `Discovery._handle_packet()`
    as synthetic UDP-format packets — **no duplicate validation logic**.
    Both UDP broadcast and mDNS announce packets go through exactly the same
    device_id/public_key self-consistency and field-validation code path.
  - **`MDNS_AVAILABLE`** flag (`bool`): `True` when `zeroconf` is installed,
    `False` otherwise.  When `False`, `Discovery.run()` logs an `INFO`
    message and continues with UDP broadcast only — mDNS is **optional**.
  - **`_build_mdns_txt()`** / **`_mdns_txt_to_packet()`** / **`_safe_int()`**
    helper functions; `get_network_info()` now includes `mdns_available`.
  - `Discovery.run()` now runs an `_mdns_loop()` coroutine in parallel with
    the existing announce/listen/prune loops when `MDNS_AVAILABLE is True`.
    TTL is refreshed every `MDNS_ANNOUNCE_INTERVAL` (10 s) seconds.  mDNS
    `reply=False` so it never triggers the UDP unicast bi-directional reply.
  - **`pyproject.toml`**: optional dependency group
    `[project.optional-dependencies] mdns = ["zeroconf>=0.131"]`.
    Install with `pip install peerc[mdns]`.  Core install unchanged.
  - **`tests/test_discovery.py`** extended with 9 new Phase 5.2 tests
    (items 8–14 in module docstring): `MDNS_AVAILABLE` type, TXT shape,
    name truncation, valid/mismatch/wrong-version packet handling via the
    shared `_handle_packet` path, `reply=False` invariant,
    `get_network_info` key, and `Discovery.run()` task count via
    monkeypatching (no real sockets required; existing 5.1 tests unchanged).


### Added
- **Phase 5.1 — Discovery V2 protocol fields** (`discovery.py`, `ui.py`):
  - Broadcast payload now carries `version` (`PROTOCOL_VERSION = 2`),
    `device_id` (renamed from `peer_id` on the wire; internal Python
    attribute name unchanged for backward compat with `chat.py`/`peer.py`/
    `ui.py`), and the sender's raw Ed25519 `public_key` (base64), per
    `docs/IMPLEMENTATION_PLAN.md` Phase 5's wire spec.
  - **Self-consistency validation** on every incoming packet: `public_key`
    must base64-decode to exactly 32 bytes, and
    `device_id == sha256(public_key)` must hold, or the packet is dropped.
    This is explicitly *not* a trust decision (discovery never was, and
    still isn't, authentication) — it only rejects packets that lie about
    which key backs their claimed device_id. Real trust decisions remain
    with `core/trust/` at Phase 6 handshake time.
  - Mismatched self-consistency emits an `AUTH_FAILED` (WARNING)
    `SecurityEvent` via the Phase 41 logging infra; malformed fields
    (bad base64, wrong length) and version mismatches are dropped
    silently, matching the existing BUG-023 field-validation behavior.
  - `Peer` dataclass gained a `public_key: bytes` field; `PeerRegistry.upsert()`
    and `Discovery.__init__()` accept/thread it through so it's available
    for later phases (e.g. Phase 6 handshake) without another discovery
    round-trip.
  - `ui.py` now fetches the local device's public key (via
    `core.identity.load_or_create_identity()`) and passes it into
    `Discovery`.
  - **`tests/test_discovery.py`** [NEW]: 9 tests covering payload shape,
    valid self-consistent packets, device_id/public_key mismatch (dropped
    + event emitted), malformed public_key, version mismatch, own-broadcast
    ignore, and a BUG-023 regression check.
  - `tests/test_upgrade_fixes.py::test_discovery_packet_validation` updated
    to the new wire shape (`device_id` + real keypairs) so it keeps
    exercising the original BUG-023 field checks rather than failing on
    the unrelated protocol-version/self-consistency checks.
  - **Not yet done (Phase 5.2, next sub-step — will land as `1.13.1`):**
    mDNS as a second discovery transport alongside UDP broadcast and
    manual `/connect`.

## [1.12.0] — Phase 41 complete: Security Event Logging

### Added
- **Phase 41 — Security Event Logging** (`core/security/events.py`,
  `core/trust/store.py`, `core/crypto/handshake.py`, `core/identity/rotation.py`,
  `core/identity/identity_file.py`):
  - **`core/security/events.py`** [NEW]: Extends Phase 28 logging with the
    `SECURITY_MODEL.md` §29 severity classification scheme:
    - `SecuritySeverity` (`INFO`, `WARNING`, `HIGH`, `CRITICAL`) with rank ordering
      and standard library `logging` level mapping (`INFO` -> 20, `WARNING` -> 30,
      `HIGH` -> 40/ERROR, `CRITICAL` -> 50/CRITICAL).
    - `SecurityEventType` defining standardized events: endpoint changes, normal key rotation,
      unknown devices, identity changes, authentication failures, invalid rotation certificates,
      revoked device attempts, nonce replays, and key compromises.
    - `SecurityEvent` dataclass with automatic defensive sanitization preventing leaks of
      private keys, session keys, or secrets into logs or event payloads.
    - `canonical_payload()` producing deterministic byte representations under domain separation
      prefix `peerc-security-event\x00` for Phase 42 group audit trail signing.
    - `emit(event)` dispatcher that routes to `peerc.security` logger and in-memory listeners.
    - Listener registry (`add_listener`, `remove_listener`) and `capture_security_events()`
      context manager.
  - **Call site integrations**:
    - `TrustStore.check()` emits `IDENTITY_CHANGED` (WARNING) on key mismatch and
      `REVOKED_DEVICE_ATTEMPT` (HIGH) on revoked devices.
    - `TrustStore.record_rotation()` emits `KEY_ROTATION` (INFO) on valid rotation,
      `INVALID_ROTATION` (WARNING) on invalid certificate, and `REVOKED_DEVICE_ATTEMPT` (HIGH)
      when a revoked device attempts rotation.
    - `TrustStore.check_with_rotation()` emits `REVOKED_DEVICE_ATTEMPT` (HIGH) when a device
      is tainted by a revoked ancestor in its rotation chain.
    - `verify_transition_certificate()` in `core/identity/rotation.py` emits `INVALID_ROTATION`
      (WARNING) on bad signature or malformed certificate.
    - `rotate_identity()` in `core/identity/identity_file.py` emits `KEY_ROTATION` (INFO).
    - `handshake.py` emits `AUTH_FAILED` (WARNING) on claimed device_id mismatch or signature
      failure, and `REPLAY_DETECTED` (HIGH) on nonce replay.
  - **`tests/test_security_events.py`** [NEW]: 10 comprehensive tests covering severity ordering,
    serialization, safe credential redaction, listeners, TrustStore, key rotation, and handshake
    call sites.

## [1.11.0] — Phase 40 complete: Device Key Rotation

### Added
- **Phase 40 — Device Key Rotation** (`core/identity/rotation.py`,
  `core/identity/identity_file.py`, `core/trust/store.py`):
  - **`core/identity/rotation.py`** [NEW]: `TransitionCertificate` dataclass and
    two pure functions — `create_transition_certificate(old_keypair, new_keypair)`
    (signs the rotation with the old private key) and
    `verify_transition_certificate(cert)` (verifies the signature, returns bool).
    Canonical payload uses a `peerc-key-rotation` domain-separation prefix and
    struct-packed timestamp to prevent cross-protocol signature reuse.
  - **`rotate_identity()`** added to `core/identity/identity_file.py`: generates
    a new Ed25519 keypair, produces a `TransitionCertificate` while the old key
    is still in memory, overwrites `KeyStore` and `identity.json` atomically, and
    records `rotated_from` in the JSON for auditability.
  - **`TrustStore.record_rotation(cert)`**: verifies the cert, inserts the
    transition into the new `identity_transitions` SQLite table, and
    automatically carries `TRUSTED` status forward to the new `device_id`
    (PENDING and REVOKED are deliberately not carried — per SECURITY_MODEL.md §15).
  - **`TrustStore.get_rotation_chain(device_id)`**: BFS traversal of
    `identity_transitions` returning all `device_id`s in the same rotation
    chain, ordered oldest → newest.
  - **`TrustStore.check_with_rotation(device_id, public_key)`**: drop-in
    replacement for `check()` that understands rotation history; REVOKED
    anywhere in the chain taints the whole chain (§17 fail-closed).
  - **`tests/test_rotation.py`** [NEW]: 12 test cases covering create + verify,
    tampered cert, wrong signing key, TRUSTED carry-over, PENDING stays PENDING,
    REVOKED blocks rotation, compromise rotation produces UNKNOWN, multi-hop
    chain ordering, and all `check_with_rotation` branches.

## [1.10.0] — Phase 12/13–20 complete: File Transfer V2 + Hardening

### Added
- **`core/transfer/`** (Phases 12–20) — Modular, hardened file transfer subsystem:
  - **`hashing.py`** (Phase 17): `sha256_file(path)` streaming hash calculation (64 KB chunks) and `IncrementalHasher` for chunk-by-chunk verification without re-reading from disk.
  - **`chunker.py`** (Phase 12): `read_chunks()` generator yielding `(sequence, offset, chunk_bytes)` with configurable chunk size (default 64 KB) and `start_offset` parameter for resume support.
  - **`resume.py`** (Phase 16): `.part` staging file lifecycle management (`get_part_path`, `get_partial_bytes`, `cleanup_part_file`), and atomic renaming via `finalize_part_file()` (`os.replace`) preventing incomplete or corrupted files from being exposed to the user.
  - **`receiver.py`** (Phases 13–17, 20): `FileReceiver` state machine managing inbound file streams with:
    - Pre-flight free disk space check (`check_disk_space`) requiring `declared_size + 50 MB` safety margin before accepting transfer.
    - Path traversal prevention (`resolve_safe_dest_path`) stripping directory separators, resolving canonical paths, and confining all writes to the target downloads directory.
    - Strict sequence order and cumulative byte offset validation (`ChunkValidationError`) preventing out-of-order, replayed, or oversized chunks.
    - Staging writes into `.part` files and SHA-256 integrity verification upon completion before atomic rename.
    - Partial file resume detection returning current bytes received for seamless transfer resumption.
  - **`sender.py`** (Phases 12, 16, 19): `FileSender` state machine managing outbound file streaming from any resume offset, progress calculation, and delivery acknowledgment awaiting with timeout (`file_complete_ack`).
  - **`manager.py`** (Phases 12, 20): `FileTransferManager` coordinating active transfers, enforcing global limits (`MAX_CONCURRENT_TRANSFERS = 5`, `MAX_TOTAL_INCOMING_SIZE = 10 GB`, `MAX_INCOMING_FILE_SIZE = 2 GB`), and tracking active transfer registry.
  - **`core/transfer/__init__.py`**: Re-exports all transfer classes, exceptions, and utility functions.
- **`file_transfer.py`**: Refactored to delegate to `core.transfer` modules while preserving 100% backward compatibility for existing callers (`peer.py`, `ui.py`, test scripts) and internal attributes (`_incoming`, `_outgoing`, `dest_path`, `_safe_dest_path`, callbacks).
- **`tests/test_file_transfer_v2.py`**: 8 automated tests covering hashing, chunk offset seeking, `.part` lifecycle, atomic renaming, path traversal rejection, disk space pre-flight validation, sender-receiver roundtrip verification, resume from partial file, chunk sequence/overflow rejection, and concurrency/size limits.
- **`.github/workflows/tests.yml`**: Added `tests/test_file_transfer_v2.py` to the automated CI test matrix.
- **`pyproject.toml`**: Added `"core.transfer"` package and bumped version to `1.10.0`.

### Compatibility
- Full backward compatibility maintained for existing UI and peer components. All 61 pytest tests and 4 stage sanity scripts pass without regression. Version bumped to `1.10.0` (MINOR: whole phase complete).

### Added
- **`core/transport/`** (Phase 9) — Decoupled secure transport architecture (`Application -> SecureSession -> EncryptedTransport -> TCP`):
  - **`timeout.py`**: Centralized transport timeouts (`CONNECT_TIMEOUT = 5.0s`, `HANDSHAKE_TIMEOUT = 5.0s`, `IDLE_TIMEOUT = 60.0s`) and custom exception hierarchy (`TransportTimeoutError`, `ConnectTimeoutError`, `HandshakeTimeoutError`, `IdleTimeoutError`, `ConnectionClosedError`).
  - **`tcp.py`**: `TCPConnection` encapsulating `(reader, writer)` with length-prefixed JSON and binary framing, peer address inspection, and `open_tcp_connection(host, port, timeout)`.
  - **`secure.py`**: `EncryptedTransport` wrapping `TCPConnection` and `SecureChannel` (Phase 8 ChaCha20-Poly1305). All framed traffic travels as uniform binary frames (`[8 bytes sequence][ciphertext + 16B Poly1305 tag]`).
  - **`session.py`**: High-level `SecureSession` providing `send(message)`, `send_binary(payload)`, and `receive()` — application code needs zero awareness of cryptography. Automated session establishment helpers `initiate_secure_session()` and `accept_secure_session()` executing the Phase 6 mutual Ed25519 handshake and Phase 7 session key derivation.
  - **`SecureSessionManager`**: Multi-session registry keyed by authenticated `device_id` (not `ip:port`), fulfilling Phase 10 design requirements early.
  - **`core/transport/__init__.py`**: Re-exports all transport classes, helpers, and timeouts.
- **`tests/test_transport.py`**: 9 automated unit and integration tests covering loopback framing, connect timeouts, bidirectional encrypted messaging, wire tampering rejection, full end-to-end mutual session establishment with chat and binary file chunks, session manager device_id tracking, session closure errors, handshake timeout aborts, and revoked peer rejection.
- **`.github/workflows/tests.yml`**: Added `tests/test_transport.py` to the CI pytest suite.
- **`pyproject.toml`**: Added `"core.transport"` package, bumped version to `1.9.0`.

### Compatibility
- Purely additive module. Existing `peer.py` and stage scripts continue to pass without changes. Version bumped to `1.9.0` (MINOR: whole phase complete).

## [1.8.0] — Phase 8 complete: ChaCha20-Poly1305 encrypted channel

### Added
- **`core/crypto/encryption.py`** (Phase 8): `SecureChannel` — a ChaCha20-Poly1305
  AEAD channel built on Phase 7's `SessionKeys` (independent `send_key`/`recv_key`
  per direction).
  - **Sequence-derived nonce, not random**: `nonce = sequence.to_bytes(12, "big")`.
    Uniqueness is guaranteed by construction (a monotonic counter can't repeat
    within a session) rather than relying on random-96-bit collision odds — and
    it means the nonce never needs to travel on the wire, since both sides
    already track their own counter.
  - `encrypt(plaintext, associated_data=b"")` → `EncryptedFrame(sequence, ciphertext)`,
    auto-incrementing sequence.
  - `decrypt(sequence, ciphertext, associated_data=b"")` enforces **strict,
    gap-free sequence order** per direction — a replayed frame, an
    out-of-order frame, or a frame from a different session's keys are all
    rejected (`ReplayOrReorderError` / `DecryptionError`), the same rigor
    already applied to file_data chunks' sequence+offset checks (BUG-008).
  - `SequenceExhaustedError` if a direction's 12-byte counter would overflow
    (a session must be re-handshaked at that point, not reused past it).
- 11 new tests (`tests/test_encryption.py`): round-trip, sequence tracking,
  tampered ciphertext, wrong key, replay, out-of-order, direction
  independence (a channel can't decrypt its own sent traffic), nonce
  determinism, sequence range validation, key-length validation, AAD
  mismatch detection.

### Compatibility
- Purely additive — no existing module touched. Not yet wired into
  `peer.py`'s connection handling (that's Phase 9, Secure Transport Layer).
- Verified: full 44-test pytest suite + 4 stage sanity scripts, all passing.

## [1.7.0] — Phase 7 complete: session key derivation (X25519 + HKDF)

### Added
- **`core/crypto/kdf.py`** (Phase 7):
  - HKDF-SHA256 (RFC 5869) session key derivation: `derive_session_keys(shared_secret, salt, is_initiator)`.
  - Cryptographic domain separation with distinct context tags:
    - `b"peerc-v2:initiator-to-responder"` (32-byte key)
    - `b"peerc-v2:responder-to-initiator"` (32-byte key)
    - `b"peerc-v2:session-id"` (16-byte unique session identifier)
  - Directional keys via `SessionKeys` (`send_key`, `recv_key`, `session_id`):
    - Guaranteed symmetry: initiator's `send_key` matches responder's `recv_key`, and initiator's `recv_key` matches responder's `send_key`.
    - Key separation: `send_key != recv_key` on the same host, preventing reflection and cross-direction key reuse attacks.
  - Transcript hash binding: uses the 32-byte authenticated handshake transcript hash as HKDF salt, ensuring derived session keys are strictly bound to the exact authenticated session.
  - Safe key representation: `SessionKeys.__repr__` masks raw key material (`***`) preventing accidental secret leakage in console logs or tracebacks.
  - Error handling: `KDFError` for invalid types or invalid key/salt lengths.
- **`core/crypto/handshake.py`**:
  - Added convenience method `HandshakeResult.derive_session_keys(is_initiator: bool) -> SessionKeys`.
- **`core/crypto/__init__.py`**:
  - Re-exports `KDFError`, `SessionKeys`, and `derive_session_keys`.
- **`tests/test_kdf.py`**:
  - Automated tests covering determinism, directional symmetry, key separation, transcript binding (avalanche effect), shared secret sensitivity, input validation, masked repr, and end-to-end TCP loopback integration with `perform_handshake_initiator` and `perform_handshake_responder`.
- **`.github/workflows/tests.yml`**:
  - Added `tests/test_kdf.py` to the CI pytest suite.

### Compatibility
- Additive module. No breaking changes. Version bumped to `1.7.0` (MINOR: whole phase complete).

## [1.6.0] — Phase 6 complete: secure authenticated handshake

### Added
- **`core/crypto/key_exchange.py`** (Phase 6.1):
  - Ephemeral X25519 keypair generation (`EphemeralKeypair`, `generate_ephemeral_keypair()`).
  - Raw and hex public key serialization (`ephemeral_public_from_bytes()`, `ephemeral_public_from_hex()`).
  - Diffie-Hellman shared secret computation (`compute_shared_secret()`), providing forward secrecy for sessions.
- **`core/crypto/handshake.py`** (Phase 6.2):
  - 3-way mutual authentication handshake state machine:
    1. `handshake_init`: initiator sends `device_id`, `public_key` (Ed25519), `ephemeral_key` (X25519), `nonce`, and `sender_name`.
    2. `handshake_response`: responder validates identity and trust, generates ephemeral key & nonce, signs the cumulative transcript, and returns signature.
    3. `handshake_finish`: initiator validates responder signature and trust, signs cumulative transcript, and completes handshake.
  - Transcript binding (`compute_responder_transcript`, `compute_initiator_transcript`, `compute_final_transcript_hash`): prevents man-in-the-middle parameter tampering or key substitution attacks.
  - Integration with `core/trust/store.py`: evaluates `TrustStore.check()`, auto-rejects `REVOKED` devices and `KEY_CHANGED` devices, records first-seen peers as `PENDING`, and updates `last_seen`.
  - Replay protection with `NonceCache` tracking fresh 32-byte nonces.
  - Enforced `HANDSHAKE_TIMEOUT = 5.0s`.
  - Asynchronous stream drivers `perform_handshake_initiator()` and `perform_handshake_responder()`.
- **`core/protocol/messages.py`**:
  - Message factories: `make_handshake_init()`, `make_handshake_response()`, `make_handshake_finish()`.
  - Wire schema validation in `REQUIRED_FIELDS` and `validate_message()`.
  - Re-exported via `core.protocol` and root `protocol.py`.
- **`tests/test_handshake.py`**:
  - Full automated coverage: ephemeral key exchange, message schemas, deterministic transcript hashing, loopback TCP handshake integration, and all mandatory security cases from Phase 30 (fake identity rejection, invalid signature rejection, MITM tampering rejection, replay detection, revoked device rejection, key change rejection, and handshake timeout).

### Compatibility
- Additive protocol extension. Re-exports through `protocol.py` preserve existing imports. Version bumped to `1.6.0` (MINOR: whole phase complete).

## [1.5.0] — Phase 4 complete: trust store + TOFU + revocation

### Added
- **`core/trust/revocation.py`** (Phase 4.2) — `revoke_device(store,
  device_id, revoked_by, reason=None)`: marks a device `REVOKED` locally
  and records an audit trail (`revoked_by`, `revoked_at`, `revoke_reason`).
  `is_revoked()` convenience check.
  - **Local-only for this phase, by design**: revocation isn't propagated
    to any other peer yet — there's no authenticated channel to send it
    over until Phase 6's handshake exists. Propagation is explicitly
    deferred, not forgotten.
  - Once `REVOKED`, a device can't silently become `TRUSTED` again —
    both `revoke_device()` (double-revoke) and `TrustStore.approve()`
    (approving a revoked device) refuse and raise rather than allow a
    quiet reversal.

### Compatibility
- Purely additive. Verified: revoke records a correct audit trail,
  double-revoke and revoke-unknown-device are rejected, `approve()`
  correctly refuses a revoked device, and `TrustStore.check()` reports
  `REVOKED` afterward. Existing 15/15 test suite unaffected.

### Note
- Phase 4 (this release) delivers `core/trust/` as a complete, standalone,
  tested primitive — TOFU evaluation, approval, and local revocation all
  work and are covered by tests. It is **not yet wired into any actual
  peer connection** (`peer.py`, `discovery.py`, `ui.py` are untouched):
  there's no cryptographic handshake yet for a `device_id`/`public_key`
  pair to be checked *against*. That wiring happens in Phase 6 (Secure
  Handshake), once a peer connection actually carries a signed identity
  to check trust against.

## [1.4.1] — Phase 4.1: trust store (SQLite) + TOFU logic

### Added
- **`core/trust/` package** (IMPLEMENTATION_PLAN.md Phase 4) — standalone,
  not yet wired into peer.py/discovery.py/ui.py (there's no handshake yet
  to wire it into — that's Phase 6):
  - `device.py` — `TrustedDevice` dataclass, `TrustStatus` enum
    (`PENDING` / `TRUSTED` / `REVOKED`).
  - `store.py` — `TrustStore`, backed by SQLite (stdlib `sqlite3`) at
    `~/.peerc/trust.db`, table `trusted_devices` matching the schema
    in IMPLEMENTATION_PLAN.md. TOFU is deliberately split into a
    **read-only** `check(device_id, public_key)` (returns `UNKNOWN` /
    `PENDING` / `TRUSTED` / `KEY_CHANGED` / `REVOKED`) and separate
    write operations (`record_first_seen`, `approve`) that only run on
    an explicit caller action — `check()` never mutates state, and a
    `public_key` mismatch for a known `device_id` is *never*
    auto-corrected (that would defeat the point of TOFU: it's the signal
    a human needs to see and decide about, not something to paper over).

### Compatibility
- Purely additive. Verified standalone: full TOFU life cycle (unknown →
  first-seen/PENDING → approved/TRUSTED → key-change detection with the
  stored key confirmed unchanged → re-insertion correctly rejected →
  `last_seen` bump → filtered listing by status).

## [1.4.0] — Phase 3 complete: device identity wired in

### Changed
- **`discovery.py`: `peer_id` is now an Ed25519-derived `device_id`**
  (Phase 3.4, closes BUG-003) — `load_or_create_identity()` and
  `save_identity()` now delegate to `core.identity` under the hood, while
  keeping their old call signatures (`(peer_id, name)` tuple in / out) so
  `chat.py`, `ui.py`, and `peer.py` needed zero changes.
  - `save_identity()` now rejects a `peer_id` that doesn't match the
    identity file's recorded `device_id` (`ValueError`) instead of
    silently overwriting — renaming is still supported, reassigning
    someone else's identity is not.
  - **Not migrated**: old pre-Phase-3 identity files
    (`.peerc_identity.json`, bare `{"peer_id": <uuid>, "name": ...}`) are
    left untouched and unused. There's nothing to migrate — a UUID has no
    keypair behind it. Any device upgrading to `1.4.0` gets a new,
    provable `device_id` (and a fresh default identity file at
    `~/.peerc/identity.json`) the first time it runs.

### Compatibility
- **Breaking for existing deployments**: peers on `<1.4.0` and `1.4.0+`
  will show up with different-looking IDs and, since discovery keys peers
  by `peer_id`, effectively look like "new" peers to each other after the
  upgrade. Expected and intentional — this is the whole point of moving
  off unauthenticated UUIDs (see Phase 3.0's rationale). No user-facing
  chat/file-transfer behavior changes; this only affects how peers are
  identified.
- Verified: full 15/15 existing test suite (unchanged, all still green),
  plus new end-to-end coverage of `discovery.py`'s wiring: first-run
  generation, reload consistency, rename, and rejection of a mismatched
  `peer_id` on rename.

### Note
- Phase 3 delivers the identity primitive only — device_id is generated,
  stored, and now used as `peer_id` in discovery. It is **not yet used
  for anything cryptographic**: no signing, no verification, no
  authenticated handshake. That's Phase 4 (Trust Store) and Phase 6
  (Secure Handshake).

## [1.3.1] — Phase 3.1–3.3: Ed25519 device identity module

### Added
- **`core/identity/` package** (IMPLEMENTATION_PLAN.md Phase 3) — not yet
  wired into `discovery.py` (that's the next sub-step). Standalone and
  fully tested on its own:
  - `device_identity.py` — `generate_keypair()` / `keypair_from_private_pem()`
    using the `cryptography` library's Ed25519 (no hand-rolled crypto, per
    Phase 3's explicit instruction). `device_id = SHA256(raw public key
    bytes)`, hex-encoded — provably tied to the key that backs it, unlike
    the random UUID it's replacing (see Phase 3.0's rationale).
  - `key_storage.py` — `KeyStore`: private key goes to the OS keyring
    (Secret Service / Credential Manager / Keychain) via the `keyring`
    library when a real backend exists, falling back to a 0600-permission
    plaintext file when it doesn't (e.g. this dev sandbox — verified: no
    keyring backend here, `KeyStore` correctly falls back and the file
    lands at exactly `0600`).
  - `fingerprint.py` — colon-separated hex formatting of a device_id
    (SSH/TLS-style), for the human-comparable fingerprint Phase 4's
    trust-on-first-use flow will need.
  - `identity_file.py` — `load_or_create_identity()`: ties the above
    together. Private key stored via `KeyStore`; public metadata
    (`device_id`, `public_key`, `name`, `created_at`) in a separate plain
    JSON file. Detects and raises `IdentityError` on a corrupted/
    out-of-sync state (identity file present but key missing, or key
    doesn't match the recorded device_id) rather than silently
    regenerating or misbehaving.

### Dependencies
- Added `cryptography` and `keyring` to `pyproject.toml`.

### Compatibility
- Purely additive — no existing module was touched. `discovery.py` still
  uses the old UUID-based `peer_id` for now.

## [1.3.0] — Phase 1.3: binary framing for file transfer

**Note on versioning:** this change breaks file-transfer interop between
peers on `<1.3.0` and `1.3.0+` (chat/handshake are unaffected). Kept as a
MINOR bump rather than MAJOR — a deliberate call while still inside
Phase 1 of active development with no external users yet; revisit this
policy once there's a real install base to consider.

### Changed
- **File chunks now travel as raw binary frames instead of base64-in-JSON**
  (IMPLEMENTATION_PLAN.md Phase 1.3, closes BUG-006/BUG-007). New module
  `core/protocol/binary.py` defines the `file_data` wire layout: a fixed
  28-byte header (16-byte UUID `transfer_id` + 4-byte `sequence` +
  8-byte `offset`) followed by the raw chunk bytes — no JSON, no base64.
  - Overhead per 64 KB chunk: **33.6% → 0.05%** (measured), roughly 25%
    fewer bytes on the wire for a file transfer overall.
  - `core/protocol/frame.py`: the length-prefix header now reserves its
    top bit as an is-binary flag (`BINARY_FLAG`). Real payload lengths
    never legitimately set that bit (max is 100 MB, the flag is bit 31),
    so this is fully backward compatible with the existing
    `[4-byte length][JSON payload]` format — old raw frames decode
    identically. New: `read_any_frame()` (returns `("json", dict)` or
    `("binary", bytes)`), `encode_binary_frame()` / `write_binary_frame()`.
  - `peer.py`: `ConnectionManager._read_loop` now branches on frame kind;
    binary frames are decoded and handed to `on_message` as a synthetic
    `{"type": "file_data", ...}` dict, so no change was needed to the
    `on_message` callback interface itself. New `ConnectionManager.send_binary()`.
  - `file_transfer.py`: `_send_chunks` / `_handle_chunk` rewritten for the
    binary path. `make_file_chunk`/the old `file_chunk` JSON type are no
    longer used by the app (kept in `messages.py` for compatibility) —
    replaced by `sequence`+`offset` validation, which is a strict
    superset of the old chunk-index-only reorder check (BUG-008).
  - The old per-chunk `is_last` flag is gone (no longer meaningful for a
    binary frame without extra header cost); BUG-009's guarantee — a
    transfer can't be declared done with incomplete bytes — is still
    fully enforced in `_handle_done` (`bytes_received == size` AND
    checksum match required before `file_complete_ack(success=True)`).

### Compatibility
- Non-file-transfer messages (chat, hello, etc.) are completely unaffected
  — same JSON frames, same header size, same behavior.
- 3 tests in `test_security_fixes.py` that hand-crafted `file_chunk`
  messages were updated to craft binary `file_data` frames instead
  (same attack scenarios: oversized chunk, out-of-order chunk, bogus
  `file_done` checksum). `test_stage4.py` required zero changes since it
  only exercises the public `offer_file()`/callback API.
- Verified: 12/12 security+upgrade tests, 3/3 stage sanity scripts, plus
  an ad hoc 5 MB / ~80-chunk end-to-end transfer with checksum
  verification — all passing.

## [1.2.0] — Phase 1.2: protocol version field

### Added
- **`version` field on every message** (IMPLEMENTATION_PLAN.md Phase 1.2) —
  `core/protocol/messages.py` gains `PROTOCOL_VERSION = 2`, and every
  `make_*()` factory now stamps its output with `"version": PROTOCOL_VERSION`.
  This is the hook future protocol changes (encryption, identity handshake)
  will use to detect what a peer speaks before sending it something it
  can't parse.
- `validate_message()` now checks `version`: missing entirely is treated as
  legacy version 1 (messages from a peer on a pre-1.2 build, before this
  field existed) rather than rejected, but a non-int value or a version
  below `MIN_SUPPORTED_VERSION` (currently 1) is rejected with
  `ProtocolError`.

### Compatibility
- Wire-format-additive only — no existing field removed or renamed.
  Verified against the full test suite (12 security/upgrade tests + 3 stage
  sanity scripts, all passing) with no test changes required.

## [1.1.1] — Phase 1.1: split protocol layer

### Changed
- **Protocol module restructured** (IMPLEMENTATION_PLAN.md Phase 1.1) —
  `protocol.py` split into `core/protocol/{frame,messages,errors}.py`:
  - `core/protocol/frame.py` — length-prefixed wire framing
    (`encode_frame` / `read_frame` / `write_frame`), independent of message
    semantics.
  - `core/protocol/messages.py` — message type constants, `make_*` factory
    functions, and `validate_message()` schema validation.
  - `core/protocol/errors.py` — `ProtocolError`.
  - Root `protocol.py` kept as a backward-compatible shim re-exporting the
    same public API (`encode_message`/`read_message`/`write_message` alias
    the renamed `encode_frame`/`read_frame`/`write_frame`), so
    `chat.py`, `peer.py`, `file_transfer.py`, `ui.py`, and all existing
    tests required no changes.
- No behavior change. Verified via full test suite: 12/12
  (`test_security_fixes.py`, `test_upgrade_fixes.py`) + 3/3 stage sanity
  scripts (`test_stage2.py`–`test_stage4.py`), all passing.

## [1.0.0] — Initial release

### Added
- **Discovery** (`discovery.py`) — UDP broadcast peer discovery (MNDP-style).
  Stable `peer_id` (UUID) persisted locally so a peer survives IP changes
  from DHCP or switching networks (e.g. LAN to WiFi hotspot). Peer registry
  automatically prunes stale/offline peers after a timeout.
- **Protocol** (`protocol.py`) — length-prefixed JSON wire format (4-byte
  big-endian length header + UTF-8 JSON payload). Message types: `announce`,
  `chat`, `chat_ack`, `file_offer`, `file_accept`, `file_reject`,
  `file_chunk`, `file_done`.
- **Transport** (`peer.py`) — `ConnectionManager`: TCP server for incoming
  connections, `connect_to()` for outgoing connections, per-connection
  async read loop dispatching to a message callback.
- **Chat with delivery acknowledgment** (`chat.py`) — `ChatSession` tracks
  each sent message's status (`sent` → `delivered` / `failed`), auto-replies
  with `chat_ack` on receipt, and marks a message failed either immediately
  (not connected) or after a timeout (default 5s, no ack received). No
  automatic retry — a peer's IP may have changed since the message was sent.
- **Staged file transfer** (`file_transfer.py`) — `FileTransferSession`:
  offer → accept/reject → chunked send (64 KB chunks, base64-in-JSON) →
  checksum-verified completion (SHA-256, checked on both source and
  destination). Rejected offers and checksum mismatches leave no partial
  file on the receiver's disk.
- **Terminal UI** (`ui.py`) — Textual-based `ChatApp` tying everything
  together: live peer list, chat log with delivery status, input box with
  `/msg`, `/send`, `/help` commands, and a modal accept/reject dialog for
  incoming file offers.
- Per-stage automated verification scripts: `test_stage2.py` (chat
  round-trip), `test_stage3.py` (ack/delivery/timeout), `test_stage4.py`
  (chunked transfer + checksum, reject flow), `test_stage5.py` (UI headless
  smoke test) — all passing.
- `README.md` documenting features, architecture, usage, and known
  limitations; `requirements.txt`; `.gitignore`; MIT `LICENSE`.
