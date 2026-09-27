# Reliability Design: Phases 28-35

Status: **in progress** — 28.1 (`1.21.0`), 29/30.1 (`1.21.1`), and 31.1
(`1.21.2`) complete (29/30.1 also delivered the core of Phase 32.1's
task registry, pulled forward at Baim's direction); 33.1 onward not yet
implemented. This document resolves the remaining work in Phases 28-35:
operational logging, test strategy, performance measurement, asyncio
ownership, explicit state machines, and the encrypted application-error
protocol.

## 1. Scope and Baseline

The repository already has useful foundations. This phase strengthens their
boundaries and makes behavior observable; it does not replace working crypto,
transport, transfer, or security-event code.

| Area | Already present | Remaining work |
|---|---|---|
| Logging | `core.security.events` emits sanitized security events through Python logging. | One application-wide diagnostic logging policy and safe runtime configuration. |
| Tests | Broad flat pytest suite, security/handshake coverage, and CI. | Explicit test layers, reliability scenarios, and non-flaky performance benchmarks. |
| File efficiency | Binary transfer frames, chunked streaming, transfer limits. | Measure event-loop impact and move only blocking file work off the loop. |
| Async work | Async network I/O, background tasks, timeouts, and EventBus. | Ownership, cancellation, bounds, and shutdown rules for every task. |
| State | Handshake and transfer code have implicit states and terminal status strings. | Single transition authority and invalid-transition handling. |
| Errors | `protocol.make_error(code, message)` exists. | Validated codes, correlation, safe disclosure, and uniform receiving behavior. |

The phases are implemented in the sequence in section 8. State-machine and
error-protocol work must follow observability and task ownership, because a
transition failure without a trace or responsible task is difficult to debug.

## 2. Phase 28: Operational Logging

### 2.1 Goals

Logging is for local diagnostics. It must not alter security decisions, become
a second audit store, or render ordinary logs inside the Textual UI.

Use named standard-library loggers rooted at `peerc`:

```
peerc.transport
peerc.protocol
peerc.transfer
peerc.vault
peerc.ui
peerc.security
```

`peerc.security` remains owned by `core.security.events`; Phase 28 must not
create a competing security-event path.

### 2.2 Default policy

- Normal interactive runs write `WARNING` and above to a rotating local
  diagnostic file. The UI log remains user-facing and separate.
- A user-selected diagnostic mode enables `INFO`; `DEBUG` is opt-in for a
  single run and must be visibly marked as diagnostic mode.
- Rotation is size-and-count bounded. Retention and file location are set in
  one startup configuration point, never ad hoc by individual modules.
- Log records use stable event names plus structured fields such as
  `device_id_prefix`, `addr_key`, `transfer_id`, `operation`, and `error_code`.
  They never log chat content, file content, full public/private keys, session
  keys, passphrases, recovery codes, link PINs, decrypted endpoint links, or
  vault plaintext.
- Exceptions use `logger.exception()` only at the boundary that handles them;
  downstream layers return typed failures. This avoids duplicate tracebacks.

Security-event sanitization remains mandatory. The Phase 28 logger adapter
adds a second allowlist for ordinary diagnostic fields rather than assuming all
callers remembered what is safe to record.

## 3. Phases 29-30: Tests and Reliability Cases

The current flat `tests/` layout is retained. Moving files merely to satisfy a
directory diagram is out of scope. Tests are classified by marker and naming:

| Layer | Purpose | Runs in ordinary CI |
|---|---|---|
| Unit | Pure parsers, validators, transitions, redaction, and error mapping. | Yes |
| Integration | Real loopback handshakes, encrypted transport, relay tunnel, vault, and persistence. | Yes |
| UI | Textual pilot workflows and modal queue behavior. | Yes |
| Security | Malformed frames, replay, identity, policy, limits, and path containment. | Yes |
| Benchmark | Throughput, latency, memory, and event-loop lag measurements. | No; scheduled/manual baseline job |

Phase 30 remains a regression suite, not a one-time checklist. Every security
test must assert both the safe outcome and the absence of a harmful side
effect: no trust record for a rejected identity, no finalized file after a bad
checksum, no persisted secret in a log record, and no active session after a
revoked-device attempt.

Required new reliability cases:

- cancellation at each await point of connection, relay, and transfer flows;
- duplicate or late acknowledgement/error messages;
- peer disconnect during each transfer state;
- task cleanup after vault lock and app shutdown;
- no event-loop stall above the chosen budget while transferring a fixture;
- invalid state transition never sending an application frame; and
- error responses that contain no peer-internal exception text.

## 4. Phase 31: Performance Measurement and Budgets

No optimization is accepted before a baseline is measured. Benchmark fixtures
are deterministic local files and loopback connections; public-network results
are reported separately and never gate correctness.

Metrics:

| Metric | Measurement | Acceptance rule |
|---|---|---|
| Transfer throughput | bytes verified per second, direct and relayed | No regression beyond the agreed tolerance for the same fixture. |
| Peak memory | process memory while transferring a large fixture | Bounded by chunk/buffer configuration, not file size. |
| Event-loop lag | periodic monotonic-timer delay during transfer | Stays within the chosen interactive responsiveness budget. |
| Handshake latency | loopback direct and relay handshake duration | Track distribution; investigate significant regression. |
| Shutdown time | cancel and await all owned tasks | Completes within a bounded timeout. |

The existing binary frames and streaming chunks remain the default. Do not add
Base64, giant JSON payloads, or whole-file buffering. Profile before moving
work to threads. Hashing a large file and blocking filesystem reads/writes are
candidates for `asyncio.to_thread`; short metadata operations stay on the
event loop to avoid thread overhead and ordering bugs.

## 5. Phase 32: Async Ownership and Cancellation

Every background task has one owner, one cancellation path, and one terminal
cleanup path. Untracked `asyncio.create_task()` calls are not allowed in new
workflow code.

| Owner | Tasks it owns | On disconnect or shutdown |
|---|---|---|
| `ConnectionManager` | per-session read loop, relay virtual-incoming work | Close stream, cancel/await children, unregister session/tunnel/pipe. |
| Chat session | delivery-ack timeout | Cancel when acknowledged, failed, or session closes. |
| Transfer session | outbound send, completion-ack wait, progress work | Cancel, close files, preserve or remove staging only according to transfer state. |
| Chat app | discovery, pruning, auto-lock, prompt queue | Cancel/await during unmount; do not leave a modal future pending. |

Implement a small internal task registry per owner, not a global task manager.
Registration happens before the task can produce externally visible work;
`finally` always unregisters it. Cleanup uses cancellation followed by a
bounded wait, and logs a sanitized warning if a task misses the deadline.

Shared mutable maps are changed only on the event-loop thread. Do not hold an
`asyncio.Lock` across disk I/O, network I/O, or a user modal. Use a semaphore
only where a measurable finite resource needs a global cap: handshakes,
transfers, or thread-offloaded file jobs.

## 6. Phases 33-34: State Machines

State machines are internal safety contracts, not additional wire messages.
Transitions are explicit, terminal states are idempotent, and a transition
function is the only way to mutate the state.

### 6.1 Connection lifecycle

```
NEW -> TCP_CONNECTED -> HANDSHAKING -> AUTHENTICATED -> ESTABLISHED
                                                   \-> CLOSING -> CLOSED
NEW/TCP_CONNECTED/HANDSHAKING --------------------> CLOSING -> CLOSED
ESTABLISHED --------------------------------------> CLOSING -> CLOSED
```

- `ESTABLISHED` requires a completed authenticated handshake. Relay tunnels
  use the same lifecycle after their inner handshake; the route does not grant
  special authorization.
- Application JSON, binary transfer frames, and relay bytes are accepted only
  after the relevant transport layer is established. Handshake frames are
  accepted only while `HANDSHAKING`.
- A trust decision (`PENDING`, `TRUSTED`, or `REVOKED`) is separate state from
  the connection lifecycle. Existing policy that permits a `PENDING` session
  continues until Phase 36/37 changes it explicitly; the state machine must
  not silently redefine trust policy.
- `CLOSING` and `CLOSED` are idempotent. A late frame, timeout, or duplicate
  close cannot revive a connection.

### 6.2 Transfer lifecycle

Outgoing:

```
OFFERED -> WAITING_FOR_ACCEPT -> SENDING -> WAITING_FOR_COMPLETE_ACK -> COMPLETED
                 |                    |                 |
                 +--------------------+-----------------+-> FAILED
                 +---------------------------------------> REJECTED
                 +---------------------------------------> CANCELLED
```

Incoming:

```
OFFERED -> ACCEPTED -> RECEIVING -> VERIFYING -> COMPLETED
   |           |            |             |
   +-----------+------------+-------------+-> REJECTED / CANCELLED / FAILED / EXPIRED
RECEIVING -> PAUSED -> RESUMING -> RECEIVING
```

Only the transfer coordinator changes state. File receiver/sender helpers
report outcomes; they do not independently invent terminal states. A duplicate
accept, late completion acknowledgement, chunk after terminal state, or resume
with a mismatched metadata/checksum is rejected as an invalid transition and
cannot overwrite an existing file.

## 7. Phase 35: Application Error Protocol

`error` is an encrypted post-handshake application message. It is never sent
during an unauthenticated handshake, where detailed responses would expose an
oracle to an attacker; those paths close with local logging only.

### 7.1 Wire shape

```json
{
  "type": "error",
  "version": 2,
  "code": "TRANSFER_NOT_FOUND",
  "message": "The requested transfer is no longer available.",
  "context": {"transfer_id": "..."}
}
```

`code` and `message` are required. `context` is optional and allowlisted to
correlation identifiers (`message_id`, `transfer_id`, `group_id`) and a
machine-safe retry hint. It must never contain a traceback, local path, peer
address, key material, secret, or raw exception text. The receiver treats an
unknown code as `INTERNAL_ERROR` for display and logs the unknown value safely.

### 7.2 Code set

| Code | Recipient meaning | Retry behavior |
|---|---|---|
| `AUTH_FAILED` | Authenticated request was not permitted. | No automatic retry. |
| `POLICY_DENIED` | A local or group policy denied the request. | User action/policy change required. |
| `PROTOCOL_MISMATCH` | Peer cannot safely process this supported-message request. | Reconnect only after compatible upgrade. |
| `INVALID_FRAME` | Authenticated application frame is malformed. | No retry; peer may close session. |
| `INVALID_STATE` | Request is valid in shape but invalid for current lifecycle state. | Refresh state before retry. |
| `TRANSFER_NOT_FOUND` | Referenced transfer no longer exists. | No automatic retry. |
| `SIZE_EXCEEDED` | Transfer breaches a size or resource limit. | User must choose a smaller transfer. |
| `DISK_FULL` | Receiver cannot reserve/write required space. | Retry only after space is available. |
| `CHECKSUM_MISMATCH` | Received content failed verification. | Restart only through explicit transfer flow. |
| `TRANSFER_EXPIRED` | Offer or resume window elapsed. | Start a new offer. |
| `RATE_LIMITED` | Peer is temporarily applying a documented limit. | Retry after an optional bounded delay. |
| `INTERNAL_ERROR` | Safe generic failure. | No automatic retry. |

Use a normal command-specific response where the protocol already defines one:
for example `file_reject`, `file_complete_ack(success=false)`, and
`relay_response(accepted=false)`. Do not send a second generic `error` for the
same expected negative outcome. Use `error` for malformed, invalid-state, or
unexpected application failures that otherwise become silent.

### 7.3 Receiving and UI behavior

The error dispatcher first validates the schema, then correlates the optional
context with an active operation. It marks that operation terminal only when
the code contract says it is terminal. Unsolicited, duplicate, or late errors
are logged at debug level and do not change unrelated state. The UI displays a
plain-language message and a retry action only for codes that allow it.

## 8. Implementation Sequence

1. **28.1 Logging foundation:** configure root `peerc` logger, redacting
   adapter, rotation, and diagnostic-mode switch; add redaction tests.
2. **29/30.1 Reliability taxonomy:** add test markers and missing cancellation,
   cleanup, and side-effect assertions without moving the flat test tree.
3. **31.1 Baselines:** add a non-gating benchmark runner and record baseline
   measurements before changing I/O behavior.
4. **32.1 Task ownership:** introduce task registries for connection, transfer,
   and app-owned work; verify bounded shutdown and cancellation cleanup.
5. **33.1 Connection FSM:** add lifecycle enum and guarded transitions around
   existing handshake/read-loop paths; retain current trust semantics.
6. **34.1 Transfer FSM:** replace free-form status writes with guarded outgoing
   and incoming transitions, then cover late/duplicate frames.
7. **35.1 Error schema:** validate the enriched `error` shape and code set,
   including safe `context` filtering.
8. **35.2 Error integration:** add errors only where an existing protocol
   response does not already represent the expected negative result.
9. **31/32.2 Regression gate:** compare benchmarks, loop lag, and shutdown
   behavior against the baseline before declaring the program complete.

## 9. Out of Scope

- changing encryption, handshake cryptography, trust policy, or relay routing;
- automatically retrying failed chat, transfer, or relay operations;
- a global unbounded task supervisor;
- plaintext telemetry or remote log upload;
- making benchmark timing a per-push CI gate; and
- refactoring working modules solely to relocate files.
