# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
