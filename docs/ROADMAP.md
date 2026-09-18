# Roadmap

Current version: **1.16.4** (see `../CHANGELOG.md` for full detail on every
release). This file is the scannable status view; `IMPLEMENTATION_PLAN.md`
has the full per-phase design detail, and `SECURE_STORAGE_DESIGN.md` has
the detailed design for Phase 39 specifically.

Versioning policy: `a.b.c` — `c` (PATCH) is a small change/sub-step within
the current phase; `b` (MINOR) identifies the phase itself and increments
whenever work moves into a new phase (e.g. Phase 5's sub-steps landed as
`1.13.0`–`1.13.1`; Phase 26 landed as `1.14.0`); `a` (MAJOR) is bumped
only once the whole project is finished — `2.x` marks the shift from active
development into maintenance/updates, not before.

## Done

| Version | Phase | What |
|---|---|---|
| `1.1.1` | 1.1 | Split `protocol.py` into `core/protocol/{frame,messages,errors}.py`, backward-compatible shim |
| `1.2.0` | 1.2 | `version` field on every protocol message |
| `1.3.0` | 1.3 | File chunks: base64-in-JSON → binary frames (33.6% → 0.05% overhead) |
| `1.3.1` | 3.1–3.3 | `core/identity/`: Ed25519 keypair, `KeyStore` (keyring + fallback), fingerprint formatting |
| `1.4.0` | 3.4 | `discovery.py`'s `peer_id` wired to the Ed25519-derived `device_id` |
| `1.4.1` | 4.1 | `core/trust/`: SQLite `TrustStore`, TOFU (`check`/`record_first_seen`/`approve`) |
| `1.5.0` | 4.2 | `core/trust/revocation.py`: local device revocation with audit trail |
| `1.6.0` | 6 | `core/crypto/`: ephemeral X25519 key exchange, authenticated 3-way handshake with Ed25519 transcript signatures, TrustStore integration |
| `1.7.0` | 7 | `core/crypto/kdf.py`: HKDF-SHA256 session key derivation with domain separation, directional tx/rx keys, and transcript hash binding |
| `1.8.0` | 8 | `core/crypto/encryption.py`: ChaCha20-Poly1305 AEAD encrypted channel (`SecureChannel`, deterministic sequence-derived nonce) |
| `1.9.0` | 9 | `core/transport/`: decoupled transport layer (`SecureSession`, `EncryptedTransport`, `TCPConnection`, `SecureSessionManager`, timeouts) |
| `1.10.0` | 12/13–20 | `core/transfer/`: modular File Transfer V2 (streaming SHA-256, chunker, `.part` resume, atomic rename, pre-flight disk check, limits) |
| `1.11.0` | 40 | `core/identity/rotation.py` [NEW]: `TransitionCertificate`, `create_transition_certificate`, `verify_transition_certificate`; `rotate_identity()` in `identity_file.py`; `identity_transitions` table + `record_rotation`/`get_rotation_chain`/`check_with_rotation` in `TrustStore` |
| `1.12.0` | 41 | `core/security/events.py` [NEW]: `SecuritySeverity` (`INFO`/`WARNING`/`HIGH`/`CRITICAL`), `SecurityEventType`, `SecurityEvent`, `emit()`, listeners, safe credential redaction; call sites in `TrustStore`, `handshake`, `rotation` |
| `1.13.0` | 5.1 | `discovery.py` wire payload gains `version`/`device_id`/`public_key`; incoming packets checked for `device_id == sha256(public_key)` self-consistency (drop + `AUTH_FAILED` event on mismatch, not a trust decision) |
| `1.13.1` | 5.2 | `MDNSDiscovery` + `_PeercServiceListener` in `discovery.py`: optional mDNS transport (`_peerc._tcp.local.`, key-value TXT record) via `zeroconf`; `MDNS_AVAILABLE` flag; shared `_handle_packet` path for both UDP and mDNS; `pip install peerc[mdns]` optional dep group |
| `1.14.0` | 26 | `core/events.py` [NEW]: `EventBus`, typed events (`ChatReceived`, `FileOffered`, `FileProgress`, `TransferCompleted`, `PeerConnected`, `PeerDisconnected`, `TrustRequired`, `SecurityWarning`), security event bridge; resolved ARCH-001 (`on_message` chaining eliminated across `peer.py`, `chat.py`, `file_transfer.py`, `ui.py`) |
| `1.15.0` | 39.1 | `core/vault/` [NEW]: DEK/KEK envelope encryption (`crypto.py` — Scrypt KDF + AES-256-GCM wrap/unwrap), `vault_keyfile.json` format + `create_vault`/`unlock_with_passphrase`/`unlock_with_recovery_code`/`change_passphrase` (`keyfile.py`), Crockford Base32 recovery code (`recovery_code.py`) |
| `1.15.1` | BUG-004 | `peer.py`'s `ConnectionManager` wired to `core/transport`'s authenticated handshake + ChaCha20-Poly1305 (Phase 6-9 finally connected to the live app, not just unit-tested); `TrustStore` (Phase 4) constructed for real in `ui.py` for the first time; BUG-005/ARCH-002 closed alongside it (self-reported `peer_id` in `hello`/`chat` now cross-checked against the authenticated `device_id`) |
| `1.15.2` | 39.2 | `core/vault/database.py` [NEW]: `VaultDatabase` encrypted DB lifecycle (unlock/flush/auto-flush/lock, tmpfs+fallback); unified schema (`trusted_devices`+`identity_transitions`+`messages`+`transfers`+`settings`); `core/vault/migration.py` retires plaintext `trust.db`; `TrustStore` can now share the vault's connection; `core/vault/persistence.py` wires `ChatReceived`/`ChatMessageSent`/`ChatMessageStatusChanged`/`TransferCompleted` into `messages`/`transfers` rows, keyed on the authenticated `peer_device_id`; `ui.py` gets a full vault-unlock modal flow (create/recovery-code/unlock) |
| `1.15.3` | 39.3 | `core/vault/session.py` [NEW]: `VaultSession` — sudo-style 5-min idle auto-lock (configurable), hard lock (DEK wipe + vault working-copy destroy), file-action re-auth policy + per-session "don't ask again", settings persistence; `ui.py` `/lock`/`Ctrl+L`/`/autolock` + mid-session re-unlock; `TrustStore.adopt_conn` / `VaultPersistence.reattach` for lock/unlock rewiring |
| `1.15.4` | 39.4 | `core/vault/session.py`: critical-action Export key primitive — optional second secret for Export only, AND-gated with the live unlocked session via HKDF, AEAD-tag verifier in encrypted vault settings, set/change/clear/verify/`authorize_export()` APIs; tests cover unset/default, wrong-key, neither-half-alone, change/clear, and persistence |
| `1.15.5` | 39.5 | `core/vault/secure_file.py`, `file_actions.py`, `executable_detection.py` [NEW]: per-file AES-256-GCM encryption with HKDF-derived keys, opaque secure_id naming; Open/Export/Delete/Move operations with VaultSession re-auth integration; magic-byte executable detection (PE/ELF/Mach-O/shebang); `ui.py` gains `/files`/`/open`/`/export`/`/secure`/`/delete` commands; 68 tests across 3 test files |
| `1.15.6` | 39.5 | Bug fixes: `is_executable()` fail-closed logic corrected for strict mode (inconclusive content now always blocks, extension/content mismatches now caught); `.bin` removed from `EXECUTABLE_EXTENSIONS`; `open_secure_file()` now catches `ExecutableDetectionError` from `check_executable_for_open` (previously only caught `ExecutableBlockedError`, so blocked-open temp files leaked undeleted and `ui.py`'s block message never fired); detected file type now surfaced in the block message before temp-file cleanup instead of being read afterward |
| `1.15.7` | 39.5 | `tests/test_stage5.py`: fixed a stale test-isolation gap — the headless UI smoke test never isolated the vault path (only identity), so on any machine without a pre-existing `~/.peerc` it hung forever waiting on `VaultCreateModal`'s interactive passphrase prompt. Now bypasses `ChatApp._unlock_vault` and isolates `VaultDatabase.unlock()` to a temp path, since this file only smoke-tests UI wiring, not the vault-unlock flow itself |
| `1.16.0` | 42.1 | `core/group/` [NEW]: `membership.py` — `Group`/`MembershipCertificate` dataclasses, Ed25519-signed issue/verify (admin's existing device identity, no new key type), `is_membership_expired()`; `store.py` — `GroupStore` (mirrors `TrustStore`'s shared-connection pattern), refuses to record a membership with an unverifiable signature, an admin/group mismatch, or a duplicate; `groups`/`group_memberships` tables added to `VaultDatabase`'s unified schema; `ui.py` wires `group_store` through the same lock/unlock lifecycle as `trust_store`. No policy enforcement or UI commands yet (`policy.py`/`admin.py`/`audit.py` are later 42.x sub-steps) |
| `1.16.1` | 42.2 | `core/group/policy.py` [NEW]: `GroupPolicy` schema (`allow_external_trust`, `allow_export`, `leave_requires_admin`, `allow_inter_group`, communication matrix), `CommunicationRule`/`PolicyAction`/`PolicyEffect`, core-level `PolicyEnforcer` (fail-closed, §5/§6/§7/§8/§10); `store.py` gains `group_policies` table + `set_policy`/`get_policy`/`list_policies`; External Trust Restriction (§6) wired into `TrustStore.record_first_seen()`; `POLICY_VIOLATION`/`POLICY_CHANGED` added to `SecurityEventType`. No multi-admin or audit log yet |
| `1.16.2` | 3.4 | Identity display metadata: `core/device_info.py` [NEW] `detect_device_model()` — best-effort, deliberately never persisted (recomputed fresh every run, see §37 `SECURITY_MODEL.md`); `DeviceIdentity.is_new` + first-run `NameSetupModal` (set a display name before the app proceeds, defaults to "peer" if skipped); `model` threaded through both discovery transports (UDP broadcast + mDNS) the same way `name` already was, shown in the peer list/`/info`; `/nick` renamed to `/name` (validation factored into shared `validate_display_name()`, still enforces BUG-020's control-char/newline/length rules) |
| `1.16.3` | 42.3 | `core/group/admin.py` [NEW]: `AdminRecord`, `ThresholdApproval` — k-of-n signature collection for any admin-gated action, Ed25519-signed (§14 Multiple Administrators, `SECURITY_MODEL.md` §22); storage-agnostic (`count_valid_signatures`/`is_approved` take the caller's current active-admin set, so a since-removed admin's signature silently stops counting). `store.py` gains `group_admins` table + `add_admin`/`remove_admin` (refuses removing the last active admin)/`list_admins`/`get_active_admin_public_keys`; `create_group()` now auto-registers the founder as the first active admin; `record_membership()`/`set_policy()` now accept a signature from ANY currently-active admin, not just the founder |
| `1.16.4` | 42.4 | `core/group/protocol.py` [NEW]: signed Join/Leave/Revoke control-plane payloads (`GroupJoinRequest`/`GroupJoinResponse`, `GroupLeaveRequest`/`GroupLeaveResponse`, `MembershipRevocation`) with domain-separated Ed25519 signatures and join self-consistency checks (`device_id == sha256(public_key)`); `core/protocol/messages.py` gains wire factories/validation for `group_join_request`, `group_join_response`, `group_leave_request`, `group_leave_response`, `group_membership_revoke`; `GroupStore` gains `process_join_response`/`process_leave_request`/`process_leave_response`/`record_revocation` + tombstone metadata accessor; vault schema now includes `group_admins`. UI commands and signed audit log still deferred |
| `1.16.5` | 42.5 | `core/group/audit.py` [NEW]: signed audit log (`sign_audit_event`/`verify_audit_event`/`create_group_audit_event`/`verify_group_audit_event`/`format_audit_event`) extending Phase 41's `SecurityEvent` with admin Ed25519 signatures; `GroupStore` gains `group_audit_log` table, `record_audit_event`/`list_audit_events`/`get_audit_event`, and automatic lifecycle audit recording (`create_group`, `record_membership`, `revoke_membership`, `set_policy`, `add_admin`, `remove_admin`); vault schema updated; `ui.py` gains `/group audit` command. Completes Phase 42 (Group Authority System) |

**Phase 1 (Protocol V2), Phase 3 (Device Identity), Phase 4 (Trust
Store), Phase 5 (Discovery V2), Phase 6 (Secure Handshake), Phase 7
(Session Keys), Phase 8 (ChaCha20-Poly1305 Encryption), Phase 9
(Secure Transport Layer), Phase 12–20 (File Transfer V2 + Hardening),
Phase 26 (Event Architecture), Phase 39 (Secure Storage), Phase 40
(Device Key Rotation), Phase 41 (Security Event Logging), and Phase 42
(Group Authority System) are complete.**

## Designed, not yet coded

| Phase | What | Where |
|---|---|---|
| 43 | Group-Gated Export Authorization (admin capability AND personal critical-action key, not either/or) | `GROUP_AUTHORITY_DESIGN.md` §Export Authorization |
| 44 | Internet P2P Connectivity (Identity/Locator separation, signed Endpoint Update) | `INTERNET_CONNECTIVITY_DESIGN.md` |
| 45 | Rendezvous Service (optional, endpoint discovery only, never a data path) | `INTERNET_CONNECTIVITY_DESIGN.md` §Rendezvous |
| 46 | NAT Traversal & Relay Fallback (optional, relay only sees ciphertext) | `INTERNET_CONNECTIVITY_DESIGN.md` §Optional Relay |
| — | File Viewer (In-memory streaming viewer: Text/Code, Media/Image/Audio, Document/PDF/EPUB) | `FILE_VIEWER_DESIGN.md` — architecture, open-source stack (PyMuPDF, Chafa/Kitty, miniaudio/mpv, Rich), zero-disk-cache security pipeline |

Phase 39 absorbs Phase 27 (Storage) — there's no plan to ship an
unencrypted persisted-chat-history release before encryption catches up.

Phases 40-46 are a later addition (Group Authority + Internet
Connectivity + the Device Key Rotation and Security Event Logging they
depend on) — not in the original phase numbering, appended after Phase
39 rather than renumbering anything earlier.

## Next up (recommended order)

Straight from `IMPLEMENTATION_PLAN.md`'s "Urutan implementasi yang
disarankan" — this is the order that makes sense to build in, not the
numeric phase order in the plan doc:

1. **Phase 42 — Group Authority System** (complete: 42.1 landed as `1.16.0`; 42.2 landed as `1.16.1`; 42.3 landed as `1.16.3`; 42.4 landed as `1.16.4`; 42.5 landed as `1.16.5`)
2. **Phase 43 — Group-Gated Export Authorization** (design-complete, depends on 39+42) ← next
3. **Phase 44 — Internet P2P Connectivity** (design-complete)
4. Phase 45/46 — Rendezvous, NAT Traversal & Relay (optional, design-complete)
5. Phase 36/37 — UI/security UX
6. Phase 28-35 — logging, performance, concurrency, state machines,
   error protocol
7. Phase 38 — Project structure final (**not done now, deliberately** —
   see note below)
8. Security audit, release

## Why Phase 38 (final project structure) isn't done yet

`IMPLEMENTATION_PLAN.md`'s Phase 38 target structure (`app/`,
`core/transport/`, `core/crypto/`, etc.) is now much closer than it was
— `core/transport/secure.py` and `core/crypto/handshake.py` both exist
today (Phase 6-9 landed). What's still missing is the newer Phase 40-46
scope: `core/identity/rotation.py`, `core/security/events.py`,
`core/group/`, `core/connectivity/` don't exist yet, since those phases
are still design-only. Restructuring into the final Phase 38 shape now
would still mean creating placeholder directories for that not-yet-built
code. What's already done matches Phase 38 exactly and needs no rework
later: `core/{protocol,identity,trust,crypto,transport,transfer}` are
all in their final destinations; `tests/` was split out; CI
(`.github/workflows/tests.yml`) runs the full suite on every push.

## How this file stays honest

Update this table whenever a version is tagged in `CHANGELOG.md` — same
commit, so this file and the changelog never drift apart the way
`IMPLEMENTATION_PLAN.md`'s "Urutan implementasi" and "Prioritas versi"
sections had (both had stale ✅/⏳ marks from before this file existed;
fixed alongside adding this one).
