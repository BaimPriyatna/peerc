# Roadmap

Current version: **1.19.2** (see `../CHANGELOG.md` for full detail on every
release). This file is the scannable status view; `IMPLEMENTATION_PLAN.md`
has the full per-phase design detail, and `SECURE_STORAGE_DESIGN.md` has
the detailed design for Phase 39 specifically.

Versioning policy: `a.b.c` — `c` (PATCH) is a small change/sub-step within
the current phase; `b` (MINOR) identifies the phase itself and increments
whenever work moves into a new phase (e.g. Phase 5's sub-steps landed as
`1.13.0`–`1.13.1`; Phase 26 landed as `1.14.0`; Phase 43 landed as `1.17.0`);
`a` (MAJOR) is bumped only once the whole project is finished — `2.x` marks
the shift from active development into maintenance/updates, not before.

## Orientation (for any agent or human picking this up)

Multiple sessions/agents work on this repo in parallel — this section
exists so a fresh one can get oriented from the repo alone, without
needing anything explained again.

**Workflow rules — non-negotiable:**
1. `git pull` before touching anything. Never assume local state is current.
2. Work in small, independently-tested sub-steps. Full regression suite
   (`pytest`, all green) before every commit — no exceptions.
3. Four files sync on every version bump, same commit: `pyproject.toml`,
   `CHANGELOG.md`, `docs/ROADMAP.md` (this file), `README.md`. See
   "Versioning policy" above for what bumps which digit.
4. Commit and push together once a sub-step is ready. Never leave
   uncommitted changes sitting in the working tree between sessions.
5. For a genuinely large/undesigned feature (no existing byte-level
   spec — Phase 45's Rendezvous was one, Phase 42/44 were not), resolve
   the design with the user FIRST and write it down (see "Phase 45
   design (resolved)" below for the shape that should take) — don't
   start writing code against an architecture diagram alone.
6. GitHub pushes use a fine-grained PAT passed inline in chat for that
   push only — redact it from all output, and tell the user to revoke
   it right after.

**Module map — where things live:**

```
core/identity/    Ed25519 device keypairs. device_id = SHA256(pubkey) —
                   never trust a self-reported identifier over this.
core/crypto/      Handshake (mutual auth + session keys), NonceCache
                   (replay protection, reused by connectivity/endpoint_update.py).
core/transport/   TCP framing + the authenticated/encrypted session layer
                   peer.py's ConnectionManager sits on top of.
core/trust/       TOFU trust decisions (TrustStore) — per-device, local only.
core/vault/       At-rest encryption (Phase 39). VaultDatabase's unified
                   schema is the ONE encrypted SQLite file every other
                   subsystem's persistent storage lives in — see below.
core/group/       Group Authority (Phase 42/43): membership certs, policy
                   enforcement, multi-admin/threshold sigs, signed audit
                   log, group-gated export capabilities.
core/connectivity/
                   Internet connectivity (Phase 44/45): Locator (endpoint
                   tracking, deliberately separate from identity), signed
                   Endpoint Update, Add-by-Link, Rendezvous (in progress).
core/security/    Cross-cutting SecurityEvent logging (Phase 41).
discovery.py      LAN peer discovery (UDP broadcast + mDNS) — in-memory,
                   this-session-only. NOT the same thing as a Locator.
peer.py           ConnectionManager — owns live TCP connections, is the
                   thing that actually knows who's "currently connected".
protocol.py       Root shim over core/protocol/{frame,messages,errors}.py
                   — wire message factories + schema validation live there.
ui.py             Textual TUI — the only place these subsystems get wired
                   together. Almost everything else is a library.
```

**Storage pattern, once you've seen it you'll see it everywhere:** every
subsystem that needs to persist something (`trust/`, `group/`,
`connectivity/`) defines its own `Store` class that can EITHER own a
private SQLite file OR share an already-open connection
(`VaultDatabase.conn`). In `ui.py` they all share the vault connection,
following the vault's own lock/unlock lifecycle (`adopt_conn(None)` on
lock, `adopt_conn(conn)` on re-unlock) — grep any existing `*_store =
...Store(conn=self.vault_db.conn)` line in `ui.py` for the pattern to
copy when adding a new one.

**Crypto pattern, also everywhere:** any new signed structure gets its
own domain-separation prefix (e.g. `_LINK_SIGN_DOMAIN`,
`_ADMIN_APPROVAL_DOMAIN`) prepended to whatever gets signed/verified —
so a signature for one purpose can never be replayed as a signature for
another. Look at `core/group/admin.py` or `core/connectivity/
endpoint_update.py` for the shape to copy.

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
| `1.17.0` | 43 | `core/group/export_auth.py` [NEW]: short-lived admin-signed `ExportCapability` & device `ExportRequest` (`GROUP_AUTHORITY_DESIGN.md` §11/§12); `PolicyEnforcer.check_export()` upgraded to Phase 43 AND-gate; `GroupStore` gains `export_capabilities` table + CRUD (`store_capability`, `get_valid_capability`, `mark_capability_used` one-shot burn, `list_capabilities`, `purge_expired_capabilities`); `core/vault/file_actions.py`'s `export_secure_file()` integrates group capability gate before personal critical-action key gate; `core/vault/database.py` schema updated; wire messages `group_export_request`/`group_export_capability` with schema validation; `ui.py` gains `/group req-export`, `/group authorize-export`, and `/group caps` commands + network callbacks. Completes Phase 43 |
| `1.18.0` | 44.1 | `core/connectivity/` [NEW]: `locator.py` — `Endpoint`/`Locator` dataclasses, deliberately separate from identity (`INTERNET_CONNECTIVITY_DESIGN.md` §1-3), `direct-v4`/`direct-v6`/`rendezvous` kinds, `Locator.sorted_endpoints()` (direct tried before rendezvous, §11); `store.py` — `LocatorStore` (mirrors `TrustStore`/`GroupStore`'s shared-connection pattern), `upsert_endpoint`/`remove_endpoint`/`list_endpoints`/`get_locator`/`prune_stale`. `device_endpoints` table added to `VaultDatabase`'s unified schema; `ui.py` wires `locator_store` through the same lock/unlock lifecycle as `trust_store`/`group_store`. Persisted and cross-session, unlike `discovery.py`'s in-memory `PeerRegistry`. No signed endpoint announcement or Add-by-Link yet (`endpoint_update.py` is 44.2, Add-by-Link is 44.3) |
| `1.18.1` | 44.2 | `core/connectivity/endpoint_update.py` [NEW]: signed endpoint announcement + verification (§4) — `create_endpoint_update()`/`verify_endpoint_update()`, Ed25519 over a domain-separated `device_id`+`kind`+`host`+`port`+`timestamp`+`nonce` payload, reuses `core/crypto/handshake.py`'s `NonceCache` for replay protection rather than inventing a new primitive. Checks run signature → freshness (±300s default) → nonce, in that order, so a forged/unsigned update never consumes a nonce-cache slot. `endpoint_update_to_endpoint()` converts a verified update into `LocatorStore.upsert_endpoint()`'s input shape. Storage-agnostic (same split as `membership.py`/`admin.py`) — no wire-protocol message type or `ui.py` integration yet, that's a later integration step once there's an actual "connect over the Internet" flow to piggyback the announcement on |
| `1.18.2` | 44.3 | `core/connectivity/link.py` [NEW]: Add-by-Link (§3a) — `PEERC1:<base64url(salt‖nonce‖ciphertext)>`, PIN-protected (6 digits), Sign-then-Encrypt (payload signed first, then the whole signed bundle AES-256-GCM-encrypted under `Scrypt(PIN, salt)` — reuses `core/vault/crypto.py`'s exact primitives, no new KDF/AEAD invented); `create_link()`/`decode_link()`, tagged `direct-v4`/`direct-v6`/`rendezvous` endpoints packed compactly (IPv4/IPv6 as raw address bytes, rendezvous as length-prefixed hostname); `LinkSignatureError` distinguished from `WrongPinError` (a correct-PIN-but-forged-signature link is the one scenario the signature exists to catch — a brute-forced PIN without the real private key). `generate_qr()` renders the same string as a terminal ASCII QR via the new optional `qrcode` dependency (`pip install peerc[qr]`; copy-paste form works fully without it). 15 new tests. No `/link` UI commands or network-connect wiring yet — this is the crypto/format primitive only, same scope pattern as 44.1/44.2 |
| `1.18.3` | 44.3 UI | Add-by-Link click UI in `ui.py`: `LinkMenuModal`/`LinkGenerateModal`/`LinkResultModal`/`LinkAddModal` (button+input driven, no command typing needed once opened), reachable two ways — `/link` command or the new Ctrl+G binding, both land on the same menu. Generate flow pre-fills detected local `host:port` (editable `TextArea`, `+ Random PIN` button); Add flow decodes a pasted link+PIN then tries each endpoint (`Locator.sorted_endpoints()` order — direct before rendezvous) via the existing `ConnectionManager.connect_to()`/hello-handshake path already used by `/connect`, persists endpoints to `locator_store`, and hands off to the existing TOFU/trust flow exactly as any freshly-discovered peer would. QR display deliberately deferred (`generate_qr()` from 44.3 exists but isn't wired into any modal yet, per Baim's call to focus on the click flow first). 15 new tests (`tests/test_link_ui.py`) |
| `1.18.4` | 44.3 UI | Visible **"+ Add by Link"** button added to the main screen itself, not just Ctrl+G/Footer/`/link` — sits above the peer list in a new `#sidebar` container (`ui.py`'s `compose()` restructured slightly: `ListView` now lives inside `Vertical(id="sidebar")` alongside the button, same overall width). Clicking it calls the same `action_add_by_link()` Ctrl+G already triggers, so all three entry points (button, keybinding, command) land on the identical `LinkMenuModal` flow. No behavior change to the flow itself — purely a third, always-visible way in |
| `1.18.5` | 44.4 | `endpoint_update` (44.2) wired into the live connection protocol: `peer.ConnectionManager.get_peer_public_key()` (raw Ed25519 bytes for an authenticated addr_key, mirrors `get_peer_device_id()`); `protocol.make_endpoint_update()` + `REQUIRED_FIELDS`/`validate_message()` entries (kind/port range checked); `ui.py` sends a signed self-announcement for each detected local IP right after every `hello`/`hello_ack` (`_send_self_endpoint_update()`), and verifies incoming ones against the connection's AUTHENTICATED public key — never anything self-reported in the message — cross-checking `device_id` too before persisting to `locator_store` (`_on_endpoint_update()`). Every successful connection (LAN or via Add-by-Link) now leaves a cryptographically-confirmed, reusable locator entry behind, not just Add-by-Link ones. 14 new tests (`tests/test_endpoint_update_wire.py`) — this closes the last "still unwired" item from Phase 44's original scope besides QR display, which stays deliberately deferred |
| `1.18.6` | 45.1 | Phase 45 (Rendezvous, opt-in per-group per Baim's direction — not a separate server) begins: own-IP-change detection, closing §7 "IP Change Problem" for the "at least one connected peer" case. `peer.ConnectionManager.list_connected_addr_keys()` [NEW]; `ui.py` polls `discovery.get_network_info()` every `IP_CHANGE_CHECK_INTERVAL` (30s, `set_interval`) against `_last_known_local_ips` (in-memory only, same non-persistence reasoning as `device_info.py`'s model string) — on a real change, re-announces (`_send_self_endpoint_update()`, reusing 44.4) to every currently-connected peer (`_reannounce_endpoint_to_connected_peers()`); a transient empty reading (network blip) is deliberately ignored rather than treated as a change, so it can't spuriously clobber the baseline or fire a no-op re-announce. The rendezvous-relay case (peer NOT currently connected) is 45.2/45.3, not this sub-step. 8 new tests (`tests/test_ip_change_detection.py`) |
| `1.18.7` | 45.2 | `core/connectivity/rendezvous.py` [NEW]: `RendezvousCache` (in-memory, never persisted) — stores signed `EndpointUpdate` blobs indexed by `(group_id, device_id)`, the host-side half of the Rendezvous protocol. `register()` checks device_id self-consistency against the authenticated channel, active group membership, and re-verifies the `EndpointUpdate`'s Ed25519 signature before caching. `lookup()` checks that both requester and target are active members, returns the cached blob verbatim (requester re-verifies). `evict()`/`evict_all_for_group()`. Three new wire messages in `core/protocol/messages.py`: `make_rendezvous_register`, `make_rendezvous_lookup`, `make_rendezvous_lookup_response` — all with `REQUIRED_FIELDS` entries and `validate_message()` checks including nested EndpointUpdate dict validation. 32 new tests (`tests/test_rendezvous_cache.py`). No `ui.py` integration yet — `/group rendezvous on|off` and wiring through rendezvous-mode peers is 45.3 |
| `1.18.8` | 45.3 | Rendezvous wired into `ui.py`, completing Phase 45. `/group rendezvous <id> on|off|find <device>` — `on`/`off` toggle this device as a host for a group (checked against real active membership; `off` evicts that group's cached entries); `find` broadcasts `rendezvous_lookup` to every currently-connected peer. Host-side handlers `_on_rendezvous_register`/`_on_rendezvous_lookup` gate on `group_id in self._rendezvous_active_groups` — a device not opted in for a group stays completely silent for it (true opt-in, not just an unused cache). Requester-side `_on_rendezvous_lookup_response` re-verifies the returned `EndpointUpdate` against the target's public key from the requester's OWN `MembershipCertificate` copy — never trusts the host — then upserts to `locator_store` and attempts a connection (reuses 44.3's `_connect_to_link_endpoint`). `_register_with_rendezvous_hosts()` fires alongside `_send_self_endpoint_update()` on every `hello`/`hello_ack` and on 45.1's IP-change re-announce, sending a `rendezvous_register` for every group this device actively belongs to. Also fixed in passing: 45.2 had added the three `make_rendezvous_*` factories to `core/protocol/messages.py` but never exported them through `core/protocol/__init__.py` or the root `protocol.py` shim — caught by this sub-step's own tests failing with `AttributeError`. 19 new tests (`tests/test_rendezvous_ui.py`). **Phase 45 complete** |
| `1.19.0` | 46.1 | Phase 46.1: relay-tunnel primitive — `TYPE_RELAY` payload marker in `EncryptedTransport`, duck-typed `RelayedStreamReader`/`RelayedStreamWriter` shim, `ConnectionManager` forwarding pipe (`open_relay_pipe`/`close_relay_pipe`) and tunnel registration (`register_relay_tunnel`/`open_relay_tunnel`). Proven end-to-end with real handshake and encrypted messages running through relay tunnel |
| `1.19.1` | 46.2 | Phase 46.2: `relay_request`/`relay_response` wire messages with validation, `authorize_relay_request()` in `core/connectivity/relay.py` (relay mode check, active member check, target reachability check), wired into `ui.py` (`_on_relay_request`, `_on_relay_response`), silent refusal gates, explicit negative replies, and happy-path `open_relay_pipe` |
| `1.19.2` | 46.3 | Phase 46.3: A-side direct-then-relay orchestration — `make_relay_candidate_query`/`make_relay_candidate_response` wire messages, `authorize_relay_candidate_query()`, `initiate_secure_session_on_connection()` refactor, `ConnectionManager.connect_via_relay_tunnel()`, incoming passive relay accept at B, and `ui.py`'s `_try_relay_connect()` orchestration with candidate broadcast, collection window, sequential query, and tunnel handshake |
| `1.19.3` | 46.4 | Phase 46.4: `/group relay <id> on|off` enables or disables in-memory relay hosting for an active group, independently of Rendezvous. Completes Phase 46 |
| `1.20.0` | 36.1 | Phase 36.1: Trust Center read-only device inventory (`/devices [pending]`, `/pairs`, `/trust <id>`, `TrustCenterModal`, `TrustDeviceDetailModal`; status filters, safe empty and vault-locked states, fingerprint clipboard copy) |
| `1.20.1` | 36.2 | Phase 36.2: Trust decisions: approve/revoke actions in `TrustDeviceDetailModal` + `TrustConfirmModal` + `/revoke <id> [reason]`; group policy denial handling and idempotence guards |

**Phase 1 (Protocol V2), Phase 3 (Device Identity), Phase 4 (Trust
Store), Phase 5 (Discovery V2), Phase 6 (Secure Handshake), Phase 7
(Session Keys), Phase 8 (ChaCha20-Poly1305 Encryption), Phase 9
(Secure Transport Layer), Phase 12–20 (File Transfer V2 + Hardening),
Phase 26 (Event Architecture), Phase 39 (Secure Storage), Phase 40
(Device Key Rotation), Phase 41 (Security Event Logging), Phase 42
(Group Authority System), and Phase 43 (Group-Gated Export Authorization)
are complete.**

## Designed, not yet coded

| Phase | What | Where |
|---|---|---|
| 46 | NAT Traversal & Relay Fallback (optional, relay only sees ciphertext) | Complete (`1.19.0`–`1.19.3`) |
| — | File Viewer (In-memory streaming viewer: Text/Code, Media/Image/Audio, Document/PDF/EPUB) | `FILE_VIEWER_DESIGN.md` — architecture, open-source stack (PyMuPDF, Chafa/Kitty, miniaudio/mpv, Rich), zero-disk-cache security pipeline |

Phase 39 absorbs Phase 27 (Storage) — there's no plan to ship an
unencrypted persisted-chat-history release before encryption catches up.

Phases 40-46 are a later addition (Group Authority + Internet
Connectivity + the Device Key Rotation and Security Event Logging they
depend on) — not in the original phase numbering, appended after Phase
39 rather than renumbering anything earlier.

## Phase 45 design (resolved)

`INTERNET_CONNECTIVITY_DESIGN.md` §9/§10's Rendezvous sections are
architecture diagrams only — no wire protocol, no auth scheme, no
registration/lookup format. Unlike Phase 42/44, this genuinely needed
new design work before any code, resolved with Baim as follows:

- **Opt-in per-group, not a separate server.** Any device that's an
  active member of a Group (Phase 42) can turn on "Rendezvous mode" for
  that group. While on, it relays already-signed `EndpointUpdate`s
  (Phase 44.2) between group members who aren't currently connected to
  each other directly.
- **No new crypto.** An `EndpointUpdate` is already self-contained-
  signed by its owner. A rendezvous host only relays the blob — the
  requester re-verifies the signature themselves against the target's
  public key (known from that group's `MembershipCertificate`s), so the
  host is a mail carrier, never a vouched-for party.
- **Three wire messages:** `rendezvous_register(group_id, endpoint_update)`
  ("relay my update to group-mates who ask"), `rendezvous_lookup(group_id,
  target_device_id)` ("got a cached update for X?"), `rendezvous_lookup_response`
  (relays the cached `EndpointUpdate` verbatim, or empty). The host checks
  only that both parties are active members of `group_id` — same
  authorization shape as every other `group_*` message.
- **Freshness is free.** `EndpointUpdate`'s own ±300s window (44.2)
  already makes a stale cached entry fail the requester's own
  verification — no separate expiry logic needed on the host side.
- **In-memory only**, not persisted to the vault — matches the design
  doc's "Rendezvous bukan data server" explicitly. A restart clears the
  cache; a relayed device re-registers once reconnected.
- **Known limitation, stated up front:** a requester still needs at
  least one connected path into the group to ask "where's X" at all —
  Rendezvous can't bootstrap a fully isolated device from zero. This is
  the same non-guarantee already documented for §8 "Simultaneous
  Offline IP Change", not a new one.

Sub-steps (all landed): 45.1 (own-IP-change detection + re-announce to
connected peers, `1.18.6`) → 45.2 (`RendezvousCache` + the three wire
messages, `1.18.7`) → 45.3 (`/group rendezvous <group_id> on|off|find`
+ wiring the IP-change trigger to push registrations through
rendezvous-mode peers too, for the case where the target isn't
currently connected, `1.18.8`).

## Phase 46 design (resolved)

`INTERNET_CONNECTIVITY_DESIGN.md` §11 "Optional Relay" is 6 lines,
architecture-only — same situation Phase 45's §9/§10 were in before that
got resolved with Baim (see "Phase 45 design (resolved)" above).
Resolved with Baim as follows:

- **NAT traversal: no active hole-punching.** "Try direct, fall back to
  relay" means: attempt a normal connect via the existing
  `ConnectionManager.connect_to` with a short timeout; on failure, fall
  straight to Relay. No STUN/ICE — out of scope, too large for a TUI app
  of this size.
- **Relay authorization: opt-in per-group, separate toggle from
  Rendezvous.** `/group relay <group_id> on|off`, distinct from
  `/group rendezvous ... on|off`. Relaying carries live bandwidth
  traffic — a heavier commitment than caching a small `EndpointUpdate`
  blob — so a device can enable Rendezvous without Relay, or vice versa.
- **Finding an available relay: live broadcast to connected peers.** When
  A can't reach B directly, A broadcasts `relay_candidate_query(group_id)`
  to its already-connected peers. Only authorized peers that currently have
  Relay mode enabled reply with `relay_candidate_response(available=true)`.
  This keeps Relay independent of Rendezvous: relay hosting can be enabled
  even when no one hosts Rendezvous, and the fast-changing relay status is
  queried live rather than inferred from a location cache. A tries the
  responding candidates one at a time with a short timeout, avoiding
  multiple half-open relay attempts.
- **Relay protocol: pure byte-pipe, no chaining.** A sends
  `relay_request(target_device_id)` to relay R over their already-
  authenticated A↔R session (no separate signature needed — the session
  itself is already Phase 6-authenticated, same trust basis as every
  other in-band command). R checks that A is an active member of the
  shared group and that R already has a live connection to B — R never
  searches for B itself, and never chains through a second relay.

  Mechanism: R's sessions with A and with B are each their own
  independently-keyed `SecureSession` (separate ChaCha20-Poly1305 keys
  from R's own handshake with each), so there is no single "A-B
  connection" R can splice directly. Instead R relays opaque bytes one
  hop-encryption layer up: a new binary wire message, `relay_data`,
  carries A-B's traffic as payload — whatever `relay_data` bytes arrive
  on R's session with one side are forwarded verbatim as `relay_data` on
  R's session with the other (`session.send_binary(payload)`), with no
  parsing at all. On A's and B's side, a small duck-typed
  reader/writer shim (satisfying just the `readexactly()` /
  `write()`+`drain()` surface `core/protocol/frame.py` and
  `core/crypto/handshake.py` need) packs outgoing bytes into
  `relay_data` messages sent over their real session with R, and unpacks
  incoming ones back into a byte stream. That shim is the only new
  primitive: `perform_handshake_initiator`/`_responder` and
  `SecureSession`/`EncryptedTransport` run over it completely
  unmodified, so the Phase 6 handshake between A and B — and everything
  after it — runs end-to-end through the tunnel exactly as it would over
  a direct TCP connection. B's incoming side needs one structural
  addition: a virtual-incoming-connection path triggered by relay
  negotiation from R (parallel to `_handle_incoming`'s real-socket-accept
  path), since a relayed connection never touches B's actual TCP server.
- **B is passive.** B is not notified or asked to approve being
  relayed — the pipe carries the same end-to-end-encrypted,
  end-to-end-authenticated traffic B would see on a direct connection,
  so B loses nothing by not knowing R is in the path.
- **Pipe lifecycle.** The pipe at R closes the moment either the A↔R or
  B↔R connection drops — no separate idle-timeout or manual-stop
  mechanism.
- **Scope relative to Rendezvous:** the two roles are independent but
  composable. A device can be a Rendezvous host, a Relay, both, or
  neither. Relay-candidate broadcast uses its own two small messages
  because candidate availability is live connection state, not cached
  endpoint-location data.

Sub-steps (see `CHANGELOG.md` for full detail on each):
- **46.1 (`1.19.0`, done)** — the relay-tunnel primitive itself: a third
  `EncryptedTransport` inner marker (`TYPE_RELAY`) so relayed bytes never
  collide with file_data's binary channel; `core/transport/relay_stream.py`'s
  `RelayedStreamReader`/`RelayedStreamWriter` shim; and
  `ConnectionManager`'s R-side forwarding table (`open_relay_pipe`/
  `close_relay_pipe`) plus A/B-side tunnel registration
  (`register_relay_tunnel`/`open_relay_tunnel`). Proven end-to-end in
  `tests/test_relay_pipe.py` with a full, unmodified Phase 6 handshake
  running through a relay tunnel. Not yet wired to anything that decides
  *when* to open a pipe or tunnel — that's 46.2/46.3.
- **46.2 (`1.19.1`, done)** — `relay_request`/`relay_response` wire
  messages (one response type with a boolean `accepted` field, mirroring
  `rendezvous_lookup_response`'s nullable-field shape) and R's
  authorization check in `core/connectivity/relay.py`
  (`authorize_relay_request()`: relay mode on for the group, requester
  is an active member, R already connected to the target — in that
  order), wired into `ui.py`'s `_on_relay_request`/`_on_relay_response`
  and calling 46.1's `open_relay_pipe()` on the happy path. Not-hosting
  and not-a-member stay silent (no reply at all); "not connected to the
  target" gets an explicit `accepted=False` — see
  `core/connectivity/relay.py`'s docstring for why that one case
  differs. Nothing sends a `relay_request` yet (that's 46.3), and there's
  no `/group relay on|off` command yet (46.4) — `_relay_active_groups`
  has to be populated directly until then.
- **46.3 (`1.19.2`, done)** — A-side orchestration: try direct via `connect_to` with a
  short timeout (`RELAY_DIRECT_TIMEOUT`), on failure discover Relay-mode candidates
  via `relay_candidate_query`/`relay_candidate_response` within `RELAY_CANDIDATE_WINDOW` (0.5s),
  and try them sequentially with `relay_request`, opening a tunnel via
  `connect_via_relay_tunnel()` once a relay accepts. Passive B accepts incoming
  relayed connections automatically.
- **46.4 (`1.19.3`, done)** — `/group relay <id> on|off` toggles
  in-memory relay hosting for active members only, separately from
  Rendezvous mode. This completes Phase 46.

## Next up (recommended order)

Straight from `IMPLEMENTATION_PLAN.md`'s "Urutan implementasi yang
disarankan" — this is the order that makes sense to build in, not the
numeric phase order in the plan doc:

1. **Phase 45 — Rendezvous** (complete: 45.1 `1.18.6`, 45.2 `1.18.7`,
   45.3 `1.18.8`)
2. **Phase 46 — NAT Traversal & Relay** (complete: 46.1 `1.19.0`,
   46.2 `1.19.1`, 46.3 `1.19.2`, 46.4 `1.19.3`)
3. **Phase 36/37 — UI/security UX** (in progress: 36.1 `1.20.0` & 36.2 `1.20.1` complete; next: 37.1 `1.20.2` event-driven pending prompt) <- next
4. Phase 28-35 — logging, performance, concurrency, state machines,
   error protocol (design resolved in `RELIABILITY_DESIGN.md`; starts after
   Phase 36/37 with logging and reliability taxonomy)
5. Phase 38 — Project structure final (design resolved in
   `PROJECT_STRUCTURE_DESIGN.md`; deferred until Phase 36/37 and 28-35
   stabilize)
6. Security audit, release

## Why Phase 38 Is Deferred

Most core packages, including Phase 44-46's `core/connectivity/`, are already
in their final locations. Phase 38 remains deferred because moving the
remaining root implementations (`peer.py`, `discovery.py`, `chat.py`,
`file_transfer.py`, and `ui.py`) changes imports and packaging across the
application. It should occur only after the Trust Center and reliability work
stabilize the workflows it must preserve. The precise target layout, shim
contract, migration order, clean-wheel verification, and acceptance criteria
are in `PROJECT_STRUCTURE_DESIGN.md`.

