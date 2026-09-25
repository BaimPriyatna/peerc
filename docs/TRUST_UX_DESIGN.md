# Trust UX Design

Status: **designed, not yet implemented**. This document resolves Phase 36
(device and trust UI) and Phase 37 (security decisions). It is the source of
truth for the user-facing trust flow; `core/trust/` remains the source of
truth for trust state and authorization.

## 1. Goal and Scope

peerc already authenticates device identities during the handshake and stores
first-seen devices as `PENDING`. The missing piece is a clear, deliberate way
for a person to inspect that identity and decide what to do with it.

This phase adds a Trust Center that lets a user:

- inspect known devices and their current trust state;
- approve a pending device after comparing its fingerprint out of band;
- locally revoke a pending or trusted device; and
- understand security events without treating a warning as a request to
  weaken identity verification.

It does not alter handshake cryptography, group authorization, relay
authorization, or network protocol messages. Trust remains local to the
vault, unless an existing group policy independently restricts external trust.

## 2. Existing Contract

The design builds on these established facts:

| Concern | Existing owner | Required UX behavior |
|---|---|---|
| Authenticated peer identity | Phase 6 handshake | Show only the identity authenticated by the session, never a self-reported value. |
| First encounter | `TrustStore.record_first_seen()` | It creates `PENDING`; user approval is always explicit. |
| Approval | `TrustStore.approve()` | Only promotes `PENDING` to `TRUSTED`; it never revives `REVOKED`. |
| Rejection | `revoke_device()` | Becomes a local revoke with an optional reason; it is intentionally not an undo action in this phase. |
| Key rotation | Phase 40 `TransitionCertificate` | A valid certificate carries trust to the new device identity. |
| Key mismatch | `TrustStore.check()` and handshake | The handshake fails. It is a security warning, not an approval prompt. |
| Group policy | `PolicyEnforcer.check_external_trust()` | A denied external-trust action must explain the policy, make no state change, and offer no bypass. |

The vault must be unlocked before opening the Trust Center or applying a
decision. If it locks while a modal is open, the modal closes without making a
change and the user is asked to unlock again.

## 3. Trust States and Allowed Actions

| State | Meaning | Primary action | Other action |
|---|---|---|---|
| `PENDING` | Identity was authenticated but has not been approved by the local user. | Trust | Reject (local revoke) |
| `TRUSTED` | Identity and stored key match a locally approved device. | View | Revoke |
| `REVOKED` | Locally distrusted device; future handshakes are rejected. | View reason | None in this phase |
| Unknown | Not yet stored. It becomes `PENDING` only after a successful authenticated handshake. | None | None |
| Key changed | A known device ID arrived with a different key. The handshake has already failed. | Review security event | Revoke stored identity |

There is deliberately no "trust new key" or "replace key" action. Device IDs
are bound to public keys, so silently replacing a key would turn an identity
mismatch into an impersonation bypass. A legitimate key change uses a verified
Phase 40 transition certificate and results in a new device identity; an
unverified mismatch remains rejected.

## 4. Entry Points

### 4.1 Immediate prompt for pending trust

When `TrustRequired(reason="first_seen")` arrives, show a non-blocking Trust
Prompt. It must not interrupt an active file-transfer decision or vault-unlock
flow. If another Trust Prompt is already open, queue the event by `peer_id` and
deduplicate repeated events for the same key.

The prompt displays:

- device name, authenticated device ID, and abbreviated fingerprint;
- a full-fingerprint reveal/copy control;
- the observed connection route only as context, labelled as untrusted
  reachability information; and
- `Trust`, `Reject`, and `Later` actions.

`Later` dismisses the prompt and leaves the device `PENDING`. It does not
disconnect the session or change the stored record. The user can revisit it in
the Trust Center.

### 4.2 Trust Center

The Trust Center is the durable management view. Phase 36 keeps the existing
command vocabulary as accessible entry points:

```
/devices                 open all known devices
/devices pending         show only pending devices
/trust <device_id>       open the matching device detail
/revoke <device_id> [reason]
```

The primary UI surface is a modal or dedicated Textual screen, not a stream of
log messages. It has three status filters: Pending, Trusted, and Revoked. Each
row shows a stable status icon, name, short device ID, and last-seen time. A
detail view shows the full device ID, public-key fingerprint, first/last seen,
revocation metadata, and the actions allowed by the state table.

`/pairs` remains an alias for `/devices`; old command names are not duplicated
in the visible UI. `/connect`, transfer commands, and `/nick` already belong to
their existing workflows and are not part of the Trust Center implementation.

### 4.3 Security-event review

Warnings from `SecurityWarning` stay visible in the log and gain a compact
Security Events view. It groups repeated events by type and device ID, keeps
the latest timestamp, and opens the associated known-device detail when one
exists. The view is informational: it cannot accept a failed identity change.

## 5. Decision Flows

### Approve pending device

1. User opens a pending-device prompt or detail view.
2. UI shows the fingerprint generated from the stored authenticated public key.
3. User compares it through an out-of-band channel.
4. User selects `Trust` and confirms the device name and fingerprint.
5. UI calls `TrustStore.approve(device_id)`.
6. UI refreshes the row to `TRUSTED` and records a local success message.

If the group policy rejects external trust, the UI keeps the device pending,
shows the policy explanation, and does not offer a retry that bypasses policy.

### Reject or revoke device

1. User selects `Reject` for `PENDING`, or `Revoke` for `TRUSTED`.
2. A confirmation modal states that the change is local and future handshakes
   from that device will be rejected.
3. The reason is optional but preserved when entered.
4. UI calls `revoke_device(store, device_id, revoked_by="local-user", reason)`.
5. UI refreshes the device as `REVOKED` and dismisses related pending prompts.

There is no un-revoke UI in this phase. Reversal needs a separate, auditable
design rather than a convenient accidental click path.

### Verified rotation

Phase 40 already provides certificate verification and rotation-chain storage,
but it does not yet distribute a certificate through the handshake. Therefore
this phase only displays rotations that have already been verified and recorded
locally:

1. `TrustStore.record_rotation()` validates a supplied certificate and carries
   a trusted ancestor's state to the new device identity.
2. The Trust Center displays the new identity as trusted and links it to the
   preceding identity in a read-only rotation history.

Certificate distribution and handshake integration need their own protocol
design. If validation fails, the result is handled as a security event; it
never opens the pending approval prompt for the asserted replacement key.

## 6. UI and Privacy Requirements

- Fingerprints are formatted in fixed-width grouped hexadecimal text and can
  be copied without exposing the raw private key or vault data.
- Name and route are context only. The authenticated device ID and public-key
  fingerprint are the authority for a trust decision.
- Buttons use explicit verbs: `Trust`, `Reject`, `Revoke`, `Later`, and
  `Close`. Destructive actions require confirmation.
- Status labels must not rely on color alone.
- No automatic trust follows discovery, a connection link, relay use,
  rendezvous use, a display-name match, or a prior IP address.
- The UI must work while the peer is no longer connected because decisions are
  against the persisted trust record, not the live connection.

## 7. Implementation Sequence

### 36.1 Read-only device inventory

1. Add a UI-facing read model over `TrustStore.list_all()` and status filters.
2. Implement `/devices`, `/devices pending`, `/pairs`, and `/trust <id>`.
3. Render device list/detail views with stable empty, loading, and vault-locked
   states.
4. Test sorting, filtering, unknown IDs, and vault lock behavior.

### 36.2 Trust decision controls

1. Add the pending-device detail actions and confirmation modal.
2. Wire `TrustStore.approve()` and `revoke_device()` without changing their
   core semantics.
3. Add `/revoke <id> [reason]` as an equivalent explicit command path.
4. Test successful transitions, revoked-device refusal, policy denial, and
   duplicate action idempotence at the UI boundary.

### 37.1 Event-driven pending prompt

1. Replace the current log-only `TrustRequired` handling with a queued Trust
   Prompt while retaining the log entry as an audit-friendly signal.
2. Deduplicate prompts by `(peer_id, public_key)` and safely dismiss them on
   vault lock or decision completion.
3. Test non-blocking behavior with file offers and multiple new peers.

### 37.2 Security-event and rotation presentation

1. Add read-only Security Events and rotation-history views using existing
   security events and `TrustStore.get_rotation_chain()`; do not add rotation
   certificate distribution in this phase.
2. Show a failed key mismatch as a rejected security event, never an approval
   choice.
3. Test valid rotation continuity, revoked-ancestor behavior, mismatch
   presentation, and absence of a key-replacement action.

### 37.3 Full workflow verification

1. Use Textual pilot tests for prompt and modal interaction.
2. Add integration coverage for first connection -> pending -> approve ->
   trusted reconnect, and first connection -> reject -> rejected reconnect.
3. Run the existing handshake, trust, rotation, group-policy, and vault
   integration suites to confirm UI work did not weaken their contracts.

## 8. Out of Scope

- remote or group-wide revocation propagation;
- un-revoke or in-place public-key replacement;
- rotation-certificate distribution or handshake integration;
- automatic trust based on topology, invitation links, or names;
- changing the handshake's behavior for revoked or mismatched identities; and
- a new network message for local trust decisions.
