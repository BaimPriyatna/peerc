<p align="center">
  <img src="assets/peerc-banner.svg" alt="PeerC Banner" />
</p>
<p align="center">
  <em>Peer-to-Peer Communication</em>
</p>

[![Tests](https://github.com/BaimPriyatna/peerc/actions/workflows/tests.yml/badge.svg)](https://github.com/BaimPriyatna/peerc/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.23.8-informational.svg)](CHANGELOG.md)

A terminal-based peer-to-peer chat and file transfer application. No central server — peers discover each other directly over the local network (LAN or WiFi hotspot) and communicate directly over encrypted TCP connections.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

- Peer discovery via UDP broadcast (MNDP-style), with stable peer identity that survives DHCP IP changes
- Direct encrypted chat with delivery acknowledgment (`sent` -> `delivered` / `failed`)
- **Resumable file transfer** with offer/accept/reject, SHA-256 verification, atomic staging, and automatic resume from interruption (Phase 47)
- Terminal UI built with Textual — peer list, chat log, and inline notifications
- Mutual authenticated handshake: each device proves its Ed25519 identity before any message is exchanged
- End-to-end encryption via ChaCha20-Poly1305 AEAD on all traffic

---

## Architecture

### Discovery

Each instance periodically broadcasts a UDP "announce" packet containing `peer_id`, `name`, and `tcp_port`. Listeners maintain a live peer list keyed by `peer_id` rather than IP address. A peer's IP can change — for example, under DHCP renewal or when switching from LAN to hotspot — without being treated as a new or different peer. Stale peers are pruned after a configurable timeout.

### Transport Stack

Connections are layered, and each layer has a single responsibility:

```
Application (core/transport/manager.py, core/transfer/session.py)
    SecureSession       — send/receive typed messages, no crypto awareness needed
        EncryptedTransport  — ChaCha20-Poly1305 AEAD framing, sequence-derived nonces
            TCPConnection   — length-prefixed binary framing over TCP
```

### Handshake and Key Derivation

Before any application message is sent, a 3-way mutual handshake runs:

1. Each side generates an ephemeral X25519 keypair and signs its public key with its long-term Ed25519 device key.
2. Both sides exchange these signed ephemeral keys and verify signatures against the trust store.
3. A shared secret is derived via X25519, then fed through HKDF-SHA256 with the full handshake transcript as a salt, producing independent `tx` and `rx` keys per direction.

This prevents man-in-the-middle attacks and binds session keys to the exact observed transcript — a replayed or forged handshake message derives a different key and is rejected automatically.

### File Transfer

Inbound files are written to a `.part` staging file and checkpointed every 4 MiB with fsync. On completion, the received content is verified against the SHA-256 checksum declared in the original offer. If verification passes, the `.part` file is atomically renamed to the final destination path via `os.replace`. If it fails, the staging file is discarded.

**Resumable transfers** (Phase 47): When a connection drops mid-transfer, the partial download is kept (with a `.part.meta` sidecar) and bound to the authenticated sender's device ID. When the same peer re-offers the same file (matching filename, size, and checksum), the receiver automatically requests resumption from the last committed offset via an optional `resume_offset` field in `file_accept`. The sender honors it if valid (aligned to 64 KiB chunk boundaries), or ignores it and restarts from zero, which the receiver detects and handles cleanly. Old peers that don't understand `resume_offset` are backward compatible: they ignore the field and send from the beginning, and the receiver's restart detection truncates the `.part` and continues without error. Partial downloads older than 7 days are automatically expired.

### Protocol

Length-prefixed JSON messages: `announce`, `chat`, `chat_ack`, `file_offer`, `file_accept`, `file_reject`, `file_data`, `file_done`, `file_complete_ack`. File chunks travel as raw binary frames rather than base64-in-JSON, reducing wire overhead from ~33% to ~0.05%.

---

## Security Model

> [!IMPORTANT]
> peerc is designed for use on trusted local networks (LAN or personal hotspot). It has not been audited for use over the public internet.

| Property | Implementation |
|---|---|
| Device identity | Ed25519 keypair, persisted in keyring (or fallback file). Fingerprint shown on first connection. |
| Trust model | TOFU (trust on first use) with local trust store. Devices can be explicitly revoked. |
| Handshake | Mutual X25519 ephemeral key exchange with Ed25519 transcript signatures. Both sides must authenticate. |
| Session keys | HKDF-SHA256, directional (separate tx/rx keys per side), transcript-bound. |
| Encryption | ChaCha20-Poly1305 AEAD. Nonce derived from sequence counter — no nonce repetition risk within a session, and no nonce transmitted on the wire. |
| Replay protection | Strict gap-free sequence enforcement per direction. Out-of-order, replayed, or tampered frames are rejected. |
| File integrity | SHA-256 checksum verified on receipt before file is made available. |
| Path traversal | Received filenames are sanitized and confined to the downloads directory before any disk write. |
| Disk safety | Pre-flight free disk space check before accepting any file offer. |

---

## Requirements

- Python 3.10 or newer
- `textual >= 8.0`
- `rich >= 13.0`
- `cryptography >= 42.0`
- `keyring >= 24.0`

---

## Installation

```bash
git clone https://github.com/BaimPriyatna/peerc.git
cd peerc
pip install -e .
```

This installs the package and creates the `peerc` entry point.

> [!NOTE]
> A virtual environment is recommended to avoid conflicts with system packages:
> ```bash
> python -m venv .venv
> source .venv/bin/activate   # Windows: .venv\Scripts\activate
> pip install -e .
> ```

---

## Usage

Launch on two or more devices on the same LAN or WiFi hotspot:

```bash
peerc
```

Peers appear automatically in the left panel as they are discovered. Once a peer is selected, type in the bottom input box and press Enter to send a chat message.

To run without installing, from the repository root:

```bash
python3 -m app.main
```

(`python3 ui.py` still works: `ui.py` is a compatibility shim that forwards to the same entry point.)

### Diagnostic Logging

Normal runs write `WARNING`-and-above diagnostics to a rotating local file
(`~/.peerc/diagnostics.log`, 5 MB × 3 backups) — separate from the in-app
chat log, and never containing chat/file content, key material, or vault
plaintext. For deeper troubleshooting:

```bash
peerc --diagnostic   # INFO and above for this run
peerc --debug        # DEBUG and above, opt-in for a single run
```

### Keyboard and Mouse

| Action | Key |
|---|---|
| Quit | `Ctrl+Q` (or `Ctrl+C` when no text is selected) |
| Copy selected text | `Ctrl+C` or `Ctrl+Shift+C` |
| Select text | Click and drag in the chat log |
| Switch peer | Click any peer in the left sidebar |

---

## Commands

Type any command into the bottom input box and press Enter:

| Command | Description |
|---|---|
| `/help` | Show available commands and keyboard shortcuts |
| `/connect <ip>[:port]` | Connect directly to a peer by IP — useful when broadcast is blocked (e.g. AP isolation) |
| `/link` (or Ctrl+G) | Add-by-Link menu — generate a PIN-protected link to share, or add a peer via one you received |
| `/peers` | List all discovered peers with IP, port, and status |
| `/msg <name\|id>` | Switch the active chat recipient |
| `/send <filepath>` | Offer a file to the active peer |
| `/name <new-name>` | Change your display name and announce to the network |
| `/copy [all\|last]` | Copy the last message or the full chat log to the clipboard |
| `/clear` | Clear the visible chat log |
| `/info` (or `/me`) | Display local identity, IP, gateway, and listening ports |
| `/devices [pending]` | Open Trust Center dialog (all or pending-only filter) |
| `/pairs` | Alias for `/devices` |
| `/trust <device_id>` | Open detailed device view with public-key fingerprint |
| `/revoke <device_id> [reason]` | Locally revoke a device (refuse future handshakes) |
| `/quit` (or `/exit`) | Quit peerc |

Anything that is not a `/` command is sent as a chat message to the active peer. Sent messages display delivery status alongside them.

---

## Project Structure

```
peerc/
├── app/                        # Application layer (depends on core)
│   ├── main.py                 # `peerc` entry point and CLI flags
│   ├── config.py               # UI port and presentation/orchestration timeouts
│   └── ui/
│       ├── app.py              # ChatApp, the Textual terminal UI
│       ├── modals/             # Identity/trust, vault, transfer, and link screens
│       └── widgets/            # SelectableRichLog and clipboard helper
├── core/                       # Protocol, security, and networking (never imports app)
│   ├── protocol/               # Wire format, message types, and binary framing
│   ├── identity/               # Ed25519 device keypair and KeyStore
│   ├── trust/                  # SQLite trust store, TOFU, and revocation
│   ├── crypto/                 # X25519 handshake, HKDF-SHA256 key derivation, ChaCha20-Poly1305
│   ├── transport/              # TCPConnection, EncryptedTransport, SecureSession, ConnectionManager
│   ├── transfer/               # File Transfer V2 helpers and FileTransferSession
│   ├── discovery/              # PeerRegistry, UDP broadcast, optional mDNS, legacy identity loader
│   ├── messaging/              # ChatSession: chat sending and delivery acknowledgment
│   ├── connectivity/           # Internet P2P connectivity (rendezvous and relay)
│   ├── group/                  # Group authority
│   ├── vault/                  # Secure storage (envelope encryption)
│   └── security/               # Security architecture and event logging
├── docs/                       # ROADMAP, design documents, and the benchmark baseline
├── scripts/                    # regression_gate.py, verify_wheel.py
├── tests/                      # Automated pytest suite and per-stage smoke scripts
├── peer.py                     # Shim -> core.transport.manager
├── discovery.py                # Shim -> core.discovery
├── chat.py                     # Shim -> core.messaging.session
├── file_transfer.py            # Shim -> core.transfer.session
├── protocol.py                 # Shim -> core.protocol
├── ui.py                       # Shim -> app (ChatApp, modals, main)
├── .github/workflows/          # CI
├── pyproject.toml
├── CHANGELOG.md
└── LICENSE
```

The layers depend in one direction only:

- `app` imports `core`; `core` never imports `app`.
- Production code imports the canonical `app.*` and `core.*` paths. The six root modules (`peer`, `discovery`, `chat`, `file_transfer`, `protocol`, `ui`) exist only so older imports such as `from peer import ConnectionManager` keep working. They contain nothing but re-exports and are published for one compatibility release cycle.
- When you rebind or monkeypatch a name, patch the canonical module that reads it (for example `core.discovery.broadcast.get_network_info`), not the shim: rebinding a name on a shim does not reach the code that uses it.

`tests/test_import_boundaries.py` enforces these rules statically and `tests/test_shims.py` pins the shim contract; both run with the normal suite. The full layout and its rationale are in [`docs/PROJECT_STRUCTURE_DESIGN.md`](docs/PROJECT_STRUCTURE_DESIGN.md).

---

## Running Tests

```bash
# Full suite (benchmark tests excluded by default — see below)
pytest

# By layer, using the markers from Phase 29/30.1 (unit/integration/ui/security/benchmark)
pytest -m unit
pytest -m security

# Dependency rules and the legacy-shim contract (also part of the full suite)
pytest tests/test_import_boundaries.py tests/test_shims.py

# Per-stage smoke scripts (no pytest test_ functions — run directly)
python3 tests/test_stage2.py
python3 tests/test_stage3.py
python3 tests/test_stage4.py
python3 tests/test_stage5.py

# Performance benchmarks (Phase 31.1) — non-gating, records docs/benchmarks/latest.json
pytest -m benchmark

# Regression gate (Phase 31/32.2) — runs the benchmarks above, then compares
# the fresh run against the committed docs/benchmarks/baseline.json. Manual
# only: never a per-push CI gate (loopback timing is noisy on shared runners).
python3 scripts/regression_gate.py

# Before a release: build the wheel, install it into a fresh virtualenv, and test the
# INSTALLED package from an empty directory (needs network for pip). CI only tests an
# editable install, so this is what exercises the packaging configuration.
python3 scripts/verify_wheel.py
```

The full suite (minus benchmarks) also runs automatically in CI on every push to `main`, alongside a separate non-gating benchmark job. The regression gate itself only runs when the CI workflow is triggered manually (`workflow_dispatch`). See `.github/workflows/tests.yml`.

`docs/benchmarks/baseline.json` was recorded on one machine, so the regression gate's absolute numbers are only meaningful there. On a different machine, compare the same benchmarks run on the commit under test against the same run on the previous tag instead.

> [!NOTE]
> If running on Windows, substitute `python` for `python3`.

---

## Known Limitations

- Discovery via UDP broadcast does not work across WiFi access points that have AP isolation (client isolation) enabled. Use `/connect <ip>` to reach peers in that case.
- No retry or queuing for messages sent while a peer is offline. The peer's IP may have changed before it reconnects.
- Room / multi-party channel support doesn't exist yet — each conversation is one-to-one (planned: Phase 42 Group Authority System).

---

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for phased progress and [`CHANGELOG.md`](CHANGELOG.md) for a full version history.

Current version: **1.23.8** — Phase 47 (file transfer resume) complete: automatic resume from interruption with backward compatibility, sidecar metadata, restart detection, and 7-day expiry; Phase 38 (project structure) complete.
Phase 36 & 37 (Trust Center UX) complete,
Phase 28-35 (Reliability program) underway: 28.1 (logging), 29/30.1
(reliability taxonomy + task registry), 31.1 (performance baselines),
33.1 (connection lifecycle FSM), 34.1 (transfer lifecycle FSM), 35 (application
error protocol), and 31/32.2 (regression gate) done — the Phase
28-35 reliability program is now fully complete, including its
optional final gate!
Interactive trust controls (`Trust`, `Reject`, `Revoke`, `TrustConfirmModal`),
command `/revoke <id> [reason]`, read-only Trust Center inventory (`/devices`),
an event-driven pending-trust prompt (`TrustPromptModal`) replacing log-only
handling, and a read-only Security Events view (`/events`) with rotation
history in the device detail screen. Diagnostic logging (`--diagnostic`/
`--debug`) now writes to a rotating `~/.peerc/diagnostics.log`, separate
from the in-app chat log and never containing secrets.
sub-steps done: vault envelope encryption, encrypted database with
chat/transfer persistence, session/auto-lock model, critical-action Export
key, and file actions (Open/Export/Delete/Move with executable detection).
Messages, transfers, trusted devices, and secure files all encrypted at rest.
Vault auto-locks after 5 min idle (configurable) or on `/lock` / Ctrl+L.
File commands: `/files`, `/open`, `/export`, `/secure`, `/delete`.

Phase 42 (Group Authority System) and Phase 43 (Group-Gated Export
Authorization) are also complete: admin-managed groups with Ed25519-signed
membership certificates, multi-admin with k-of-n threshold signatures,
core-level policy enforcement (external trust restriction, communication
matrix), a signed audit log, and short-lived admin-issued export capabilities
that gate `/export` alongside the personal critical-action key (an admin
approval AND a personal key, not either/or). Group commands: `/groups`,
`/group create|info|members|admins|join|leave|approve|reject|revoke|
addadmin|policy|audit|req-export|authorize-export|caps|rendezvous` — see
`/help` in-app for the full list with usage.

Phase 44 (Internet P2P Connectivity) is feature-complete except QR display
(deliberately deferred): Locator (persisted, cross-session endpoint
tracking, separate from identity), signed Endpoint Update (now wired into
every connection — LAN, `/connect`, or Add-by-Link all leave a
cryptographically-confirmed, reusable locator entry), and Add-by-Link
(`/link`, Ctrl+G, or the sidebar button — generate or redeem a
PIN-protected `PEERC1:` connection link, click-driven) are all done.

Phase 45 (Rendezvous) is done: own-IP-change detection with automatic
re-announcement to connected peers, plus opt-in per-group endpoint
relaying (`/group rendezvous <id> on|off|find <device>`) for group-mates
who aren't currently connected — any active group member can host, no
new crypto (the host only relays already-signed Endpoint Updates, the
requester re-verifies everything itself against the group's membership
records).

Phase 46 (optional Relay fallback) is also complete: peerc tries a direct
connection first, then discovers live relay hosts by broadcasting to peers
already connected to the group. Relay hosting is opt-in per group with
`/group relay <id> on|off` and stays independent from Rendezvous hosting;
the relay only forwards end-to-end encrypted traffic.

---

## License

MIT — see [LICENSE](LICENSE).
