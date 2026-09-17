<p align="center">
  <img src="assets/peerc-banner.svg" alt="PeerC Banner" />
</p>
<p align="center">
  <em>Peer-to-Peer Communication</em>
</p>

[![Tests](https://github.com/BaimPriyatna/peerc/actions/workflows/tests.yml/badge.svg)](https://github.com/BaimPriyatna/peerc/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.16.2-informational.svg)](CHANGELOG.md)

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
- Hardened file transfer with offer/accept/reject, SHA-256 verification, atomic staging, and transfer resumption
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
Application (peer.py / file_transfer.py)
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

Inbound files are written to a `.part` staging file. On completion, the received content is verified against the SHA-256 checksum declared in the original offer. If verification passes, the `.part` file is atomically renamed to the final destination path via `os.replace`. If it fails, the staging file is discarded.

Transfers are resumable: if a `.part` file already exists, its size is reported back to the sender as the resume offset, and only the remaining bytes are streamed.

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

This installs the package and creates the `peerc` (and `pchat`) entry points.

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

To run without installing, use:

```bash
python3 ui.py
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
| `/peers` | List all discovered peers with IP, port, and status |
| `/msg <name\|id>` | Switch the active chat recipient |
| `/send <filepath>` | Offer a file to the active peer |
| `/name <new-name>` | Change your display name and announce to the network |
| `/copy [all\|last]` | Copy the last message or the full chat log to the clipboard |
| `/clear` | Clear the visible chat log |
| `/info` (or `/me`) | Display local identity, IP, gateway, and listening ports |
| `/quit` (or `/exit`) | Quit peerc |

Anything that is not a `/` command is sent as a chat message to the active peer. Sent messages display delivery status alongside them.

---

## Project Structure

```
peerc/
├── core/
│   ├── protocol/       # Wire format, message types, and binary framing
│   ├── identity/       # Ed25519 device keypair and KeyStore
│   ├── trust/          # SQLite trust store, TOFU, and revocation
│   ├── crypto/         # X25519 handshake, HKDF-SHA256 key derivation, ChaCha20-Poly1305
│   ├── transport/      # Decoupled transport stack (TCPConnection, EncryptedTransport, SecureSession)
│   └── transfer/       # File Transfer V2 (chunker, hashing, resume, receiver, sender, manager)
├── docs/
│   ├── ROADMAP.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── DESIGN.md
│   ├── BUG_REPORT.md
│   └── SECURE_STORAGE_DESIGN.md
├── tests/              # Automated pytest suite and per-stage smoke scripts
├── discovery.py        # UDP broadcast peer discovery
├── protocol.py         # Backward-compatible shim over core.protocol
├── peer.py             # TCP connection management
├── chat.py             # Chat and delivery acknowledgment
├── file_transfer.py    # File transfer protocol handler (delegates to core.transfer)
├── ui.py               # Textual terminal UI (entry point)
├── .github/workflows/  # CI
├── pyproject.toml
├── CHANGELOG.md
└── LICENSE
```

---

## Running Tests

```bash
# Full automated test suite
pytest tests/test_security_fixes.py tests/test_upgrade_fixes.py \
       tests/test_handshake.py tests/test_kdf.py tests/test_encryption.py \
       tests/test_transport.py tests/test_file_transfer_v2.py \
       --asyncio-mode=auto -v

# Per-stage smoke scripts (run directly, not via pytest)
python3 tests/test_stage2.py
python3 tests/test_stage3.py
python3 tests/test_stage4.py
python3 tests/test_stage5.py
```

The full suite also runs automatically in CI on every push to `main`. See `.github/workflows/tests.yml`.

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

Current version: **1.16.2** — Phase 39 (Secure Storage) complete! All 5
sub-steps done: vault envelope encryption, encrypted database with
chat/transfer persistence, session/auto-lock model, critical-action Export
key, and file actions (Open/Export/Delete/Move with executable detection).
Messages, transfers, trusted devices, and secure files all encrypted at rest.
Vault auto-locks after 5 min idle (configurable) or on `/lock` / Ctrl+L.
File commands: `/files`, `/open`, `/export`, `/secure`, `/delete`.
Next planned: Phase 42 (Group Authority System).

---

## License

MIT — see [LICENSE](LICENSE).
