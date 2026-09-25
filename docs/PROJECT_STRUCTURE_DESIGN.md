# Project Structure Design: Phase 38

Status: **design resolved, intentionally deferred**. Phase 38 is a one-shot
structural and packaging refactor to be performed only after Phases 36/37 and
28-35 stabilize their public workflows. It changes imports, file locations,
and package entry points only; it must not redesign behavior or security
policy.

## 1. Current Baseline

The core package structure is already largely final:

```
core/
  connectivity/  crypto/  group/  identity/  protocol/  security/
  transfer/      transport/ trust/ vault/
```

`core/protocol` is already canonical and `protocol.py` is already a
compatibility shim. The remaining root implementations are:

| Current module | Canonical destination | Compatibility shim after Phase 38 |
|---|---|---|
| `peer.py` | `core/transport/manager.py` | `peer.py` |
| `discovery.py` | `core/discovery/` | `discovery.py` |
| `chat.py` | `core/messaging/session.py` | `chat.py` |
| `file_transfer.py` | `core/transfer/session.py` | `file_transfer.py` |
| `ui.py` | `app/ui/app.py` and `app/main.py` | `ui.py` |

The Phase 44-46 `core/connectivity/` package is already present and requires
no structural migration. Tests remain in their existing flat `tests/` layout;
Phase 38 does not move them for appearance alone.

## 2. Target Layout

```text
peerc/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   └── ui/
│       ├── __init__.py
│       ├── app.py
│       ├── widgets/
│       │   └── rich_log.py
│       └── modals/
│           ├── identity.py
│           ├── link.py
│           ├── transfer.py
│           └── vault.py
├── core/
│   ├── connectivity/
│   ├── crypto/
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── broadcast.py
│   │   ├── identity_loader.py
│   │   ├── mdns.py
│   │   └── registry.py
│   ├── group/
│   ├── identity/
│   ├── messaging/
│   │   ├── __init__.py
│   │   └── session.py
│   ├── protocol/
│   ├── security/
│   ├── transfer/
│   │   └── session.py
│   ├── transport/
│   │   └── manager.py
│   ├── trust/
│   └── vault/
├── chat.py             # compatibility shim
├── discovery.py        # compatibility shim
├── file_transfer.py    # compatibility shim
├── peer.py             # compatibility shim
├── protocol.py         # compatibility shim
└── ui.py               # compatibility shim
```

`app/config.py` owns application-only configuration such as UI listen port,
key bindings, and presentation timeouts. Protocol, handshake, transport, and
transfer limits remain next to their core owners. A configuration move must
not centralize unrelated security constants merely for convenience.

## 3. Dependency Rules

```text
app --------> core
root shims -> app or core
core -------X-> app
core -------X-> root shims
app --------X-> root shims
```

- Production imports use canonical `app.*` or `core.*` paths.
- Root modules only re-export documented legacy symbols and carry no business
  logic, runtime initialization, or import-time side effects.
- A shim preserves object identity where practical: importing
  `ConnectionManager` from `peer` and `core.transport.manager` returns the
  same class object.
- Tests migrate to canonical imports by default. A small dedicated shim suite
  is the only place that relies on root imports after migration.

## 4. Canonical Module Responsibilities

### Transport manager

`core.transport.manager` owns `ConnectionManager`, connection limits, session
registration, per-session read loops, relay pipes/tunnels, and connection
shutdown. It may depend on `core.protocol`, `core.crypto`, `core.trust`, and
other `core` packages, but never on app/UI code.

### Discovery

`core.discovery.registry` owns `Peer` and `PeerRegistry`.
`broadcast` owns UDP announce/send/receive mechanics, `mdns` owns the optional
zeroconf adapter, and `identity_loader` owns legacy identity-loading adapters.
The common packet validation path stays singular, so broadcast and mDNS cannot
drift into accepting different identity shapes.

### Messaging and transfer sessions

`core.messaging.session` owns chat acknowledgement state and timeouts.
`core.transfer.session` owns the high-level offer/accept/chunk/completion
workflow and composes the existing lower-level `core.transfer` helpers. These
sessions publish typed `core.events` events and do not import the Textual app.

### Application and UI

`app.main` is the only console-script target. `app.ui.app` owns `ChatApp` and
application orchestration. Modal classes are grouped by domain, while reusable
widgets stay separate. Moving a class is not a reason to change its user
interaction, state, or accessibility behavior.

## 5. Migration Sequence

1. Create a dedicated branch and tag the exact starting commit as
   `pre-phase38-refactor`. No functional change may share the branch.
2. Add empty target packages and a packaging configuration capable of including
   `app` plus all nested `core` packages. Do not change console scripts yet.
3. Move `ConnectionManager` to `core.transport.manager`; turn `peer.py` into a
   re-export shim; migrate production imports; verify direct and relay paths.
4. Split discovery by responsibility while retaining one packet validation
   implementation; turn `discovery.py` into a re-export shim; verify UDP and
   optional mDNS discovery.
5. Move `ChatSession` to `core.messaging.session` and the high-level transfer
   session to `core.transfer.session`; convert root modules to shims; verify
   acknowledgement and transfer-resume workflows.
6. Move `ChatApp`, modals, widgets, and application-only configuration into
   `app`; make `ui.py` a shim that re-exports the legacy public UI API.
7. Change console scripts to `app.main:main`; retain `peerc` and `pchat` names
   exactly. Do not leave an entry point targeting a root shim.
8. Run import audit. Production code must contain no imports of `peer`,
   `discovery`, `chat`, `file_transfer`, `protocol`, or `ui` except inside the
   six shims.
9. Add and run shim tests, full regression, Textual pilot flows, direct and
   relay connection smoke tests, and an installed-wheel test in a clean
   environment.
10. Update README architecture and contributor documentation only after the
    installed wheel and both console commands succeed.

Each migration step is separately reviewable, but the Phase 38 branch is
released only when all steps are complete. The tag is the rollback point; no
partial structural release is supported.

## 6. Packaging and Compatibility Contract

The build configuration must discover nested packages rather than maintain a
manually enumerated package list. Root shim modules remain published as
`py-modules` for one compatibility release cycle.

Required checks:

```text
peerc --help
pchat --help
python -m app.main --help
python -c "from peer import ConnectionManager"
python -c "from discovery import Discovery, PeerRegistry"
python -c "from chat import ChatSession"
python -c "from file_transfer import FileTransferSession"
python -c "from ui import ChatApp, main"
```

The clean-install test installs the wheel into a new environment, never an
editable checkout. It verifies that neither repository-root imports nor a
developer's `PYTHONPATH` mask missing package data.

## 7. Acceptance Criteria

- Canonical production imports obey the dependency rules in section 3.
- Legacy imports resolve to the canonical public objects and preserve behavior.
- The full automated suite passes using canonical imports.
- Dedicated shim tests cover every supported root export.
- UDP discovery, optional mDNS, direct transport, relay transport, chat,
  transfer, vault unlock/lock, and Textual modal flows pass smoke tests.
- A wheel installed into a clean environment exposes both console commands and
  runs without the source checkout on `sys.path`.
- No protocol version, database schema, vault format, trust rule, or user
  workflow changes as part of this phase.

## 8. Out of Scope

- feature work from Phases 36/37 or 28-35;
- new wire messages or compatibility policy changes;
- removal of root shims in the same release as the migration;
- test-directory reorganization without a test-maintenance reason; and
- cosmetic rewrites of functioning core modules.
