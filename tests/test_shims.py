"""tests/test_shims.py — Phase 38.9: the dedicated shim suite.

The six root modules (peer, discovery, chat, file_transfer, protocol, ui) are
backward-compatibility shims over the canonical `app.*` / `core.*` modules
(docs/PROJECT_STRUCTURE_DESIGN.md sections 3 and 6). After the Phase 38
migration this file is where root imports are *supposed* to be exercised.

It pins the compatibility contract:

  1. Every legacy name resolves to the SAME object as its canonical home
     (object identity, not equality) — so isinstance checks, class-level
     monkeypatching and exception handling behave identically either way.
  2. Each shim's public `__all__` is exactly the documented legacy surface;
     nothing undocumented is exported and nothing documented is missing.
  3. Importing a non-UI shim starts no threads and does not drag in the
     Textual UI (`app`, `textual`); the UI stays out of core.
  4. The documented legacy launch paths (`python -m ui`, `python -m app.main`)
     still start the app.

Static shape rules (re-export only, no logic) live in
tests/test_import_boundaries.py.
"""

import importlib
import logging
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent

# shim -> {legacy name: (canonical module, canonical attribute)}
# Names starting with "_" are private: kept only because existing tests import
# them, and slated to go with the test-import migration.
_D = "core.discovery"
_UI = "app.ui.modals"
CANONICAL = {
    "peer": {
        **{n: ("core.transport.manager", n) for n in (
            "CONNECT_TIMEOUT", "MAX_CONNECTIONS", "ConnectionLimitError", "ConnectionManager", "OnMessage")},
    },
    "discovery": {
        **{n: (f"{_D}.broadcast", n) for n in (
            "ANNOUNCE_INTERVAL", "Discovery", "get_broadcast_targets", "get_network_info")},
        **{n: (f"{_D}.constants", n) for n in ("BROADCAST_PORT", "PROTOCOL_VERSION")},
        **{n: (f"{_D}.identity_loader", n) for n in ("load_or_create_identity", "save_identity")},
        **{n: (f"{_D}.mdns", n) for n in (
            "MDNS_ANNOUNCE_INTERVAL", "MDNS_AVAILABLE", "MDNS_SERVICE_TYPE", "MDNSDiscovery",
            "_build_mdns_txt", "_log", "_mdns_txt_to_packet")},
        **{n: (f"{_D}.registry", n) for n in ("PEER_TIMEOUT", "Peer", "PeerRegistry")},
    },
    "chat": {
        **{n: ("core.messaging.session", n) for n in (
            "ACK_TIMEOUT", "ChatSession", "OnChatReceived", "OnStatusChange", "SentMessageState")},
    },
    "file_transfer": {
        **{n: ("core.transfer.session", n) for n in (
            "CHUNK_SIZE", "FileTransferSession", "IncomingTransfer", "OnComplete", "OnOfferReceived",
            "OnProgress", "OutgoingTransfer", "PathTraversalError", "_ERROR_REPORT_CAP")},
        "ErrorCode": ("core.protocol", "ErrorCode"),
    },
    "ui": {
        **{n: ("app.config", n) for n in (
            "AUTO_LOCK_POLL_SECONDS", "IP_CHANGE_CHECK_INTERVAL", "RELAY_CANDIDATE_WINDOW",
            "RELAY_DIRECT_TIMEOUT", "RELAY_RESPONSE_TIMEOUT", "UI_TCP_PORT")},
        "ChatApp": ("app.ui.app", "ChatApp"),
        "main": ("app.main", "main"),
        **{n: (f"{_UI}.identity", n) for n in (
            "NameSetupModal", "SecurityEventsModal", "TrustCenterModal", "TrustConfirmModal",
            "TrustDeviceDetailModal", "TrustPromptModal", "validate_display_name", "_group_security_events")},
        **{n: (f"{_UI}.link", n) for n in (
            "LinkAddModal", "LinkGenerateModal", "LinkMenuModal", "LinkResultModal", "_parse_endpoint_line")},
        "FileOfferModal": (f"{_UI}.transfer", "FileOfferModal"),
        **{n: (f"{_UI}.vault", n) for n in (
            "CriticalActionKeyModal", "VaultCreateModal", "VaultRecoveryCodeModal", "VaultUnlockModal")},
        **{n: ("app.ui.widgets.rich_log", n) for n in (
            "SelectableRichLog", "apply_selection_to_strip", "copy_to_system_clipboard")},
    },
}

# protocol.py predates Phase 38 (Phase 1.1); three names are aliases of the
# framing functions in core.protocol. Everything else keeps its name.
PROTOCOL_ALIASES = {
    "encode_message": "encode_frame",
    "read_message": "read_frame",
    "write_message": "write_frame",
}
# The message builders/validators production code and tests have always used.
PROTOCOL_MUST_EXPORT = (
    "ProtocolError", "PROTOCOL_VERSION", "MAX_MESSAGE_SIZE", "validate_message", "make_error",
    "make_chat_message", "make_chat_ack", "make_file_offer", "make_file_accept", "make_file_chunk",
    "make_file_done", "make_hello", "make_handshake_init", "make_relay_request", "make_rendezvous_lookup",
    "encode_message", "read_message", "write_message", "decode_file_data", "encode_file_data",
)

NON_UI_SHIMS = ("peer", "discovery", "chat", "file_transfer", "protocol")


def _canonical(module: str, attr: str):
    return getattr(importlib.import_module(module), attr)


# ---------------------------------------------------------------------------
# 1. Object identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "shim, name, module, attr",
    [(s, n, m, a) for s, table in CANONICAL.items() for n, (m, a) in table.items()],
    ids=lambda v: str(v),
)
def test_legacy_name_is_the_canonical_object(shim, name, module, attr):
    legacy = getattr(importlib.import_module(shim), name)
    assert legacy is _canonical(module, attr), f"{shim}.{name} is not {module}.{attr}"


def test_protocol_shim_names_are_the_canonical_objects():
    import protocol
    import core.protocol as canonical

    assert protocol.__all__, "protocol.__all__ is empty"
    assert len(protocol.__all__) == len(set(protocol.__all__)), "duplicate names in protocol.__all__"
    for name in protocol.__all__:
        target = PROTOCOL_ALIASES.get(name, name)
        assert getattr(protocol, name) is getattr(canonical, target), f"protocol.{name} != core.protocol.{target}"


@pytest.mark.parametrize("name", PROTOCOL_MUST_EXPORT)
def test_protocol_shim_still_exports_the_historical_names(name):
    import protocol

    assert name in protocol.__all__
    assert hasattr(protocol, name)


def test_discovery_private_logger_keeps_its_name():
    import discovery

    assert discovery._log is logging.getLogger("peerc.discovery")


# ---------------------------------------------------------------------------
# 2. Documented surface == __all__
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shim", sorted(CANONICAL))
def test_all_is_exactly_the_documented_public_surface(shim):
    module = importlib.import_module(shim)
    documented = {n for n in CANONICAL[shim] if not n.startswith("_")}
    assert set(module.__all__) == documented, (
        f"{shim}.__all__ drifted from the documented surface; "
        f"undocumented: {sorted(set(module.__all__) - documented)}, "
        f"missing: {sorted(documented - set(module.__all__))}"
    )


# ---------------------------------------------------------------------------
# 3. No import-time side effects; the UI stays out of core
# ---------------------------------------------------------------------------

_PROBE = """
import sys, threading
import {shim}
leaked = sorted(m for m in ("app", "textual") if m in sys.modules)
print("THREADS", threading.active_count())
print("LEAKED", ",".join(leaked) or "-")
"""


@pytest.mark.parametrize("shim", NON_UI_SHIMS)
def test_importing_a_non_ui_shim_is_side_effect_free(shim):
    out = subprocess.run(
        [sys.executable, "-c", _PROBE.format(shim=shim)],
        cwd=str(REPO), capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    lines = dict(line.split(" ", 1) for line in out.stdout.strip().splitlines())
    assert lines["THREADS"] == "1", f"importing {shim} started a thread"
    assert lines["LEAKED"] == "-", f"importing {shim} pulled in the UI: {lines['LEAKED']}"


# ---------------------------------------------------------------------------
# 4. Legacy launch paths
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.parametrize("module", ["ui", "app.main"])
def test_legacy_and_canonical_launch_paths_start_the_app(module):
    """`python -m ui` exercises the shim's documented __main__ guard (the same
    path as the README's `python3 ui.py`); `python -m app.main` is canonical."""
    out = subprocess.run(
        [sys.executable, "-m", module, "--help"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("usage: peerc"), out.stdout[:200]
    assert "--diagnostic" in out.stdout and "--debug" in out.stdout
