"""tests/test_discovery.py — Phase 5.1 + 5.2: Discovery V2 protocol field tests.

Phase 5.1 covers:
  1. Outgoing payload carries version/device_id/public_key (wire spec in
     IMPLEMENTATION_PLAN.md "Phase 5 — Discovery V2").
  2. A well-formed, self-consistent packet is accepted into the registry.
  3. device_id/public_key self-consistency mismatch is dropped and emits
     an AUTH_FAILED SecurityEvent (Phase 41 infra), not registered as a peer.
  4. Malformed public_key (not base64, wrong length) is dropped.
  5. Missing/wrong version is dropped silently (no SecurityEvent — protocol
     mismatch, not an attack).
  6. Own broadcast is still ignored.
  7. Pre-existing BUG-023 field validation (name/tcp_port) still holds.

Phase 5.2 (mDNS) covers:
  8.  MDNS_AVAILABLE is a bool (True if zeroconf installed, False otherwise).
  9.  _build_mdns_txt() produces the correct key-value TXT dict.
  10. _mdns_txt_to_packet() converts a valid TXT dict into a packet that
      _handle_packet() accepts (same validation path as UDP broadcast).
  11. _mdns_txt_to_packet() with a mismatched device_id/public_key is dropped
      by _handle_packet() and emits AUTH_FAILED (shared validation path check).
  12. _mdns_txt_to_packet() with a wrong version is dropped silently.
  13. get_network_info() includes an mdns_available key.
  14. Discovery.run() task list includes mDNS only when MDNS_AVAILABLE is True
      (tested via monkeypatching, no real sockets needed).

Deliberately NOT tested here: whether an accepted peer is "trusted" —
that's core/trust/'s job (Phase 4), out of scope for discovery.
"""

import asyncio
import base64
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.identity.device_identity import generate_keypair
from core.security import SecurityEventType, capture_security_events
from discovery import (
    BROADCAST_PORT,
    MDNS_AVAILABLE,
    MDNS_SERVICE_TYPE,
    PROTOCOL_VERSION,
    Discovery,
    MDNSDiscovery,
    PeerRegistry,
    _build_mdns_txt,
    _mdns_txt_to_packet,
    get_network_info,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_discovery(registry: PeerRegistry | None = None) -> tuple[Discovery, "generate_keypair"]:
    keypair = generate_keypair()
    registry = registry or PeerRegistry()
    disc = Discovery(
        peer_id=keypair.device_id,
        name="tester",
        tcp_port=5656,
        registry=registry,
        public_key=keypair.public_key_bytes(),
    )
    return disc, keypair


def _valid_packet(device_id: str, public_key: bytes, **overrides) -> bytes:
    msg = {
        "type": "announce",
        "version": PROTOCOL_VERSION,
        "device_id": device_id,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "name": "peer-a",
        "tcp_port": 6000,
        "reply": False,
    }
    msg.update(overrides)
    return json.dumps(msg).encode("utf-8")


# ---------------------------------------------------------------------------
# Phase 5.1 tests (unchanged from original)
# ---------------------------------------------------------------------------

def test_build_payload_has_v2_fields():
    disc, keypair = _make_discovery()
    payload = json.loads(disc._build_payload(reply=False))

    assert payload["version"] == PROTOCOL_VERSION
    assert payload["device_id"] == keypair.device_id
    assert base64.b64decode(payload["public_key"]) == keypair.public_key_bytes()
    assert payload["tcp_port"] == 5656


def test_valid_self_consistent_packet_is_registered():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    packet = _valid_packet(peer_keypair.device_id, peer_keypair.public_key_bytes())
    disc._handle_packet(packet, ("10.0.0.5", 9999))

    peer = registry.get(peer_keypair.device_id)
    assert peer is not None
    assert peer.name == "peer-a"
    assert peer.tcp_port == 6000
    assert peer.public_key == peer_keypair.public_key_bytes()


def test_device_id_pubkey_mismatch_dropped_and_logged():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    real_keypair = generate_keypair()
    other_keypair = generate_keypair()

    # Claims real_keypair's device_id but ships other_keypair's public_key.
    packet = _valid_packet(real_keypair.device_id, other_keypair.public_key_bytes())

    with capture_security_events() as events:
        disc._handle_packet(packet, ("10.0.0.6", 9999))

    assert registry.get(real_keypair.device_id) is None
    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.AUTH_FAILED.value
    assert events[0].details["reason"] == "device_id_pubkey_mismatch"
    assert events[0].details["source_ip"] == "10.0.0.6"


@pytest.mark.parametrize("bad_public_key", [
    "not-valid-base64!!!",
    base64.b64encode(b"too-short").decode("ascii"),
    base64.b64encode(b"x" * 33).decode("ascii"),  # wrong length (not 32)
])
def test_malformed_public_key_dropped(bad_public_key):
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    msg = {
        "type": "announce",
        "version": PROTOCOL_VERSION,
        "device_id": peer_keypair.device_id,
        "public_key": bad_public_key,
        "name": "peer-a",
        "tcp_port": 6000,
        "reply": False,
    }
    packet = json.dumps(msg).encode("utf-8")
    with capture_security_events() as events:
        disc._handle_packet(packet, ("10.0.0.7", 9999))

    assert registry.get(peer_keypair.device_id) is None
    assert events == []  # malformed field, not a self-consistency failure


def test_missing_or_wrong_version_dropped_silently():
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    for overrides in ({"version": 1}, {}):
        packet = _valid_packet(peer_keypair.device_id, peer_keypair.public_key_bytes())
        msg = json.loads(packet)
        msg.pop("version", None)
        msg.update(overrides)
        packet = json.dumps(msg).encode("utf-8")

        with capture_security_events() as events:
            disc._handle_packet(packet, ("10.0.0.8", 9999))

        assert registry.get(peer_keypair.device_id) is None
        assert events == []


def test_own_broadcast_ignored():
    registry = PeerRegistry()
    disc, keypair = _make_discovery(registry)

    packet = _valid_packet(keypair.device_id, keypair.public_key_bytes())
    disc._handle_packet(packet, ("10.0.0.9", 9999))

    assert registry.get(keypair.device_id) is None


def test_bug_023_field_validation_still_holds():
    """Regression: name/tcp_port validation from BUG-023 must survive the
    Phase 5.1 changes (self-consistency check runs before these, but
    shouldn't short-circuit them for otherwise-valid packets)."""
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    bad_port_packet = _valid_packet(
        peer_keypair.device_id, peer_keypair.public_key_bytes(), tcp_port=-999,
    )
    disc._handle_packet(bad_port_packet, ("10.0.0.10", 9999))
    assert registry.get(peer_keypair.device_id) is None


# ---------------------------------------------------------------------------
# Phase 5.2 tests — mDNS helpers and integration
# ---------------------------------------------------------------------------

def test_mdns_available_is_bool():
    """MDNS_AVAILABLE must be a plain bool regardless of zeroconf install state."""
    assert isinstance(MDNS_AVAILABLE, bool)


def test_build_mdns_txt_shape():
    """_build_mdns_txt returns all expected keys with correct string types."""
    keypair = generate_keypair()
    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION,
        device_id=keypair.device_id,
        public_key=keypair.public_key_bytes(),
        name="test-device",
        tcp_port=5656,
    )
    assert txt["version"] == str(PROTOCOL_VERSION)
    assert txt["device_id"] == keypair.device_id
    assert base64.b64decode(txt["public_key"]) == keypair.public_key_bytes()
    assert txt["name"] == "test-device"
    assert txt["tcp_port"] == "5656"
    # All values must be str (zeroconf encodes them as UTF-8 in TXT records)
    for k, v in txt.items():
        assert isinstance(v, str), f"TXT value for {k!r} is {type(v)}, expected str"


def test_build_mdns_txt_name_capped_at_64():
    """Display name is truncated to 64 characters in TXT records."""
    keypair = generate_keypair()
    long_name = "A" * 100
    txt = _build_mdns_txt(PROTOCOL_VERSION, keypair.device_id,
                          keypair.public_key_bytes(), long_name, 5000)
    assert len(txt["name"]) == 64


def test_mdns_txt_to_packet_valid_accepted_by_handle_packet():
    """A valid mDNS TXT dict, converted by _mdns_txt_to_packet, is accepted
    by _handle_packet and registered — the shared validation path works."""
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION,
        device_id=peer_keypair.device_id,
        public_key=peer_keypair.public_key_bytes(),
        name="mdns-peer",
        tcp_port=7000,
    )
    src_ip = "192.168.1.50"
    packet = _mdns_txt_to_packet(txt, src_ip)
    disc._handle_packet(packet, (src_ip, BROADCAST_PORT))

    peer = registry.get(peer_keypair.device_id)
    assert peer is not None
    assert peer.name == "mdns-peer"
    assert peer.tcp_port == 7000
    assert peer.ip == src_ip


def test_mdns_txt_to_packet_mismatch_dropped_and_logged():
    """An mDNS TXT packet with mismatched device_id/public_key is rejected
    by _handle_packet with AUTH_FAILED — shared validation path."""
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    real_keypair = generate_keypair()
    other_keypair = generate_keypair()

    # Lie: use real_keypair's device_id but other_keypair's public key
    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION,
        device_id=real_keypair.device_id,
        public_key=other_keypair.public_key_bytes(),
        name="evil-mdns-peer",
        tcp_port=7000,
    )
    src_ip = "192.168.1.99"
    packet = _mdns_txt_to_packet(txt, src_ip)

    with capture_security_events() as events:
        disc._handle_packet(packet, (src_ip, BROADCAST_PORT))

    assert registry.get(real_keypair.device_id) is None
    assert len(events) == 1
    assert events[0].event_type == SecurityEventType.AUTH_FAILED.value
    assert events[0].details["reason"] == "device_id_pubkey_mismatch"


def test_mdns_txt_to_packet_wrong_version_dropped_silently():
    """An mDNS TXT packet with a wrong/missing version is dropped silently
    (not an attack — version mismatch), no SecurityEvent emitted."""
    registry = PeerRegistry()
    disc, _ = _make_discovery(registry)
    peer_keypair = generate_keypair()

    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION,
        device_id=peer_keypair.device_id,
        public_key=peer_keypair.public_key_bytes(),
        name="old-mdns-peer",
        tcp_port=7001,
    )
    txt["version"] = "1"  # wrong version
    src_ip = "192.168.1.51"
    packet = _mdns_txt_to_packet(txt, src_ip)

    with capture_security_events() as events:
        disc._handle_packet(packet, (src_ip, BROADCAST_PORT))

    assert registry.get(peer_keypair.device_id) is None
    assert events == []


def test_mdns_txt_to_packet_reply_is_false():
    """mDNS packets must have reply=False so _handle_packet never sends a
    UDP unicast reply back (mDNS already handles bidirectional discovery)."""
    keypair = generate_keypair()
    txt = _build_mdns_txt(PROTOCOL_VERSION, keypair.device_id,
                          keypair.public_key_bytes(), "peer", 5000)
    packet = _mdns_txt_to_packet(txt, "10.0.0.1")
    msg = json.loads(packet)
    assert msg["reply"] is False


def test_get_network_info_includes_mdns_available():
    """get_network_info() must expose mdns_available so callers (e.g. /info
    command in ui.py) can report mDNS status to the user."""
    info = get_network_info()
    assert "mdns_available" in info
    assert isinstance(info["mdns_available"], bool)
    assert info["mdns_available"] == MDNS_AVAILABLE


@pytest.mark.asyncio
async def test_discovery_run_includes_mdns_task_only_when_available():
    """Discovery.run() adds _mdns_loop to the gather task list if and only if
    MDNS_AVAILABLE is True.  Tested by monkeypatching gather and checking
    which coroutines were passed — no real sockets needed.
    """
    registry = PeerRegistry()
    keypair = generate_keypair()
    disc = Discovery(
        peer_id=keypair.device_id,
        name="test",
        tcp_port=5001,
        registry=registry,
        public_key=keypair.public_key_bytes(),
    )

    gathered_tasks: list = []

    async def fake_gather(*coros):
        gathered_tasks.extend(coros)
        # Cancel all so they don't actually run
        for c in coros:
            c.close()

    with patch("discovery.asyncio.gather", side_effect=fake_gather):
        with patch("discovery.MDNS_AVAILABLE", True):
            try:
                await disc.run()
            except Exception:
                pass

    # With mDNS available: 4 tasks (announce, listen, prune, mdns)
    assert len(gathered_tasks) == 4

    gathered_tasks.clear()

    with patch("discovery.asyncio.gather", side_effect=fake_gather):
        with patch("discovery.MDNS_AVAILABLE", False):
            try:
                await disc.run()
            except Exception:
                pass

    # Without mDNS: 3 tasks (announce, listen, prune)
    assert len(gathered_tasks) == 3


# ---------------------------------------------------------------------------
# Phase 3.4: self-reported device "model" string — display-only, threaded
# through both discovery transports the same way "name" already is.
# ---------------------------------------------------------------------------

def test_build_payload_includes_model():
    keypair = generate_keypair()
    registry = PeerRegistry()
    disc = Discovery(
        peer_id=keypair.device_id, name="tester", tcp_port=5656, registry=registry,
        public_key=keypair.public_key_bytes(), model="Linux (x86_64)",
    )
    payload = json.loads(disc._build_payload(reply=False))
    assert payload["model"] == "Linux (x86_64)"


def test_build_payload_model_defaults_to_empty_string():
    disc, _ = _make_discovery()  # no model= passed
    payload = json.loads(disc._build_payload(reply=False))
    assert payload["model"] == ""


def test_handle_packet_stores_model_on_registry():
    registry = PeerRegistry()
    keypair = generate_keypair()
    disc = Discovery(peer_id="self-id", name="self", tcp_port=5656, registry=registry)
    packet = _valid_packet(keypair.device_id, keypair.public_key_bytes(), model="Pixel 7")

    disc._handle_packet(packet, ("10.0.0.5", BROADCAST_PORT))

    peer = registry.get(keypair.device_id)
    assert peer is not None
    assert peer.model == "Pixel 7"


def test_handle_packet_missing_model_defaults_to_empty_string():
    """Legacy peers (pre-Phase-3.4) that never send a model field must
    still be accepted — model just stays empty, same as name/public_key
    handled legacy peers before."""
    registry = PeerRegistry()
    keypair = generate_keypair()
    disc = Discovery(peer_id="self-id", name="self", tcp_port=5656, registry=registry)
    msg = {
        "type": "announce",
        "version": PROTOCOL_VERSION,
        "device_id": keypair.device_id,
        "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
        "name": "legacy-peer",
        "tcp_port": 6000,
        "reply": False,
        # no "model" key at all
    }
    packet = json.dumps(msg).encode("utf-8")

    disc._handle_packet(packet, ("10.0.0.6", BROADCAST_PORT))

    peer = registry.get(keypair.device_id)
    assert peer is not None
    assert peer.model == ""


def test_handle_packet_non_string_model_dropped_to_empty_string():
    """A malformed/spoofed model field (wrong type) must not crash
    validation — same defensive handling as tcp_port/name."""
    registry = PeerRegistry()
    keypair = generate_keypair()
    disc = Discovery(peer_id="self-id", name="self", tcp_port=5656, registry=registry)
    packet = _valid_packet(keypair.device_id, keypair.public_key_bytes(), model=12345)

    disc._handle_packet(packet, ("10.0.0.7", BROADCAST_PORT))

    peer = registry.get(keypair.device_id)
    assert peer is not None
    assert peer.model == ""


def test_peer_registry_upsert_updates_model_without_clearing_it():
    """Same rule public_key already follows: an update announce with no
    (or empty) model must not blank out a previously-known one."""
    registry = PeerRegistry()
    registry.upsert("dev-1", "Alice", "10.0.0.1", 5656, model="MacBook Air M2")
    assert registry.get("dev-1").model == "MacBook Air M2"

    registry.upsert("dev-1", "Alice", "10.0.0.1", 5656)  # no model= this time
    assert registry.get("dev-1").model == "MacBook Air M2"

    registry.upsert("dev-1", "Alice", "10.0.0.1", 5656, model="MacBook Pro M3")
    assert registry.get("dev-1").model == "MacBook Pro M3"


def test_build_mdns_txt_includes_model():
    keypair = generate_keypair()
    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION, device_id=keypair.device_id,
        public_key=keypair.public_key_bytes(), name="test-device", tcp_port=5656,
        model="WSL Linux (x86_64)",
    )
    assert txt["model"] == "WSL Linux (x86_64)"
    assert isinstance(txt["model"], str)


def test_build_mdns_txt_model_capped_at_64():
    keypair = generate_keypair()
    long_model = "M" * 100
    txt = _build_mdns_txt(PROTOCOL_VERSION, keypair.device_id,
                          keypair.public_key_bytes(), "name", 5656, model=long_model)
    assert len(txt["model"]) == 64


def test_mdns_txt_to_packet_roundtrips_model():
    keypair = generate_keypair()
    txt = _build_mdns_txt(
        version=PROTOCOL_VERSION, device_id=keypair.device_id,
        public_key=keypair.public_key_bytes(), name="test-device", tcp_port=5656,
        model="Android (Termux)",
    )
    packet = json.loads(_mdns_txt_to_packet(txt, "10.0.0.9"))
    assert packet["model"] == "Android (Termux)"
