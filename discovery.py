"""discovery.py — backward-compatible shim over core.discovery (Phase 38).

Peer discovery now lives in the core/discovery/ package:

    registry.py        Peer, PeerRegistry, PEER_TIMEOUT
    broadcast.py       Discovery (UDP broadcast + packet validation),
                       get_broadcast_targets, get_network_info
    mdns.py            optional zeroconf adapter (MDNSDiscovery, MDNS_AVAILABLE)
    identity_loader.py save_identity, load_or_create_identity
    constants.py       BROADCAST_PORT, PROTOCOL_VERSION

This module only re-exports those names so legacy `import discovery` /
`from discovery import ...` call sites keep working; the objects are
identical to the canonical ones. It carries no logic and no import-time side
effects. New code should import from core.discovery.* directly.

Caveat for callers that patch module attributes: rebinding a name on this
shim (e.g. monkeypatch.setattr(discovery, "MDNS_AVAILABLE", ...)) does not
reach the canonical modules that actually read it. Patch the canonical
module instead (e.g. core.discovery.broadcast.MDNS_AVAILABLE).

The three underscore names at the bottom are private; they are re-exported
only because existing tests import them, and go away with the test migration.
"""

from core.discovery.broadcast import (
    ANNOUNCE_INTERVAL,
    Discovery,
    get_broadcast_targets,
    get_network_info,
)
from core.discovery.constants import BROADCAST_PORT, PROTOCOL_VERSION
from core.discovery.identity_loader import load_or_create_identity, save_identity
from core.discovery.mdns import (
    MDNS_ANNOUNCE_INTERVAL,
    MDNS_AVAILABLE,
    MDNS_SERVICE_TYPE,
    MDNSDiscovery,
    _build_mdns_txt,
    _log,
    _mdns_txt_to_packet,
)
from core.discovery.registry import PEER_TIMEOUT, Peer, PeerRegistry

__all__ = [
    "ANNOUNCE_INTERVAL",
    "BROADCAST_PORT",
    "Discovery",
    "MDNSDiscovery",
    "MDNS_ANNOUNCE_INTERVAL",
    "MDNS_AVAILABLE",
    "MDNS_SERVICE_TYPE",
    "PEER_TIMEOUT",
    "PROTOCOL_VERSION",
    "Peer",
    "PeerRegistry",
    "get_broadcast_targets",
    "get_network_info",
    "load_or_create_identity",
    "save_identity",
]
