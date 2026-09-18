"""core/connectivity/locator.py — Phase 44.1: Locator (IP/port tracking),
deliberately separate from identity.

See docs/INTERNET_CONNECTIVITY_DESIGN.md §1-3: identity (device_id,
Phase 3) and locator (where a device currently is on the network) are
two different things that must never be conflated. A device keeps its
device_id forever (barring key rotation, Phase 40); its locator changes
constantly — new Wi-Fi, new DHCP lease, switching from LAN to a mobile
hotspot, a VPN interface coming up. One device can have several
endpoints at once (§3's example: a LAN IP, a VPN IP, an IPv6 address,
and a public IP, all for the same device_id).

This module is pure data — no storage (core/connectivity/store.py,
LocatorStore, mirrors TrustStore/GroupStore's shared vault-connection
pattern), no signing (core/connectivity/endpoint_update.py, a later
44.2 sub-step), no network I/O.

Not to be confused with discovery.py's Peer/PeerRegistry: that's an
in-memory, this-session-only cache of LAN broadcast/mDNS sightings,
pruned on a short timeout (PEER_TIMEOUT) and never persisted. Locator
is the opposite — a persisted, cross-session record of how to reach a
device over the Internet, updated by a signed Endpoint Update (44.2)
rather than re-discovered fresh every run.
"""

import time
from dataclasses import dataclass, field
from typing import List

# Endpoint kinds (§3a Link Format's tagging scheme, reused here).
KIND_DIRECT_V4 = "direct-v4"
KIND_DIRECT_V6 = "direct-v6"
KIND_RENDEZVOUS = "rendezvous"

VALID_KINDS = frozenset({KIND_DIRECT_V4, KIND_DIRECT_V6, KIND_RENDEZVOUS})

# How long an endpoint can go without a fresh sighting/update before
# it's considered stale enough to prune (LocatorStore.prune_stale()).
# Generous on purpose — Internet endpoints legitimately go quiet for
# days between sessions; this is not discovery.py's PEER_TIMEOUT.
DEFAULT_STALE_SECONDS = 30 * 24 * 3600  # 30 days


class LocatorError(Exception):
    """Raised for invalid Locator/Endpoint construction."""


@dataclass
class Endpoint:
    """One way to reach a device: an (kind, host, port) triple plus
    when it was last confirmed current.

    kind is one of KIND_DIRECT_V4/KIND_DIRECT_V6/KIND_RENDEZVOUS — see
    §3a Link Format, whose tagging scheme this reuses. "direct" is
    tried before "rendezvous" per §11's Try Direct → Relay pattern,
    applied here to endpoint resolution (see
    Locator.sorted_endpoints()).
    """

    device_id: str
    kind: str
    host: str
    port: int
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.kind not in VALID_KINDS:
            raise LocatorError(f"invalid endpoint kind {self.kind!r}, must be one of {sorted(VALID_KINDS)}")
        if not self.host:
            raise LocatorError("host is required")
        if not (0 < self.port <= 65535):
            raise LocatorError(f"invalid port {self.port!r}")

    def is_stale(self, max_age_seconds: float = DEFAULT_STALE_SECONDS) -> bool:
        return (time.time() - self.updated_at) > max_age_seconds


@dataclass
class Locator:
    """All currently-known endpoints for one device_id.

    Purely a convenience grouping for callers that want "give me
    everything I know about how to reach device X" in one call —
    LocatorStore (44.1) is the actual source of truth; this dataclass
    just shapes what a read from it looks like.
    """

    device_id: str
    endpoints: List[Endpoint] = field(default_factory=list)

    def sorted_endpoints(self) -> List[Endpoint]:
        """Direct endpoints first (freshest first), rendezvous last —
        §3a/§11's "try direct, fall back to rendezvous" order."""
        direct = sorted(
            (e for e in self.endpoints if e.kind in (KIND_DIRECT_V4, KIND_DIRECT_V6)),
            key=lambda e: e.updated_at,
            reverse=True,
        )
        rendezvous = sorted(
            (e for e in self.endpoints if e.kind == KIND_RENDEZVOUS),
            key=lambda e: e.updated_at,
            reverse=True,
        )
        return direct + rendezvous
