"""core/discovery/registry.py — the live list of discovered peers.

Owns Peer and PeerRegistry. Peers are keyed by peer_id (a device_id derived
from an Ed25519 key), never by IP, and are evicted once they have not
announced for PEER_TIMEOUT seconds (handles DHCP IP changes and peers going
offline). Transport-agnostic: both UDP broadcast and mDNS feed this registry.
"""

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

PEER_TIMEOUT = 10.0       # seconds of silence before a peer is considered offline


@dataclass
class Peer:
    peer_id: str
    name: str
    ip: str
    tcp_port: int
    public_key: bytes = b""  # raw Ed25519 public key bytes (Phase 5.1); empty for legacy/unset
    model: str = ""  # self-reported device/platform string (core/device_info.py); "" for legacy/unset, display-only
    last_seen: float = field(default_factory=time.time)


class PeerRegistry:
    """Thread/async-safe-enough store of currently known peers.

    Keyed by peer_id (NOT ip), since IP can change under DHCP or when
    switching between LAN and hotspot.
    """

    def __init__(self, on_peer_new: Optional[Callable[[Peer], None]] = None,
                 on_peer_lost: Optional[Callable[[Peer], None]] = None):
        self._peers: dict[str, Peer] = {}
        self._on_peer_new = on_peer_new
        self._on_peer_lost = on_peer_lost

    def upsert(self, peer_id: str, name: str, ip: str, tcp_port: int,
               public_key: bytes = b"", model: str = "") -> None:
        existing = self._peers.get(peer_id)
        now = time.time()
        if existing is None:
            self._peers[peer_id] = Peer(peer_id, name, ip, tcp_port, public_key, model, now)
            if self._on_peer_new:
                self._on_peer_new(self._peers[peer_id])
        else:
            # Update in place — IP/port may have changed (DHCP renew, network switch)
            existing.name = name
            existing.ip = ip
            existing.tcp_port = tcp_port
            if public_key:
                existing.public_key = public_key
            if model:
                existing.model = model
            existing.last_seen = now

    def prune_stale(self) -> None:
        now = time.time()
        stale_ids = [
            pid for pid, p in self._peers.items()
            if now - p.last_seen > PEER_TIMEOUT
        ]
        for pid in stale_ids:
            peer = self._peers.pop(pid)
            if self._on_peer_lost:
                self._on_peer_lost(peer)

    def list_peers(self) -> list[Peer]:
        return list(self._peers.values())

    def get(self, peer_id: str) -> Optional[Peer]:
        return self._peers.get(peer_id)
