"""core.discovery — peer discovery (Phase 38).

    registry.py         Peer and PeerRegistry — the live peer list
    broadcast.py        Discovery: UDP announce/send/receive, the single packet
                        validation path (_handle_packet), and composition of
                        the optional mDNS transport
    mdns.py             optional zeroconf adapter (MDNS_AVAILABLE gates it)
    identity_loader.py  legacy (peer_id, name) identity-loading adapters
    constants.py        wire constants shared by broadcast and mDNS

Import from the submodules directly. The root-level discovery.py is a
backward-compatible shim that re-exports this package's public names.
"""
