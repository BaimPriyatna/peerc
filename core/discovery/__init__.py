"""core.discovery — peer discovery (Phase 38).

Will own PeerRegistry, UDP broadcast, optional mDNS, and legacy identity
loading. Populated by the Phase 38 discovery split; until then the
implementation still lives in the root discovery.py.
"""
