"""core/discovery/constants.py — wire constants shared by every discovery transport.

BROADCAST_PORT and PROTOCOL_VERSION are needed by both the UDP broadcast path
(broadcast.py) and the optional mDNS adapter (mdns.py). broadcast.py depends
on mdns.py, so defining them in either of those two would create an import
cycle; they live here, below both.
"""

BROADCAST_PORT = 9999
PROTOCOL_VERSION = 2      # Phase 5.1: discovery payload schema version
