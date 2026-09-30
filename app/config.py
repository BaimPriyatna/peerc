"""app/config.py — application-only configuration (Phase 38).

The UI listen port and the presentation / orchestration timeouts that used
to sit at the top of the root ui.py. Protocol, handshake, transport, and
transfer limits deliberately stay next to their core owners; do not move
unrelated security constants here for convenience.
"""

UI_TCP_PORT = 5656
IP_CHANGE_CHECK_INTERVAL = 30  # seconds — Phase 45.1's own-IP-change poll
AUTO_LOCK_POLL_SECONDS = 1.0
# Phase 46.3: relay orchestration timeouts.
# Short direct-connect attempt before falling back to relay; then a brief
# window to collect relay_candidate_response replies (all peers reply
# near-simultaneously, so 0.5 s is more than enough on a LAN/VPN),
# and a per-candidate wait for relay_response.
RELAY_DIRECT_TIMEOUT = 3.0        # seconds — direct connect attempt before relay
RELAY_CANDIDATE_WINDOW = 0.5      # seconds — collect relay_candidate_response replies
RELAY_RESPONSE_TIMEOUT = 3.0      # seconds — wait for accepted/declined from one candidate
