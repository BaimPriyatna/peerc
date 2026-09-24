"""core/connectivity/relay.py — Phase 46.2: R-side authorization logic
for relay_request.

See docs/ROADMAP.md's "Phase 46 design (resolved)" and
docs/INTERNET_CONNECTIVITY_DESIGN.md §11.

Design summary
--------------
A device that is an active member of a Group AND has turned relay mode
on for that group (Phase 46.4's `/group relay <id> on|off` — separate
toggle from Rendezvous, since relaying carries live bandwidth traffic)
may bridge a connection between two other group-mates it's already
connected to.

One wire message drives the request side:

  relay_request(group_id, target_device_id)
    Sent by A to a group-mate R it believes is in Relay mode. R checks:
    - relay mode is on for group_id on this device,
    - the sender (A) is an active member of group_id,
    - R is already connected to target_device_id — R never searches for
      B itself.
    If all hold, R opens the pipe (Phase 46.1's
    ConnectionManager.open_relay_pipe()) and replies
    relay_response(accepted=True). A may then open a relay tunnel
    through this same session (open_relay_tunnel()) and run the normal
    Phase 6 handshake with B over it (Phase 46.3) — R has no further
    role beyond blind forwarding from here.

Authorization shape mirrors core/connectivity/rendezvous.py closely,
with one deliberate difference in what gets a reply: not-hosting and
not-a-member stay fully silent (no relay_response at all), same posture
as _on_rendezvous_lookup's auth-failure gate in ui.py — but "not
currently connected to the target" is NOT a security-sensitive fact
once the first two checks pass, so that case gets an explicit
relay_response(accepted=False), mirroring rendezvous_lookup_response's
endpoint_update=None for a legitimate-but-empty answer. This matters
for Phase 46.3: a fast explicit "no" lets A move on to the next
Relay-mode candidate immediately instead of waiting out a timeout for
what may be the ordinary case of R simply not being connected to B
right now.

This module is pure data + authorization logic — no network I/O, no
knowledge of "is R connected to the target" beyond what the caller
tells it (that's peer.ConnectionManager's job). ui.py owns the actual
send/receive wiring, same division as rendezvous.py.
"""

from __future__ import annotations

from core.group.store import GroupStore, MembershipStatus


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RelayError(Exception):
    """Raised when a relay_request is refused."""


class RelayNotHostingError(RelayError):
    """Relay mode is not turned on for this group on this device.

    Caller should stay silent — same posture as rendezvous's
    not-hosting gate (don't confirm/deny understanding the protocol to
    a peer who hasn't been let in).
    """


class RelayAuthError(RelayError):
    """Requester is not an active member of the group.

    Caller should stay silent — same posture as every other group_*
    authorization failure.
    """


class RelayTargetUnreachableError(RelayError):
    """Authorization passed, but this device is not currently connected
    to the requested target.

    Caller SHOULD reply relay_response(accepted=False) — this is the
    ordinary "legitimate query, negative answer" case, not a security
    refusal; see this module's docstring.
    """


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


def authorize_relay_request(
    *,
    group_id: str,
    requester_device_id: str,
    relay_active_groups: set,
    group_store: GroupStore,
    is_target_connected: bool,
) -> None:
    """Raise a RelayError subclass if bridging this relay_request would
    not be authorized right now. Returns None (silently) if it's fine
    for the caller to go ahead and open the pipe.

    Checks in order, so the caller can distinguish "stay silent" from
    "send an explicit accepted=False" (see this module's docstring):
      1. RelayNotHostingError      — relay mode is off for group_id here
      2. RelayAuthError            — requester isn't an active member
      3. RelayTargetUnreachableError — not connected to the target right now
    """
    if group_id not in relay_active_groups:
        raise RelayNotHostingError(
            f"relay_request: relay mode is not on for group {group_id!r}"
        )

    status = group_store.get_membership_status(group_id, requester_device_id)
    if status is None or status != MembershipStatus.ACTIVE:
        raise RelayAuthError(
            f"relay_request: requester {requester_device_id!r} is not an "
            f"active member of group {group_id!r}"
        )

    if not is_target_connected:
        raise RelayTargetUnreachableError(
            "relay_request: not currently connected to the requested target"
        )


def authorize_relay_candidate_query(
    *,
    group_id: str,
    requester_device_id: str,
    relay_active_groups: set,
    group_store: GroupStore,
) -> None:
    """Raise a RelayError subclass if replying to this relay_candidate_query
    would not be authorized right now. Returns None (silently) if this device
    is currently in relay mode for the group and the requester is an active member.

    Checks in order:
      1. RelayNotHostingError — relay mode is off for group_id here
      2. RelayAuthError       — requester isn't an active member
    """
    if group_id not in relay_active_groups:
        raise RelayNotHostingError(
            f"relay_candidate_query: relay mode is not on for group {group_id!r}"
        )

    status = group_store.get_membership_status(group_id, requester_device_id)
    if status is None or status != MembershipStatus.ACTIVE:
        raise RelayAuthError(
            f"relay_candidate_query: requester {requester_device_id!r} is not an "
            f"active member of group {group_id!r}"
        )

