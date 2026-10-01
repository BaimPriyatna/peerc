"""core/connectivity/rendezvous.py — Phase 45.2: RendezvousCache + the
three Rendezvous wire-message handlers.

See docs/ROADMAP.md "Phase 45 design (resolved)" and
docs/INTERNET_CONNECTIVITY_DESIGN.md §9/§10.

Design summary
--------------
Any device that is an active member of a Group (Phase 42) may act as a
"Rendezvous host" for that group. While in rendezvous mode it relays
already-signed EndpointUpdates (Phase 44.2) between group members who
are NOT currently connected to each other directly.

Three wire messages drive the protocol:

1. rendezvous_register(group_id, endpoint_update)
   Sent by a device that wants its current endpoint cached so other
   group-mates can look it up later.  The host verifies:
   - the sender is an active member of group_id (GroupStore check),
   - the EndpointUpdate's embedded device_id matches the sending peer's
     authenticated device_id (from the live handshake — never the
     self-reported field in the message),
   - the EndpointUpdate's own Ed25519 signature verifies (via
     verify_endpoint_update()).
   On success the host stores the blob in its in-memory RendezvousCache.

2. rendezvous_lookup(group_id, target_device_id)
   Sent by a device that wants to know the current endpoint of another
   group member.  The host verifies:
   - the requester is an active member of group_id,
   - the target is an active member of group_id.
   Responds with rendezvous_lookup_response carrying the cached
   EndpointUpdate if present, or empty if not.

3. rendezvous_lookup_response(endpoint_update | None)
   The host's reply to a lookup.  If an EndpointUpdate was found, the
   requester re-verifies it using the target's public key from the
   group MembershipCertificate — the host is a mail carrier, never a
   vouched-for party.

Freshness is inherited for free: EndpointUpdate's own ±300s window (Phase
44.2) means a stale cached blob fails the requester's own
verify_endpoint_update() call even if the host kept it too long.

Authorization shape
-------------------
The host checks ONLY that both parties hold an active, non-revoked
MembershipCertificate for group_id — same authorization shape as every
other group_* message.  The host never inspects private keys and never
generates its own signatures.

In-memory only
--------------
RendezvousCache is never persisted to the vault.  A restart clears the
cache; a relayed device re-registers once it reconnects to a host.  This
matches the design doc's "Rendezvous bukan data server" explicitly.

This module is pure data + authorization logic — no network I/O.
Callers (app/ui/app.py, wired in 45.3) own the actual send/receive wiring.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from core.connectivity.endpoint_update import EndpointUpdate, verify_endpoint_update
from core.crypto.handshake import NonceCache
from core.group.store import GroupStore, MembershipStatus


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RendezvousError(Exception):
    """Raised when a rendezvous operation is refused."""


class RendezvousAuthError(RendezvousError):
    """Sender or target is not an active member of the requested group."""


class RendezvousSignatureError(RendezvousError):
    """EndpointUpdate signature verification failed at the host."""


class RendezvousDeviceIdMismatchError(RendezvousError):
    """EndpointUpdate.device_id does not match the authenticated sender."""


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------


@dataclass
class _CacheEntry:
    """One cached EndpointUpdate blob for one (group_id, device_id) pair."""

    group_id: str
    device_id: str
    update: EndpointUpdate
    cached_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# RendezvousCache
# ---------------------------------------------------------------------------


class RendezvousCache:
    """In-memory cache of EndpointUpdates for active rendezvous hosts.

    Indexed by (group_id, device_id).  Thread-safety is NOT provided here
    — callers in asyncio land run everything on the event loop, so a plain
    dict is correct.

    The NonceCache supplied at construction is shared with the rest of the
    app (same instance endpoint_update_wire.py already uses in app/ui/app.py for
    incoming endpoint_update messages) — domain-separation in
    core.connectivity.endpoint_update ensures endpoint-update signatures
    can never collide with any other message type.
    """

    def __init__(self, nonce_cache: NonceCache) -> None:
        self._entries: Dict[Tuple[str, str], _CacheEntry] = {}
        self._nonce_cache = nonce_cache

    # ------------------------------------------------------------------
    # Host-side: register / evict
    # ------------------------------------------------------------------

    def register(
        self,
        *,
        group_id: str,
        authenticated_device_id: str,
        update: EndpointUpdate,
        sender_public_key: bytes,
        group_store: GroupStore,
    ) -> None:
        """Process a rendezvous_register request from an already-authenticated
        peer.

        *authenticated_device_id* MUST come from the live handshake
        (core.transport.manager.ConnectionManager.get_peer_device_id()), never from the
        message itself.

        Raises:
          RendezvousDeviceIdMismatchError — update.device_id != authenticated_device_id
          RendezvousAuthError             — sender is not an active member of group_id
          RendezvousSignatureError        — EndpointUpdate signature fails verification
        """
        # 1. device_id self-consistency: EndpointUpdate must advertise the
        #    same device the authenticated channel belongs to.
        if update.device_id != authenticated_device_id:
            raise RendezvousDeviceIdMismatchError(
                f"rendezvous_register: EndpointUpdate.device_id {update.device_id!r} "
                f"does not match authenticated sender {authenticated_device_id!r}"
            )

        # 2. Membership check: the sender must be an active member of the group.
        _require_active_member(group_store, group_id, authenticated_device_id, "sender")

        # 3. Verify the EndpointUpdate's own Ed25519 signature.
        if not verify_endpoint_update(update, sender_public_key, self._nonce_cache):
            raise RendezvousSignatureError(
                f"rendezvous_register: EndpointUpdate signature verification failed "
                f"for device {update.device_id!r} in group {group_id!r}"
            )

        # All checks passed — cache it.
        self._entries[(group_id, update.device_id)] = _CacheEntry(
            group_id=group_id,
            device_id=update.device_id,
            update=update,
        )

    def evict(self, group_id: str, device_id: str) -> None:
        """Remove a cached entry, e.g. when a member's session ends or they
        leave the group.  No-op if the entry doesn't exist."""
        self._entries.pop((group_id, device_id), None)

    def evict_all_for_group(self, group_id: str) -> int:
        """Remove all cached entries for *group_id* (e.g. when rendezvous
        mode is turned off for a group).  Returns the number of entries
        removed."""
        to_delete = [k for k in self._entries if k[0] == group_id]
        for k in to_delete:
            del self._entries[k]
        return len(to_delete)

    def size(self) -> int:
        """Total number of cached entries across all groups."""
        return len(self._entries)

    # ------------------------------------------------------------------
    # Host-side: lookup
    # ------------------------------------------------------------------

    def lookup(
        self,
        *,
        group_id: str,
        requester_device_id: str,
        target_device_id: str,
        group_store: GroupStore,
    ) -> Optional[EndpointUpdate]:
        """Process a rendezvous_lookup request from an already-authenticated
        peer.

        Returns the cached EndpointUpdate for (group_id, target_device_id)
        if it exists, or None if nothing is cached (the requester should
        treat None as "try later or connect via other means").

        Raises:
          RendezvousAuthError — requester or target is not an active member
        """
        # Both parties must be active members.
        _require_active_member(group_store, group_id, requester_device_id, "requester")
        _require_active_member(group_store, group_id, target_device_id, "target")

        entry = self._entries.get((group_id, target_device_id))
        return entry.update if entry is not None else None

    # ------------------------------------------------------------------
    # Introspection (testing / diagnostics)
    # ------------------------------------------------------------------

    def get_raw(self, group_id: str, device_id: str) -> Optional[_CacheEntry]:
        """Direct cache access for tests; not part of the public protocol API."""
        return self._entries.get((group_id, device_id))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_active_member(
    group_store: GroupStore,
    group_id: str,
    device_id: str,
    role_label: str,
) -> None:
    """Raise RendezvousAuthError unless *device_id* is an active member of
    *group_id* in *group_store*.

    *role_label* is only used in the error message ("sender" or "target").
    """
    status = group_store.get_membership_status(group_id, device_id)
    if status is None or status != MembershipStatus.ACTIVE:
        raise RendezvousAuthError(
            f"rendezvous: {role_label} device {device_id!r} is not an active member of group {group_id!r}"
        )
