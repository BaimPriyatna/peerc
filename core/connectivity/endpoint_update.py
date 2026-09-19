"""core/connectivity/endpoint_update.py — Phase 44.2: signed endpoint
announcement + verification.

See docs/INTERNET_CONNECTIVITY_DESIGN.md §4 "Endpoint Update". When a
device's IP/port changes, it signs an announcement with its existing
identity key (the SAME key — this is the trivial case where device_id
doesn't change at all, unlike Key Rotation/Phase 40, which is for when
the key itself changes). A peer that already trusts that device_id can
verify the signature and update its locator with no human involvement —
"Device A claims it's now at IP X" is never enough on its own, it must
be proven by Device A's identity key.

Reuses Phase 6's existing machinery rather than inventing new
primitives: Ed25519 signing (same as the handshake transcript) and
core.crypto.handshake.NonceCache for replay protection.

This module is pure crypto/data — no storage (LocatorStore, 44.1, is
the caller's job: verify here, then upsert_endpoint() there) and no
network I/O. The caller supplies the NonceCache instance (see
verify_endpoint_update's docstring) so this module stays storage- and
state-agnostic, same split as membership.py/admin.py.
"""

import base64
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from core.crypto.handshake import NonceCache
from core.identity.device_identity import DeviceKeypair, public_key_from_bytes
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

from .locator import VALID_KINDS, Endpoint

# Domain-separation prefix — ensures an endpoint-update signature can't
# be replayed as any other kind of peerc signature.
_ENDPOINT_UPDATE_DOMAIN = b"peerc-endpoint-update\x00"

# How far a timestamp may drift from "now" (either direction — clocks
# aren't perfectly synced) before an update is rejected as stale/
# not-yet-valid. Same order of magnitude as the handshake's own nonce
# TTL (core.crypto.handshake.NonceCache's default 300s).
DEFAULT_MAX_AGE_SECONDS = 300.0


class EndpointUpdateError(Exception):
    """Raised for invalid EndpointUpdate construction."""


@dataclass
class EndpointUpdate:
    """A device's signed claim "I am now reachable at host:port"."""

    device_id: str
    kind: str
    host: str
    port: int
    timestamp: float
    nonce: str
    signature: str = ""  # base64(64-byte Ed25519 signature)


def create_endpoint_update(keypair: DeviceKeypair, kind: str, host: str, port: int) -> EndpointUpdate:
    """Sign a fresh endpoint update from *keypair*'s device.

    Uses the device's own existing identity key — this is deliberately
    the SAME key used for everything else the device signs (handshakes,
    membership certs it might issue if it's a group admin, etc.); an
    endpoint change alone never touches identity (see the "Endpoint
    Update and Key Rotation" comparison in the design doc — this is the
    "locator changed, identity key unaffected" branch).
    """
    if kind not in VALID_KINDS:
        raise EndpointUpdateError(f"invalid endpoint kind {kind!r}, must be one of {sorted(VALID_KINDS)}")
    if not host:
        raise EndpointUpdateError("host is required")
    if not (0 < port <= 65535):
        raise EndpointUpdateError(f"invalid port {port!r}")

    timestamp = time.time()
    nonce = uuid.uuid4().hex
    payload = _update_payload(keypair.device_id, kind, host, port, timestamp, nonce)
    sig_bytes = keypair.sign(payload)
    return EndpointUpdate(
        device_id=keypair.device_id,
        kind=kind,
        host=host,
        port=port,
        timestamp=timestamp,
        nonce=nonce,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )


def verify_endpoint_update(
    update: EndpointUpdate,
    public_key: bytes,
    nonce_cache: NonceCache,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
) -> bool:
    """Verify *update* was validly signed by the device_id/public_key it
    claims, is fresh, and isn't a replay.

    *nonce_cache*: the caller's NonceCache instance — one per running
    app is normal (the same instance the handshake already uses would
    work fine too, since the domain-separation prefix keeps this
    module's payloads from ever colliding with a handshake's). This
    module never creates its own, so a restart naturally starts a fresh
    replay window rather than silently persisting (or losing) state
    nobody asked it to manage.

    Checks run signature FIRST, then freshness, then replay — an
    unsigned/forged update never gets to consume a nonce-cache slot or
    be judged on its timestamp at all. Returns False on any failure;
    raises nothing.
    """
    try:
        device_pub_key = public_key_from_bytes(public_key)
        payload = _update_payload(update.device_id, update.kind, update.host, update.port, update.timestamp, update.nonce)
        device_pub_key.verify(base64.b64decode(update.signature), payload)
    except Exception as e:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description=f"endpoint update signature invalid for device {update.device_id}: {e}",
                device_id=update.device_id,
            )
        )
        return False

    age = abs(time.time() - update.timestamp)
    if age > max_age_seconds:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_FAILED,
                severity=SecuritySeverity.WARNING,
                description=(
                    f"endpoint update from device {update.device_id} has a stale/future timestamp "
                    f"({age:.0f}s outside the {max_age_seconds:.0f}s window)"
                ),
                device_id=update.device_id,
            )
        )
        return False

    if not nonce_cache.check_and_add(update.nonce):
        emit(
            SecurityEvent(
                event_type=SecurityEventType.REPLAY_DETECTED,
                severity=SecuritySeverity.HIGH,
                description=f"endpoint update replay detected for device {update.device_id} (nonce reused)",
                device_id=update.device_id,
            )
        )
        return False

    return True


def endpoint_update_to_endpoint(update: EndpointUpdate) -> Endpoint:
    """Convert a verified EndpointUpdate into the Endpoint shape
    LocatorStore.upsert_endpoint() expects. Callers should only do this
    AFTER verify_endpoint_update() returns True — this function itself
    does no verification, it's just a shape conversion."""
    return Endpoint(
        device_id=update.device_id,
        kind=update.kind,
        host=update.host,
        port=update.port,
        updated_at=update.timestamp,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _update_payload(device_id: str, kind: str, host: str, port: int, timestamp: float, nonce: str) -> bytes:
    device_id_b = device_id.encode("utf-8")
    kind_b = kind.encode("utf-8")
    host_b = host.encode("utf-8")
    nonce_b = nonce.encode("utf-8")
    return (
        _ENDPOINT_UPDATE_DOMAIN
        + struct.pack(">I", len(device_id_b))
        + device_id_b
        + struct.pack(">I", len(kind_b))
        + kind_b
        + struct.pack(">I", len(host_b))
        + host_b
        + struct.pack(">I", port)
        + struct.pack(">d", timestamp)
        + struct.pack(">I", len(nonce_b))
        + nonce_b
    )
