"""core/group/membership.py — Phase 42.1: Group Authority System, membership certs.

See docs/GROUP_AUTHORITY_DESIGN.md §3/§4. An admin is just a device whose
public key is additionally recorded as a group's authority — same
core/identity/ Ed25519 machinery from Phase 3, not a separate key type.

A Membership Certificate is the admin's signed proof that a device
belongs to a group with a given role/permissions, valid until an optional
expiry. Any peer that already trusts the group's admin public key can
verify a certificate offline — it doesn't need to ask the admin.

This module is pure crypto/data — no storage, no policy enforcement, no
network I/O. Storage is core/group/store.py (GroupStore). Policy
enforcement (external trust restriction, communication policy, etc.) is
core/group/policy.py, a later sub-step.
"""

import base64
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.exceptions import InvalidSignature

from core.identity.device_identity import DeviceKeypair, public_key_from_bytes
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

# Domain-separation prefix — ensures a membership-certificate signature
# cannot be replayed as any other kind of peerc signature (mirrors
# core/identity/rotation.py's _ROTATION_DOMAIN).
_MEMBERSHIP_DOMAIN = b"peerc-group-membership\x00"

DEFAULT_ROLE = "member"


class MembershipError(Exception):
    """Raised when issuing a membership certificate fails."""


@dataclass
class Group:
    """A group's identity: who its admin is, nothing about its members.

    Membership itself lives in MembershipCertificate rows (GroupStore),
    not here — a Group record is just the trust anchor (admin_public_key)
    that certificates are verified against.
    """

    group_id: str
    name: str
    admin_device_id: str
    admin_public_key: str  # base64(raw 32 bytes)
    created_at: float


def create_group(admin_keypair: DeviceKeypair, name: str, group_id: Optional[str] = None) -> Group:
    """Create a new group with *admin_keypair*'s device as its sole admin.

    Multi-admin (additional admins, k-of-n threshold signatures) is
    core/group/admin.py, a later sub-step — a fresh group always starts
    with exactly one admin.
    """
    return Group(
        group_id=group_id or str(uuid.uuid4()),
        name=name,
        admin_device_id=admin_keypair.device_id,
        admin_public_key=base64.b64encode(admin_keypair.public_key_bytes()).decode("ascii"),
        created_at=time.time(),
    )


@dataclass
class MembershipCertificate:
    """Cryptographic proof that a device belongs to a group.

    The signature covers a canonical payload (see _build_payload) that
    binds device_id, device_public_key, group_id, role, permissions,
    issued_at, expires_at, and admin_device_id together under the
    domain-separation prefix. All key fields are base64-encoded raw
    Ed25519 public key bytes, matching the project-wide convention.

    admin_public_key is deliberately NOT part of the signed payload or a
    field here — verification takes the admin's public key as a separate
    argument (the verifier's own trust anchor for that group, e.g. from a
    stored Group record), the same way a certificate never gets to vouch
    for which key it was signed by.
    """

    device_id: str
    device_public_key: str  # base64(raw 32 bytes)
    group_id: str
    role: str
    permissions: List[str] = field(default_factory=list)
    issued_at: float = 0.0
    expires_at: Optional[float] = None  # None = never expires
    admin_device_id: str = ""
    signature: str = ""  # base64(64-byte Ed25519 signature by admin key)
    status: str = "active"

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "device_public_key": self.device_public_key,
            "group_id": self.group_id,
            "role": self.role,
            "permissions": list(self.permissions),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "admin_device_id": self.admin_device_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MembershipCertificate":
        return cls(
            device_id=data["device_id"],
            device_public_key=data["device_public_key"],
            group_id=data["group_id"],
            role=data["role"],
            permissions=list(data.get("permissions", [])),
            issued_at=float(data["issued_at"]),
            expires_at=data.get("expires_at"),
            admin_device_id=data["admin_device_id"],
            signature=data.get("signature", ""),
            status=data.get("status", "active"),
        )


def issue_membership_certificate(
    admin_keypair: DeviceKeypair,
    *,
    device_id: str,
    device_public_key: bytes,
    group_id: str,
    role: str = DEFAULT_ROLE,
    permissions: Optional[List[str]] = None,
    ttl_seconds: Optional[float] = None,
) -> MembershipCertificate:
    """Sign a membership certificate for *device_id* in *group_id*.

    ttl_seconds=None means the certificate never expires (until revoked —
    revocation is GroupStore's concern, a status flag on the stored row,
    not something this offline-verifiable certificate can express).
    """
    if not device_id or not group_id:
        raise MembershipError("device_id and group_id are required")

    permissions = list(permissions or [])
    device_pub_b64 = base64.b64encode(device_public_key).decode("ascii")
    issued_at = time.time()
    expires_at = (issued_at + ttl_seconds) if ttl_seconds is not None else None

    payload = _build_payload(
        device_id=device_id,
        device_public_key_b64=device_pub_b64,
        group_id=group_id,
        role=role,
        permissions=permissions,
        issued_at=issued_at,
        expires_at=expires_at,
        admin_device_id=admin_keypair.device_id,
    )
    sig_bytes = admin_keypair.sign(payload)

    return MembershipCertificate(
        device_id=device_id,
        device_public_key=device_pub_b64,
        group_id=group_id,
        role=role,
        permissions=permissions,
        issued_at=issued_at,
        expires_at=expires_at,
        admin_device_id=admin_keypair.device_id,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )


def verify_membership_certificate(cert: MembershipCertificate, admin_public_key: bytes) -> bool:
    """Verify *cert* was signed by the private key matching *admin_public_key*.

    Purely cryptographic — does NOT check expiry (see is_membership_expired)
    or revocation status (GroupStore's concern). Returns True on a valid
    signature, False on any cryptographic failure or malformed data.
    Raises nothing — callers can treat False as "untrusted".
    """
    try:
        admin_pub_key = public_key_from_bytes(admin_public_key)
        sig_bytes = base64.b64decode(cert.signature)

        payload = _build_payload(
            device_id=cert.device_id,
            device_public_key_b64=cert.device_public_key,
            group_id=cert.group_id,
            role=cert.role,
            permissions=cert.permissions,
            issued_at=cert.issued_at,
            expires_at=cert.expires_at,
            admin_device_id=cert.admin_device_id,
        )
        admin_pub_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, Exception) as e:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.INVALID_AUTHORITY_CHAIN,
                severity=SecuritySeverity.CRITICAL,
                description=f"membership certificate verification failed for device {getattr(cert, 'device_id', 'unknown')} in group {getattr(cert, 'group_id', 'unknown')}: {e}",
                device_id=getattr(cert, "device_id", None),
            )
        )
        return False


def is_membership_expired(cert: MembershipCertificate) -> bool:
    """True if cert.expires_at is set and in the past. Never-expiring
    certificates (expires_at=None) are never expired."""
    return cert.expires_at is not None and time.time() > cert.expires_at


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_payload(
    *,
    device_id: str,
    device_public_key_b64: str,
    group_id: str,
    role: str,
    permissions: List[str],
    issued_at: float,
    expires_at: Optional[float],
    admin_device_id: str,
) -> bytes:
    """Canonical payload signed/verified for a membership certificate.

    Permissions are sorted before joining so the same permission set
    always produces the same bytes regardless of list order. expires_at
    uses -1.0 as the "never expires" sentinel when packing (issued_at is
    always a real Unix timestamp, so -1.0 can never collide with a real
    expiry).
    """
    permissions_str = ",".join(sorted(permissions))
    expires_marker = expires_at if expires_at is not None else -1.0
    return (
        _MEMBERSHIP_DOMAIN
        + device_id.encode("utf-8")
        + b"\x00"
        + device_public_key_b64.encode("utf-8")
        + b"\x00"
        + group_id.encode("utf-8")
        + b"\x00"
        + role.encode("utf-8")
        + b"\x00"
        + permissions_str.encode("utf-8")
        + b"\x00"
        + admin_device_id.encode("utf-8")
        + b"\x00"
        + struct.pack(">d", issued_at)
        + struct.pack(">d", expires_marker)
    )
