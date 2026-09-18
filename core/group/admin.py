"""core/group/admin.py — Phase 42.3: multi-admin + k-of-n threshold signatures.

See docs/GROUP_AUTHORITY_DESIGN.md §14 "Multiple Administrators" and
docs/SECURITY_MODEL.md §22 "Multi-Admin Security".

Two things live here:

  1. AdminRecord — an admin is just a device whose public key is
     additionally recorded as one of a group's (possibly several)
     authorities, same as membership.py's Group/MembershipCertificate
     split: no new key type, storage lives in GroupStore.group_admins
     (store.py).

  2. ThresholdApproval — a generic k-of-n signature collector for any
     admin-gated action. Each admin who approves signs the same
     domain-separated payload with their own existing device key.
     is_approved()/count_valid_signatures() take the CURRENT active-admin
     set as an argument rather than looking it up themselves, so a
     signature from an admin who's since been removed silently stops
     counting toward the threshold without this module needing to know
     about storage at all (same storage-agnostic split as
     verify_membership_certificate() in membership.py).

Phase 42.3 builds only the primitive — Phase 43 (Group-Gated Export
Authorization) and future admin-only policy changes are its first real
callers.
"""

import base64
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from core.identity.device_identity import DeviceKeypair, public_key_from_bytes
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

# Domain-separation prefix — ensures a threshold-approval signature can't
# be replayed as any other kind of peerc signature.
_ADMIN_APPROVAL_DOMAIN = b"peerc-group-admin-approval\x00"


class AdminError(Exception):
    """Raised for admin-management or threshold-approval failures."""


@dataclass
class AdminRecord:
    """One device recorded as an administrator of a group.

    added_by is None only for the founding admin (the device that ran
    create_group()) — every subsequently-added admin must have been
    added by an already-active admin (GroupStore.add_admin() enforces
    this).
    """

    group_id: str
    device_id: str
    public_key: str  # base64(raw 32 bytes)
    added_at: float
    added_by: Optional[str] = None


@dataclass
class ThresholdApproval:
    """A k-of-n signature collection for one admin-gated action.

    action_id must be unique per real-world action (e.g. an export
    request id, a policy version bump) — signing binds group_id +
    action_id + action_payload together, so a signature can never be
    replayed onto a different action even if action_payload happens to
    match byte-for-byte.
    """

    group_id: str
    action_id: str
    action_payload: bytes
    required_threshold: int
    signatures: Dict[str, str] = field(default_factory=dict)  # device_id -> base64 signature
    created_at: float = field(default_factory=time.time)


def create_threshold_approval(
    group_id: str, action_id: str, action_payload: bytes, required_threshold: int
) -> ThresholdApproval:
    if required_threshold < 1:
        raise AdminError("required_threshold must be >= 1")
    if not group_id or not action_id:
        raise AdminError("group_id and action_id are required")
    return ThresholdApproval(
        group_id=group_id,
        action_id=action_id,
        action_payload=action_payload,
        required_threshold=required_threshold,
    )


def sign_approval(approval: ThresholdApproval, admin_keypair: DeviceKeypair) -> ThresholdApproval:
    """Add *admin_keypair*'s signature to *approval* in place (and return
    it, for chaining). Refuses (AdminError) a second signature from the
    same admin device — one vote per device, not per call."""
    if admin_keypair.device_id in approval.signatures:
        raise AdminError(
            f"device {admin_keypair.device_id!r} has already signed action {approval.action_id!r}"
        )
    payload = _approval_payload(approval.group_id, approval.action_id, approval.action_payload)
    sig_bytes = admin_keypair.sign(payload)
    approval.signatures[admin_keypair.device_id] = base64.b64encode(sig_bytes).decode("ascii")
    return approval


def verify_approval_signature(approval: ThresholdApproval, device_id: str, public_key: bytes) -> bool:
    """Verify one admin's signature on *approval* against *public_key*.

    Pure crypto — does NOT check whether device_id is a currently-active
    admin of the group (that's what the active_admins argument to
    count_valid_signatures()/is_approved() is for, since admin status can
    change after a signature was collected). Returns False on any missing
    signature or cryptographic failure. Raises nothing.
    """
    sig_b64 = approval.signatures.get(device_id)
    if sig_b64 is None:
        return False
    try:
        admin_pub_key = public_key_from_bytes(public_key)
        payload = _approval_payload(approval.group_id, approval.action_id, approval.action_payload)
        admin_pub_key.verify(base64.b64decode(sig_b64), payload)
        return True
    except Exception as e:
        emit(
            SecurityEvent(
                event_type=SecurityEventType.INVALID_AUTHORITY_CHAIN,
                severity=SecuritySeverity.CRITICAL,
                description=(
                    f"threshold-approval signature invalid for device {device_id} on action "
                    f"{approval.action_id!r} in group {approval.group_id!r}: {e}"
                ),
                device_id=device_id,
            )
        )
        return False


def count_valid_signatures(approval: ThresholdApproval, active_admins: Dict[str, bytes]) -> int:
    """*active_admins*: device_id -> raw public key bytes, for admins
    CURRENTLY active in the group — build this from
    GroupStore.get_active_admin_public_keys(group_id). Passed in rather
    than looked up here so this module stays storage-agnostic (mirrors
    verify_membership_certificate()'s split in membership.py). A
    signature from a device not present in active_admins (never was an
    admin, or was since removed) simply doesn't count — no error, it
    just doesn't contribute to the threshold."""
    return sum(
        1
        for device_id, pubkey in active_admins.items()
        if verify_approval_signature(approval, device_id, pubkey)
    )


def is_approved(approval: ThresholdApproval, active_admins: Dict[str, bytes]) -> bool:
    """True once at least required_threshold CURRENTLY-active admins
    have a valid signature on *approval*."""
    return count_valid_signatures(approval, active_admins) >= approval.required_threshold


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _approval_payload(group_id: str, action_id: str, action_payload: bytes) -> bytes:
    group_id_b = group_id.encode("utf-8")
    action_id_b = action_id.encode("utf-8")
    return (
        _ADMIN_APPROVAL_DOMAIN
        + struct.pack(">I", len(group_id_b))
        + group_id_b
        + struct.pack(">I", len(action_id_b))
        + action_id_b
        + struct.pack(">I", len(action_payload))
        + action_payload
    )
