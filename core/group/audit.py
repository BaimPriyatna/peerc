"""core/group/audit.py — Phase 42.5: Signed Audit Log for Group Authority.

See docs/GROUP_AUTHORITY_DESIGN.md §13 "Audit Log" and
docs/SECURITY_MODEL.md §29 "Security Event Logging".

Extends Phase 41 (core.security.events) with cryptographic signing by group
administrators and structured accountability formatting.

Components:
  1. sign_audit_event: Ed25519-signs a SecurityEvent's canonical_payload()
     under the _EVENT_DOMAIN prefix.
  2. verify_audit_event: Cryptographically verifies a signed SecurityEvent
     against a given administrator's public key.
  3. create_group_audit_event: Factory creating a structured SecurityEvent
     specifically for group authority actions, with optional signing.
  4. verify_group_audit_event: Verifies an event against the current active
     administrators of a group (storage-agnostic).
  5. format_audit_event: Produces human-readable log lines formatted per
     docs/GROUP_AUTHORITY_DESIGN.md §13.
"""

import base64
import time
import uuid
from typing import Any, Dict, List, Optional

from core.identity.device_identity import (
    DeviceKeypair,
    compute_device_id,
    public_key_from_bytes,
)
from core.security.events import (
    SecurityEvent,
    SecurityEventType,
    SecuritySeverity,
    emit,
)


class AuditError(Exception):
    """Raised for audit log signing or verification failures."""


def sign_audit_event(event: SecurityEvent, admin_keypair: DeviceKeypair) -> SecurityEvent:
    """Ed25519-sign *event*'s canonical_payload with *admin_keypair*.

    Attaches base64 signature and signer_device_id to the event in place
    and returns it.
    """
    payload = event.canonical_payload()
    sig_bytes = admin_keypair.sign(payload)
    event.signature = base64.b64encode(sig_bytes).decode("ascii")
    event.signer_device_id = admin_keypair.device_id
    return event


def verify_audit_event(event: SecurityEvent, admin_public_key: bytes) -> bool:
    """Verify *event*'s signature against raw *admin_public_key* bytes.

    Returns True if valid. Returns False if signature is missing,
    malformed, does not match, or if signer_device_id does not match
    the provided public key's device_id.
    """
    if not event.signature:
        return False
    expected_device_id = compute_device_id(admin_public_key)
    if event.signer_device_id and event.signer_device_id != expected_device_id:
        return False
    try:
        sig_bytes = base64.b64decode(event.signature)
        pub = public_key_from_bytes(admin_public_key)
        pub.verify(sig_bytes, event.canonical_payload())
        return True
    except Exception:
        return False


def create_group_audit_event(
    group_id: str,
    event_type: str | SecurityEventType,
    description: str,
    *,
    severity: SecuritySeverity = SecuritySeverity.INFO,
    device_id: Optional[str] = None,
    actor_device_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[float] = None,
    admin_keypair: Optional[DeviceKeypair] = None,
) -> SecurityEvent:
    """Create a SecurityEvent tailored for group authority actions."""
    if not group_id:
        raise AuditError("group_id is required for group audit events")

    event_details: Dict[str, Any] = {"group_id": group_id}
    if actor_device_id:
        event_details["actor_device_id"] = actor_device_id
    if details:
        event_details.update(details)

    ev = SecurityEvent(
        event_type=event_type.value if isinstance(event_type, SecurityEventType) else event_type,
        severity=severity,
        description=description,
        device_id=device_id or actor_device_id,
        timestamp=time.time() if timestamp is None else timestamp,
        details=event_details,
    )

    if admin_keypair is not None:
        sign_audit_event(ev, admin_keypair)

    return ev


def verify_group_audit_event(
    event: SecurityEvent,
    active_admins: Dict[str, bytes],
) -> bool:
    """Verify that *event* is signed by one of the group's active administrators.

    *active_admins*: mapping of device_id -> raw public_key bytes for current
    active admins (from GroupStore.get_active_admin_public_keys()).
    """
    if not event.signature or not event.signer_device_id:
        return False
    admin_pub = active_admins.get(event.signer_device_id)
    if not admin_pub:
        return False
    return verify_audit_event(event, admin_pub)


def format_audit_event(event: SecurityEvent) -> str:
    """Format an audit event into a standardized line per §13.

    Example:
    2026-09-18 18:30:00  ADMIN(78ab1234)  membership_issued  Membership issued  Device: 78ab1234  Group: ops-1  [signed]
    """
    t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
    actor = event.signer_device_id[:8] if event.signer_device_id else "LOCAL"
    sig_flag = "[signed]" if event.signature else "[unsigned]"
    dev_info = f"  Device: {event.device_id[:8]}" if event.device_id else ""
    gid = event.details.get("group_id", "")
    grp_info = f"  Group: {gid}" if gid else ""
    return f"{t_str}  ADMIN({actor})  {event.event_type}  {event.description}{dev_info}{grp_info}  {sig_flag}"
