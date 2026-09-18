"""core/group/export_auth.py — Phase 43: Group-Gated Export Authorization.

See docs/GROUP_AUTHORITY_DESIGN.md §11 (Export Authorization) and §12
(Short-Lived Capability).

Two-object model:

  ExportRequest   — device → admin: "I want to export file X from group G"
                    Signed by the requesting device's own private key
                    (proves device identity; admin verifies before issuing).

  ExportCapability — admin → device: "You are authorized to export file X
                    until <expires_at>"
                    Signed by an admin's private key; device verifies before
                    proceeding past the group gate.

Both objects carry domain-separated Ed25519 signatures, matching the pattern
established in membership.py, protocol.py, and policy.py.

Key design constraints (§11):
  - Capability is scoped: device_id + file_id + action + group_id.
  - Short-lived: default TTL 300 s (§12 "5 minutes").
  - One-shot: GroupStore.mark_capability_used() burns it after export.
  - AND-gate: the group capability is checked BEFORE (and in addition to)
    the personal Secure Storage critical-action key — neither substitutes
    for the other.

file_id = "*" acts as a wildcard capability (admin grants export for any
file in the group) — useful when per-file granularity is impractical.
"""

import base64
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

# Domain-separation prefixes (must not overlap with any other peerc domain).
_REQUEST_DOMAIN = b"peerc-group-export-request\x00"
_CAPABILITY_DOMAIN = b"peerc-group-export-capability\x00"

DEFAULT_CAPABILITY_TTL = 300.0  # seconds (§12 "5 minutes")
ACTION_EXPORT = "EXPORT"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ExportAuthError(Exception):
    """Base class for export authorization errors."""


class InvalidCapabilityError(ExportAuthError):
    """Raised when a capability's admin signature is invalid or malformed."""


class ExpiredCapabilityError(ExportAuthError):
    """Raised when a capability is past its expiry timestamp."""


class InvalidRequestError(ExportAuthError):
    """Raised when a request's device signature is invalid or malformed."""


# ---------------------------------------------------------------------------
# ExportRequest — device → admin
# ---------------------------------------------------------------------------


@dataclass
class ExportRequest:
    """A device's signed request to the admin asking for export authorization.

    Fields mirror GROUP_AUTHORITY_DESIGN.md §11's "Export Request" diagram.
    """

    request_id: str          # UUID / random hex — correlation key
    device_id: str           # sha256(public_key) of the requesting device
    device_public_key: str   # base64(raw 32 bytes) — admin uses this to verify
    group_id: str
    file_id: str             # secure_id of the file, or "*"
    action: str = ACTION_EXPORT
    timestamp: float = field(default_factory=time.time)
    reason: Optional[str] = None
    signature: Optional[str] = None  # base64(Ed25519 over canonical_payload())

    def canonical_payload(self) -> bytes:
        """Deterministic bytes for Ed25519 signing / verification."""
        req_id_b = self.request_id.encode("utf-8")
        dev_id_b = self.device_id.encode("utf-8")
        group_id_b = self.group_id.encode("utf-8")
        file_id_b = self.file_id.encode("utf-8")
        action_b = self.action.encode("utf-8")
        reason_b = (self.reason or "").encode("utf-8")
        return (
            _REQUEST_DOMAIN
            + struct.pack(">I", len(req_id_b)) + req_id_b
            + struct.pack(">I", len(dev_id_b)) + dev_id_b
            + struct.pack(">I", len(group_id_b)) + group_id_b
            + struct.pack(">I", len(file_id_b)) + file_id_b
            + struct.pack(">I", len(action_b)) + action_b
            + struct.pack(">d", self.timestamp)
            + struct.pack(">I", len(reason_b)) + reason_b
        )

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "device_id": self.device_id,
            "device_public_key": self.device_public_key,
            "group_id": self.group_id,
            "file_id": self.file_id,
            "action": self.action,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ExportRequest":
        return cls(
            request_id=d["request_id"],
            device_id=d["device_id"],
            device_public_key=d["device_public_key"],
            group_id=d["group_id"],
            file_id=d["file_id"],
            action=d.get("action", ACTION_EXPORT),
            timestamp=float(d["timestamp"]),
            reason=d.get("reason"),
            signature=d.get("signature"),
        )


def create_export_request(
    device_private_key: Ed25519PrivateKey,
    device_id: str,
    device_public_key_b64: str,
    group_id: str,
    file_id: str,
    reason: Optional[str] = None,
) -> ExportRequest:
    """Build and sign an ExportRequest with the requesting device's key."""
    req = ExportRequest(
        request_id=secrets.token_hex(16),
        device_id=device_id,
        device_public_key=device_public_key_b64,
        group_id=group_id,
        file_id=file_id,
        reason=reason,
    )
    sig_bytes = device_private_key.sign(req.canonical_payload())
    req.signature = base64.b64encode(sig_bytes).decode("ascii")
    return req


def verify_export_request(req: ExportRequest) -> bool:
    """Verify the requesting device's Ed25519 signature over the request.

    Returns True if valid, False on any cryptographic or structural failure.
    The device_public_key field carries the raw 32-byte key in base64.
    """
    if req.signature is None or req.device_public_key is None:
        return False
    try:
        raw_pub = base64.b64decode(req.device_public_key)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
        sig_bytes = base64.b64decode(req.signature)
        pub_key.verify(sig_bytes, req.canonical_payload())
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# ExportCapability — admin → device
# ---------------------------------------------------------------------------


@dataclass
class ExportCapability:
    """Admin-signed export capability token.

    Fields mirror GROUP_AUTHORITY_DESIGN.md §11's "Export Authorization"
    diagram.  nonce prevents replay of a capability that matched a previous
    (request_id, file_id) pair.
    """

    capability_id: str        # random hex — primary key in DB
    request_id: str           # echoes ExportRequest.request_id
    device_id: str            # device this capability is bound to
    group_id: str
    file_id: str              # specific file, or "*"
    action: str = ACTION_EXPORT
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + DEFAULT_CAPABILITY_TTL)
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    admin_device_id: Optional[str] = None
    signature: Optional[str] = None  # base64(Ed25519 over canonical_payload())

    def canonical_payload(self) -> bytes:
        """Deterministic bytes for Ed25519 signing / verification."""
        cap_id_b = self.capability_id.encode("utf-8")
        req_id_b = self.request_id.encode("utf-8")
        dev_id_b = self.device_id.encode("utf-8")
        group_id_b = self.group_id.encode("utf-8")
        file_id_b = self.file_id.encode("utf-8")
        action_b = self.action.encode("utf-8")
        nonce_b = self.nonce.encode("utf-8")
        admin_id_b = (self.admin_device_id or "").encode("utf-8")
        return (
            _CAPABILITY_DOMAIN
            + struct.pack(">I", len(cap_id_b)) + cap_id_b
            + struct.pack(">I", len(req_id_b)) + req_id_b
            + struct.pack(">I", len(dev_id_b)) + dev_id_b
            + struct.pack(">I", len(group_id_b)) + group_id_b
            + struct.pack(">I", len(file_id_b)) + file_id_b
            + struct.pack(">I", len(action_b)) + action_b
            + struct.pack(">dd", self.issued_at, self.expires_at)
            + struct.pack(">I", len(nonce_b)) + nonce_b
            + struct.pack(">I", len(admin_id_b)) + admin_id_b
        )

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def matches(self, device_id: str, file_id: str, group_id: str) -> bool:
        """True if this capability applies to the given (device, file, group)."""
        dev_match = self.device_id == device_id
        group_match = self.group_id == group_id
        file_match = self.file_id == "*" or self.file_id == file_id
        return dev_match and group_match and file_match

    def to_dict(self) -> dict:
        return {
            "capability_id": self.capability_id,
            "request_id": self.request_id,
            "device_id": self.device_id,
            "group_id": self.group_id,
            "file_id": self.file_id,
            "action": self.action,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "admin_device_id": self.admin_device_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ExportCapability":
        return cls(
            capability_id=d["capability_id"],
            request_id=d["request_id"],
            device_id=d["device_id"],
            group_id=d["group_id"],
            file_id=d["file_id"],
            action=d.get("action", ACTION_EXPORT),
            issued_at=float(d["issued_at"]),
            expires_at=float(d["expires_at"]),
            nonce=d["nonce"],
            admin_device_id=d.get("admin_device_id"),
            signature=d.get("signature"),
        )


def issue_export_capability(
    admin_private_key: Ed25519PrivateKey,
    admin_device_id: str,
    request: ExportRequest,
    ttl: float = DEFAULT_CAPABILITY_TTL,
) -> ExportCapability:
    """Admin signs an ExportCapability in response to a verified request.

    The capability is bound to the requesting device and file, and expires
    after `ttl` seconds (default 300 s per §12).

    Callers should call verify_export_request() first and only call this
    after confirming the request is valid.
    """
    now = time.time()
    cap = ExportCapability(
        capability_id=secrets.token_hex(16),
        request_id=request.request_id,
        device_id=request.device_id,
        group_id=request.group_id,
        file_id=request.file_id,
        issued_at=now,
        expires_at=now + ttl,
        admin_device_id=admin_device_id,
    )
    sig_bytes = admin_private_key.sign(cap.canonical_payload())
    cap.signature = base64.b64encode(sig_bytes).decode("ascii")
    return cap


def verify_export_capability(
    cap: ExportCapability,
    admin_public_keys_b64: list[str],
    now: Optional[float] = None,
) -> bool:
    """Verify that *cap* is validly signed by any of the given admin keys
    and has not yet expired.

    Returns True only when:
      - the capability is not expired, AND
      - at least one of admin_public_keys_b64 produced a valid Ed25519
        signature over cap.canonical_payload().

    Returns False (never raises) on any crypto or data failure, matching
    the fail-closed, non-throwing convention used by is_approved() in admin.py.

    Args:
        cap: The ExportCapability to verify.
        admin_public_keys_b64: Current active admin public keys (base64 raw
            32 bytes). Callers should get this from
            GroupStore.get_active_admin_public_keys().
        now: Override for "current time" (for testing).
    """
    if cap.signature is None:
        return False
    if cap.is_expired(now):
        emit(
            SecurityEvent(
                event_type=SecurityEventType.POLICY_VIOLATION,
                severity=SecuritySeverity.WARNING,
                description=(
                    f"export capability {cap.capability_id} for device {cap.device_id} "
                    f"file {cap.file_id} in group {cap.group_id} has expired"
                ),
                device_id=cap.device_id,
                details={
                    "capability_id": cap.capability_id,
                    "group_id": cap.group_id,
                    "file_id": cap.file_id,
                    "expired_at": cap.expires_at,
                },
            )
        )
        return False

    payload = cap.canonical_payload()
    try:
        sig_bytes = base64.b64decode(cap.signature)
    except Exception:
        return False

    for pub_b64 in admin_public_keys_b64:
        try:
            raw_pub = base64.b64decode(pub_b64)
            pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
            pub_key.verify(sig_bytes, payload)
            return True  # first valid admin signature → accept
        except (InvalidSignature, Exception):
            continue

    return False
