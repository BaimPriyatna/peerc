"""core/group/protocol.py — Phase 42.4: group join/leave/revoke messages.

These are storage-agnostic, signed control-plane payloads for Group
Authority membership changes. They are intentionally not UI flows and not
data-plane messages; peers can serialize them into core.protocol wire
messages, then GroupStore applies the verified result.
"""

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from core.identity.device_identity import DeviceKeypair, compute_device_id, public_key_from_bytes
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

from .membership import DEFAULT_ROLE, MembershipCertificate

_JOIN_REQUEST_DOMAIN = b"peerc-group-join-request\x00"
_JOIN_RESPONSE_DOMAIN = b"peerc-group-join-response\x00"
_LEAVE_REQUEST_DOMAIN = b"peerc-group-leave-request\x00"
_LEAVE_RESPONSE_DOMAIN = b"peerc-group-leave-response\x00"
_REVOCATION_DOMAIN = b"peerc-group-membership-revoke\x00"


class GroupProtocolError(Exception):
    """Raised for malformed or unverifiable group control messages."""


@dataclass
class GroupJoinRequest:
    request_id: str
    group_id: str
    device_id: str
    device_public_key: str  # base64(raw 32 bytes)
    requested_role: str = DEFAULT_ROLE
    requested_permissions: list[str] = field(default_factory=list)
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "device_public_key": self.device_public_key,
            "requested_role": self.requested_role,
            "requested_permissions": list(self.requested_permissions),
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroupJoinRequest":
        return cls(
            request_id=data["request_id"],
            group_id=data["group_id"],
            device_id=data["device_id"],
            device_public_key=data["device_public_key"],
            requested_role=data.get("requested_role", DEFAULT_ROLE),
            requested_permissions=list(data.get("requested_permissions", [])),
            reason=data.get("reason"),
            timestamp=float(data.get("timestamp", time.time())),
            signature=data.get("signature", ""),
        )


@dataclass
class GroupJoinResponse:
    request_id: str
    group_id: str
    device_id: str
    approved: bool
    admin_device_id: str
    certificate: Optional[MembershipCertificate] = None
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "approved": self.approved,
            "admin_device_id": self.admin_device_id,
            "certificate": _cert_to_dict(self.certificate) if self.certificate else None,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroupJoinResponse":
        cert_data = data.get("certificate")
        return cls(
            request_id=data["request_id"],
            group_id=data["group_id"],
            device_id=data["device_id"],
            approved=bool(data["approved"]),
            admin_device_id=data["admin_device_id"],
            certificate=_cert_from_dict(cert_data) if cert_data else None,
            reason=data.get("reason"),
            timestamp=float(data.get("timestamp", time.time())),
            signature=data.get("signature", ""),
        )


@dataclass
class GroupLeaveRequest:
    request_id: str
    group_id: str
    device_id: str
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroupLeaveRequest":
        return cls(
            request_id=data["request_id"],
            group_id=data["group_id"],
            device_id=data["device_id"],
            reason=data.get("reason"),
            timestamp=float(data.get("timestamp", time.time())),
            signature=data.get("signature", ""),
        )


@dataclass
class MembershipRevocation:
    revocation_id: str
    group_id: str
    device_id: str
    revoked_by: str
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "revocation_id": self.revocation_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "revoked_by": self.revoked_by,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MembershipRevocation":
        return cls(
            revocation_id=data["revocation_id"],
            group_id=data["group_id"],
            device_id=data["device_id"],
            revoked_by=data["revoked_by"],
            reason=data.get("reason"),
            timestamp=float(data.get("timestamp", time.time())),
            signature=data.get("signature", ""),
        )


@dataclass
class GroupLeaveResponse:
    request_id: str
    group_id: str
    device_id: str
    approved: bool
    admin_device_id: str
    revocation: Optional[MembershipRevocation] = None
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "group_id": self.group_id,
            "device_id": self.device_id,
            "approved": self.approved,
            "admin_device_id": self.admin_device_id,
            "revocation": self.revocation.to_dict() if self.revocation else None,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroupLeaveResponse":
        rev_data = data.get("revocation")
        return cls(
            request_id=data["request_id"],
            group_id=data["group_id"],
            device_id=data["device_id"],
            approved=bool(data["approved"]),
            admin_device_id=data["admin_device_id"],
            revocation=MembershipRevocation.from_dict(rev_data) if rev_data else None,
            reason=data.get("reason"),
            timestamp=float(data.get("timestamp", time.time())),
            signature=data.get("signature", ""),
        )


def create_join_request(
    device_keypair: DeviceKeypair,
    *,
    group_id: str,
    requested_role: str = DEFAULT_ROLE,
    requested_permissions: Optional[list[str]] = None,
    reason: Optional[str] = None,
    request_id: Optional[str] = None,
) -> GroupJoinRequest:
    if not group_id:
        raise GroupProtocolError("group_id is required")
    req = GroupJoinRequest(
        request_id=request_id or str(uuid.uuid4()),
        group_id=group_id,
        device_id=device_keypair.device_id,
        device_public_key=base64.b64encode(device_keypair.public_key_bytes()).decode("ascii"),
        requested_role=requested_role,
        requested_permissions=list(requested_permissions or []),
        reason=reason,
    )
    req.signature = _sign(device_keypair, _join_request_payload(req))
    return req


def verify_join_request(request: GroupJoinRequest) -> bool:
    try:
        public_key = base64.b64decode(request.device_public_key)
        if compute_device_id(public_key) != request.device_id:
            raise GroupProtocolError("join request device_id does not match device_public_key")
        return _verify(public_key, request.signature, _join_request_payload(request))
    except Exception as e:
        _emit_invalid("join request", request.device_id, request.group_id, e)
        return False


def create_join_response(
    admin_keypair: DeviceKeypair,
    request: GroupJoinRequest,
    *,
    approved: bool,
    certificate: Optional[MembershipCertificate] = None,
    reason: Optional[str] = None,
) -> GroupJoinResponse:
    if approved and certificate is None:
        raise GroupProtocolError("approved join response requires a membership certificate")
    res = GroupJoinResponse(
        request_id=request.request_id,
        group_id=request.group_id,
        device_id=request.device_id,
        approved=approved,
        admin_device_id=admin_keypair.device_id,
        certificate=certificate,
        reason=reason,
    )
    res.signature = _sign(admin_keypair, _join_response_payload(res))
    return res


def verify_join_response(response: GroupJoinResponse, admin_public_key: bytes) -> bool:
    try:
        return _verify(admin_public_key, response.signature, _join_response_payload(response))
    except Exception as e:
        _emit_invalid("join response", response.device_id, response.group_id, e)
        return False


def create_leave_request(
    device_keypair: DeviceKeypair,
    *,
    group_id: str,
    reason: Optional[str] = None,
    request_id: Optional[str] = None,
) -> GroupLeaveRequest:
    if not group_id:
        raise GroupProtocolError("group_id is required")
    req = GroupLeaveRequest(
        request_id=request_id or str(uuid.uuid4()),
        group_id=group_id,
        device_id=device_keypair.device_id,
        reason=reason,
    )
    req.signature = _sign(device_keypair, _leave_request_payload(req))
    return req


def verify_leave_request(request: GroupLeaveRequest, member_public_key: bytes) -> bool:
    try:
        if compute_device_id(member_public_key) != request.device_id:
            raise GroupProtocolError("leave request device_id does not match member public key")
        return _verify(member_public_key, request.signature, _leave_request_payload(request))
    except Exception as e:
        _emit_invalid("leave request", request.device_id, request.group_id, e)
        return False


def create_membership_revocation(
    admin_keypair: DeviceKeypair,
    *,
    group_id: str,
    device_id: str,
    reason: Optional[str] = None,
    revocation_id: Optional[str] = None,
) -> MembershipRevocation:
    if not group_id or not device_id:
        raise GroupProtocolError("group_id and device_id are required")
    revocation = MembershipRevocation(
        revocation_id=revocation_id or str(uuid.uuid4()),
        group_id=group_id,
        device_id=device_id,
        revoked_by=admin_keypair.device_id,
        reason=reason,
    )
    revocation.signature = _sign(admin_keypair, _revocation_payload(revocation))
    return revocation


def verify_membership_revocation(revocation: MembershipRevocation, admin_public_key: bytes) -> bool:
    try:
        return _verify(admin_public_key, revocation.signature, _revocation_payload(revocation))
    except Exception as e:
        _emit_invalid("membership revocation", revocation.device_id, revocation.group_id, e)
        return False


def create_leave_response(
    admin_keypair: DeviceKeypair,
    request: GroupLeaveRequest,
    *,
    approved: bool,
    revocation: Optional[MembershipRevocation] = None,
    reason: Optional[str] = None,
) -> GroupLeaveResponse:
    if approved and revocation is None:
        raise GroupProtocolError("approved leave response requires a membership revocation")
    res = GroupLeaveResponse(
        request_id=request.request_id,
        group_id=request.group_id,
        device_id=request.device_id,
        approved=approved,
        admin_device_id=admin_keypair.device_id,
        revocation=revocation,
        reason=reason,
    )
    res.signature = _sign(admin_keypair, _leave_response_payload(res))
    return res


def verify_leave_response(response: GroupLeaveResponse, admin_public_key: bytes) -> bool:
    try:
        return _verify(admin_public_key, response.signature, _leave_response_payload(response))
    except Exception as e:
        _emit_invalid("leave response", response.device_id, response.group_id, e)
        return False


def _sign(keypair: DeviceKeypair, payload: bytes) -> str:
    return base64.b64encode(keypair.sign(payload)).decode("ascii")


def _verify(public_key: bytes, signature_b64: str, payload: bytes) -> bool:
    public_key_from_bytes(public_key).verify(base64.b64decode(signature_b64), payload)
    return True


def _cert_to_dict(cert: Optional[MembershipCertificate]) -> Optional[dict[str, Any]]:
    if cert is None:
        return None
    return {
        "device_id": cert.device_id,
        "device_public_key": cert.device_public_key,
        "group_id": cert.group_id,
        "role": cert.role,
        "permissions": list(cert.permissions),
        "issued_at": cert.issued_at,
        "expires_at": cert.expires_at,
        "admin_device_id": cert.admin_device_id,
        "signature": cert.signature,
    }


def _cert_from_dict(data: dict[str, Any]) -> MembershipCertificate:
    return MembershipCertificate(
        device_id=data["device_id"],
        device_public_key=data["device_public_key"],
        group_id=data["group_id"],
        role=data["role"],
        permissions=list(data.get("permissions", [])),
        issued_at=float(data["issued_at"]),
        expires_at=data.get("expires_at"),
        admin_device_id=data["admin_device_id"],
        signature=data["signature"],
    )


def _json_payload(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _join_request_payload(req: GroupJoinRequest) -> bytes:
    return _JOIN_REQUEST_DOMAIN + _json_payload(
        {
            "request_id": req.request_id,
            "group_id": req.group_id,
            "device_id": req.device_id,
            "device_public_key": req.device_public_key,
            "requested_role": req.requested_role,
            "requested_permissions": sorted(req.requested_permissions),
            "reason": req.reason,
            "timestamp": req.timestamp,
        }
    )


def _join_response_payload(res: GroupJoinResponse) -> bytes:
    return _JOIN_RESPONSE_DOMAIN + _json_payload(
        {
            "request_id": res.request_id,
            "group_id": res.group_id,
            "device_id": res.device_id,
            "approved": res.approved,
            "admin_device_id": res.admin_device_id,
            "certificate": _cert_to_dict(res.certificate),
            "reason": res.reason,
            "timestamp": res.timestamp,
        }
    )


def _leave_request_payload(req: GroupLeaveRequest) -> bytes:
    return _LEAVE_REQUEST_DOMAIN + _json_payload(
        {
            "request_id": req.request_id,
            "group_id": req.group_id,
            "device_id": req.device_id,
            "reason": req.reason,
            "timestamp": req.timestamp,
        }
    )


def _revocation_payload(revocation: MembershipRevocation) -> bytes:
    return _REVOCATION_DOMAIN + _json_payload(
        {
            "revocation_id": revocation.revocation_id,
            "group_id": revocation.group_id,
            "device_id": revocation.device_id,
            "revoked_by": revocation.revoked_by,
            "reason": revocation.reason,
            "timestamp": revocation.timestamp,
        }
    )


def _leave_response_payload(res: GroupLeaveResponse) -> bytes:
    return _LEAVE_RESPONSE_DOMAIN + _json_payload(
        {
            "request_id": res.request_id,
            "group_id": res.group_id,
            "device_id": res.device_id,
            "approved": res.approved,
            "admin_device_id": res.admin_device_id,
            "revocation": res.revocation.to_dict() if res.revocation else None,
            "reason": res.reason,
            "timestamp": res.timestamp,
        }
    )


def _emit_invalid(kind: str, device_id: str, group_id: str, error: Exception) -> None:
    emit(
        SecurityEvent(
            event_type=SecurityEventType.INVALID_AUTHORITY_CHAIN,
            severity=SecuritySeverity.CRITICAL,
            description=f"group {kind} verification failed for device {device_id} in group {group_id}: {error}",
            device_id=device_id,
            details={"group_id": group_id, "message_kind": kind},
        )
    )
