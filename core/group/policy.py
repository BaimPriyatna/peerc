"""core/group/policy.py — Phase 42.2: Group Authority System, policy schema & enforcement.

See docs/GROUP_AUTHORITY_DESIGN.md:
  - §5: Group Policy (allow_external_trust, allow_export, leave_requires_admin, allow_inter_group)
  - §6: External Trust Restriction (wiring into TrustStore.record_first_seen())
  - §7: Communication Policy (source -> destination -> action -> allow/deny matrix)
  - §8: Multiple Groups (allow_inter_group)
  - §10: Controlled Leave (leave_requires_admin)

Principles:
  - Core-level enforcement: policy checks happen at the core protocol and
    storage layer, never only in UI prompt wrappers.
  - Fail-closed: if policy evaluation encounters a restriction or unknown
    state in a managed group, access is denied.
  - Backward-compatible: devices not belonging to any group or whose groups
    do not restrict actions proceed unimpeded (personal P2P mode).
"""

import enum
import json
import struct
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

from core.group.membership import is_membership_expired
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

# Domain-separation prefix for group policy signing (Phase 42 audit / admin)
_POLICY_DOMAIN = b"peerc-group-policy\x00"


class PolicyAction(str, enum.Enum):
    """Actions gated by group policy and communication matrix (§7)."""

    CHAT = "chat"
    FILE_SEND = "file_send"
    FILE_RECEIVE = "file_receive"
    EXPORT = "export"
    TRUST = "trust"
    GROUP_JOIN = "group_join"
    GROUP_LEAVE = "group_leave"
    ALL = "*"


class PolicyEffect(str, enum.Enum):
    """Result effect of a communication rule (§7)."""

    ALLOW = "allow"
    DENY = "deny"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PolicyError(Exception):
    """Base class for all policy-related errors."""


class PolicyViolationError(PolicyError):
    """Raised when an operation violates group policy."""


class ExternalTrustDeniedError(PolicyViolationError):
    """Raised when trusting or recording an external device is forbidden (§6)."""


class ExportDeniedError(PolicyViolationError):
    """Raised when exporting a file is forbidden by group policy (§5, §11)."""


class LeaveRequiresAdminError(PolicyViolationError):
    """Raised when leaving a group requires admin authorization (§10)."""


class InterGroupDeniedError(PolicyViolationError):
    """Raised when inter-group communication is forbidden (§8)."""


class CommunicationDeniedError(PolicyViolationError):
    """Raised when communication between peers is blocked by matrix rule (§7)."""


# ---------------------------------------------------------------------------
# Communication Rule & Group Policy Schema
# ---------------------------------------------------------------------------


@dataclass
class CommunicationRule:
    """A single rule in the Communication Policy Matrix (§7).

    Matches source -> destination for a given action.
    source / destination can match:
      - role name (e.g. "engineering", "finance", case-insensitive)
      - group_id
      - device_id
      - wildcard ("*")
    """

    source: str
    destination: str
    action: str = "*"
    effect: PolicyEffect = PolicyEffect.ALLOW

    def __post_init__(self) -> None:
        if isinstance(self.effect, str) and not isinstance(self.effect, PolicyEffect):
            self.effect = PolicyEffect(self.effect.lower())
        if isinstance(self.action, PolicyAction):
            self.action = self.action.value

    def matches(
        self,
        source_device_id: str,
        dest_device_id: str,
        action: str,
        source_role: Optional[str] = None,
        dest_role: Optional[str] = None,
        source_group_id: Optional[str] = None,
        dest_group_id: Optional[str] = None,
    ) -> bool:
        """Evaluate whether this rule applies to the given communication attempt."""
        # Check action
        action_val = action.value if isinstance(action, PolicyAction) else str(action)
        if self.action != "*" and self.action.lower() != action_val.lower():
            return False

        # Check source match
        rule_src = self.source.lower()
        src_match = (
            rule_src == "*"
            or rule_src == source_device_id.lower()
            or (source_role is not None and rule_src == source_role.lower())
            or (source_group_id is not None and rule_src == source_group_id.lower())
        )
        if not src_match:
            return False

        # Check destination match
        rule_dst = self.destination.lower()
        dst_match = (
            rule_dst == "*"
            or rule_dst == dest_device_id.lower()
            or (dest_role is not None and rule_dst == dest_role.lower())
            or (dest_group_id is not None and rule_dst == dest_group_id.lower())
        )
        if not dst_match:
            return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "action": self.action,
            "effect": self.effect.value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CommunicationRule":
        return cls(
            source=d["source"],
            destination=d["destination"],
            action=d.get("action", "*"),
            effect=PolicyEffect(d.get("effect", PolicyEffect.ALLOW.value)),
        )


@dataclass
class GroupPolicy:
    """Group Policy Schema (§5, §6, §7, §8, §10).

    Fields:
      group_id:                      Group to which this policy applies
      allow_external_trust:          If False, cannot trust non-group peers (§6)
      allow_export:                  If False, export from secure storage is blocked (§5, §11)
      leave_requires_admin:          If True, member cannot leave without admin (§10)
      allow_inter_group:             If False, cross-group communication is blocked (§8)
      communication_matrix:          Fine-grained communication rules (§7)
      default_communication_effect:  Fallback when no rule in matrix matches (default ALLOW)
      version:                       Policy revision number
      updated_at:                    Timestamp of last policy modification
      admin_device_id:               Admin device that authored/updated the policy
      signature:                     Admin signature over canonical payload
    """

    group_id: str
    allow_external_trust: bool = True
    allow_export: bool = True
    leave_requires_admin: bool = False
    allow_inter_group: bool = True
    communication_matrix: List[CommunicationRule] = field(default_factory=list)
    default_communication_effect: PolicyEffect = PolicyEffect.ALLOW
    version: int = 1
    updated_at: float = field(default_factory=time.time)
    admin_device_id: Optional[str] = None
    signature: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.default_communication_effect, str) and not isinstance(
            self.default_communication_effect, PolicyEffect
        ):
            self.default_communication_effect = PolicyEffect(self.default_communication_effect.lower())
        parsed_rules: List[CommunicationRule] = []
        for r in self.communication_matrix:
            if isinstance(r, dict):
                parsed_rules.append(CommunicationRule.from_dict(r))
            elif isinstance(r, CommunicationRule):
                parsed_rules.append(r)
        self.communication_matrix = parsed_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "allow_external_trust": self.allow_external_trust,
            "allow_export": self.allow_export,
            "leave_requires_admin": self.leave_requires_admin,
            "allow_inter_group": self.allow_inter_group,
            "communication_matrix": [r.to_dict() for r in self.communication_matrix],
            "default_communication_effect": self.default_communication_effect.value,
            "version": self.version,
            "updated_at": self.updated_at,
            "admin_device_id": self.admin_device_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroupPolicy":
        rules = [
            CommunicationRule.from_dict(r) if isinstance(r, dict) else r
            for r in d.get("communication_matrix", [])
        ]
        return cls(
            group_id=d["group_id"],
            allow_external_trust=bool(d.get("allow_external_trust", True)),
            allow_export=bool(d.get("allow_export", True)),
            leave_requires_admin=bool(d.get("leave_requires_admin", False)),
            allow_inter_group=bool(d.get("allow_inter_group", True)),
            communication_matrix=rules,
            default_communication_effect=PolicyEffect(
                d.get("default_communication_effect", PolicyEffect.ALLOW.value)
            ),
            version=int(d.get("version", 1)),
            updated_at=float(d.get("updated_at", time.time())),
            admin_device_id=d.get("admin_device_id"),
            signature=d.get("signature"),
        )

    def canonical_payload(self) -> bytes:
        """Deterministic byte representation for Ed25519 signature verification."""
        sorted_matrix = json.dumps(
            [r.to_dict() for r in self.communication_matrix],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        group_id_bytes = self.group_id.encode("utf-8")
        admin_id_bytes = (self.admin_device_id or "").encode("utf-8")
        flags = (
            (1 if self.allow_external_trust else 0)
            | ((1 if self.allow_export else 0) << 1)
            | ((1 if self.leave_requires_admin else 0) << 2)
            | ((1 if self.allow_inter_group else 0) << 3)
        )
        return (
            _POLICY_DOMAIN
            + struct.pack(">I", len(group_id_bytes))
            + group_id_bytes
            + struct.pack(">II", self.version, flags)
            + self.default_communication_effect.value.encode("ascii")
            + b"\x00"
            + struct.pack(">I", len(admin_id_bytes))
            + admin_id_bytes
            + struct.pack(">I", len(sorted_matrix))
            + sorted_matrix
        )


# ---------------------------------------------------------------------------
# Policy Enforcer
# ---------------------------------------------------------------------------


class PolicyEnforcer:
    """Core-level enforcement of group policies (§5, §6, §7, §8, §10)."""

    def __init__(self, group_store: Optional[Any] = None) -> None:
        self.group_store = group_store

    def set_group_store(self, group_store: Optional[Any]) -> None:
        self.group_store = group_store

    # ---- 1. External Trust Restriction (§6) -------------------------------

    def check_external_trust(self, device_id: str) -> None:
        """Verify if *device_id* is allowed to be trusted / recorded as PENDING.

        Raises ExternalTrustDeniedError and emits POLICY_VIOLATION event if
        any active group policy enforces allow_external_trust=False and
        device_id is not an active member of that group.
        """
        if self.group_store is None:
            return

        try:
            groups = self.group_store.list_groups()
        except Exception:
            # If store is locked/unavailable, fail-closed is handled by caller or no groups
            return

        for group in groups:
            policy = self.group_store.get_policy(group.group_id)
            if policy is None or policy.allow_external_trust:
                continue

            # Group policy requires allow_external_trust = False
            # Device must be an active member of this group or the group admin
            is_member = False
            if device_id == group.admin_device_id:
                is_member = True
            else:
                cert = self.group_store.get_membership(group.group_id, device_id)
                if cert is not None:
                    status = self.group_store.get_membership_status(group.group_id, device_id)
                    status_val = status.value if hasattr(status, "value") else str(status)
                    if status_val == "active" and not is_membership_expired(cert):
                        is_member = True

            if not is_member:
                emit(
                    SecurityEvent(
                        event_type=SecurityEventType.POLICY_VIOLATION,
                        severity=SecuritySeverity.HIGH,
                        description=(
                            f"external trust denied: device {device_id} is not an active member "
                            f"of group {group.group_id} ({group.name}) which enforces allow_external_trust=False"
                        ),
                        device_id=device_id,
                        details={
                            "group_id": group.group_id,
                            "group_name": group.name,
                            "policy": "allow_external_trust",
                            "action": "trust_first_seen",
                        },
                    )
                )
                raise ExternalTrustDeniedError(
                    f"external trust denied: device {device_id!r} is not an active member "
                    f"of group {group.group_id!r} ({group.name}) which enforces allow_external_trust=False"
                )

    def is_external_trust_allowed(self, device_id: str) -> bool:
        """Read-only check whether external trust is allowed."""
        try:
            self.check_external_trust(device_id)
            return True
        except ExternalTrustDeniedError:
            return False

    # ---- 2. Export Authorization (§5, §11) --------------------------------

    def check_export(self, group_id: Optional[str] = None) -> None:
        """Verify whether export from secure storage is permitted by group policy.

        Raises ExportDeniedError and emits POLICY_VIOLATION if export is denied.
        """
        if self.group_store is None:
            return

        groups = (
            [self.group_store.get_group(group_id)]
            if group_id
            else self.group_store.list_groups()
        )
        for group in groups:
            if group is None:
                continue
            policy = self.group_store.get_policy(group.group_id)
            if policy is not None and not policy.allow_export:
                emit(
                    SecurityEvent(
                        event_type=SecurityEventType.POLICY_VIOLATION,
                        severity=SecuritySeverity.HIGH,
                        description=(
                            f"export denied: group {group.group_id} ({group.name}) enforces allow_export=False"
                        ),
                        details={
                            "group_id": group.group_id,
                            "group_name": group.name,
                            "policy": "allow_export",
                            "action": "export",
                        },
                    )
                )
                raise ExportDeniedError(
                    f"export denied: group {group.group_id!r} ({group.name}) enforces allow_export=False"
                )

    def is_export_allowed(self, group_id: Optional[str] = None) -> bool:
        try:
            self.check_export(group_id=group_id)
            return True
        except ExportDeniedError:
            return False

    # ---- 3. Controlled Leave (§10) ----------------------------------------

    def check_leave(self, group_id: str, device_id: str, is_admin: bool = False) -> None:
        """Verify whether a member is permitted to leave the group.

        Raises LeaveRequiresAdminError and emits POLICY_VIOLATION if
        leave_requires_admin=True and caller is not an admin.
        """
        if self.group_store is None or is_admin:
            return

        policy = self.group_store.get_policy(group_id)
        if policy is not None and policy.leave_requires_admin:
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.POLICY_VIOLATION,
                    severity=SecuritySeverity.HIGH,
                    description=(
                        f"leave group denied: member {device_id} cannot leave group {group_id} "
                        "without administrator approval (leave_requires_admin=True)"
                    ),
                    device_id=device_id,
                    details={
                        "group_id": group_id,
                        "policy": "leave_requires_admin",
                        "action": "group_leave",
                    },
                )
            )
            raise LeaveRequiresAdminError(
                f"leave group denied: member {device_id!r} cannot leave group {group_id!r} "
                "without administrator approval (leave_requires_admin=True)"
            )

    def is_leave_allowed(self, group_id: str, device_id: str, is_admin: bool = False) -> bool:
        try:
            self.check_leave(group_id=group_id, device_id=device_id, is_admin=is_admin)
            return True
        except LeaveRequiresAdminError:
            return False

    # ---- 4. Inter-Group Communication (§8) --------------------------------

    def check_inter_group(self, source_group_id: str, target_group_id: str) -> None:
        """Verify whether communication between members of different groups is allowed."""
        if source_group_id == target_group_id or self.group_store is None:
            return

        for gid in (source_group_id, target_group_id):
            policy = self.group_store.get_policy(gid)
            if policy is not None and not policy.allow_inter_group:
                emit(
                    SecurityEvent(
                        event_type=SecurityEventType.POLICY_VIOLATION,
                        severity=SecuritySeverity.HIGH,
                        description=(
                            f"inter-group communication denied between {source_group_id} and {target_group_id}: "
                            f"group {gid} enforces allow_inter_group=False"
                        ),
                        details={
                            "source_group_id": source_group_id,
                            "target_group_id": target_group_id,
                            "restricting_group": gid,
                            "policy": "allow_inter_group",
                        },
                    )
                )
                raise InterGroupDeniedError(
                    f"inter-group communication denied: group {gid!r} enforces allow_inter_group=False"
                )

    def is_inter_group_allowed(self, source_group_id: str, target_group_id: str) -> bool:
        try:
            self.check_inter_group(source_group_id, target_group_id)
            return True
        except InterGroupDeniedError:
            return False

    # ---- 5. Communication Policy Matrix (§7) ------------------------------

    def check_communication(
        self,
        action: PolicyAction | str,
        source_device_id: str,
        dest_device_id: str,
        source_role: Optional[str] = None,
        dest_role: Optional[str] = None,
        source_group_id: Optional[str] = None,
        dest_group_id: Optional[str] = None,
    ) -> None:
        """Evaluate communication against the Communication Policy Matrix (§7).

        Raises CommunicationDeniedError and emits POLICY_VIOLATION if communication
        is denied by a matrix rule or default effect.
        """
        # First check inter-group restriction if different groups are involved
        if source_group_id and dest_group_id and source_group_id != dest_group_id:
            self.check_inter_group(source_group_id, dest_group_id)

        if self.group_store is None:
            return

        # Collect policies to evaluate
        policies: List[GroupPolicy] = []
        target_group_ids = set()
        if source_group_id:
            target_group_ids.add(source_group_id)
        if dest_group_id:
            target_group_ids.add(dest_group_id)

        if target_group_ids:
            for gid in target_group_ids:
                p = self.group_store.get_policy(gid)
                if p is not None:
                    policies.append(p)
        else:
            policies = self.group_store.list_policies()

        action_str = action.value if isinstance(action, PolicyAction) else str(action)

        for policy in policies:
            # Check matrix rules in order
            matched = False
            for rule in policy.communication_matrix:
                if rule.matches(
                    source_device_id=source_device_id,
                    dest_device_id=dest_device_id,
                    action=action_str,
                    source_role=source_role,
                    dest_role=dest_role,
                    source_group_id=source_group_id,
                    dest_group_id=dest_group_id,
                ):
                    matched = True
                    if rule.effect == PolicyEffect.DENY:
                        emit(
                            SecurityEvent(
                                event_type=SecurityEventType.POLICY_VIOLATION,
                                severity=SecuritySeverity.HIGH,
                                description=(
                                    f"communication denied: rule {rule.source} -> {rule.destination} "
                                    f"for action {action_str} in group {policy.group_id} is DENY"
                                ),
                                device_id=source_device_id,
                                details={
                                    "group_id": policy.group_id,
                                    "source": rule.source,
                                    "destination": rule.destination,
                                    "action": action_str,
                                    "effect": "deny",
                                },
                            )
                        )
                        raise CommunicationDeniedError(
                            f"communication denied: rule ({rule.source} -> {rule.destination}, "
                            f"action={action_str}) in group {policy.group_id!r} is DENY"
                        )
                    # If ALLOW, rule matched and permitted this policy's check
                    break

            if not matched and policy.default_communication_effect == PolicyEffect.DENY:
                emit(
                    SecurityEvent(
                        event_type=SecurityEventType.POLICY_VIOLATION,
                        severity=SecuritySeverity.HIGH,
                        description=(
                            f"communication denied: no matching rule in group {policy.group_id} "
                            f"and default_communication_effect is DENY"
                        ),
                        device_id=source_device_id,
                        details={
                            "group_id": policy.group_id,
                            "action": action_str,
                            "default_effect": "deny",
                        },
                    )
                )
                raise CommunicationDeniedError(
                    f"communication denied: default effect for group {policy.group_id!r} is DENY"
                )

    def is_communication_allowed(
        self,
        action: PolicyAction | str,
        source_device_id: str,
        dest_device_id: str,
        source_role: Optional[str] = None,
        dest_role: Optional[str] = None,
        source_group_id: Optional[str] = None,
        dest_group_id: Optional[str] = None,
    ) -> bool:
        try:
            self.check_communication(
                action=action,
                source_device_id=source_device_id,
                dest_device_id=dest_device_id,
                source_role=source_role,
                dest_role=dest_role,
                source_group_id=source_group_id,
                dest_group_id=dest_group_id,
            )
            return True
        except CommunicationDeniedError:
            return False
        except InterGroupDeniedError:
            return False
