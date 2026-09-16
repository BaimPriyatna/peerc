"""core.group — Group Authority System (Phase 42).

    membership.py — Group dataclass, MembershipCertificate issue/verify
                     (pure crypto/data, no storage, no policy)
    store.py       — GroupStore: SQLite-backed groups/group_memberships/group_policies
                     (mirrors core/trust/store.py's shared-connection pattern)
    policy.py      — GroupPolicy schema, CommunicationRule matrix, core-level
                     PolicyEnforcer and policy violation exceptions (§5, §6, §7, §8, §10)

Not yet present (later Phase 42 sub-steps, see docs/GROUP_AUTHORITY_DESIGN.md
and the ROADMAP): admin.py (multi-admin, k-of-n threshold signatures),
audit.py (signed audit log).
"""

from .membership import (
    DEFAULT_ROLE,
    Group,
    MembershipCertificate,
    MembershipError,
    create_group,
    is_membership_expired,
    issue_membership_certificate,
    verify_membership_certificate,
)
from .policy import (
    CommunicationDeniedError,
    CommunicationRule,
    ExportDeniedError,
    ExternalTrustDeniedError,
    GroupPolicy,
    InterGroupDeniedError,
    LeaveRequiresAdminError,
    PolicyAction,
    PolicyEffect,
    PolicyEnforcer,
    PolicyError,
    PolicyViolationError,
)
from .store import DEFAULT_DB_PATH, GroupStore, GroupStoreError, MembershipStatus

__all__ = [
    "DEFAULT_ROLE",
    "Group",
    "MembershipCertificate",
    "MembershipError",
    "create_group",
    "is_membership_expired",
    "issue_membership_certificate",
    "verify_membership_certificate",
    "DEFAULT_DB_PATH",
    "GroupStore",
    "GroupStoreError",
    "MembershipStatus",
    # Phase 42.2: policy schema & enforcement
    "CommunicationDeniedError",
    "CommunicationRule",
    "ExportDeniedError",
    "ExternalTrustDeniedError",
    "GroupPolicy",
    "InterGroupDeniedError",
    "LeaveRequiresAdminError",
    "PolicyAction",
    "PolicyEffect",
    "PolicyEnforcer",
    "PolicyError",
    "PolicyViolationError",
]
