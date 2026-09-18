"""core.group — Group Authority System (Phase 42).

    membership.py — Group dataclass, MembershipCertificate issue/verify
                     (pure crypto/data, no storage, no policy)
    store.py       — GroupStore: SQLite-backed groups/group_memberships/
                     group_policies/group_admins (mirrors core/trust/store.py's
                     shared-connection pattern)
    policy.py      — GroupPolicy schema, CommunicationRule matrix, core-level
                     PolicyEnforcer and policy violation exceptions (§5, §6, §7, §8, §10)
    admin.py       — AdminRecord, ThresholdApproval (k-of-n signature collection
                     for admin-gated actions) (§14 Multiple Administrators)

Not yet present (later Phase 42 sub-step, see docs/GROUP_AUTHORITY_DESIGN.md
and the ROADMAP): audit.py (signed audit log).
"""

from .admin import (
    AdminError,
    AdminRecord,
    ThresholdApproval,
    count_valid_signatures,
    create_threshold_approval,
    is_approved,
    sign_approval,
    verify_approval_signature,
)
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
from .protocol import (
    GroupJoinRequest,
    GroupJoinResponse,
    GroupLeaveRequest,
    GroupLeaveResponse,
    GroupProtocolError,
    MembershipRevocation,
    create_join_request,
    create_join_response,
    create_leave_request,
    create_leave_response,
    create_membership_revocation,
    verify_join_request,
    verify_join_response,
    verify_leave_request,
    verify_leave_response,
    verify_membership_revocation,
)
from .store import (
    AdminStatus,
    DEFAULT_DB_PATH,
    GroupStore,
    GroupStoreError,
    MembershipRevocationRecord,
    MembershipStatus,
)

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
    # Phase 42.3: multi-admin + k-of-n threshold signatures
    "AdminError",
    "AdminRecord",
    "AdminStatus",
    "ThresholdApproval",
    "count_valid_signatures",
    "create_threshold_approval",
    "is_approved",
    "sign_approval",
    "verify_approval_signature",
    # Phase 42.4: join/leave/revoke protocol messages
    "GroupJoinRequest",
    "GroupJoinResponse",
    "GroupLeaveRequest",
    "GroupLeaveResponse",
    "GroupProtocolError",
    "MembershipRevocation",
    "MembershipRevocationRecord",
    "create_join_request",
    "create_join_response",
    "create_leave_request",
    "create_leave_response",
    "create_membership_revocation",
    "verify_join_request",
    "verify_join_response",
    "verify_leave_request",
    "verify_leave_response",
    "verify_membership_revocation",
]
