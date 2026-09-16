"""core.group — Group Authority System (Phase 42).

    membership.py — Group dataclass, MembershipCertificate issue/verify
                     (pure crypto/data, no storage, no policy)
    store.py       — GroupStore: SQLite-backed groups/group_memberships
                     (mirrors core/trust/store.py's shared-connection pattern)

Not yet present (later Phase 42 sub-steps, see docs/GROUP_AUTHORITY_DESIGN.md
and the ROADMAP): policy.py (schema + core-level enforcement), admin.py
(multi-admin, k-of-n threshold signatures), audit.py (signed audit log).
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
]
