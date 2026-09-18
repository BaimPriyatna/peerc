"""core/group/store.py — Phase 42.1: SQLite-backed group/membership storage.

Mirrors core/trust/store.py's shape: default to opening/owning its own
db_path file, but accept an already-open connection to share instead
(Phase 39.2's unified vault database is the only real caller — group
data lives in the same encrypted VaultDatabase as everything else, per
the discuss-before-build decision recorded for Phase 42.1).

Membership certificates are verified before they're ever written here
(record_membership refuses an invalid signature) — this store never
silently persists something it can't cryptographically justify.
"""

import base64
from dataclasses import dataclass
import enum
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

import uuid
from core.security.events import SecurityEvent, SecurityEventType, SecuritySeverity, emit
from .admin import AdminRecord
from .audit import create_group_audit_event, verify_group_audit_event
from .membership import Group, MembershipCertificate, verify_membership_certificate
from .policy import CommunicationRule, GroupPolicy, LeaveRequiresAdminError, PolicyEffect
from .protocol import (
    GroupJoinResponse,
    GroupLeaveRequest,
    GroupLeaveResponse,
    MembershipRevocation,
    verify_join_response,
    verify_leave_request,
    verify_leave_response,
    verify_membership_revocation,
)

DEFAULT_DB_PATH = os.path.expanduser("~/.peerc/group.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    group_id         TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    admin_device_id  TEXT NOT NULL,
    admin_public_key TEXT NOT NULL,
    created_at       REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS group_memberships (
    group_id          TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    role              TEXT NOT NULL,
    permissions       TEXT NOT NULL,
    issued_at         REAL NOT NULL,
    expires_at        REAL,
    admin_device_id   TEXT NOT NULL,
    signature         TEXT NOT NULL,
    status            TEXT NOT NULL,
    revoked_by        TEXT,
    revoked_at        REAL,
    revoke_reason     TEXT,
    PRIMARY KEY (group_id, device_id)
);
CREATE TABLE IF NOT EXISTS group_policies (
    group_id                      TEXT PRIMARY KEY,
    allow_external_trust          INTEGER NOT NULL DEFAULT 1,
    allow_export                  INTEGER NOT NULL DEFAULT 1,
    leave_requires_admin          INTEGER NOT NULL DEFAULT 0,
    allow_inter_group             INTEGER NOT NULL DEFAULT 1,
    communication_matrix          TEXT NOT NULL DEFAULT '[]',
    default_communication_effect  TEXT NOT NULL DEFAULT 'allow',
    version                       INTEGER NOT NULL DEFAULT 1,
    updated_at                    REAL NOT NULL,
    admin_device_id               TEXT,
    signature                     TEXT
);
CREATE TABLE IF NOT EXISTS group_admins (
    group_id    TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    added_at    REAL NOT NULL,
    added_by    TEXT,
    status      TEXT NOT NULL,
    removed_at  REAL,
    removed_by  TEXT,
    PRIMARY KEY (group_id, device_id)
);
CREATE TABLE IF NOT EXISTS group_audit_log (
    event_id         TEXT PRIMARY KEY,
    group_id         TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    severity         TEXT NOT NULL,
    description      TEXT NOT NULL,
    device_id        TEXT,
    timestamp        REAL NOT NULL,
    details          TEXT NOT NULL,
    signature        TEXT,
    signer_device_id TEXT
);
"""


class MembershipStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class AdminStatus(str, enum.Enum):
    ACTIVE = "active"
    REMOVED = "removed"


class GroupStoreError(Exception):
    """Base class for group store errors."""


@dataclass
class MembershipRevocationRecord:
    group_id: str
    device_id: str
    revoked_by: str
    revoked_at: float
    reason: Optional[str] = None


def _row_to_group(row: sqlite3.Row) -> Group:
    return Group(
        group_id=row["group_id"],
        name=row["name"],
        admin_device_id=row["admin_device_id"],
        admin_public_key=row["admin_public_key"],
        created_at=row["created_at"],
    )


def _row_to_cert(row: sqlite3.Row) -> MembershipCertificate:
    return MembershipCertificate(
        device_id=row["device_id"],
        device_public_key=row["device_public_key"],
        group_id=row["group_id"],
        role=row["role"],
        permissions=row["permissions"].split(",") if row["permissions"] else [],
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        admin_device_id=row["admin_device_id"],
        signature=row["signature"],
        status=row["status"] if "status" in row.keys() else "active",
    )


def _row_to_audit_event(row: sqlite3.Row) -> SecurityEvent:
    details_raw = json.loads(row["details"]) if row["details"] else {}
    return SecurityEvent(
        event_type=row["event_type"],
        severity=SecuritySeverity(row["severity"]),
        description=row["description"],
        device_id=row["device_id"],
        timestamp=row["timestamp"],
        details=details_raw,
        signature=row["signature"],
        signer_device_id=row["signer_device_id"],
    )


def _row_to_admin(row: sqlite3.Row) -> AdminRecord:
    return AdminRecord(
        group_id=row["group_id"],
        device_id=row["device_id"],
        public_key=row["public_key"],
        added_at=row["added_at"],
        added_by=row["added_by"],
        status=AdminStatus(row["status"]) if "status" in row.keys() else AdminStatus.ACTIVE,
        removed_at=row["removed_at"] if "removed_at" in row.keys() else None,
        removed_by=row["removed_by"] if "removed_by" in row.keys() else None,
    )


def _row_to_policy(row: sqlite3.Row) -> GroupPolicy:
    matrix_raw = json.loads(row["communication_matrix"]) if row["communication_matrix"] else []
    rules = [CommunicationRule.from_dict(r) if isinstance(r, dict) else r for r in matrix_raw]
    return GroupPolicy(
        group_id=row["group_id"],
        allow_external_trust=bool(row["allow_external_trust"]),
        allow_export=bool(row["allow_export"]),
        leave_requires_admin=bool(row["leave_requires_admin"]),
        allow_inter_group=bool(row["allow_inter_group"]),
        communication_matrix=rules,
        default_communication_effect=PolicyEffect(row["default_communication_effect"]),
        version=row["version"],
        updated_at=row["updated_at"],
        admin_device_id=row["admin_device_id"],
        signature=row["signature"],
    )


def _row_to_revocation(row: sqlite3.Row) -> Optional[MembershipRevocationRecord]:
    if not row or row["status"] != MembershipStatus.REVOKED.value or row["revoked_at"] is None:
        return None
    return MembershipRevocationRecord(
        group_id=row["group_id"],
        device_id=row["device_id"],
        revoked_by=row["revoked_by"],
        revoked_at=row["revoked_at"],
        reason=row["revoke_reason"],
    )


class GroupStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, conn: Optional[sqlite3.Connection] = None):
        """conn, if given, is an already-open connection to share (the
        unified vault database) — db_path is ignored in that case, and
        this instance does NOT own/close that connection. When conn is
        None (the default), this store opens and owns its own db_path
        file — matches core/trust/store.py's TrustStore exactly."""
        self.db_path = db_path
        if conn is not None:
            self._conn = conn
            self._owns_conn = False
        else:
            directory = os.path.dirname(db_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(db_path)
            self._owns_conn = True
        self._conn.row_factory = sqlite3.Row
        self._require_conn().executescript(_SCHEMA)
        self._require_conn().commit()

    def close(self) -> None:
        if self._owns_conn and self._conn is not None:
            self._conn.close()
            self._conn = None

    def adopt_conn(self, conn: Optional[sqlite3.Connection]) -> None:
        """Swap onto a new shared vault connection after a session
        re-unlock (or detach with conn=None while the vault is locked).
        Never closes a connection we don't own."""
        if self._owns_conn and self._conn is not None:
            self._conn.close()
        self._conn = conn
        self._owns_conn = False
        if conn is not None:
            self._conn.row_factory = sqlite3.Row

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("GroupStore has no active connection (vault locked)")
        return self._conn

    # ---- groups -------------------------------------------------------

    def create_group(self, group: Group) -> Group:
        """Create *group* and auto-register its founding admin (the
        group_id/admin_device_id it already names) as the first row in
        group_admins — from here on, group_admins is the single source
        of truth for "who can sign for this group" (see add_admin());
        groups.admin_device_id/admin_public_key just keep recording the
        founder for provenance."""
        if self.get_group(group.group_id) is not None:
            raise GroupStoreError(f"group_id {group.group_id!r} already exists")
        self._require_conn().execute(
            "INSERT INTO groups (group_id, name, admin_device_id, admin_public_key, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (group.group_id, group.name, group.admin_device_id, group.admin_public_key, group.created_at),
        )
        self._require_conn().execute(
            "INSERT INTO group_admins (group_id, device_id, public_key, added_at, added_by, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                group.group_id,
                group.admin_device_id,
                group.admin_public_key,
                group.created_at,
                None,
                AdminStatus.ACTIVE.value,
            ),
        )
        self._require_conn().commit()
        self.record_audit_event(
            group.group_id,
            create_group_audit_event(
                group_id=group.group_id,
                event_type=SecurityEventType.GROUP_CREATED,
                description=f"Group '{group.name}' created by founder",
                severity=SecuritySeverity.INFO,
                actor_device_id=group.admin_device_id,
                details={"name": group.name, "admin_device_id": group.admin_device_id},
            ),
        )
        return group

    def get_group(self, group_id: str) -> Optional[Group]:
        row = self._require_conn().execute(
            "SELECT * FROM groups WHERE group_id = ?", (group_id,)
        ).fetchone()
        return _row_to_group(row) if row else None

    def list_groups(self) -> List[Group]:
        rows = self._require_conn().execute("SELECT * FROM groups ORDER BY created_at DESC").fetchall()
        return [_row_to_group(r) for r in rows]

    # ---- memberships ----------------------------------------------------

    def record_membership(self, cert: MembershipCertificate) -> MembershipCertificate:
        """Verify *cert* against ANY currently-active admin of its group
        (§14 Multiple Administrators — not just the founding admin),
        then insert it as ACTIVE. Refuses (GroupStoreError) if:
          - the group doesn't exist,
          - the certificate's admin_device_id isn't a currently-active
            admin of the group (no accepting a cert signed by a non-admin,
            or by an admin who's since been removed),
          - the signature doesn't verify,
          - a membership already exists for (group_id, device_id) — use
            revoke_membership() first, this never silently overwrites.
        """
        group = self.get_group(cert.group_id)
        if group is None:
            raise GroupStoreError(f"cannot record membership for unknown group_id {cert.group_id!r}")
        admin = self.get_admin(cert.group_id, cert.admin_device_id)
        if admin is None or self.get_admin_status(cert.group_id, cert.admin_device_id) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"certificate admin_device_id {cert.admin_device_id!r} is not a currently-active "
                f"admin of group {cert.group_id!r}"
            )
        admin_public_key = base64.b64decode(admin.public_key)
        if not verify_membership_certificate(cert, admin_public_key):
            raise GroupStoreError(
                f"membership certificate signature invalid for device {cert.device_id!r} in group {cert.group_id!r}"
            )
        if self.get_membership(cert.group_id, cert.device_id) is not None:
            raise GroupStoreError(
                f"membership already exists for device {cert.device_id!r} in group {cert.group_id!r} — "
                "use revoke_membership() first, this never silently overwrites"
            )
        self._require_conn().execute(
            "INSERT INTO group_memberships "
            "(group_id, device_id, device_public_key, role, permissions, issued_at, expires_at, "
            " admin_device_id, signature, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cert.group_id,
                cert.device_id,
                cert.device_public_key,
                cert.role,
                ",".join(sorted(cert.permissions)),
                cert.issued_at,
                cert.expires_at,
                cert.admin_device_id,
                cert.signature,
                MembershipStatus.ACTIVE.value,
            ),
        )
        self._require_conn().commit()
        self.record_audit_event(
            cert.group_id,
            create_group_audit_event(
                group_id=cert.group_id,
                event_type=SecurityEventType.MEMBERSHIP_ISSUED,
                description=f"Membership recorded for device {cert.device_id[:8]} (role={cert.role})",
                severity=SecuritySeverity.INFO,
                device_id=cert.device_id,
                actor_device_id=cert.admin_device_id,
                details={"role": cert.role, "permissions": cert.permissions},
            ),
        )
        return cert

    def get_membership(self, group_id: str, device_id: str) -> Optional[MembershipCertificate]:
        row = self._require_conn().execute(
            "SELECT * FROM group_memberships WHERE group_id = ? AND device_id = ?",
            (group_id, device_id),
        ).fetchone()
        return _row_to_cert(row) if row else None

    def get_membership_status(self, group_id: str, device_id: str) -> Optional[MembershipStatus]:
        row = self._require_conn().execute(
            "SELECT status FROM group_memberships WHERE group_id = ? AND device_id = ?",
            (group_id, device_id),
        ).fetchone()
        return MembershipStatus(row["status"]) if row else None

    def list_memberships(self, group_id: str, status: Optional[MembershipStatus] = None) -> List[MembershipCertificate]:
        if status is None:
            rows = self._require_conn().execute(
                "SELECT * FROM group_memberships WHERE group_id = ? ORDER BY issued_at DESC", (group_id,)
            ).fetchall()
        else:
            rows = self._require_conn().execute(
                "SELECT * FROM group_memberships WHERE group_id = ? AND status = ? ORDER BY issued_at DESC",
                (group_id, status.value),
            ).fetchall()
        return [_row_to_cert(r) for r in rows]

    def revoke_membership(self, group_id: str, device_id: str, revoked_by: str, reason: Optional[str] = None) -> None:
        """Admin-driven local revocation.

        Phase 42.4's network path should prefer record_revocation(),
        which verifies an admin-signed MembershipRevocation payload first.
        This direct API remains for local/admin callers but now still
        requires revoked_by to be a currently-active admin.
        """
        if self.get_admin_status(group_id, revoked_by) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"{revoked_by!r} is not a currently-active admin of group {group_id!r}"
            )
        self._mark_membership_revoked(group_id, device_id, revoked_by=revoked_by, reason=reason)

    def get_membership_revocation(self, group_id: str, device_id: str) -> Optional[MembershipRevocationRecord]:
        row = self._require_conn().execute(
            "SELECT * FROM group_memberships WHERE group_id = ? AND device_id = ?",
            (group_id, device_id),
        ).fetchone()
        return _row_to_revocation(row) if row else None

    def process_join_response(self, response: GroupJoinResponse) -> MembershipCertificate:
        """Verify and apply an approved admin-signed join response."""
        if not response.approved:
            raise GroupStoreError(f"join request {response.request_id!r} was not approved")
        if response.certificate is None:
            raise GroupStoreError("approved join response missing membership certificate")
        admin = self.get_admin(response.group_id, response.admin_device_id)
        if admin is None or self.get_admin_status(response.group_id, response.admin_device_id) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"join response admin_device_id {response.admin_device_id!r} is not a currently-active "
                f"admin of group {response.group_id!r}"
            )
        if not verify_join_response(response, base64.b64decode(admin.public_key)):
            raise GroupStoreError(f"join response signature invalid for request {response.request_id!r}")

        cert = response.certificate
        if cert.group_id != response.group_id or cert.device_id != response.device_id:
            raise GroupStoreError("join response certificate does not match response target")
        if cert.admin_device_id != response.admin_device_id:
            raise GroupStoreError("join response certificate was not issued by the response admin")
        return self.record_membership(cert)

    def process_leave_request(self, request: GroupLeaveRequest) -> None:
        """Apply a member-signed self-leave when group policy permits it."""
        cert = self.get_membership(request.group_id, request.device_id)
        if cert is None:
            raise GroupStoreError(
                f"cannot process leave request for unknown membership ({request.group_id!r}, {request.device_id!r})"
            )
        if self.get_membership_status(request.group_id, request.device_id) != MembershipStatus.ACTIVE:
            raise GroupStoreError(
                f"cannot process leave request for inactive membership ({request.group_id!r}, {request.device_id!r})"
            )
        if not verify_leave_request(request, base64.b64decode(cert.device_public_key)):
            raise GroupStoreError(f"leave request signature invalid for device {request.device_id!r}")

        policy = self.get_policy(request.group_id)
        if policy is not None and policy.leave_requires_admin:
            raise LeaveRequiresAdminError(
                f"leave group denied: member {request.device_id!r} cannot leave group {request.group_id!r} "
                "without administrator approval (leave_requires_admin=True)"
            )
        self._mark_membership_revoked(
            request.group_id,
            request.device_id,
            revoked_by=request.device_id,
            reason=request.reason or "member left group",
            revoked_at=request.timestamp,
        )

    def process_leave_response(self, response: GroupLeaveResponse) -> None:
        """Verify and apply an approved admin leave response."""
        if not response.approved:
            raise GroupStoreError(f"leave request {response.request_id!r} was not approved")
        if response.revocation is None:
            raise GroupStoreError("approved leave response missing membership revocation")
        admin = self.get_admin(response.group_id, response.admin_device_id)
        if admin is None or self.get_admin_status(response.group_id, response.admin_device_id) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"leave response admin_device_id {response.admin_device_id!r} is not a currently-active "
                f"admin of group {response.group_id!r}"
            )
        admin_key = base64.b64decode(admin.public_key)
        if not verify_leave_response(response, admin_key):
            raise GroupStoreError(f"leave response signature invalid for request {response.request_id!r}")
        revocation = response.revocation
        if revocation.group_id != response.group_id or revocation.device_id != response.device_id:
            raise GroupStoreError("leave response revocation does not match response target")
        if revocation.revoked_by != response.admin_device_id:
            raise GroupStoreError("leave response revocation was not issued by the response admin")
        self.record_revocation(revocation)

    def record_revocation(self, revocation: MembershipRevocation) -> None:
        """Verify an admin-signed revocation message, then tombstone the membership."""
        admin = self.get_admin(revocation.group_id, revocation.revoked_by)
        if admin is None or self.get_admin_status(revocation.group_id, revocation.revoked_by) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"revocation signer {revocation.revoked_by!r} is not a currently-active "
                f"admin of group {revocation.group_id!r}"
            )
        if not verify_membership_revocation(revocation, base64.b64decode(admin.public_key)):
            raise GroupStoreError(f"membership revocation signature invalid for device {revocation.device_id!r}")
        self._mark_membership_revoked(
            revocation.group_id,
            revocation.device_id,
            revoked_by=revocation.revoked_by,
            reason=revocation.reason,
            revoked_at=revocation.timestamp,
        )

    def _mark_membership_revoked(
        self,
        group_id: str,
        device_id: str,
        *,
        revoked_by: str,
        reason: Optional[str] = None,
        revoked_at: Optional[float] = None,
    ) -> None:
        if self.get_membership(group_id, device_id) is None:
            raise GroupStoreError(f"cannot revoke unknown membership ({group_id!r}, {device_id!r})")
        if self.get_membership_status(group_id, device_id) != MembershipStatus.ACTIVE:
            raise GroupStoreError(f"cannot revoke inactive membership ({group_id!r}, {device_id!r})")
        self._require_conn().execute(
            "UPDATE group_memberships SET status = ?, revoked_by = ?, revoked_at = ?, revoke_reason = ? "
            "WHERE group_id = ? AND device_id = ?",
            (MembershipStatus.REVOKED.value, revoked_by, revoked_at or time.time(), reason, group_id, device_id),
        )
        self._require_conn().commit()
        self.record_audit_event(
            group_id,
            create_group_audit_event(
                group_id=group_id,
                event_type=SecurityEventType.MEMBERSHIP_REVOKED,
                description=f"Membership revoked for device {device_id[:8]}",
                severity=SecuritySeverity.WARNING,
                device_id=device_id,
                actor_device_id=revoked_by,
                details={"reason": reason or "", "revoked_by": revoked_by},
            ),
        )

    # ---- policies -------------------------------------------------------

    def set_policy(self, policy: GroupPolicy) -> GroupPolicy:
        """Insert or update group policy.

        Refuses if the group does not exist, or if policy.admin_device_id
        is set but isn't a currently-active admin of the group (§14
        Multiple Administrators — any active admin may set policy, not
        just the founder).
        """
        group = self.get_group(policy.group_id)
        if group is None:
            raise GroupStoreError(f"cannot set policy for unknown group_id {policy.group_id!r}")
        if policy.admin_device_id and self.get_admin_status(policy.group_id, policy.admin_device_id) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"policy admin_device_id {policy.admin_device_id!r} is not a currently-active "
                f"admin of group {group.group_id!r}"
            )

        matrix_json = json.dumps([r.to_dict() for r in policy.communication_matrix])
        self._require_conn().execute(
            "INSERT INTO group_policies "
            "(group_id, allow_external_trust, allow_export, leave_requires_admin, allow_inter_group, "
            " communication_matrix, default_communication_effect, version, updated_at, admin_device_id, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(group_id) DO UPDATE SET "
            "allow_external_trust=excluded.allow_external_trust, "
            "allow_export=excluded.allow_export, "
            "leave_requires_admin=excluded.leave_requires_admin, "
            "allow_inter_group=excluded.allow_inter_group, "
            "communication_matrix=excluded.communication_matrix, "
            "default_communication_effect=excluded.default_communication_effect, "
            "version=excluded.version, "
            "updated_at=excluded.updated_at, "
            "admin_device_id=excluded.admin_device_id, "
            "signature=excluded.signature",
            (
                policy.group_id,
                1 if policy.allow_external_trust else 0,
                1 if policy.allow_export else 0,
                1 if policy.leave_requires_admin else 0,
                1 if policy.allow_inter_group else 0,
                matrix_json,
                policy.default_communication_effect.value,
                policy.version,
                policy.updated_at,
                policy.admin_device_id,
                policy.signature,
            ),
        )
        self._require_conn().commit()
        self.record_audit_event(
            policy.group_id,
            create_group_audit_event(
                group_id=policy.group_id,
                event_type=SecurityEventType.POLICY_CHANGED,
                description=f"Policy version {policy.version} updated for group {policy.group_id}",
                severity=SecuritySeverity.INFO,
                actor_device_id=policy.admin_device_id,
                details={
                    "version": policy.version,
                    "allow_external_trust": policy.allow_external_trust,
                    "allow_export": policy.allow_export,
                    "leave_requires_admin": policy.leave_requires_admin,
                },
            ),
        )
        return policy

    def get_policy(self, group_id: str) -> Optional[GroupPolicy]:
        row = self._require_conn().execute(
            "SELECT * FROM group_policies WHERE group_id = ?", (group_id,)
        ).fetchone()
        return _row_to_policy(row) if row else None

    def list_policies(self) -> List[GroupPolicy]:
        rows = self._require_conn().execute(
            "SELECT * FROM group_policies ORDER BY updated_at DESC"
        ).fetchall()
        return [_row_to_policy(r) for r in rows]

    # ---- admins (§14 Multiple Administrators) ----------------------------

    def add_admin(self, group_id: str, device_id: str, public_key: bytes, added_by: str) -> AdminRecord:
        """Register *device_id* as a new admin of *group_id*.

        Refuses (GroupStoreError) if the group doesn't exist, if
        *added_by* isn't a currently-active admin (only an existing admin
        can add another — no self-appointment), or if *device_id* is
        already an admin (active or removed — re-adding a removed admin
        needs a fresh explicit add_admin call, which this allows once
        their prior row's status no longer blocks the primary key... see
        note below).
        """
        if self.get_group(group_id) is None:
            raise GroupStoreError(f"cannot add admin to unknown group_id {group_id!r}")
        if self.get_admin_status(group_id, added_by) != AdminStatus.ACTIVE:
            raise GroupStoreError(
                f"{added_by!r} is not a currently-active admin of group {group_id!r} — "
                "only an existing admin can add another"
            )
        if self.get_admin(group_id, device_id) is not None:
            raise GroupStoreError(
                f"device {device_id!r} already has an admin record in group {group_id!r} "
                "(active or removed) — remove_admin() first if re-adding a removed admin"
            )
        record = AdminRecord(
            group_id=group_id,
            device_id=device_id,
            public_key=base64.b64encode(public_key).decode("ascii"),
            added_at=time.time(),
            added_by=added_by,
            status=AdminStatus.ACTIVE,
        )
        self._require_conn().execute(
            "INSERT INTO group_admins (group_id, device_id, public_key, added_at, added_by, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (record.group_id, record.device_id, record.public_key, record.added_at, record.added_by, AdminStatus.ACTIVE.value),
        )
        self._require_conn().commit()
        self.record_audit_event(
            group_id,
            create_group_audit_event(
                group_id=group_id,
                event_type=SecurityEventType.ADMIN_ADDED,
                description=f"Admin {device_id[:8]} added to group {group_id}",
                severity=SecuritySeverity.INFO,
                device_id=device_id,
                actor_device_id=added_by,
            ),
        )
        return record

    def remove_admin(self, group_id: str, device_id: str, removed_by: str, reason: Optional[str] = None) -> None:
        """Remove *device_id* as an admin of *group_id*.

        Refuses (GroupStoreError) if *device_id* isn't a currently-active
        admin, or if they're the LAST currently-active admin — a group
        must always have at least one admin, removing the last one would
        orphan it (nobody left who can sign memberships/policy)."""
        if self.get_admin_status(group_id, device_id) != AdminStatus.ACTIVE:
            raise GroupStoreError(f"{device_id!r} is not a currently-active admin of group {group_id!r}")
        active_count = len(self.list_admins(group_id, status=AdminStatus.ACTIVE))
        if active_count <= 1:
            raise GroupStoreError(
                f"cannot remove {device_id!r} — the last active admin of group {group_id!r} "
                "(a group must always have at least one admin)"
            )
        self._require_conn().execute(
            "UPDATE group_admins SET status = ?, removed_by = ?, removed_at = ? "
            "WHERE group_id = ? AND device_id = ?",
            (AdminStatus.REMOVED.value, removed_by, time.time(), group_id, device_id),
        )
        self._require_conn().commit()
        self.record_audit_event(
            group_id,
            create_group_audit_event(
                group_id=group_id,
                event_type=SecurityEventType.ADMIN_REMOVED,
                description=f"Admin {device_id[:8]} removed from group {group_id}",
                severity=SecuritySeverity.WARNING,
                device_id=device_id,
                actor_device_id=removed_by,
                details={"reason": reason or "", "removed_by": removed_by},
            ),
        )

    def get_admin(self, group_id: str, device_id: str) -> Optional[AdminRecord]:
        row = self._require_conn().execute(
            "SELECT * FROM group_admins WHERE group_id = ? AND device_id = ?",
            (group_id, device_id),
        ).fetchone()
        return _row_to_admin(row) if row else None

    def get_admin_status(self, group_id: str, device_id: str) -> Optional[AdminStatus]:
        row = self._require_conn().execute(
            "SELECT status FROM group_admins WHERE group_id = ? AND device_id = ?",
            (group_id, device_id),
        ).fetchone()
        return AdminStatus(row["status"]) if row else None

    def is_admin(self, group_id: str, device_id: str) -> bool:
        return self.get_admin_status(group_id, device_id) == AdminStatus.ACTIVE

    def list_admins(self, group_id: str, status: Optional[AdminStatus] = None) -> List[AdminRecord]:
        if status is None:
            rows = self._require_conn().execute(
                "SELECT * FROM group_admins WHERE group_id = ? ORDER BY added_at ASC", (group_id,)
            ).fetchall()
        else:
            rows = self._require_conn().execute(
                "SELECT * FROM group_admins WHERE group_id = ? AND status = ? ORDER BY added_at ASC",
                (group_id, status.value),
            ).fetchall()
        return [_row_to_admin(r) for r in rows]

    def get_active_admin_public_keys(self, group_id: str) -> Dict[str, bytes]:
        """device_id -> raw public key bytes, for every currently-active
        admin of *group_id* — feed this straight into
        core.group.admin.count_valid_signatures()/is_approved()."""
        return {
            a.device_id: base64.b64decode(a.public_key)
            for a in self.list_admins(group_id, status=AdminStatus.ACTIVE)
        }

    def record_audit_event(
        self,
        group_id: str,
        event: SecurityEvent,
        verify_with_admins: bool = False,
    ) -> SecurityEvent:
        """Record a SecurityEvent into group_audit_log.

        If *verify_with_admins* is True and *event* is signed, verifies that
        the signer is currently an active admin of *group_id*.
        """
        if not group_id:
            raise GroupStoreError("group_id is required to record an audit event")
        if self.get_group(group_id) is None:
            raise GroupStoreError(f"cannot record audit event for unknown group_id {group_id!r}")

        if verify_with_admins and event.signature:
            active_admins = self.get_active_admin_public_keys(group_id)
            if not verify_group_audit_event(event, active_admins):
                raise GroupStoreError(
                    f"audit event signature unverifiable against active admins of group {group_id!r}"
                )

        event_id = event.details.get("event_id") if isinstance(event.details, dict) else None
        if not event_id:
            event_id = str(uuid.uuid4())

        details_json = json.dumps(event.details or {}, sort_keys=True)
        self._require_conn().execute(
            "INSERT INTO group_audit_log "
            "(event_id, group_id, event_type, severity, description, device_id, timestamp, details, signature, signer_device_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                group_id,
                event.event_type,
                event.severity.value,
                event.description,
                event.device_id,
                event.timestamp,
                details_json,
                event.signature,
                event.signer_device_id,
            ),
        )
        self._require_conn().commit()
        emit(event)
        return event

    def list_audit_events(
        self,
        group_id: str,
        limit: Optional[int] = None,
        event_type: Optional[str] = None,
        severity: Optional[SecuritySeverity] = None,
        since: Optional[float] = None,
    ) -> List[SecurityEvent]:
        """Query audit log entries for *group_id* in chronological order."""
        query = "SELECT * FROM group_audit_log WHERE group_id = ?"
        params: List[Any] = [group_id]

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value if isinstance(severity, SecuritySeverity) else severity)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        rows = self._require_conn().execute(query, tuple(params)).fetchall()
        return [_row_to_audit_event(r) for r in rows]

    def get_audit_event(self, event_id: str) -> Optional[SecurityEvent]:
        """Fetch one audit event by event_id."""
        row = self._require_conn().execute(
            "SELECT * FROM group_audit_log WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return _row_to_audit_event(row) if row else None
