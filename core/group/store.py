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
import enum
import json
import os
import sqlite3
import time
from typing import Dict, List, Optional

from .admin import AdminRecord
from .membership import Group, MembershipCertificate, verify_membership_certificate
from .policy import CommunicationRule, GroupPolicy, PolicyEffect

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
"""


class MembershipStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class AdminStatus(str, enum.Enum):
    ACTIVE = "active"
    REMOVED = "removed"


class GroupStoreError(Exception):
    """Base class for group store errors."""


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
    )


def _row_to_admin(row: sqlite3.Row) -> AdminRecord:
    return AdminRecord(
        group_id=row["group_id"],
        device_id=row["device_id"],
        public_key=row["public_key"],
        added_at=row["added_at"],
        added_by=row["added_by"],
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
        if self.get_membership(group_id, device_id) is None:
            raise GroupStoreError(f"cannot revoke unknown membership ({group_id!r}, {device_id!r})")
        self._require_conn().execute(
            "UPDATE group_memberships SET status = ?, revoked_by = ?, revoked_at = ?, revoke_reason = ? "
            "WHERE group_id = ? AND device_id = ?",
            (MembershipStatus.REVOKED.value, revoked_by, time.time(), reason, group_id, device_id),
        )
        self._require_conn().commit()

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
        )
        self._require_conn().execute(
            "INSERT INTO group_admins (group_id, device_id, public_key, added_at, added_by, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (record.group_id, record.device_id, record.public_key, record.added_at, record.added_by, AdminStatus.ACTIVE.value),
        )
        self._require_conn().commit()
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

