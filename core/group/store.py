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
import os
import sqlite3
import time
from typing import List, Optional

from .membership import Group, MembershipCertificate, verify_membership_certificate

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
"""


class MembershipStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


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
        if self.get_group(group.group_id) is not None:
            raise GroupStoreError(f"group_id {group.group_id!r} already exists")
        self._require_conn().execute(
            "INSERT INTO groups (group_id, name, admin_device_id, admin_public_key, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (group.group_id, group.name, group.admin_device_id, group.admin_public_key, group.created_at),
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
        """Verify *cert* against its group's recorded admin_public_key,
        then insert it as ACTIVE. Refuses (GroupStoreError) if:
          - the group doesn't exist,
          - the certificate's admin_device_id doesn't match the group's
            recorded admin (no accepting a cert signed by a non-admin),
          - the signature doesn't verify,
          - a membership already exists for (group_id, device_id) — use
            revoke_membership() first, this never silently overwrites.
        """
        group = self.get_group(cert.group_id)
        if group is None:
            raise GroupStoreError(f"cannot record membership for unknown group_id {cert.group_id!r}")
        if cert.admin_device_id != group.admin_device_id:
            raise GroupStoreError(
                f"certificate admin_device_id {cert.admin_device_id!r} does not match "
                f"group {cert.group_id!r}'s recorded admin {group.admin_device_id!r}"
            )
        admin_public_key = base64.b64decode(group.admin_public_key)
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
