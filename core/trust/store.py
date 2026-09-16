"""core/trust/store.py — SQLite-backed trusted_devices store (Phase 4/40).

TOFU (trust-on-first-use) is intentionally split into two steps that never
happen automatically together:

    1. check(device_id, public_key) — read-only. Tells the caller what's
       going on: never seen before, waiting on approval, trusted and
       matching, trusted but the key CHANGED (possible impersonation/MITM
       — never silently accepted), or revoked.
    2. Only on an explicit caller/user action do record_first_seen() or
       approve() actually write anything. A key mismatch is never
       auto-corrected by this module — that would defeat the point of
       TOFU. (Re-approving a changed key, if ever wanted, is a distinct,
       explicit operation for a later phase, not something check() does.)

Phase 40 adds the identity_transitions table: a cryptographically proven
chain of device_id rotations.  record_rotation() verifies a TransitionCertificate
and carries TRUSTED status forward; check_with_rotation() is a drop-in
replacement for check() that understands rotation history.

Not thread-safe across threads (sqlite3 default); fine for this app, which
drives everything from a single asyncio event loop.
"""

import enum
import os
import sqlite3
import time
from typing import TYPE_CHECKING, Any, Optional

from core.group.policy import ExternalTrustDeniedError, PolicyEnforcer
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit
from .device import TrustedDevice, TrustStatus

if TYPE_CHECKING:
    from core.identity.rotation import TransitionCertificate
    from core.group.store import GroupStore

DEFAULT_DB_PATH = os.path.expanduser("~/.peerc/trust.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id     TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    name          TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    status        TEXT NOT NULL,
    revoked_by    TEXT,
    revoked_at    REAL,
    revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS identity_transitions (
    old_device_id TEXT NOT NULL,
    new_device_id TEXT NOT NULL,
    old_public_key TEXT NOT NULL,
    new_public_key TEXT NOT NULL,
    timestamp      REAL NOT NULL,
    signature      TEXT NOT NULL,
    recorded_at    REAL NOT NULL,
    PRIMARY KEY (old_device_id, new_device_id)
);
"""


class TrustDecision(str, enum.Enum):
    UNKNOWN = "unknown"          # never seen this device_id before
    PENDING = "pending"          # seen, awaiting user approval, key matches what's on file
    TRUSTED = "trusted"          # approved, key matches what's on file — OK
    KEY_CHANGED = "key_changed"  # device_id known, but public_key does NOT match — WARNING
    REVOKED = "revoked"          # explicitly distrusted


class TrustStore:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        conn: Optional[sqlite3.Connection] = None,
        group_store: Optional[Any] = None,
        policy_enforcer: Optional[PolicyEnforcer] = None,
    ):
        """conn, if given, is an already-open connection to share (Phase
        39.2: the unified vault database) — db_path is ignored in that
        case, and this instance does NOT own/close that connection; the
        owner (e.g. VaultDatabase) is responsible for that. When conn is
        None (the default, and every pre-Phase-39.2 call site), behavior
        is unchanged: TrustStore opens and owns its own db_path file.

        Phase 42.2: group_store and policy_enforcer allow TrustStore to
        enforce External Trust Restriction (§6) on record_first_seen().
        """
        self.db_path = db_path
        self._group_store = group_store
        self._policy_enforcer = policy_enforcer
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

    def set_group_store(self, group_store: Optional[Any]) -> None:
        """Wire or update GroupStore reference for policy enforcement (§6)."""
        self._group_store = group_store
        if self._policy_enforcer is not None:
            self._policy_enforcer.set_group_store(group_store)

    def set_policy_enforcer(self, policy_enforcer: Optional[PolicyEnforcer]) -> None:
        """Wire or update PolicyEnforcer directly."""
        self._policy_enforcer = policy_enforcer

    def _get_policy_enforcer(self) -> Optional[PolicyEnforcer]:
        if self._policy_enforcer is not None:
            return self._policy_enforcer
        if self._group_store is not None:
            self._policy_enforcer = PolicyEnforcer(self._group_store)
            return self._policy_enforcer
        return None

    def close(self) -> None:
        if self._owns_conn and self._conn is not None:
            self._conn.close()
            self._conn = None

    def adopt_conn(self, conn: Optional[sqlite3.Connection]) -> None:
        """Phase 39.3: swap onto a new shared vault connection after a
        session re-unlock (or detach with conn=None while the vault is
        locked). Never closes a connection we don't own. After detach,
        read/write methods raise RuntimeError until a live conn returns.
        """
        if self._owns_conn and self._conn is not None:
            self._conn.close()
        self._conn = conn
        self._owns_conn = False
        if conn is not None:
            self._conn.row_factory = sqlite3.Row

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("TrustStore has no active connection (vault locked)")
        return self._conn

    # ---- read -------------------------------------------------------

    def get(self, device_id: str) -> Optional[TrustedDevice]:
        row = self._require_conn().execute(
            "SELECT * FROM trusted_devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return _row_to_device(row) if row else None

    def check(self, device_id: str, public_key: str) -> TrustDecision:
        """Read-only TOFU evaluation. Never writes anything."""
        device = self.get(device_id)
        if device is None:
            return TrustDecision.UNKNOWN
        if device.public_key != public_key:
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.IDENTITY_CHANGED,
                    severity=SecuritySeverity.WARNING,
                    description=f"device {device_id} public key does not match stored key (possible impersonation)",
                    device_id=device_id,
                )
            )
            return TrustDecision.KEY_CHANGED
        if device.status == TrustStatus.REVOKED:
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.REVOKED_DEVICE_ATTEMPT,
                    severity=SecuritySeverity.HIGH,
                    description=f"revoked device {device_id} evaluated in trust store",
                    device_id=device_id,
                )
            )
            return TrustDecision.REVOKED
        if device.status == TrustStatus.TRUSTED:
            return TrustDecision.TRUSTED
        return TrustDecision.PENDING

    def list_all(self, status: Optional[TrustStatus] = None) -> list[TrustedDevice]:
        if status is None:
            rows = self._require_conn().execute("SELECT * FROM trusted_devices ORDER BY last_seen DESC").fetchall()
        else:
            rows = self._require_conn().execute(
                "SELECT * FROM trusted_devices WHERE status = ? ORDER BY last_seen DESC",
                (status.value,),
            ).fetchall()
        return [_row_to_device(r) for r in rows]

    # ---- write --------------------------------------------------------

    def record_first_seen(self, device_id: str, public_key: str, name: str) -> TrustedDevice:
        """Insert a brand-new device as PENDING. Caller should only call
        this after check() returned UNKNOWN — calling it for a device_id
        that already exists raises, rather than silently overwriting a
        possibly-different stored public_key.

        Phase 42.2: External Trust Restriction (§6). If group policy
        enforces allow_external_trust=False and device_id is not an active
        member of that group, raises ExternalTrustDeniedError and emits a
        POLICY_VIOLATION security event before anything is written.
        """
        if self.get(device_id) is not None:
            raise ValueError(
                f"device_id {device_id!r} is already known — use check() first; "
                "record_first_seen() must not overwrite an existing entry"
            )

        # Enforce group policy (§6 External Trust Restriction)
        enforcer = self._get_policy_enforcer()
        if enforcer is not None:
            enforcer.check_external_trust(device_id)

        now = time.time()
        self._require_conn().execute(
            "INSERT INTO trusted_devices (device_id, public_key, name, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, public_key, name, now, now, TrustStatus.PENDING.value),
        )
        self._require_conn().commit()
        return self.get(device_id)

    def touch_last_seen(self, device_id: str) -> None:
        """Bump last_seen on a re-encounter with a matching key. No-op if
        the device isn't known (call check() first)."""
        self._require_conn().execute(
            "UPDATE trusted_devices SET last_seen = ? WHERE device_id = ?",
            (time.time(), device_id),
        )
        self._require_conn().commit()

    def approve(self, device_id: str) -> TrustedDevice:
        """User has seen the fingerprint and approved it: PENDING -> TRUSTED.

        Refuses to approve a device that's REVOKED (must be un-revoked
        through a deliberate separate action, not this) or that doesn't
        exist yet.
        """
        device = self.get(device_id)
        if device is None:
            raise ValueError(f"cannot approve unknown device_id {device_id!r}")
        if device.status == TrustStatus.REVOKED:
            raise ValueError(
                f"device_id {device_id!r} is REVOKED — approve() refuses to "
                "silently re-trust a revoked device"
            )
        self._require_conn().execute(
            "UPDATE trusted_devices SET status = ? WHERE device_id = ?",
            (TrustStatus.TRUSTED.value, device_id),
        )
        self._require_conn().commit()
        return self.get(device_id)

    def _set_revoked(self, device_id: str, revoked_by: str, reason: Optional[str]) -> TrustedDevice:
        """Internal — see core/trust/revocation.py for the public entrypoint."""
        if self.get(device_id) is None:
            raise ValueError(f"cannot revoke unknown device_id {device_id!r}")
        self._require_conn().execute(
            "UPDATE trusted_devices SET status = ?, revoked_by = ?, revoked_at = ?, revoke_reason = ? "
            "WHERE device_id = ?",
            (TrustStatus.REVOKED.value, revoked_by, time.time(), reason, device_id),
        )
        self._require_conn().commit()
        return self.get(device_id)

    # ---- Phase 40: key rotation -------------------------------------------

    def record_rotation(self, cert: "TransitionCertificate") -> None:
        """Record a verified key rotation and carry TRUSTED status forward.

        Steps:
          1. Verify the TransitionCertificate signature (raises RotationError on
             failure — never silently accept an unverified cert).
          2. Check that old_device_id is not REVOKED (a revoked device may not
             silently bootstrap a new identity via rotation).
          3. Insert the transition record into identity_transitions.
          4. If old_device_id was TRUSTED, insert (or update) new_device_id in
             trusted_devices with TRUSTED status, inheriting the old device's
             name.  PENDING is deliberately NOT carried over — the user hasn't
             explicitly approved this device yet, so the new key is also PENDING.

        Raises RotationError if the cert is invalid or if old_device_id is REVOKED.
        """
        # Inline import to avoid a circular-import chain at module load time.
        from core.identity.rotation import RotationError, verify_transition_certificate

        if not verify_transition_certificate(cert):
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.INVALID_ROTATION,
                    severity=SecuritySeverity.WARNING,
                    description=f"TransitionCertificate signature is invalid for rotation {cert.old_device_id} -> {cert.new_device_id}",
                    device_id=cert.old_device_id,
                    details={"old_device_id": cert.old_device_id, "new_device_id": cert.new_device_id},
                )
            )
            raise RotationError(
                f"TransitionCertificate signature is invalid for rotation "
                f"{cert.old_device_id!r} → {cert.new_device_id!r}"
            )

        old_device = self.get(cert.old_device_id)
        if old_device is not None and old_device.status == TrustStatus.REVOKED:
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.REVOKED_DEVICE_ATTEMPT,
                    severity=SecuritySeverity.HIGH,
                    description=f"revoked device {cert.old_device_id} attempted key rotation to {cert.new_device_id}",
                    device_id=cert.old_device_id,
                    details={"old_device_id": cert.old_device_id, "new_device_id": cert.new_device_id},
                )
            )
            raise RotationError(
                f"old device_id {cert.old_device_id!r} is REVOKED — "
                "a revoked device cannot authorise a key rotation"
            )

        now = time.time()
        self._require_conn().execute(
            """
            INSERT OR REPLACE INTO identity_transitions
                (old_device_id, new_device_id, old_public_key, new_public_key,
                 timestamp, signature, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert.old_device_id,
                cert.new_device_id,
                cert.old_public_key,
                cert.new_public_key,
                cert.timestamp,
                cert.signature,
                now,
            ),
        )

        # Only TRUSTED carries over — PENDING stays PENDING (or UNKNOWN stays
        # UNKNOWN until the user explicitly approves).
        if old_device is not None and old_device.status == TrustStatus.TRUSTED:
            existing_new = self.get(cert.new_device_id)
            if existing_new is None:
                self._require_conn().execute(
                    """
                    INSERT INTO trusted_devices
                        (device_id, public_key, name, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cert.new_device_id,
                        cert.new_public_key,
                        old_device.name,
                        now,
                        now,
                        TrustStatus.TRUSTED.value,
                    ),
                )
            elif existing_new.status not in (TrustStatus.TRUSTED, TrustStatus.REVOKED):
                # Promote PENDING → TRUSTED if a valid rotation backs it.
                self._require_conn().execute(
                    "UPDATE trusted_devices SET status = ?, last_seen = ? WHERE device_id = ?",
                    (TrustStatus.TRUSTED.value, now, cert.new_device_id),
                )

        self._require_conn().commit()
        emit(
            SecurityEvent(
                event_type=SecurityEventType.KEY_ROTATION,
                severity=SecuritySeverity.INFO,
                description=f"recorded valid key rotation from {cert.old_device_id} to {cert.new_device_id}",
                device_id=cert.new_device_id,
                details={"old_device_id": cert.old_device_id, "new_device_id": cert.new_device_id},
            )
        )

    def get_rotation_chain(self, device_id: str) -> list[str]:
        """Return all device_ids that belong to the same rotation chain as *device_id*.

        Traverses identity_transitions both forward (as old_device_id) and
        backward (as new_device_id) to build the complete chain.  The returned
        list is ordered from oldest to newest device_id, with *device_id*
        included wherever it falls in that chain.

        Returns [device_id] if the device has no rotation history.
        """
        # Collect the entire reachable graph using a simple BFS.
        visited: set[str] = set()
        queue = [device_id]
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            # Successors: device_ids this one rotated TO.
            rows = self._require_conn().execute(
                "SELECT new_device_id FROM identity_transitions WHERE old_device_id = ?",
                (current,),
            ).fetchall()
            queue.extend(r[0] for r in rows)
            # Predecessors: device_ids that rotated INTO this one.
            rows = self._require_conn().execute(
                "SELECT old_device_id FROM identity_transitions WHERE new_device_id = ?",
                (current,),
            ).fetchall()
            queue.extend(r[0] for r in rows)

        # Order by the timestamp of the transition that introduced each node;
        # the very first device_id has no predecessor row, so it sorts to 0.
        def _order_key(did: str) -> float:
            row = self._require_conn().execute(
                "SELECT timestamp FROM identity_transitions WHERE new_device_id = ?",
                (did,),
            ).fetchone()
            return row[0] if row else 0.0

        return sorted(visited, key=_order_key)

    def check_with_rotation(
        self, device_id: str, public_key: str
    ) -> "TrustDecision":
        """Like check(), but also accepts a new device_id that has a valid
        rotation chain leading back to a TRUSTED old device_id.

        Decision priority (same as check() for all existing cases, with one
        addition):
          REVOKED      — device or ANY node in the rotation chain is REVOKED
                         (REVOKED is a terminal taint on the whole chain —
                         SECURITY_MODEL.md §17)
          TRUSTED      — device is directly trusted, OR has a rotation chain
                         from a TRUSTED predecessor (and no REVOKED anywhere)
          PENDING      — seen once but not yet approved
          UNKNOWN      — never seen before and no trusted chain
          KEY_CHANGED  — device_id known, but public_key does not match
        """
        # KEY_CHANGED: public_key doesn't match stored record — reject early.
        direct = self.check(device_id, public_key)
        if direct == TrustDecision.KEY_CHANGED:
            return direct

        # Always walk the whole chain to detect REVOKED anywhere — REVOKED is
        # a terminal state that taints every node in the chain (§17), so we
        # cannot short-circuit on TRUSTED without first ruling out revocation.
        chain = self.get_rotation_chain(device_id)
        chain_has_trusted = False

        for chain_id in chain:
            node = self.get(chain_id)
            if node is None:
                continue
            if node.status == TrustStatus.REVOKED:
                if direct != TrustDecision.REVOKED:
                    emit(
                        SecurityEvent(
                            event_type=SecurityEventType.REVOKED_DEVICE_ATTEMPT,
                            severity=SecuritySeverity.HIGH,
                            description=f"device {device_id} is tainted by revoked ancestor {chain_id} in rotation chain",
                            device_id=device_id,
                            details={"tainted_by": chain_id},
                        )
                    )
                return TrustDecision.REVOKED
            if node.status == TrustStatus.TRUSTED:
                chain_has_trusted = True

        if chain_has_trusted:
            return TrustDecision.TRUSTED

        return direct


def _row_to_device(row: sqlite3.Row) -> TrustedDevice:
    return TrustedDevice(
        device_id=row["device_id"],
        public_key=row["public_key"],
        name=row["name"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        status=TrustStatus(row["status"]),
        revoked_by=row["revoked_by"],
        revoked_at=row["revoked_at"],
        revoke_reason=row["revoke_reason"],
    )
