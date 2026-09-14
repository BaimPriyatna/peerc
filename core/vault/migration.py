"""core/vault/migration.py — Phase 39.2: one-time trust.db migration.

Phase 4 shipped `trust.db` as a plain, unencrypted SQLite file before the
vault existed. §12 of docs/SECURE_STORAGE_DESIGN.md calls this out
explicitly as "worth its own tested sub-step... not something to
hand-wave as 'just copy it over.'"

Since there are no real users yet, the old plaintext file is deleted
outright once its rows are safely inside the vault — no `.migrated`
backup kept (a decision made explicitly for this project's current
stage, not a general policy).
"""

import os
import sqlite3

from .database import VaultDatabase


def migrate_plaintext_trust_db(vault_db: VaultDatabase, old_trust_db_path: str) -> int:
    """Copy trusted_devices + identity_transitions rows from the old
    plaintext trust.db into vault_db, then delete the old file.

    Returns the number of trusted_devices rows migrated. A no-op
    (returns 0) if old_trust_db_path doesn't exist — most installs
    running this for the first time won't have one.
    """
    if not os.path.exists(old_trust_db_path):
        return 0

    old_conn = sqlite3.connect(old_trust_db_path)
    try:
        old_conn.row_factory = sqlite3.Row
        device_rows = old_conn.execute("SELECT * FROM trusted_devices").fetchall()
        try:
            transition_rows = old_conn.execute("SELECT * FROM identity_transitions").fetchall()
        except sqlite3.OperationalError:
            # Pre-Phase-40 trust.db files won't have this table at all.
            transition_rows = []
    finally:
        old_conn.close()

    for row in device_rows:
        vault_db.conn.execute(
            """INSERT OR REPLACE INTO trusted_devices
               (device_id, public_key, name, first_seen, last_seen, status,
                revoked_by, revoked_at, revoke_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["device_id"], row["public_key"], row["name"], row["first_seen"],
                row["last_seen"], row["status"], row["revoked_by"], row["revoked_at"],
                row["revoke_reason"],
            ),
        )

    for row in transition_rows:
        vault_db.conn.execute(
            """INSERT OR REPLACE INTO identity_transitions
               (old_device_id, new_device_id, old_public_key, new_public_key,
                timestamp, signature, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                row["old_device_id"], row["new_device_id"], row["old_public_key"],
                row["new_public_key"], row["timestamp"], row["signature"], row["recorded_at"],
            ),
        )

    vault_db.conn.commit()
    vault_db.flush()

    # No real users yet — per project decision, retire the old plaintext
    # file outright rather than keeping a .migrated backup.
    os.remove(old_trust_db_path)

    return len(device_rows)
