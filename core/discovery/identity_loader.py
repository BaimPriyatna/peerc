"""core/discovery/identity_loader.py — legacy identity-loading adapters.

Phase 3: peer_id is a device_id derived from an Ed25519 keypair
(core/identity/), not a random UUID — see core/identity/device_identity.py
for why a bare UUID isn't good enough (anyone could claim any UUID; a
device_id is provably tied to the key that backs it). These helpers keep the
old (peer_id, name) tuple shape so callers didn't need to change, but what is
inside peer_id changed completely.
"""

import json
import os
import socket

import core.identity as identity


def save_identity(peer_id: str, name: str, config_path: str = identity.DEFAULT_IDENTITY_FILE) -> None:
    """Update the display name in the identity file (used by ui.py's /name
    rename command).

    peer_id is accepted for backward compatibility with the pre-Phase-3
    call signature but is no longer something this function can change:
    device_id is derived from the Ed25519 keypair, not freely assignable.
    If the caller's peer_id doesn't match what's on file, that's a sign
    something's out of sync — better to raise than silently ignore it.
    """
    if not os.path.exists(config_path):
        return  # nothing to rename yet — load_or_create_identity() creates it first

    with open(config_path, "r") as f:
        meta = json.load(f)

    if meta.get("device_id") != peer_id:
        raise ValueError(
            f"save_identity called with peer_id={peer_id!r}, but the identity "
            f"file's device_id is {meta.get('device_id')!r} — refusing to "
            "rename what looks like a different identity"
        )

    meta["name"] = name
    with open(config_path, "w") as f:
        json.dump(meta, f, indent=2)


def load_or_create_identity(config_path: str = identity.DEFAULT_IDENTITY_FILE) -> tuple[str, str]:
    """Return (peer_id, name).

    peer_id is now an Ed25519-derived device_id (Phase 3) — generated and
    persisted via core.identity on first run, loaded from the same file on
    every run after. Old pre-Phase-3 identity files (a bare
    {"peer_id": <uuid>, "name": ...} at .peerc_identity.json) are not
    migrated: they used a fundamentally different scheme with no keypair
    behind them, so there's nothing to carry forward. A device upgrading
    to this version gets a new device_id the first time it runs.
    """
    dev_identity = identity.load_or_create_identity(
        name=socket.gethostname(), identity_file=config_path,
    )
    return dev_identity.device_id, dev_identity.name
