"""core/identity/identity_file.py — the Phase 3.3 identity file + load_or_create.

Two things are persisted, deliberately kept apart:
  - the PRIVATE key, via KeyStore (core/identity/key_storage.py) — OS
    keyring, or a 0600 plaintext file fallback. Never written into the
    identity JSON file below.
  - PUBLIC metadata — device_id, public_key, display name, created_at —
    in a plain JSON file. Safe to read, back up, or hand to another peer;
    it contains nothing secret.

This is the direct replacement for discovery.py's old
load_or_create_identity(), which generated a bare random UUID. See
Phase 3.0 in IMPLEMENTATION_PLAN.md for why that wasn't good enough.
"""

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rotation import TransitionCertificate

from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit
from .device_identity import DeviceKeypair, generate_keypair, keypair_from_private_pem
from .key_storage import KeyStore

IDENTITY_SCHEMA_VERSION = 1
DEFAULT_IDENTITY_DIR = os.path.expanduser("~/.peerc")
DEFAULT_IDENTITY_FILE = os.path.join(DEFAULT_IDENTITY_DIR, "identity.json")
KEYRING_USERNAME = "device-identity"  # one identity per device, so this is a fixed key


class IdentityError(Exception):
    """Raised when the identity file and key storage disagree or are corrupt."""


@dataclass
class DeviceIdentity:
    keypair: DeviceKeypair
    name: str
    created_at: float
    storage_backend: str  # "keyring" or "plaintext-file" — worth surfacing to the user
    is_new: bool = False  # True only for the load_or_create_identity() call that
    # generated this identity for the very first time — lets callers (ui.py) show
    # a first-run "set your name" prompt exactly once, never on subsequent loads.

    @property
    def device_id(self) -> str:
        return self.keypair.device_id


def load_or_create_identity(
    name: str | None = None,
    identity_file: str = DEFAULT_IDENTITY_FILE,
    key_store: KeyStore | None = None,
) -> DeviceIdentity:
    """Load the existing device identity, or generate one on first run.

    `name` is only used on first run (to set the initial display name);
    on subsequent runs the name stored in the identity file wins, matching
    the old UUID-based load_or_create_identity()'s behavior.
    """
    key_store = key_store or KeyStore()

    if os.path.exists(identity_file):
        return _load_existing(identity_file, key_store)
    return _create_new(name or "peer", identity_file, key_store)


def _load_existing(identity_file: str, key_store: KeyStore) -> DeviceIdentity:
    with open(identity_file, "r") as f:
        meta = json.load(f)

    pem = key_store.load_private_key(KEYRING_USERNAME)
    if pem is None:
        raise IdentityError(
            f"identity file {identity_file!r} exists but its private key is "
            "missing from storage — the device's identity can't be proven "
            "without it. If the key is genuinely gone, delete the identity "
            "file to generate a fresh identity (this changes your device_id)."
        )

    keypair = keypair_from_private_pem(pem)
    if keypair.device_id != meta.get("device_id"):
        raise IdentityError(
            f"stored private key does not match device_id in {identity_file!r} "
            "— identity file and key storage are out of sync"
        )

    return DeviceIdentity(
        keypair=keypair,
        name=meta.get("name") or "peer",
        created_at=meta.get("created_at", time.time()),
        storage_backend=key_store.backend_name,
        is_new=False,
    )


def _create_new(name: str, identity_file: str, key_store: KeyStore) -> DeviceIdentity:
    keypair = generate_keypair()
    created_at = time.time()

    backend_used = key_store.save_private_key(KEYRING_USERNAME, keypair.private_key_pem())

    directory = os.path.dirname(identity_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    meta = {
        "version": IDENTITY_SCHEMA_VERSION,
        "device_id": keypair.device_id,
        "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
        "name": name,
        "created_at": created_at,
    }
    with open(identity_file, "w") as f:
        json.dump(meta, f, indent=2)

    return DeviceIdentity(keypair=keypair, name=name, created_at=created_at, storage_backend=backend_used, is_new=True)


def rotate_identity(
    current: "DeviceIdentity",
    new_name: str | None = None,
    identity_file: str = DEFAULT_IDENTITY_FILE,
    key_store: KeyStore | None = None,
) -> tuple["DeviceIdentity", "TransitionCertificate"]:
    """Replace the device's Ed25519 keypair and produce a Transition Certificate.

    The old private key signs the new public key before being discarded, so
    any peer that already trusts this device can verify the rotation and carry
    TRUSTED status forward to the new device_id automatically — no fresh TOFU
    needed (SECURITY_MODEL.md §15).

    Returns (new_DeviceIdentity, TransitionCertificate).  The caller is
    responsible for passing the certificate to TrustStore.record_rotation()
    and for distributing the cert to peers (e.g. via the handshake protocol).

    This is PLANNED rotation only — for a compromise-triggered rotation
    simply call load_or_create_identity() after deleting the identity file,
    and do NOT create a TransitionCertificate from the compromised key.
    """
    # Import here to avoid circular imports between identity and rotation.
    from .rotation import TransitionCertificate, create_transition_certificate

    key_store = key_store or KeyStore()

    # 1. Generate the new keypair BEFORE touching any stored state.
    new_keypair = generate_keypair()

    # 2. Produce the certificate while the old private key is still in memory.
    cert: TransitionCertificate = create_transition_certificate(current.keypair, new_keypair)

    # 3. Persist the new private key (overwrites the old one under the same
    #    username — there is only ever one active identity key).
    backend_used = key_store.save_private_key(KEYRING_USERNAME, new_keypair.private_key_pem())

    # 4. Overwrite identity.json with new public metadata, recording where we
    #    rotated from so the file is self-documenting.
    name = new_name or current.name
    created_at = time.time()

    directory = os.path.dirname(identity_file)
    if directory:
        os.makedirs(directory, exist_ok=True)

    meta = {
        "version": IDENTITY_SCHEMA_VERSION,
        "device_id": new_keypair.device_id,
        "public_key": base64.b64encode(new_keypair.public_key_bytes()).decode("ascii"),
        "name": name,
        "created_at": created_at,
        "rotated_from": current.keypair.device_id,
    }
    with open(identity_file, "w") as f:
        json.dump(meta, f, indent=2)

    new_identity = DeviceIdentity(
        keypair=new_keypair,
        name=name,
        created_at=created_at,
        storage_backend=backend_used,
    )
    emit(
        SecurityEvent(
            event_type=SecurityEventType.KEY_ROTATION,
            severity=SecuritySeverity.INFO,
            description=f"local device identity rotated from {current.keypair.device_id} to {new_keypair.device_id}",
            device_id=new_keypair.device_id,
            details={"old_device_id": current.keypair.device_id, "new_device_id": new_keypair.device_id},
        )
    )
    return new_identity, cert

