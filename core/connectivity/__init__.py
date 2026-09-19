"""core.connectivity — Internet P2P Connectivity (Phase 44).

    locator.py         — Endpoint/Locator dataclasses (pure data, no storage) —
                          deliberately separate from identity (device_id);
                          see docs/INTERNET_CONNECTIVITY_DESIGN.md §1-3
    store.py            — LocatorStore: SQLite-backed device_endpoints
                          (mirrors core/trust/store.py's shared-connection pattern)
    endpoint_update.py  — signed endpoint announcement + verification (§4),
                          reuses core.crypto.handshake.NonceCache for replay
                          protection; storage-agnostic, same split as
                          membership.py/admin.py
    link.py             — Add-by-Link (§3a): PIN-protected PEERC1: connection
                          links (Sign-then-Encrypt, Scrypt+AES-256-GCM reusing
                          core/vault/crypto.py's primitives) + terminal QR
                          rendering (optional `qrcode` dependency)

Phase 44 is now feature-complete per the design doc's core scope.
"""

from .endpoint_update import (
    DEFAULT_MAX_AGE_SECONDS,
    EndpointUpdate,
    EndpointUpdateError,
    create_endpoint_update,
    endpoint_update_to_endpoint,
    verify_endpoint_update,
)
from .link import (
    LINK_PREFIX,
    PIN_LENGTH,
    QRCODE_AVAILABLE,
    LinkError,
    LinkFormatError,
    LinkPayload,
    LinkSignatureError,
    QrCodeUnavailableError,
    WrongPinError,
    create_link,
    decode_link,
    generate_qr,
)
from .locator import (
    DEFAULT_STALE_SECONDS,
    KIND_DIRECT_V4,
    KIND_DIRECT_V6,
    KIND_RENDEZVOUS,
    VALID_KINDS,
    Endpoint,
    Locator,
    LocatorError,
)
from .store import DEFAULT_DB_PATH, LocatorStore, LocatorStoreError

__all__ = [
    "DEFAULT_STALE_SECONDS",
    "KIND_DIRECT_V4",
    "KIND_DIRECT_V6",
    "KIND_RENDEZVOUS",
    "VALID_KINDS",
    "Endpoint",
    "Locator",
    "LocatorError",
    "DEFAULT_DB_PATH",
    "LocatorStore",
    "LocatorStoreError",
    # Phase 44.2: signed endpoint announcement + verification
    "DEFAULT_MAX_AGE_SECONDS",
    "EndpointUpdate",
    "EndpointUpdateError",
    "create_endpoint_update",
    "endpoint_update_to_endpoint",
    "verify_endpoint_update",
    # Phase 44.3: Add-by-Link
    "LINK_PREFIX",
    "PIN_LENGTH",
    "QRCODE_AVAILABLE",
    "LinkError",
    "LinkFormatError",
    "LinkPayload",
    "LinkSignatureError",
    "QrCodeUnavailableError",
    "WrongPinError",
    "create_link",
    "decode_link",
    "generate_qr",
]
