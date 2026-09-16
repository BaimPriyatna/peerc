"""core.trust — SQLite trust store + TOFU + local revocation + key rotation (Phase 4/40).

    device.py     — TrustedDevice dataclass, TrustStatus enum
    store.py      — TrustStore: TOFU check()/record_first_seen()/approve()
                    Phase 40: record_rotation()/get_rotation_chain()/check_with_rotation()
    revocation.py — revoke_device()/is_revoked(): local-only for now
"""

from .device import TrustedDevice, TrustStatus
from .revocation import RevocationError, is_revoked, revoke_device
from .store import DEFAULT_DB_PATH, ExternalTrustDeniedError, TrustDecision, TrustStore

__all__ = [
    "TrustedDevice",
    "TrustStatus",
    "RevocationError",
    "is_revoked",
    "revoke_device",
    "DEFAULT_DB_PATH",
    "TrustDecision",
    "TrustStore",
    "ExternalTrustDeniedError",
    # key rotation (methods on TrustStore, re-exported for convenience)
    "record_rotation",
    "get_rotation_chain",
    "check_with_rotation",
]
