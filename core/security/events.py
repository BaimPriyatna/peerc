"""core/security/events.py — Phase 41: Security Event Logging.

Extends Phase 28 (Logging) with the severity classification and event types
defined in SECURITY_MODEL.md §29:

    INFO      — endpoint changed, normal key rotation
    WARNING   — unknown device, identity changed, failed authentication, invalid rotation
    HIGH      — revoked device attempted connection, repeated auth failures,
                 replay detected, suspicious authorization
    CRITICAL  — admin key compromise, identity private key compromise,
                 invalid authority chain

Principles:
  - Every module making a security-relevant decision emits a SecurityEvent
    at the decision point.
  - Zero sensitive leaks: private keys, session keys, and plaintext secrets
    must never be logged or recorded in event payloads.
  - Optionally signable for group authority audit trails (GROUP_AUTHORITY_DESIGN.md §13)
    via canonical_payload().
"""

import contextlib
import enum
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

# Domain separation prefix for signing security events (Phase 42 group audit).
_EVENT_DOMAIN = b"peerc-security-event\x00"

logger = logging.getLogger("peerc.security")

# Sensitive keys that must be redacted if accidentally passed in event details.
_SENSITIVE_KEYS = {
    "private_key",
    "session_key",
    "secret",
    "password",
    "key_hex",
    "seed",
    "token",
    "shared_secret",
}


class SecuritySeverity(str, enum.Enum):
    """Severity classification from SECURITY_MODEL.md §29."""

    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        _RANKS = {
            SecuritySeverity.INFO: 10,
            SecuritySeverity.WARNING: 20,
            SecuritySeverity.HIGH: 30,
            SecuritySeverity.CRITICAL: 40,
        }
        return _RANKS[self]

    def to_logging_level(self) -> int:
        """Map to standard library logging levels."""
        _LOG_MAP = {
            SecuritySeverity.INFO: logging.INFO,
            SecuritySeverity.WARNING: logging.WARNING,
            SecuritySeverity.HIGH: logging.ERROR,
            SecuritySeverity.CRITICAL: logging.CRITICAL,
        }
        return _LOG_MAP[self]

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, SecuritySeverity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        if isinstance(other, SecuritySeverity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, SecuritySeverity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: Any) -> bool:
        if isinstance(other, SecuritySeverity):
            return self.rank >= other.rank
        return NotImplemented


class SecurityEventType(str, enum.Enum):
    """Standard event types classified per SECURITY_MODEL.md §29."""

    # INFO
    ENDPOINT_CHANGED = "endpoint_changed"
    KEY_ROTATION = "key_rotation"
    POLICY_CHANGED = "policy_changed"

    # WARNING
    UNKNOWN_DEVICE = "unknown_device"
    IDENTITY_CHANGED = "identity_changed"
    AUTH_FAILED = "auth_failed"
    INVALID_ROTATION = "invalid_rotation"

    # HIGH
    REVOKED_DEVICE_ATTEMPT = "revoked_device_attempt"
    REPEATED_AUTH_FAILURES = "repeated_auth_failures"
    REPLAY_DETECTED = "replay_detected"
    SUSPICIOUS_AUTHORIZATION = "suspicious_authorization"
    POLICY_VIOLATION = "policy_violation"

    # CRITICAL
    ADMIN_KEY_COMPROMISE = "admin_key_compromise"
    PRIVATE_KEY_COMPROMISE = "private_key_compromise"
    INVALID_AUTHORITY_CHAIN = "invalid_authority_chain"


def _sanitize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return {
            k: ("[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEYS) else _sanitize_value(v))
            for k, v in val.items()
        }
    if isinstance(val, list):
        return [_sanitize_value(x) for x in val]
    return val


@dataclass
class SecurityEvent:
    """A structured, security-relevant occurrence in peerc.

    Optionally signable by an administrator or device key for group audit logs.
    """

    event_type: str
    severity: SecuritySeverity
    description: str
    device_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None       # base64(signature) for Phase 42 audit
    signer_device_id: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.event_type, SecurityEventType):
            self.event_type = self.event_type.value
        if isinstance(self.severity, str) and not isinstance(self.severity, SecuritySeverity):
            self.severity = SecuritySeverity(self.severity)
        self.details = _sanitize_value(self.details)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "event_type": self.event_type,
            "severity": self.severity.value,
            "description": self.description,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }
        if self.signature is not None:
            d["signature"] = self.signature
        if self.signer_device_id is not None:
            d["signer_device_id"] = self.signer_device_id
        return d

    def canonical_payload(self) -> bytes:
        """Deterministic canonical byte serialization for signing/verification.

        Format:
            _EVENT_DOMAIN              (b"peerc-security-event\\x00")
            timestamp                  (8 bytes, big-endian IEEE 754 double)
            NUL (0x00)
            severity.value             (UTF-8)
            NUL (0x00)
            event_type                 (UTF-8)
            NUL (0x00)
            device_id or ""            (UTF-8)
            NUL (0x00)
            description                (UTF-8)
            NUL (0x00)
            sorted details json        (UTF-8)
        """
        details_json = json.dumps(self.details, sort_keys=True, separators=(",", ":"))
        return (
            _EVENT_DOMAIN
            + struct.pack(">d", self.timestamp)
            + b"\x00"
            + self.severity.value.encode("utf-8")
            + b"\x00"
            + self.event_type.encode("utf-8")
            + b"\x00"
            + (self.device_id or "").encode("utf-8")
            + b"\x00"
            + self.description.encode("utf-8")
            + b"\x00"
            + details_json.encode("utf-8")
        )


# In-memory listeners for UI notifications, audit logs, and test assertions.
_LISTENERS: list[Callable[[SecurityEvent], None]] = []


def add_listener(listener: Callable[[SecurityEvent], None]) -> None:
    """Register a callback to be invoked on every emitted SecurityEvent."""
    if listener not in _LISTENERS:
        _LISTENERS.append(listener)


def remove_listener(listener: Callable[[SecurityEvent], None]) -> None:
    """Remove a previously registered callback."""
    if listener in _LISTENERS:
        _LISTENERS.remove(listener)


@contextlib.contextmanager
def capture_security_events() -> Iterator[list[SecurityEvent]]:
    """Context manager capturing all events emitted during its block.

    Useful for tests and scoped audit inspection.
    """
    captured: list[SecurityEvent] = []

    def _handler(ev: SecurityEvent) -> None:
        captured.append(ev)

    add_listener(_handler)
    try:
        yield captured
    finally:
        remove_listener(_handler)


def emit(event: SecurityEvent) -> None:
    """Emit a SecurityEvent to python logging and all registered listeners.

    Guaranteed never to raise an unhandled exception into the caller.
    """
    try:
        # Standard library logging
        log_lvl = event.severity.to_logging_level()
        msg = f"[{event.severity.value}] {event.event_type}: {event.description}"
        if event.device_id:
            msg += f" (device={event.device_id[:16]}...)"
        logger.log(log_lvl, msg)

        # Notify in-memory listeners
        for listener in list(_LISTENERS):
            try:
                listener(event)
            except Exception as e:
                logger.warning(f"Error in security event listener {listener}: {e}")
    except Exception as e:
        # Defensive: emission failure should never break security decisions
        pass
