"""core/protocol/error_codes.py — Phase 35.1: Application error schema.

RELIABILITY_DESIGN.md §7: `error` is an encrypted post-handshake
application message with a closed code set, a plain-language message, and
an allowlisted `context`. This module owns the *shape and contract* of
that message — it has no I/O and no dependency on frame.py/messages.py
internals, so both the sender side (build_error) and the receiver side
(parse_error_message) share one definition.

Safety rules enforced here, not left to each call site:
  - `context` is limited to correlation identifiers (message_id,
    transfer_id, group_id) and a bounded retry hint (retry_after). Any
    other key, and any value that doesn't look like a plain identifier,
    is dropped — a traceback, local path, peer address, key material or
    raw exception text cannot ride along in context.
  - A sender-supplied `message` that looks like a traceback, path,
    address or key/secret material is replaced by the code's canonical
    plain-language text.
  - The receiver never displays the peer's `message` at all: it shows the
    *local* canonical text for the code, so a hostile peer can't inject
    misleading text or terminal escapes. The peer's text is only ever
    logged, sanitized and truncated. An unknown code is displayed as
    INTERNAL_ERROR and its raw value is logged (sanitized).

`error` is never sent during an unauthenticated handshake (those paths
close with local logging only, to avoid an oracle), and never in reply to
another `error` — enforcing that is the sender's job (35.2).
"""

import enum
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from .errors import ProtocolError

MAX_ERROR_MESSAGE_LEN = 512      # receiver rejects anything longer as malformed
MAX_SENT_MESSAGE_LEN = 200       # sender-side canonical texts stay well under this
MAX_CODE_LEN = 64
MAX_CONTEXT_ID_LEN = 128
MAX_RETRY_AFTER_SECONDS = 3600


class ErrorCode(enum.Enum):
    AUTH_FAILED = "AUTH_FAILED"
    POLICY_DENIED = "POLICY_DENIED"
    PROTOCOL_MISMATCH = "PROTOCOL_MISMATCH"
    INVALID_FRAME = "INVALID_FRAME"
    INVALID_STATE = "INVALID_STATE"
    TRANSFER_NOT_FOUND = "TRANSFER_NOT_FOUND"
    SIZE_EXCEEDED = "SIZE_EXCEEDED"
    DISK_FULL = "DISK_FULL"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    TRANSFER_EXPIRED = "TRANSFER_EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class ErrorContract:
    """What a code *means* to the receiver (§7.2's table)."""

    text: str                       # canonical plain-language message
    retryable: bool                 # UI may offer a retry action
    terminal: bool                  # marks a correlated operation terminal
    retry_hint: Optional[str] = None  # plain-language "what to do next"


# terminal=False only where §7.2 says state may simply be refreshed
# (INVALID_STATE) or the peer is applying a temporary limit (RATE_LIMITED).
# Everything else means the referenced operation did not and will not
# succeed as asked.
CONTRACTS: Dict[ErrorCode, ErrorContract] = {
    ErrorCode.AUTH_FAILED: ErrorContract(
        "The peer did not permit that request.", retryable=False, terminal=True,
    ),
    ErrorCode.POLICY_DENIED: ErrorContract(
        "A policy on the peer's side denied that request.", retryable=False, terminal=True,
        retry_hint="This needs a policy change before it can work.",
    ),
    ErrorCode.PROTOCOL_MISMATCH: ErrorContract(
        "The peer cannot process that request with its current version.",
        retryable=False, terminal=True,
        retry_hint="Reconnect after both sides are on a compatible version.",
    ),
    ErrorCode.INVALID_FRAME: ErrorContract(
        "The peer could not understand a message that was sent to it.",
        retryable=False, terminal=True,
    ),
    ErrorCode.INVALID_STATE: ErrorContract(
        "That request does not fit what the peer is currently doing.",
        retryable=True, terminal=False,
        retry_hint="Check the current state, then try again.",
    ),
    ErrorCode.TRANSFER_NOT_FOUND: ErrorContract(
        "The requested transfer is no longer available.", retryable=False, terminal=True,
    ),
    ErrorCode.SIZE_EXCEEDED: ErrorContract(
        "That transfer is larger than the peer allows.", retryable=False, terminal=True,
        retry_hint="Choose a smaller file.",
    ),
    ErrorCode.DISK_FULL: ErrorContract(
        "The peer does not have enough free space.", retryable=True, terminal=True,
        retry_hint="Try again once the peer has freed up space.",
    ),
    ErrorCode.CHECKSUM_MISMATCH: ErrorContract(
        "The received file failed verification.", retryable=False, terminal=True,
        retry_hint="Send the file again to restart the transfer.",
    ),
    ErrorCode.TRANSFER_EXPIRED: ErrorContract(
        "That transfer offer has expired.", retryable=True, terminal=True,
        retry_hint="Start a new offer.",
    ),
    ErrorCode.RATE_LIMITED: ErrorContract(
        "The peer is temporarily limiting requests.", retryable=True, terminal=False,
        retry_hint="Wait a moment, then try again.",
    ),
    ErrorCode.INTERNAL_ERROR: ErrorContract(
        "The peer hit an unexpected problem.", retryable=False, terminal=True,
    ),
}

# Every code must have a contract — checked at import so a code added to
# the enum without one fails loudly rather than at first use.
assert set(CONTRACTS) == set(ErrorCode), "every ErrorCode needs an ErrorContract"


# ---------------------------------------------------------------------
# Context filtering
# ---------------------------------------------------------------------

_ID_KEYS = ("message_id", "transfer_id", "group_id")
ALLOWED_CONTEXT_KEYS = frozenset(_ID_KEYS) | {"retry_after"}
_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,%d}$" % MAX_CONTEXT_ID_LEN)


def filter_context(context: Any) -> Dict[str, Any]:
    """Keep only allowlisted keys whose values look like what they claim
    to be. Never raises: anything else is dropped, because this runs on
    both the sending side (a caller's bug must not leak) and the
    receiving side (a peer's payload is untrusted)."""
    if not isinstance(context, Mapping):
        return {}
    out: Dict[str, Any] = {}
    for key in _ID_KEYS:
        val = context.get(key)
        if isinstance(val, str) and _ID_RE.match(val):
            out[key] = val
    retry = context.get("retry_after")
    if (
        isinstance(retry, (int, float))
        and not isinstance(retry, bool)
        and 0 < retry <= MAX_RETRY_AFTER_SECONDS
    ):
        out["retry_after"] = retry
    return out


# ---------------------------------------------------------------------
# Message text safety
# ---------------------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SUSPICIOUS_RES = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"traceback \(most recent call",   # python traceback
        r'file "[^"]+", line \d+',          # traceback frame
        r"(^|[\s'\"(])(/[\w.\-]+){2,}",     # unix-style path with 2+ segments
        r"[A-Za-z]:\\[\w\\.\-]+",           # windows path
        r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b",  # ipv4[:port]
        r"\b[0-9a-f]{32,}\b",               # long hex run (keys, hashes)
        r"[A-Za-z0-9+/_\-]{40,}={0,2}",     # long base64/base64url-ish run
        r"\b\w+(Error|Exception)\b:",        # raw exception text
    )
)


def sanitize_for_log(value: Any, limit: int = 120) -> str:
    """Make an untrusted value safe to put in a log line: coerce to str,
    strip control characters, truncate."""
    text = value if isinstance(value, str) else repr(value)
    text = _CONTROL_RE.sub("?", text)
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def is_safe_message(text: Any) -> bool:
    """Heuristic screen for a sender-supplied message. Not a proof — it's
    a backstop behind the real defense (senders use canonical text)."""
    if not isinstance(text, str) or not text.strip():
        return False
    if len(text) > MAX_SENT_MESSAGE_LEN or _CONTROL_RE.search(text):
        return False
    return not any(rx.search(text) for rx in _SUSPICIOUS_RES)


# ---------------------------------------------------------------------
# Sender side
# ---------------------------------------------------------------------

def coerce_code(code: Any) -> ErrorCode:
    if isinstance(code, ErrorCode):
        return code
    try:
        return ErrorCode(code)
    except ValueError:
        raise ValueError(f"unknown error code: {sanitize_for_log(code)}") from None


def build_error(
    code: Any,
    *,
    message: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
    version: int = 2,
) -> dict:
    """Build a wire-ready `error` message.

    An unknown `code` is a programming error and raises ValueError. A bad
    `context` or `message` never raises — this runs in failure paths where
    a second failure would mask the first — the unsafe parts are dropped
    or replaced by the canonical text instead."""
    ec = coerce_code(code)
    text = message if (message is not None and is_safe_message(message)) else CONTRACTS[ec].text
    out: Dict[str, Any] = {
        "type": "error",
        "version": version,
        "code": ec.value,
        "message": text,
    }
    ctx = filter_context(context)
    if ctx:
        out["context"] = ctx
    return out


# ---------------------------------------------------------------------
# Receiver side
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class ErrorInfo:
    """A validated, sanitized view of a received `error` message."""

    code: ErrorCode                 # INTERNAL_ERROR for an unknown raw_code
    raw_code: str                   # what the peer actually sent (log with sanitize_for_log)
    known: bool
    peer_message: str               # sanitized + truncated; for logs only, never displayed
    context: Dict[str, Any] = field(default_factory=dict)

    @property
    def display_text(self) -> str:
        return CONTRACTS[self.code].text

    @property
    def retryable(self) -> bool:
        return CONTRACTS[self.code].retryable

    @property
    def terminal(self) -> bool:
        return CONTRACTS[self.code].terminal

    @property
    def retry_hint(self) -> Optional[str]:
        return CONTRACTS[self.code].retry_hint

    @property
    def retry_after(self) -> Optional[float]:
        return self.context.get("retry_after")


def parse_error_message(message: Any) -> ErrorInfo:
    """Validate the schema of a received `error` and return a sanitized
    ErrorInfo. Raises ProtocolError (never KeyError/TypeError) if it's
    malformed. An unknown `code` is *not* malformed — a newer peer may
    have added one — it's reported as INTERNAL_ERROR with known=False."""
    if not isinstance(message, dict):
        raise ProtocolError("error message is not an object")
    if message.get("type") != "error":
        raise ProtocolError("not an 'error' message")

    raw_code = message.get("code")
    if not isinstance(raw_code, str) or not raw_code or len(raw_code) > MAX_CODE_LEN:
        raise ProtocolError("error.code must be a non-empty string")

    peer_message = message.get("message")
    if not isinstance(peer_message, str):
        raise ProtocolError("error.message must be a string")
    if len(peer_message) > MAX_ERROR_MESSAGE_LEN:
        raise ProtocolError(f"error.message exceeds {MAX_ERROR_MESSAGE_LEN} characters")

    raw_context = message.get("context")
    if raw_context is not None and not isinstance(raw_context, dict):
        raise ProtocolError("error.context must be an object when present")

    try:
        code, known = ErrorCode(raw_code), True
    except ValueError:
        code, known = ErrorCode.INTERNAL_ERROR, False

    return ErrorInfo(
        code=code,
        raw_code=raw_code,
        known=known,
        peer_message=sanitize_for_log(peer_message, limit=MAX_SENT_MESSAGE_LEN),
        context=filter_context(raw_context),
    )
