"""core/app_errors.py — Phase 35.2: shared helpers for handling `error`.

The schema and contracts live in core/protocol/error_codes.py (35.1);
this is the thin, logging-aware layer sessions use when an `error` frame
arrives. Everything here follows RELIABILITY_DESIGN.md §7.3: validate the
schema first, then let the owner of the referenced operation decide
whether the code contract makes it terminal; unsolicited, duplicate or
late errors are logged at debug level and change nothing.

Never sends anything — and by design nothing that handles an `error`
ever sends one back, so two peers can't ping-pong errors at each other.
"""

import logging
from typing import Any, Optional

from core.protocol import ErrorInfo, ProtocolError, parse_error_message
from core.protocol.error_codes import sanitize_for_log

logger = logging.getLogger("peerc.errors")


def parse_or_log(message: Any) -> Optional[ErrorInfo]:
    """Parse a received `error`; a malformed one is logged (sanitized) at
    debug level and ignored — the connection-level validate_message() has
    already had its say about whether the frame is acceptable."""
    try:
        info = parse_error_message(message)
    except ProtocolError as exc:
        logger.debug("ignoring malformed error frame: %s", sanitize_for_log(str(exc)))
        return None
    if not info.known:
        logger.debug(
            "peer sent unrecognized error code %s (treated as INTERNAL_ERROR)",
            sanitize_for_log(info.raw_code, limit=64),
        )
    return info


def log_not_applied(info: ErrorInfo, reason: str) -> None:
    """An error that was valid but didn't change any state (unsolicited,
    duplicate, late, from the wrong peer, or a non-terminal code)."""
    logger.debug(
        "error %s not applied: %s", info.code.value, reason,
        extra={"error_code": info.code.value},
    )
