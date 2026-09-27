"""core/connection_state.py — Phase 33.1: Connection lifecycle state machine.

RELIABILITY_DESIGN.md §6.1:

    NEW -> TCP_CONNECTED -> HANDSHAKING -> AUTHENTICATED -> ESTABLISHED
                                                       \\-> CLOSING -> CLOSED
    NEW/TCP_CONNECTED/HANDSHAKING --------------------> CLOSING -> CLOSED
    ESTABLISHED --------------------------------------> CLOSING -> CLOSED

This is an internal safety contract, not a wire message — nothing here
changes what bytes go on the wire. `transition_to()` is the only way to
mutate state; illegal transitions raise, but CLOSING/CLOSED are
idempotent (a late frame, timeout, or duplicate close cannot revive a
connection or raise). A trust decision (PENDING/TRUSTED/REVOKED) is
separate state entirely — this module knows nothing about trust.
"""

import enum
from typing import FrozenSet


class ConnectionState(enum.Enum):
    NEW = "new"
    TCP_CONNECTED = "tcp_connected"
    HANDSHAKING = "handshaking"
    AUTHENTICATED = "authenticated"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


class InvalidConnectionTransition(Exception):
    """Raised by transition_to() for a transition not in the table below
    — e.g. skipping a step, or trying to leave a terminal state for
    anything other than idempotently re-entering it."""


# The adjacency table, straight from §6.1's diagram. CLOSING/CLOSED are
# reachable from every non-terminal state (a connection can die at any
# point in its life), and each terminal state's only "next" state is
# itself — that's what makes re-closing/re-timing-out a no-op instead of
# an error.
_ALLOWED_TRANSITIONS: dict[ConnectionState, FrozenSet[ConnectionState]] = {
    ConnectionState.NEW: frozenset({ConnectionState.TCP_CONNECTED, ConnectionState.CLOSING}),
    ConnectionState.TCP_CONNECTED: frozenset({ConnectionState.HANDSHAKING, ConnectionState.CLOSING}),
    ConnectionState.HANDSHAKING: frozenset({ConnectionState.AUTHENTICATED, ConnectionState.CLOSING}),
    ConnectionState.AUTHENTICATED: frozenset({ConnectionState.ESTABLISHED, ConnectionState.CLOSING}),
    ConnectionState.ESTABLISHED: frozenset({ConnectionState.CLOSING}),
    ConnectionState.CLOSING: frozenset({ConnectionState.CLOSING, ConnectionState.CLOSED}),
    ConnectionState.CLOSED: frozenset({ConnectionState.CLOSED}),
}


class ConnectionStateMachine:
    """One instance per connection (attach it to the session object, or
    keep it in a manager-level dict keyed by addr_key — either way,
    exactly one owner). Not thread-safe by design: like the rest of
    peerc's async code, this is only ever touched from the event-loop
    thread."""

    def __init__(self) -> None:
        self._state = ConnectionState.NEW

    @property
    def state(self) -> ConnectionState:
        return self._state

    def is_established(self) -> bool:
        return self._state is ConnectionState.ESTABLISHED

    def is_terminal(self) -> bool:
        return self._state in (ConnectionState.CLOSING, ConnectionState.CLOSED)

    def transition_to(self, new_state: ConnectionState) -> None:
        current = self._state
        if new_state not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidConnectionTransition(
                f"cannot transition from {current.value} to {new_state.value}"
            )
        self._state = new_state

    def require_established(self, what: str = "this operation") -> None:
        """Guard for accepting application JSON, binary transfer frames,
        or relay bytes — §6.1: "accepted only after the relevant
        transport layer is established." Call this before dispatching an
        inbound application-level frame; it raises rather than silently
        processing data against a connection that isn't (or no longer
        is) ESTABLISHED."""
        if not self.is_established():
            raise InvalidConnectionTransition(
                f"{what} requires an ESTABLISHED connection, currently {self._state.value}"
            )
