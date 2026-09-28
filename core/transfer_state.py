"""core/transfer_state.py — Phase 34.1: Transfer lifecycle state machines.

RELIABILITY_DESIGN.md §6.2:

    Outgoing:
    OFFERED -> WAITING_FOR_ACCEPT -> SENDING -> WAITING_FOR_COMPLETE_ACK -> COMPLETED
                     |                    |                 |
                     +--------------------+-----------------+-> FAILED
                     +---------------------------------------> REJECTED
                     +---------------------------------------> CANCELLED

    Incoming:
    OFFERED -> ACCEPTED -> RECEIVING -> VERIFYING -> COMPLETED
       |           |            |             |
       +-----------+------------+-------------+-> REJECTED / CANCELLED / FAILED / EXPIRED
    RECEIVING -> PAUSED -> RESUMING -> RECEIVING

Only the transfer coordinator (file_transfer.py's FileTransferSession)
changes state — file/chunk helpers report outcomes, they do not
independently invent terminal states. transition_to() is the only
mutator; an illegal transition (duplicate accept, late completion ack,
chunk after a terminal state) raises InvalidTransferTransition rather
than silently overwriting whatever the transfer was already resolved
to. Terminal states are idempotent (re-entering one is a no-op).

Scoping note: PAUSED/RESUMING are modeled here per the diagram, but
nothing in file_transfer.py drives them yet — there's no pause/resume
feature wired in (core/transfer/resume.py exists but isn't used by the
live transfer path). They're legal-but-currently-unreachable target
states, ready for when that feature is built, same as how
CANCELLED/REJECTED/EXPIRED cover outcomes no current UI command
triggers yet either.
"""

import enum
from typing import Dict, FrozenSet


class InvalidTransferTransition(Exception):
    """Raised by transition_to() for a transition not in the relevant
    table — a duplicate accept, a late completion ack, a chunk after a
    terminal state, or any other move the transfer coordinator didn't
    itself request in order."""


class OutgoingTransferState(enum.Enum):
    OFFERED = "offered"
    WAITING_FOR_ACCEPT = "waiting_for_accept"
    SENDING = "sending"
    WAITING_FOR_COMPLETE_ACK = "waiting_for_complete_ack"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


_OUTGOING_TRANSITIONS: Dict[OutgoingTransferState, FrozenSet[OutgoingTransferState]] = {
    OutgoingTransferState.OFFERED: frozenset({OutgoingTransferState.WAITING_FOR_ACCEPT}),
    OutgoingTransferState.WAITING_FOR_ACCEPT: frozenset({
        OutgoingTransferState.SENDING,
        OutgoingTransferState.FAILED,
        OutgoingTransferState.REJECTED,
        OutgoingTransferState.CANCELLED,
    }),
    OutgoingTransferState.SENDING: frozenset({
        OutgoingTransferState.WAITING_FOR_COMPLETE_ACK,
        OutgoingTransferState.FAILED,
        OutgoingTransferState.CANCELLED,
    }),
    OutgoingTransferState.WAITING_FOR_COMPLETE_ACK: frozenset({
        OutgoingTransferState.COMPLETED,
        OutgoingTransferState.FAILED,
        OutgoingTransferState.CANCELLED,
    }),
    OutgoingTransferState.COMPLETED: frozenset({OutgoingTransferState.COMPLETED}),
    OutgoingTransferState.FAILED: frozenset({OutgoingTransferState.FAILED}),
    OutgoingTransferState.REJECTED: frozenset({OutgoingTransferState.REJECTED}),
    OutgoingTransferState.CANCELLED: frozenset({OutgoingTransferState.CANCELLED}),
}


class IncomingTransferState(enum.Enum):
    OFFERED = "offered"
    ACCEPTED = "accepted"
    RECEIVING = "receiving"
    PAUSED = "paused"
    RESUMING = "resuming"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"
    EXPIRED = "expired"


_INCOMING_TERMINAL_OUTCOMES = frozenset({
    IncomingTransferState.REJECTED,
    IncomingTransferState.CANCELLED,
    IncomingTransferState.FAILED,
    IncomingTransferState.EXPIRED,
})

_INCOMING_TRANSITIONS: Dict[IncomingTransferState, FrozenSet[IncomingTransferState]] = {
    IncomingTransferState.OFFERED: frozenset(
        {IncomingTransferState.ACCEPTED} | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.ACCEPTED: frozenset(
        {IncomingTransferState.RECEIVING} | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.RECEIVING: frozenset(
        {IncomingTransferState.RECEIVING, IncomingTransferState.VERIFYING, IncomingTransferState.PAUSED}
        | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.PAUSED: frozenset(
        {IncomingTransferState.RESUMING} | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.RESUMING: frozenset(
        {IncomingTransferState.RECEIVING} | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.VERIFYING: frozenset(
        {IncomingTransferState.COMPLETED} | _INCOMING_TERMINAL_OUTCOMES
    ),
    IncomingTransferState.COMPLETED: frozenset({IncomingTransferState.COMPLETED}),
    IncomingTransferState.REJECTED: frozenset({IncomingTransferState.REJECTED}),
    IncomingTransferState.CANCELLED: frozenset({IncomingTransferState.CANCELLED}),
    IncomingTransferState.FAILED: frozenset({IncomingTransferState.FAILED}),
    IncomingTransferState.EXPIRED: frozenset({IncomingTransferState.EXPIRED}),
}


class _TransferStateMachine:
    """Shared mechanics for both directions — one instance per transfer
    object (OutgoingTransfer/IncomingTransfer), not shared across
    transfers. Not thread-safe by design, like the rest of peerc's async
    code: only ever touched from the event-loop thread."""

    def __init__(self, initial_state, table) -> None:
        self._state = initial_state
        self._table = table

    @property
    def state(self):
        return self._state

    def is_terminal(self) -> bool:
        return self._table[self._state] == frozenset({self._state})

    def transition_to(self, new_state) -> None:
        current = self._state
        if new_state not in self._table[current]:
            raise InvalidTransferTransition(
                f"cannot transition from {current.value} to {new_state.value}"
            )
        self._state = new_state


class OutgoingTransferStateMachine(_TransferStateMachine):
    def __init__(self) -> None:
        super().__init__(OutgoingTransferState.OFFERED, _OUTGOING_TRANSITIONS)


class IncomingTransferStateMachine(_TransferStateMachine):
    def __init__(self) -> None:
        super().__init__(IncomingTransferState.OFFERED, _INCOMING_TRANSITIONS)
