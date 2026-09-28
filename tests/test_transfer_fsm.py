"""tests/test_transfer_fsm.py — Phase 34.1: Transfer lifecycle FSMs.

Unit tests for core/transfer_state.py in isolation: happy paths for both
directions, illegal transitions (duplicate accept, chunk after
terminal), idempotent terminal states, and the resume sub-cycle.
"""

import pytest

from core.transfer_state import (
    IncomingTransferState,
    IncomingTransferStateMachine,
    InvalidTransferTransition,
    OutgoingTransferState,
    OutgoingTransferStateMachine,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------
# Outgoing
# ---------------------------------------------------------------------

def test_outgoing_starts_offered():
    fsm = OutgoingTransferStateMachine()
    assert fsm.state is OutgoingTransferState.OFFERED
    assert not fsm.is_terminal()


def test_outgoing_happy_path_to_completed():
    fsm = OutgoingTransferStateMachine()
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm.transition_to(OutgoingTransferState.SENDING)
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_COMPLETE_ACK)
    fsm.transition_to(OutgoingTransferState.COMPLETED)
    assert fsm.state is OutgoingTransferState.COMPLETED
    assert fsm.is_terminal()


def test_outgoing_rejected_only_reachable_from_waiting_for_accept():
    fsm = OutgoingTransferStateMachine()
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm.transition_to(OutgoingTransferState.REJECTED)
    assert fsm.state is OutgoingTransferState.REJECTED
    assert fsm.is_terminal()

    # Once SENDING, a "reject" no longer makes sense — the peer already accepted.
    fsm2 = OutgoingTransferStateMachine()
    fsm2.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm2.transition_to(OutgoingTransferState.SENDING)
    with pytest.raises(InvalidTransferTransition):
        fsm2.transition_to(OutgoingTransferState.REJECTED)


def test_outgoing_duplicate_accept_after_sending_is_illegal():
    """A second file_accept for a transfer already SENDING (or further
    along) must be rejected, not silently re-processed."""
    fsm = OutgoingTransferStateMachine()
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm.transition_to(OutgoingTransferState.SENDING)
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(OutgoingTransferState.SENDING)  # duplicate accept


def test_outgoing_cannot_skip_waiting_for_accept():
    fsm = OutgoingTransferStateMachine()
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(OutgoingTransferState.SENDING)


@pytest.mark.parametrize(
    "terminal",
    [OutgoingTransferState.FAILED, OutgoingTransferState.REJECTED, OutgoingTransferState.CANCELLED],
)
def test_outgoing_terminal_states_are_idempotent(terminal):
    fsm = OutgoingTransferStateMachine()
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm.transition_to(terminal)
    fsm.transition_to(terminal)  # duplicate/late signal — no-op, not an error
    assert fsm.state is terminal
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(OutgoingTransferState.SENDING)  # cannot be revived


def test_outgoing_completed_is_idempotent():
    fsm = OutgoingTransferStateMachine()
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_ACCEPT)
    fsm.transition_to(OutgoingTransferState.SENDING)
    fsm.transition_to(OutgoingTransferState.WAITING_FOR_COMPLETE_ACK)
    fsm.transition_to(OutgoingTransferState.COMPLETED)
    fsm.transition_to(OutgoingTransferState.COMPLETED)  # duplicate/late ack — no-op
    assert fsm.state is OutgoingTransferState.COMPLETED
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(OutgoingTransferState.SENDING)  # cannot be revived


# ---------------------------------------------------------------------
# Incoming
# ---------------------------------------------------------------------

def test_incoming_starts_offered():
    fsm = IncomingTransferStateMachine()
    assert fsm.state is IncomingTransferState.OFFERED


def test_incoming_happy_path_to_completed():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.VERIFYING)
    fsm.transition_to(IncomingTransferState.COMPLETED)
    assert fsm.state is IncomingTransferState.COMPLETED
    assert fsm.is_terminal()


def test_incoming_receiving_self_loop_for_repeat_chunks():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.RECEIVING)  # next chunk — must not raise
    fsm.transition_to(IncomingTransferState.RECEIVING)  # and again
    assert fsm.state is IncomingTransferState.RECEIVING


def test_incoming_chunk_after_terminal_state_is_rejected():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.FAILED)  # e.g. out-of-order chunk aborted it
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(IncomingTransferState.RECEIVING)  # a further chunk arrives late


def test_incoming_pause_resume_cycle():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.PAUSED)
    fsm.transition_to(IncomingTransferState.RESUMING)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.VERIFYING)
    fsm.transition_to(IncomingTransferState.COMPLETED)
    assert fsm.state is IncomingTransferState.COMPLETED


def test_incoming_can_be_cancelled_while_paused():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.PAUSED)
    fsm.transition_to(IncomingTransferState.CANCELLED)
    assert fsm.state is IncomingTransferState.CANCELLED
    assert fsm.is_terminal()


@pytest.mark.parametrize(
    "terminal",
    [IncomingTransferState.FAILED, IncomingTransferState.REJECTED,
     IncomingTransferState.CANCELLED, IncomingTransferState.EXPIRED],
)
def test_incoming_terminal_states_are_idempotent(terminal):
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(terminal)  # reachable directly from OFFERED
    fsm.transition_to(terminal)  # duplicate signal — no-op
    assert fsm.state is terminal
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(IncomingTransferState.ACCEPTED)


def test_incoming_completed_is_idempotent():
    fsm = IncomingTransferStateMachine()
    fsm.transition_to(IncomingTransferState.ACCEPTED)
    fsm.transition_to(IncomingTransferState.RECEIVING)
    fsm.transition_to(IncomingTransferState.VERIFYING)
    fsm.transition_to(IncomingTransferState.COMPLETED)
    fsm.transition_to(IncomingTransferState.COMPLETED)  # duplicate file_done — no-op
    assert fsm.state is IncomingTransferState.COMPLETED
    with pytest.raises(InvalidTransferTransition):
        fsm.transition_to(IncomingTransferState.ACCEPTED)
