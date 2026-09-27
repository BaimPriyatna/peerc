"""tests/test_connection_fsm.py — Phase 33.1: Connection lifecycle FSM.

Unit tests for core/connection_state.py in isolation (no networking):
the happy path, illegal skips, idempotent terminal states, and the
require_established() guard.
"""

import pytest

from core.connection_state import (
    ConnectionState,
    ConnectionStateMachine,
    InvalidConnectionTransition,
)

pytestmark = pytest.mark.unit


def test_starts_in_new():
    fsm = ConnectionStateMachine()
    assert fsm.state is ConnectionState.NEW
    assert not fsm.is_established()
    assert not fsm.is_terminal()


def test_happy_path_to_established():
    fsm = ConnectionStateMachine()
    fsm.transition_to(ConnectionState.TCP_CONNECTED)
    fsm.transition_to(ConnectionState.HANDSHAKING)
    fsm.transition_to(ConnectionState.AUTHENTICATED)
    fsm.transition_to(ConnectionState.ESTABLISHED)
    assert fsm.state is ConnectionState.ESTABLISHED
    assert fsm.is_established()
    assert not fsm.is_terminal()


def test_happy_path_to_closed():
    fsm = ConnectionStateMachine()
    for state in (
        ConnectionState.TCP_CONNECTED,
        ConnectionState.HANDSHAKING,
        ConnectionState.AUTHENTICATED,
        ConnectionState.ESTABLISHED,
        ConnectionState.CLOSING,
        ConnectionState.CLOSED,
    ):
        fsm.transition_to(state)
    assert fsm.state is ConnectionState.CLOSED
    assert fsm.is_terminal()
    assert not fsm.is_established()


@pytest.mark.parametrize(
    "from_state",
    [
        ConnectionState.NEW,
        ConnectionState.TCP_CONNECTED,
        ConnectionState.HANDSHAKING,
        ConnectionState.AUTHENTICATED,
        ConnectionState.ESTABLISHED,
    ],
)
def test_any_non_terminal_state_can_go_to_closing(from_state):
    """A connection can die at any point in its life — §6.1's two extra
    arrows into CLOSING from every earlier state, not just ESTABLISHED."""
    fsm = ConnectionStateMachine()
    _drive_to(fsm, from_state)
    fsm.transition_to(ConnectionState.CLOSING)
    assert fsm.state is ConnectionState.CLOSING


def _drive_to(fsm: ConnectionStateMachine, target: ConnectionState) -> None:
    order = [
        ConnectionState.NEW,
        ConnectionState.TCP_CONNECTED,
        ConnectionState.HANDSHAKING,
        ConnectionState.AUTHENTICATED,
        ConnectionState.ESTABLISHED,
    ]
    for state in order[1: order.index(target) + 1]:
        fsm.transition_to(state)


def test_cannot_skip_a_step():
    fsm = ConnectionStateMachine()
    with pytest.raises(InvalidConnectionTransition):
        fsm.transition_to(ConnectionState.ESTABLISHED)  # NEW -> ESTABLISHED, illegal


def test_cannot_go_backwards():
    fsm = ConnectionStateMachine()
    _drive_to(fsm, ConnectionState.ESTABLISHED)
    with pytest.raises(InvalidConnectionTransition):
        fsm.transition_to(ConnectionState.HANDSHAKING)


def test_closing_is_idempotent():
    fsm = ConnectionStateMachine()
    _drive_to(fsm, ConnectionState.ESTABLISHED)
    fsm.transition_to(ConnectionState.CLOSING)
    fsm.transition_to(ConnectionState.CLOSING)  # duplicate close signal — must not raise
    assert fsm.state is ConnectionState.CLOSING


def test_closed_is_idempotent_and_terminal():
    fsm = ConnectionStateMachine()
    _drive_to(fsm, ConnectionState.ESTABLISHED)
    fsm.transition_to(ConnectionState.CLOSING)
    fsm.transition_to(ConnectionState.CLOSED)
    fsm.transition_to(ConnectionState.CLOSED)  # a late timeout/duplicate close — no-op
    assert fsm.state is ConnectionState.CLOSED


def test_closed_cannot_be_revived():
    fsm = ConnectionStateMachine()
    _drive_to(fsm, ConnectionState.ESTABLISHED)
    fsm.transition_to(ConnectionState.CLOSING)
    fsm.transition_to(ConnectionState.CLOSED)
    for target in (
        ConnectionState.NEW,
        ConnectionState.TCP_CONNECTED,
        ConnectionState.HANDSHAKING,
        ConnectionState.AUTHENTICATED,
        ConnectionState.ESTABLISHED,
    ):
        with pytest.raises(InvalidConnectionTransition):
            fsm.transition_to(target)
    assert fsm.state is ConnectionState.CLOSED


def test_require_established_guard():
    fsm = ConnectionStateMachine()
    with pytest.raises(InvalidConnectionTransition):
        fsm.require_established("dispatching a chat frame")

    _drive_to(fsm, ConnectionState.ESTABLISHED)
    fsm.require_established("dispatching a chat frame")  # must not raise

    fsm.transition_to(ConnectionState.CLOSING)
    with pytest.raises(InvalidConnectionTransition):
        fsm.require_established("dispatching a late chat frame")
