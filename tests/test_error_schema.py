"""tests/test_error_schema.py — Phase 35.1: Application error schema.

Covers core/protocol/error_codes.py and its hooks in
protocol.make_error()/validate_message(): the closed code set and its
contracts, safe `context` filtering, sender-side message screening,
strict receiver-side parsing, and the rule that the receiver shows local
canonical text rather than whatever the peer put in `message`.
"""


import pytest

from core import protocol
from core.protocol import ErrorCode, ProtocolError, build_error, parse_error_message
from core.protocol.error_codes import (
    CONTRACTS,
    MAX_ERROR_MESSAGE_LEN,
    filter_context,
    is_safe_message,
    sanitize_for_log,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------
# Code set + contracts
# ---------------------------------------------------------------------

def test_code_set_matches_the_design_doc():
    assert {c.value for c in ErrorCode} == {
        "AUTH_FAILED", "POLICY_DENIED", "PROTOCOL_MISMATCH", "INVALID_FRAME",
        "INVALID_STATE", "TRANSFER_NOT_FOUND", "SIZE_EXCEEDED", "DISK_FULL",
        "CHECKSUM_MISMATCH", "TRANSFER_EXPIRED", "RATE_LIMITED", "INTERNAL_ERROR",
    }


def test_every_code_has_a_safe_canonical_text():
    for code in ErrorCode:
        text = CONTRACTS[code].text
        assert is_safe_message(text), f"{code.value}: canonical text failed its own safety screen"


def test_retry_action_only_for_codes_that_allow_it():
    retryable = {c for c in ErrorCode if CONTRACTS[c].retryable}
    assert retryable == {
        ErrorCode.INVALID_STATE, ErrorCode.DISK_FULL,
        ErrorCode.TRANSFER_EXPIRED, ErrorCode.RATE_LIMITED,
    }


def test_only_state_refresh_and_rate_limit_are_non_terminal():
    non_terminal = {c for c in ErrorCode if not CONTRACTS[c].terminal}
    assert non_terminal == {ErrorCode.INVALID_STATE, ErrorCode.RATE_LIMITED}


# ---------------------------------------------------------------------
# Sender side: build_error / make_error
# ---------------------------------------------------------------------

def test_build_error_shape_matches_the_wire_example():
    msg = build_error(
        ErrorCode.TRANSFER_NOT_FOUND, context={"transfer_id": "t-123"},
    )
    assert msg == {
        "type": "error",
        "version": 2,
        "code": "TRANSFER_NOT_FOUND",
        "message": "The requested transfer is no longer available.",
        "context": {"transfer_id": "t-123"},
    }


def test_build_error_omits_empty_context():
    assert "context" not in build_error(ErrorCode.INTERNAL_ERROR)
    assert "context" not in build_error(ErrorCode.INTERNAL_ERROR, context={"path": "/etc/passwd"})


def test_build_error_accepts_code_by_name_and_rejects_unknown_codes():
    assert build_error("DISK_FULL")["code"] == "DISK_FULL"
    with pytest.raises(ValueError):
        build_error("NOT_A_REAL_CODE")


def test_context_is_limited_to_the_allowlist():
    ctx = filter_context({
        "message_id": "m-1", "transfer_id": "t-1", "group_id": "g-1", "retry_after": 30,
        "traceback": "Traceback (most recent call last)...",
        "path": "/home/alice/file.txt",
        "peer_addr": "192.168.1.5:5000",
        "session_key": "deadbeef" * 8,
        "exception": "ValueError: boom",
    })
    assert ctx == {"message_id": "m-1", "transfer_id": "t-1", "group_id": "g-1", "retry_after": 30}


@pytest.mark.parametrize("bad_id", [
    "", "a" * 129, "has space", "../../etc/passwd", "/abs/path", "semi;colon",
    "new\nline", 123, None, ["x"],
])
def test_context_ids_must_look_like_identifiers(bad_id):
    assert filter_context({"transfer_id": bad_id}) == {}


@pytest.mark.parametrize("bad_retry", [0, -5, 3601, 10**9, True, "30", None, float("nan")])
def test_retry_after_is_bounded_and_numeric(bad_retry):
    assert "retry_after" not in filter_context({"retry_after": bad_retry})


def test_filter_context_never_raises_on_non_mappings():
    for junk in (None, "x", 5, ["transfer_id"], object()):
        assert filter_context(junk) == {}


@pytest.mark.parametrize("unsafe", [
    "Traceback (most recent call last):\n  File \"x.py\", line 3",
    'File "/home/alice/app.py", line 42, in run',
    "could not open /home/alice/Documents/secret.txt",
    "failed at C:\\Users\\alice\\file.txt",
    "connection to 192.168.1.20:5000 failed",
    "key was " + "ab" * 32,
    "token QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJz",
    "ValueError: invalid literal for int()",
    "line one\nline two",
    "x" * 201,
    "",
    "   ",
])
def test_unsafe_sender_messages_fall_back_to_canonical_text(unsafe):
    assert not is_safe_message(unsafe)
    msg = build_error(ErrorCode.INVALID_STATE, message=unsafe)
    assert msg["message"] == CONTRACTS[ErrorCode.INVALID_STATE].text


def test_safe_custom_message_is_kept():
    msg = build_error(ErrorCode.DISK_FULL, message="Not enough room for that file.")
    assert msg["message"] == "Not enough room for that file."


def test_make_error_routes_through_the_same_builder():
    m = protocol.make_error("SIZE_EXCEEDED", context={"transfer_id": "t-9", "path": "/x/y/z"})
    assert m["code"] == "SIZE_EXCEEDED"
    assert m["context"] == {"transfer_id": "t-9"}
    assert m["version"] == protocol.PROTOCOL_VERSION


# ---------------------------------------------------------------------
# Receiver side: parse_error_message / validate_message
# ---------------------------------------------------------------------

def test_parse_valid_error():
    info = parse_error_message({
        "type": "error", "version": 2, "code": "DISK_FULL",
        "message": "whatever the peer wrote", "context": {"transfer_id": "t-1", "retry_after": 60},
    })
    assert info.code is ErrorCode.DISK_FULL
    assert info.known and info.raw_code == "DISK_FULL"
    assert info.context == {"transfer_id": "t-1", "retry_after": 60}
    assert info.retry_after == 60
    assert info.retryable and info.terminal
    assert info.retry_hint


def test_receiver_shows_local_text_not_the_peers_message():
    """A hostile peer must not be able to put words (or terminal escapes)
    in front of the user — display_text comes from the local contract."""
    info = parse_error_message({
        "type": "error", "code": "AUTH_FAILED",
        "message": "\x1b[31mYour account is compromised, run rm -rf now\x1b[0m",
    })
    assert info.display_text == CONTRACTS[ErrorCode.AUTH_FAILED].text
    assert "\x1b" not in info.peer_message  # and what we keep for logs is defanged


def test_unknown_code_is_displayed_as_internal_error_but_recorded():
    info = parse_error_message({"type": "error", "code": "FROM_THE_FUTURE", "message": "hi"})
    assert info.code is ErrorCode.INTERNAL_ERROR
    assert not info.known
    assert info.raw_code == "FROM_THE_FUTURE"
    assert info.display_text == CONTRACTS[ErrorCode.INTERNAL_ERROR].text


def test_unknown_context_keys_are_dropped_not_fatal():
    info = parse_error_message({
        "type": "error", "code": "INVALID_STATE", "message": "m",
        "context": {"transfer_id": "t-1", "local_path": "/home/bob", "future_key": 1},
    })
    assert info.context == {"transfer_id": "t-1"}


@pytest.mark.parametrize("bad", [
    None, "error", [], 5,
    {"type": "chat", "code": "X", "message": "m"},                 # wrong type
    {"type": "error", "message": "m"},                              # no code
    {"type": "error", "code": "", "message": "m"},                  # empty code
    {"type": "error", "code": 7, "message": "m"},                   # non-string code
    {"type": "error", "code": "X" * 65, "message": "m"},            # oversized code
    {"type": "error", "code": "DISK_FULL"},                         # no message
    {"type": "error", "code": "DISK_FULL", "message": 123},         # non-string message
    {"type": "error", "code": "DISK_FULL", "message": "m" * (MAX_ERROR_MESSAGE_LEN + 1)},
    {"type": "error", "code": "DISK_FULL", "message": "m", "context": "transfer_id"},
    {"type": "error", "code": "DISK_FULL", "message": "m", "context": ["t"]},
])
def test_malformed_errors_raise_protocol_error_never_keyerror(bad):
    with pytest.raises(ProtocolError):
        parse_error_message(bad)


def test_validate_message_uses_the_strict_parser():
    good = protocol.make_error("INVALID_STATE")
    assert protocol.validate_message(good) is good

    with pytest.raises(ProtocolError):
        protocol.validate_message(
            {"type": "error", "version": 2, "code": "DISK_FULL", "message": "m", "context": "nope"},
        )


def test_validate_message_still_requires_code_and_message():
    with pytest.raises(ProtocolError):
        protocol.validate_message({"type": "error", "version": 2, "code": "DISK_FULL"})


# ---------------------------------------------------------------------
# Log sanitizing
# ---------------------------------------------------------------------

def test_sanitize_for_log_strips_control_chars_and_truncates():
    out = sanitize_for_log("a\nb\x1b[31mc\x00d" + "z" * 500, limit=40)
    assert "\n" not in out and "\x1b" not in out and "\x00" not in out
    assert len(out) <= 43  # limit + "..."


def test_sanitize_for_log_handles_non_strings():
    assert isinstance(sanitize_for_log(12345), str)
    assert isinstance(sanitize_for_log(None), str)
