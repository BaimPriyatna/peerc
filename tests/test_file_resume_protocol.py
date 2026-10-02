"""tests/test_file_resume_protocol.py — Phase 47.3: optional `resume_offset` in file_accept.

The field is how a receiver asks a sender to continue an interrupted transfer
(docs/FILE_RESUME_DESIGN.md section 4). It must be invisible to older peers:
a fresh transfer's file_accept stays byte-for-byte what it always was, and the
validator keeps treating `transfer_id` as the only required field.
"""

import json

import pytest

from core.protocol import ProtocolError, make_file_accept, validate_message
from core.protocol.messages import REQUIRED_FIELDS

pytestmark = pytest.mark.unit

LEGACY_KEYS = {"type", "version", "transfer_id", "timestamp"}


def test_a_fresh_accept_is_identical_in_shape_to_the_legacy_message():
    assert set(make_file_accept("t1")) == LEGACY_KEYS
    assert set(make_file_accept("t1", resume_offset=0)) == LEGACY_KEYS
    assert make_file_accept("t1")["type"] == "file_accept"


def test_a_resume_accept_carries_the_offset_and_still_validates():
    message = make_file_accept("t1", resume_offset=3 * 65536)
    assert set(message) == LEGACY_KEYS | {"resume_offset"}
    assert message["resume_offset"] == 3 * 65536
    assert validate_message(message) is message


def test_the_offset_survives_a_json_round_trip_as_an_int():
    message = json.loads(json.dumps(make_file_accept("t1", resume_offset=2 ** 40)))
    assert message["resume_offset"] == 2 ** 40 and isinstance(message["resume_offset"], int)
    validate_message(message)


@pytest.mark.parametrize("bad", [-1, -65536, True, False, 1.5, 65536.0, "65536", None, [1], {"a": 1}])
def test_the_builder_refuses_values_that_would_make_a_malformed_message(bad):
    with pytest.raises(ValueError):
        make_file_accept("t1", resume_offset=bad)


@pytest.mark.parametrize("bad", [-1, -65536, True, False, 1.5, 65536.0, "65536", None, [1], {"a": 1}])
def test_the_validator_rejects_a_malformed_offset(bad):
    message = make_file_accept("t1")
    message["resume_offset"] = bad
    with pytest.raises(ProtocolError, match="resume_offset"):
        validate_message(message)


@pytest.mark.parametrize("ok", [0, 1, 65536, 2 ** 40])
def test_the_validator_accepts_any_non_negative_int(ok):
    message = make_file_accept("t1")
    message["resume_offset"] = ok
    assert validate_message(message) is message


def test_an_old_validator_could_not_object_to_the_new_field():
    """Older peers validate required fields only, so an extra optional field is
    ignored rather than rejected. This pins the property the compatibility
    story relies on: transfer_id stays the only required field."""
    assert REQUIRED_FIELDS["file_accept"] == ("transfer_id",)


def test_the_offset_is_not_accepted_on_other_message_types_by_accident():
    # file_reject has no resume semantics; the validator must not start policing
    # (or requiring) the field there.
    from core.protocol import make_file_reject
    message = make_file_reject("t1")
    assert "resume_offset" not in message
    assert validate_message(message) is message
