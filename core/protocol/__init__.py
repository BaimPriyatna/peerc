"""core.protocol — peerc wire protocol, split into frame / messages / errors.

    frame.py    - length-prefixed JSON framing (bytes on the wire)
    messages.py - message types, factories, schema validation
    errors.py   - ProtocolError

The root-level protocol.py is kept as a backward-compatible shim that
re-exports this package's public API, so existing `import protocol` call
sites keep working unchanged.
"""

from .errors import ProtocolError
from .binary import decode_file_data, encode_file_data
from .frame import (
    BINARY_FLAG,
    LENGTH_PREFIX_FORMAT,
    LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
    encode_binary_frame,
    encode_frame,
    read_any_frame,
    read_frame,
    write_binary_frame,
    write_frame,
)
from .messages import (
    MAX_CHAT_TEXT_SIZE,
    MIN_SUPPORTED_VERSION,
    PROTOCOL_VERSION,
    REQUIRED_FIELDS,
    make_chat_ack,
    make_chat_message,
    make_error,
    make_file_accept,
    make_file_chunk,
    make_file_complete_ack,
    make_file_done,
    make_file_offer,
    make_file_reject,
    make_handshake_finish,
    make_handshake_init,
    make_handshake_response,
    make_hello,
    make_hello_ack,
    make_group_join_request,
    make_group_join_response,
    make_group_leave_request,
    make_group_leave_response,
    make_group_membership_revoke,
    make_group_export_request,
    make_group_export_capability,
    new_message_id,
    validate_message,
)

__all__ = [
    "ProtocolError",
    "BINARY_FLAG",
    "LENGTH_PREFIX_FORMAT",
    "LENGTH_PREFIX_SIZE",
    "MAX_MESSAGE_SIZE",
    "decode_file_data",
    "encode_binary_frame",
    "encode_file_data",
    "encode_frame",
    "read_any_frame",
    "read_frame",
    "write_binary_frame",
    "write_frame",
    "MAX_CHAT_TEXT_SIZE",
    "MIN_SUPPORTED_VERSION",
    "PROTOCOL_VERSION",
    "REQUIRED_FIELDS",
    "make_chat_ack",
    "make_chat_message",
    "make_error",
    "make_file_accept",
    "make_file_chunk",
    "make_file_complete_ack",
    "make_file_done",
    "make_file_offer",
    "make_file_reject",
    "make_handshake_finish",
    "make_handshake_init",
    "make_handshake_response",
    "make_hello",
    "make_hello_ack",
    "make_group_join_request",
    "make_group_join_response",
    "make_group_leave_request",
    "make_group_leave_response",
    "make_group_membership_revoke",
    "make_group_export_request",
    "make_group_export_capability",
    "new_message_id",
    "validate_message",
]
