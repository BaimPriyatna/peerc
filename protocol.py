"""protocol.py — backward-compatible shim over core.protocol (Phase 1.1).

The wire protocol used to live entirely in this one file. It has been
split into core/protocol/{frame,messages,errors}.py so framing, message
schema, and error types can evolve independently (see IMPLEMENTATION_PLAN.md
Phase 1).

Everything below is re-exported unchanged so existing `import protocol`
call sites across the codebase (chat.py, peer.py, file_transfer.py, ui.py,
tests) keep working with no changes required. New code should prefer
importing directly from `core.protocol`.

Two names changed under the hood but are aliased here for compatibility:
    encode_message -> core.protocol.encode_frame
    read_message    -> core.protocol.read_frame
    write_message   -> core.protocol.write_frame
"""

from core.protocol import (
    BINARY_FLAG,
    LENGTH_PREFIX_FORMAT,
    LENGTH_PREFIX_SIZE,
    MAX_CHAT_TEXT_SIZE,
    MAX_MESSAGE_SIZE,
    MIN_SUPPORTED_VERSION,
    PROTOCOL_VERSION,
    REQUIRED_FIELDS,
    ProtocolError,
    decode_file_data,
    encode_binary_frame,
    encode_file_data,
    encode_frame as encode_message,
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
    read_any_frame,
    read_frame as read_message,
    validate_message,
    write_binary_frame,
    write_frame as write_message,
)

__all__ = [
    "BINARY_FLAG",
    "LENGTH_PREFIX_FORMAT",
    "LENGTH_PREFIX_SIZE",
    "MAX_CHAT_TEXT_SIZE",
    "MAX_MESSAGE_SIZE",
    "MIN_SUPPORTED_VERSION",
    "PROTOCOL_VERSION",
    "REQUIRED_FIELDS",
    "ProtocolError",
    "decode_file_data",
    "encode_binary_frame",
    "encode_file_data",
    "encode_message",
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
    "read_any_frame",
    "read_message",
    "validate_message",
    "write_binary_frame",
    "write_message",
]
