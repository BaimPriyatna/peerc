"""core/protocol/messages.py — message types, factories, and schema validation.

This module knows what a message *means*: which types exist, what fields
each one requires, and how to build one. It doesn't know how bytes get on
the wire (that's frame.py).

Message types:
    chat              - a plain text chat message
    chat_ack          - acknowledges receipt of a chat message (Stage 3)
    file_offer        - proposes a file transfer (Stage 4)
    file_accept       - accepts a pending file offer (Stage 4)
    file_reject       - rejects a pending file offer (Stage 4)
    file_chunk        - one chunk of file data (Stage 4)
    file_done         - signals file transfer complete + checksum (Stage 4)
    file_complete_ack - receiver confirms verification succeeded (BUG-012)
    hello / hello_ack - peer handshake
    error             - generic error report
"""

import time
import uuid

from .errors import ProtocolError

MAX_CHAT_TEXT_SIZE = 64 * 1024  # 64 KB — a chat message is not a file (BUG-021)

# Protocol version (Phase 1.2). Bumped whenever the wire format changes in a
# way a receiver needs to know about (new required field, changed framing,
# etc). Every message produced by make_*() carries this. See
# IMPLEMENTATION_PLAN.md Phase 1.2 for the compatibility policy:
# a message with no "version" field is treated as version 1 (pre-versioning,
# from before this field existed) rather than rejected outright.
PROTOCOL_VERSION = 2

# Oldest peer protocol version this build can still talk to.
MIN_SUPPORTED_VERSION = 1


def new_message_id() -> str:
    return str(uuid.uuid4())


def make_chat_message(sender_id: str, sender_name: str, text: str) -> dict:
    return {
        "type": "chat",
        "version": PROTOCOL_VERSION,
        "message_id": new_message_id(),
        "sender_id": sender_id,
        "sender_name": sender_name,
        "text": text,
        "timestamp": time.time(),
    }


def make_chat_ack(message_id: str) -> dict:
    """Sent back by the receiver to confirm a chat message arrived intact."""
    return {
        "type": "chat_ack",
        "version": PROTOCOL_VERSION,
        "message_id": message_id,
        "timestamp": time.time(),
    }


def make_file_offer(
    transfer_id: str, sender_id: str, sender_name: str,
    filename: str, size: int, checksum: str,
) -> dict:
    return {
        "type": "file_offer",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "filename": filename,
        "size": size,
        "checksum": checksum,
        "timestamp": time.time(),
    }


def make_file_accept(transfer_id: str) -> dict:
    return {
        "type": "file_accept",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "timestamp": time.time(),
    }


def make_file_reject(transfer_id: str) -> dict:
    return {
        "type": "file_reject",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "timestamp": time.time(),
    }


def make_file_chunk(transfer_id: str, chunk_index: int, data_b64: str, is_last: bool) -> dict:
    return {
        "type": "file_chunk",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "chunk_index": chunk_index,
        "data": data_b64,
        "is_last": is_last,
    }


def make_file_done(transfer_id: str, checksum: str) -> dict:
    return {
        "type": "file_done",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "checksum": checksum,
    }


def make_file_complete_ack(transfer_id: str, success: bool, detail: str = "") -> dict:
    """Sent by the receiver after it has verified the file (BUG-012).

    The sender should not consider a transfer "done" until this arrives —
    file_done only means "I sent all the bytes", not "you're happy with them".
    """
    return {
        "type": "file_complete_ack",
        "version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "success": success,
        "detail": detail,
    }


def make_error(code: str, message: str) -> dict:
    return {"type": "error", "version": PROTOCOL_VERSION, "code": code, "message": message}


def make_hello(peer_id: str, sender_name: str, tcp_port: int) -> dict:
    return {
        "type": "hello",
        "version": PROTOCOL_VERSION,
        "peer_id": peer_id,
        "sender_name": sender_name,
        "tcp_port": tcp_port,
        "timestamp": time.time(),
    }


def make_hello_ack(peer_id: str, sender_name: str, tcp_port: int) -> dict:
    return {
        "type": "hello_ack",
        "version": PROTOCOL_VERSION,
        "peer_id": peer_id,
        "sender_name": sender_name,
        "tcp_port": tcp_port,
        "timestamp": time.time(),
    }


def make_handshake_init(
    device_id: str,
    public_key: str,
    ephemeral_key: str,
    nonce: str,
    sender_name: str,
) -> dict:
    return {
        "type": "handshake_init",
        "version": PROTOCOL_VERSION,
        "device_id": device_id,
        "public_key": public_key,
        "ephemeral_key": ephemeral_key,
        "nonce": nonce,
        "sender_name": sender_name,
        "timestamp": time.time(),
    }


def make_handshake_response(
    device_id: str,
    public_key: str,
    ephemeral_key: str,
    nonce: str,
    sender_name: str,
    signature: str,
) -> dict:
    return {
        "type": "handshake_response",
        "version": PROTOCOL_VERSION,
        "device_id": device_id,
        "public_key": public_key,
        "ephemeral_key": ephemeral_key,
        "nonce": nonce,
        "sender_name": sender_name,
        "signature": signature,
        "timestamp": time.time(),
    }


def make_handshake_finish(signature: str) -> dict:
    return {
        "type": "handshake_finish",
        "version": PROTOCOL_VERSION,
        "signature": signature,
        "timestamp": time.time(),
    }


def make_group_join_request(
    request_id: str,
    group_id: str,
    device_id: str,
    device_public_key: str,
    requested_role: str,
    requested_permissions: list[str],
    signature: str,
    reason: str | None = None,
    timestamp: float | None = None,
) -> dict:
    return {
        "type": "group_join_request",
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "group_id": group_id,
        "device_id": device_id,
        "device_public_key": device_public_key,
        "requested_role": requested_role,
        "requested_permissions": requested_permissions,
        "reason": reason,
        "timestamp": time.time() if timestamp is None else timestamp,
        "signature": signature,
    }


def make_group_join_response(
    request_id: str,
    group_id: str,
    device_id: str,
    approved: bool,
    admin_device_id: str,
    signature: str,
    certificate: dict | None = None,
    reason: str | None = None,
    timestamp: float | None = None,
) -> dict:
    return {
        "type": "group_join_response",
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "group_id": group_id,
        "device_id": device_id,
        "approved": approved,
        "admin_device_id": admin_device_id,
        "certificate": certificate,
        "reason": reason,
        "timestamp": time.time() if timestamp is None else timestamp,
        "signature": signature,
    }


def make_group_leave_request(
    request_id: str,
    group_id: str,
    device_id: str,
    signature: str,
    reason: str | None = None,
    timestamp: float | None = None,
) -> dict:
    return {
        "type": "group_leave_request",
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "group_id": group_id,
        "device_id": device_id,
        "reason": reason,
        "timestamp": time.time() if timestamp is None else timestamp,
        "signature": signature,
    }


def make_group_leave_response(
    request_id: str,
    group_id: str,
    device_id: str,
    approved: bool,
    admin_device_id: str,
    signature: str,
    revocation: dict | None = None,
    reason: str | None = None,
    timestamp: float | None = None,
) -> dict:
    return {
        "type": "group_leave_response",
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "group_id": group_id,
        "device_id": device_id,
        "approved": approved,
        "admin_device_id": admin_device_id,
        "revocation": revocation,
        "reason": reason,
        "timestamp": time.time() if timestamp is None else timestamp,
        "signature": signature,
    }


def make_group_membership_revoke(
    revocation_id: str,
    group_id: str,
    device_id: str,
    revoked_by: str,
    signature: str,
    reason: str | None = None,
    timestamp: float | None = None,
) -> dict:
    return {
        "type": "group_membership_revoke",
        "version": PROTOCOL_VERSION,
        "revocation_id": revocation_id,
        "group_id": group_id,
        "device_id": device_id,
        "revoked_by": revoked_by,
        "reason": reason,
        "timestamp": time.time() if timestamp is None else timestamp,
        "signature": signature,
    }


# ---- Schema validation --------------------------------------------------
#
# read_frame() only guarantees "valid JSON". It does NOT guarantee the
# result is a dict, has a "type", or carries the fields that type requires.
# validate_message() closes that gap (BUG-017 / BUG-018) so handlers can
# trust message["field"] instead of needing their own defensive code.

REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "chat": ("message_id", "sender_id", "sender_name", "text"),
    "chat_ack": ("message_id",),
    "file_offer": ("transfer_id", "filename", "size", "checksum"),
    "file_accept": ("transfer_id",),
    "file_reject": ("transfer_id",),
    "file_chunk": ("transfer_id", "chunk_index", "data", "is_last"),
    "file_done": ("transfer_id", "checksum"),
    "file_complete_ack": ("transfer_id", "success"),
    "hello": ("peer_id", "sender_name", "tcp_port"),
    "hello_ack": ("peer_id", "sender_name", "tcp_port"),
    "handshake_init": ("device_id", "public_key", "ephemeral_key", "nonce", "sender_name"),
    "handshake_response": ("device_id", "public_key", "ephemeral_key", "nonce", "sender_name", "signature"),
    "handshake_finish": ("signature",),
    "group_join_request": (
        "request_id", "group_id", "device_id", "device_public_key",
        "requested_role", "requested_permissions", "timestamp", "signature",
    ),
    "group_join_response": (
        "request_id", "group_id", "device_id", "approved",
        "admin_device_id", "timestamp", "signature",
    ),
    "group_leave_request": ("request_id", "group_id", "device_id", "timestamp", "signature"),
    "group_leave_response": (
        "request_id", "group_id", "device_id", "approved",
        "admin_device_id", "timestamp", "signature",
    ),
    "group_membership_revoke": (
        "revocation_id", "group_id", "device_id", "revoked_by", "timestamp", "signature",
    ),
    "error": ("code", "message"),
}


def validate_message(message) -> dict:
    """Validate a decoded message against the wire schema.

    Raises ProtocolError (never KeyError/TypeError) if the message isn't a
    dict, has no recognized "type", or is missing fields that type requires.
    Returns the message unchanged on success, for convenient chaining.
    """
    if not isinstance(message, dict):
        raise ProtocolError(f"message is not an object: {type(message).__name__}")

    msg_type = message.get("type")
    if not isinstance(msg_type, str) or not msg_type:
        raise ProtocolError("message missing string 'type' field")

    # "version" is absent on messages from peers running pre-1.2 builds —
    # treat that as version 1 rather than rejecting it (BUG-free interop
    # across a rolling upgrade). A version below what we still support IS
    # rejected, since we can no longer promise we understand that wire
    # format.
    version = message.get("version", 1)
    if not isinstance(version, int):
        raise ProtocolError(f"'version' must be an int, got {type(version).__name__}")
    if version < MIN_SUPPORTED_VERSION:
        raise ProtocolError(
            f"message version {version} is older than the minimum supported "
            f"version {MIN_SUPPORTED_VERSION}"
        )

    required = REQUIRED_FIELDS.get(msg_type)
    if required is None:
        # Unknown type: let it through untyped-checked so the protocol can
        # still be extended/ignored gracefully by older peers.
        return message

    missing = [f for f in required if f not in message]
    if missing:
        raise ProtocolError(f"'{msg_type}' message missing fields: {missing}")

    if msg_type == "chat":
        if not isinstance(message["text"], str):
            raise ProtocolError("chat.text must be a string")
        if len(message["text"].encode("utf-8", errors="replace")) > MAX_CHAT_TEXT_SIZE:
            raise ProtocolError(f"chat.text exceeds {MAX_CHAT_TEXT_SIZE} bytes")

    if msg_type == "file_offer":
        if not isinstance(message["filename"], str) or not message["filename"]:
            raise ProtocolError("file_offer.filename must be a non-empty string")
        if not isinstance(message["size"], int) or message["size"] < 0:
            raise ProtocolError("file_offer.size must be a non-negative int")
        if not isinstance(message["checksum"], str) or not message["checksum"]:
            raise ProtocolError("file_offer.checksum must be a non-empty string")

    if msg_type == "file_chunk":
        if not isinstance(message["chunk_index"], int) or message["chunk_index"] < 0:
            raise ProtocolError("file_chunk.chunk_index must be a non-negative int")
        if not isinstance(message["data"], str):
            raise ProtocolError("file_chunk.data must be a base64 string")

    if msg_type == "hello" or msg_type == "hello_ack":
        port = message["tcp_port"]
        if not isinstance(port, int) or not (0 < port < 65536):
            raise ProtocolError(f"{msg_type}.tcp_port out of range: {port!r}")

    if msg_type in ("handshake_init", "handshake_response"):
        for field_name in ("device_id", "public_key", "ephemeral_key", "nonce"):
            val = message[field_name]
            if not isinstance(val, str) or not val:
                raise ProtocolError(f"{msg_type}.{field_name} must be a non-empty string")
        if not isinstance(message["sender_name"], str):
            raise ProtocolError(f"{msg_type}.sender_name must be a string")

    if msg_type in ("handshake_response", "handshake_finish"):
        sig = message["signature"]
        if not isinstance(sig, str) or not sig:
            raise ProtocolError(f"{msg_type}.signature must be a non-empty string")

    if msg_type.startswith("group_"):
        for field_name in ("group_id", "device_id", "signature"):
            if field_name in message:
                val = message[field_name]
                if not isinstance(val, str) or not val:
                    raise ProtocolError(f"{msg_type}.{field_name} must be a non-empty string")
        if "timestamp" in message and not isinstance(message["timestamp"], (int, float)):
            raise ProtocolError(f"{msg_type}.timestamp must be numeric")

    if msg_type == "group_join_request":
        if not isinstance(message["device_public_key"], str) or not message["device_public_key"]:
            raise ProtocolError("group_join_request.device_public_key must be a non-empty string")
        if not isinstance(message["requested_role"], str) or not message["requested_role"]:
            raise ProtocolError("group_join_request.requested_role must be a non-empty string")
        if not isinstance(message["requested_permissions"], list):
            raise ProtocolError("group_join_request.requested_permissions must be a list")
        if not all(isinstance(p, str) for p in message["requested_permissions"]):
            raise ProtocolError("group_join_request.requested_permissions must contain only strings")

    if msg_type in ("group_join_response", "group_leave_response"):
        if not isinstance(message["approved"], bool):
            raise ProtocolError(f"{msg_type}.approved must be a bool")
        if not isinstance(message["admin_device_id"], str) or not message["admin_device_id"]:
            raise ProtocolError(f"{msg_type}.admin_device_id must be a non-empty string")
        if msg_type == "group_join_response" and message["approved"] and not isinstance(message.get("certificate"), dict):
            raise ProtocolError("approved group_join_response requires certificate object")
        if msg_type == "group_leave_response" and message["approved"] and not isinstance(message.get("revocation"), dict):
            raise ProtocolError("approved group_leave_response requires revocation object")

    if msg_type == "group_membership_revoke":
        for field_name in ("revocation_id", "revoked_by"):
            val = message[field_name]
            if not isinstance(val, str) or not val:
                raise ProtocolError(f"group_membership_revoke.{field_name} must be a non-empty string")

    return message
