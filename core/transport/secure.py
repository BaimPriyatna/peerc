"""core/transport/secure.py — Encrypted wire transport (Phase 9).

Wraps a TCPConnection and a Phase 8 SecureChannel (ChaCha20-Poly1305), providing
authenticated and confidential stream transport for framed messages.
"""

import json
import struct
from typing import Optional, Tuple, Union

from core.crypto.encryption import (
    DecryptionError,
    EncryptionError,
    ReplayOrReorderError,
    SecureChannel,
    SequenceExhaustedError,
)
from .tcp import TCPConnection
from .timeout import ConnectionClosedError, TransportError

# Inner payload type markers (encrypted inside the AEAD frame)
TYPE_JSON = b"J"
TYPE_BINARY = b"B"
TYPE_RELAY = b"R"  # Phase 46.1: opaque relay-tunnel bytes, kept fully
                    # separate from TYPE_BINARY (file_data) so relayed
                    # traffic never touches decode_file_data's framing.

SEQUENCE_FORMAT = ">Q"
SEQUENCE_SIZE = struct.calcsize(SEQUENCE_FORMAT)  # 8 bytes
MIN_ENCRYPTED_PAYLOAD_LEN = SEQUENCE_SIZE + 16    # 8 bytes sequence + 16 bytes Poly1305 tag


class EncryptedTransport:
    """Provides authenticated and encrypted message framing over an underlying TCPConnection."""

    def __init__(self, tcp: TCPConnection, channel: SecureChannel):
        self.tcp = tcp
        self.channel = channel

    @property
    def peer_addr(self) -> Tuple[str, int]:
        return self.tcp.peer_addr

    @property
    def addr_key(self) -> str:
        return self.tcp.addr_key

    @property
    def is_closing(self) -> bool:
        return self.tcp.is_closing

    async def send_message(self, message: dict, associated_data: bytes = b"") -> None:
        """Encrypt and send a JSON control message frame."""
        if not isinstance(message, dict):
            raise TransportError(f"Expected dict message, got {type(message).__name__}")

        raw_json = json.dumps(message).encode("utf-8")
        inner_payload = TYPE_JSON + raw_json
        await self._send_encrypted(inner_payload, associated_data=associated_data)

    async def send_binary(self, payload: bytes, associated_data: bytes = b"") -> None:
        """Encrypt and send a raw binary data frame (e.g. file chunks)."""
        if not isinstance(payload, (bytes, bytearray)):
            raise TransportError(f"Expected bytes payload, got {type(payload).__name__}")

        inner_payload = TYPE_BINARY + bytes(payload)
        await self._send_encrypted(inner_payload, associated_data=associated_data)

    async def send_relay(self, payload: bytes, associated_data: bytes = b"") -> None:
        """Encrypt and send an opaque relay-tunnel chunk (Phase 46.1).

        Same wire mechanics as send_binary — just a distinct inner marker
        so the receiving end's dispatch (peer.py's _read_loop) can tell a
        relay-tunnel chunk apart from a file_data chunk without either
        one having to inspect the other's payload shape.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TransportError(f"Expected bytes payload, got {type(payload).__name__}")

        inner_payload = TYPE_RELAY + bytes(payload)
        await self._send_encrypted(inner_payload, associated_data=associated_data)

    async def _send_encrypted(self, inner_payload: bytes, associated_data: bytes = b"") -> None:
        try:
            frame = self.channel.encrypt(inner_payload, associated_data=associated_data)
        except SequenceExhaustedError as e:
            await self.close()
            raise TransportError(f"Session sequence exhausted: {e}") from e
        except EncryptionError as e:
            raise TransportError(f"Frame encryption failed: {e}") from e

        # Wire layout: [8-byte sequence uint64][N-byte ciphertext with Poly1305 tag]
        seq_header = struct.pack(SEQUENCE_FORMAT, frame.sequence)
        wire_payload = seq_header + frame.ciphertext

        await self.tcp.write_binary_frame(wire_payload)

    async def receive_frame(
        self,
        associated_data: bytes = b"",
    ) -> Tuple[str, Union[dict, bytes]]:
        """Read, authenticate, and decrypt the next frame.

        Returns:
            ("json", dict) for control messages or ("binary", bytes) for binary chunks.

        Raises:
            ConnectionClosedError: If peer disconnected.
            DecryptionError: If ciphertext failed Poly1305 authentication.
            ReplayOrReorderError: If frame sequence was out of order or replayed.
            TransportError: If frame framing or deserialization failed.
        """
        kind, wire_payload = await self.tcp.read_frame()

        if kind != "binary":
            raise TransportError("Expected encrypted binary frame, got plain JSON frame")

        if not isinstance(wire_payload, bytes) or len(wire_payload) < MIN_ENCRYPTED_PAYLOAD_LEN:
            raise TransportError(
                f"Encrypted wire frame too short: {len(wire_payload) if isinstance(wire_payload, bytes) else 0} bytes"
            )

        (sequence,) = struct.unpack(SEQUENCE_FORMAT, wire_payload[:SEQUENCE_SIZE])
        ciphertext = wire_payload[SEQUENCE_SIZE:]

        # Decrypt using SecureChannel (verifies sequence order and Poly1305 tag)
        plaintext = self.channel.decrypt(
            sequence=sequence,
            ciphertext=ciphertext,
            associated_data=associated_data,
        )

        if not plaintext:
            raise TransportError("Decrypted frame contained empty payload marker")

        marker = plaintext[:1]
        body = plaintext[1:]

        if marker == TYPE_JSON:
            try:
                message = json.loads(body.decode("utf-8"))
                return "json", message
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise TransportError(f"Decrypted JSON frame malformed: {e}") from e
        elif marker == TYPE_BINARY:
            return "binary", body
        elif marker == TYPE_RELAY:
            return "relay", body
        else:
            return "raw", plaintext

    async def close(self) -> None:
        """Close the underlying TCP connection."""
        await self.tcp.close()

    def __repr__(self) -> str:
        return f"<EncryptedTransport {self.addr_key} ({'closed' if self.is_closing else 'active'})>"
