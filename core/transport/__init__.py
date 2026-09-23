"""core/transport/ — Secure Transport Layer for peerc (Phase 9).

Provides the high-level decoupled transport architecture:
    Application -> SecureSession -> EncryptedTransport -> TCP

Modules:
    timeout.py — Transport timeout constants and timeout exception hierarchy.
    tcp.py     — TCPConnection abstraction managing raw asyncio streams.
    secure.py  — EncryptedTransport providing ChaCha20-Poly1305 wire framing.
    session.py — SecureSession, session initiators, and SecureSessionManager.
"""

from .secure import (
    MIN_ENCRYPTED_PAYLOAD_LEN,
    SEQUENCE_FORMAT,
    SEQUENCE_SIZE,
    TYPE_BINARY,
    TYPE_JSON,
    TYPE_RELAY,
    EncryptedTransport,
)
from .relay_stream import RelayedStreamReader, RelayedStreamWriter
from .session import (
    SecureSession,
    SecureSessionManager,
    accept_secure_session,
    initiate_secure_session,
)
from .tcp import (
    TCPConnection,
    open_tcp_connection,
)
from .timeout import (
    CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    IDLE_TIMEOUT,
    ConnectionClosedError,
    ConnectTimeoutError,
    HandshakeTimeoutError,
    IdleTimeoutError,
    TransportError,
    TransportTimeoutError,
)

__all__ = [
    "CONNECT_TIMEOUT",
    "HANDSHAKE_TIMEOUT",
    "IDLE_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "TransportError",
    "TransportTimeoutError",
    "ConnectTimeoutError",
    "HandshakeTimeoutError",
    "IdleTimeoutError",
    "ConnectionClosedError",
    "TCPConnection",
    "open_tcp_connection",
    "TYPE_JSON",
    "TYPE_BINARY",
    "TYPE_RELAY",
    "RelayedStreamReader",
    "RelayedStreamWriter",
    "SEQUENCE_FORMAT",
    "SEQUENCE_SIZE",
    "MIN_ENCRYPTED_PAYLOAD_LEN",
    "EncryptedTransport",
    "SecureSession",
    "SecureSessionManager",
    "initiate_secure_session",
    "accept_secure_session",
]
