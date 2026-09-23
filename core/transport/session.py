"""core/transport/session.py — High-level SecureSession abstraction (Phase 9).

Decouples the application layer from cryptography. The application interacts with
a SecureSession via session.send() and session.receive(), with all authentication,
key derivation, ChaCha20-Poly1305 encryption, and sequence tracking handled automatically.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from core.crypto.encryption import SecureChannel
from core.crypto.handshake import (
    HANDSHAKE_TIMEOUT,
    HandshakeResult,
    NonceCache,
    perform_handshake_initiator,
    perform_handshake_responder,
)
from core.identity.device_identity import DeviceKeypair
from core.trust.store import TrustDecision, TrustStore
from .secure import EncryptedTransport
from .tcp import TCPConnection, open_tcp_connection
from .timeout import CONNECT_TIMEOUT, ConnectionClosedError, TransportError


class SecureSession:
    """Represents an established, authenticated, and encrypted peer session."""

    def __init__(
        self,
        transport: EncryptedTransport,
        handshake_result: HandshakeResult,
        session_id: str,
        is_initiator: bool,
    ):
        self.transport = transport
        self.handshake = handshake_result
        self.session_id = session_id
        self.is_initiator = is_initiator
        self.created_at = time.time()
        self.last_activity = self.created_at

    @property
    def peer_device_id(self) -> str:
        """The verified Ed25519 device_id of the remote peer."""
        return self.handshake.peer_device_id

    @property
    def peer_public_key(self) -> str:
        """The hex-encoded Ed25519 public key of the remote peer."""
        return self.handshake.peer_public_key

    @property
    def peer_name(self) -> str:
        """The advertised display name of the remote peer."""
        return self.handshake.peer_name

    @property
    def trust_decision(self) -> TrustDecision:
        """TrustStore decision for this peer (TRUSTED, PENDING, etc.)."""
        return self.handshake.trust_decision

    @property
    def remote_addr(self) -> Tuple[str, int]:
        """(ip, port) of the remote peer."""
        return self.transport.peer_addr

    @property
    def addr_key(self) -> str:
        """'ip:port' string identifier."""
        return self.transport.addr_key

    @property
    def is_alive(self) -> bool:
        """True if the underlying encrypted connection is still open."""
        return not self.transport.is_closing

    async def send(self, message: dict) -> None:
        """Send a JSON message dict securely to the peer.

        Application code does not need to know about keys or encryption:
            await session.send({"type": "chat", "text": "Hello"})
        """
        self.last_activity = time.time()
        await self.transport.send_message(message)

    async def send_binary(self, payload: bytes) -> None:
        """Send raw binary payload securely to the peer (e.g. file chunks)."""
        self.last_activity = time.time()
        await self.transport.send_binary(payload)

    async def send_relay(self, payload: bytes) -> None:
        """Send an opaque relay-tunnel chunk securely to the peer (Phase 46.1).

        Distinct wire marker from send_binary — see
        core/transport/secure.py's TYPE_RELAY for why.
        """
        self.last_activity = time.time()
        await self.transport.send_relay(payload)

    async def receive(self) -> Tuple[str, Union[dict, bytes]]:
        """Receive the next authenticated and decrypted frame from the peer.

        Returns:
            ("json", dict) for control messages, ("binary", bytes) for
            binary chunks, or ("relay", bytes) for an opaque relay-tunnel
            chunk (Phase 46.1).
        """
        result = await self.transport.receive_frame()
        self.last_activity = time.time()
        return result

    async def close(self) -> None:
        """Gracefully close the secure session."""
        await self.transport.close()

    def __repr__(self) -> str:
        status = "alive" if self.is_alive else "closed"
        return (
            f"<SecureSession peer={self.peer_name!r} id={self.peer_device_id[:8]} "
            f"role={'init' if self.is_initiator else 'resp'} ({status})>"
        )


async def initiate_secure_session(
    host: str,
    port: int,
    my_identity: DeviceKeypair,
    my_name: str,
    trust_store: Optional[TrustStore] = None,
    connect_timeout: float = CONNECT_TIMEOUT,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
    nonce_cache: Optional[NonceCache] = None,
) -> SecureSession:
    """Establish an outgoing secure session to a remote peer.

    Workflow:
        1. Open raw TCP connection (guarded by connect_timeout).
        2. Perform mutual authenticated 3-way handshake (guarded by handshake_timeout).
        3. Derive directional ChaCha20-Poly1305 session keys via HKDF.
        4. Wrap in EncryptedTransport and return high-level SecureSession.
    """
    tcp_conn = await open_tcp_connection(host, port, timeout=connect_timeout)

    try:
        handshake_res = await perform_handshake_initiator(
            reader=tcp_conn.reader,
            writer=tcp_conn.writer,
            my_identity=my_identity,
            my_name=my_name,
            trust_store=trust_store,
            timeout=handshake_timeout,
            nonce_cache=nonce_cache,
        )
        session_keys = handshake_res.derive_session_keys(is_initiator=True)
        channel = SecureChannel(session_keys)
        transport = EncryptedTransport(tcp_conn, channel)

        return SecureSession(
            transport=transport,
            handshake_result=handshake_res,
            session_id=session_keys.session_id,
            is_initiator=True,
        )
    except Exception:
        await tcp_conn.close()
        raise


async def accept_secure_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    my_identity: DeviceKeypair,
    my_name: str,
    trust_store: Optional[TrustStore] = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
    nonce_cache: Optional[NonceCache] = None,
) -> SecureSession:
    """Accept an incoming connection and establish a secure session as responder.

    Workflow:
        1. Perform mutual authenticated 3-way handshake as responder.
        2. Derive directional ChaCha20-Poly1305 session keys via HKDF.
        3. Wrap in EncryptedTransport and return high-level SecureSession.
    """
    tcp_conn = TCPConnection(reader, writer)

    try:
        handshake_res = await perform_handshake_responder(
            reader=reader,
            writer=writer,
            my_identity=my_identity,
            my_name=my_name,
            trust_store=trust_store,
            timeout=handshake_timeout,
            nonce_cache=nonce_cache,
        )
        session_keys = handshake_res.derive_session_keys(is_initiator=False)
        channel = SecureChannel(session_keys)
        transport = EncryptedTransport(tcp_conn, channel)

        return SecureSession(
            transport=transport,
            handshake_result=handshake_res,
            session_id=session_keys.session_id,
            is_initiator=False,
        )
    except Exception:
        await tcp_conn.close()
        raise


class SecureSessionManager:
    """Tracks active SecureSessions keyed by peer device_id rather than ip:port.

    Addresses Phase 10 requirements: connection keys should be tied to authenticated
    device identity because peer source ports can dynamically change.
    """

    def __init__(self):
        self._sessions: Dict[str, SecureSession] = {}

    def register(self, session: SecureSession) -> None:
        """Register a newly established secure session, replacing any stale previous one."""
        old = self._sessions.get(session.peer_device_id)
        if old and old.is_alive and old is not session:
            asyncio.create_task(old.close())
        self._sessions[session.peer_device_id] = session

    def get(self, device_id: str) -> Optional[SecureSession]:
        """Retrieve active session by device_id."""
        session = self._sessions.get(device_id)
        if session and not session.is_alive:
            self._sessions.pop(device_id, None)
            return None
        return session

    def remove(self, device_id: str) -> Optional[SecureSession]:
        """Remove a session from the manager."""
        return self._sessions.pop(device_id, None)

    def active_device_ids(self) -> List[str]:
        """List all currently active peer device IDs."""
        # Filter dead sessions
        dead = [k for k, v in self._sessions.items() if not v.is_alive]
        for k in dead:
            del self._sessions[k]
        return list(self._sessions.keys())

    async def close_all(self) -> None:
        """Close all active sessions."""
        sessions = list(self._sessions.values())
        self._sessions.clear()
        for s in sessions:
            await s.close()

    def __len__(self) -> int:
        return len(self._sessions)
