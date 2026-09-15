"""
peer.py — direct TCP connections between peers (transport layer).

Discovery (discovery.py) tells us WHO is out there and WHERE (ip:tcp_port).
This module handles actually connecting to them and exchanging framed,
authenticated, encrypted messages over TCP.

BUG-004 (v1.15.1): every connection, incoming or outgoing, now goes
through core/transport's mutual authenticated handshake and
ChaCha20-Poly1305 session encryption (initiate_secure_session /
accept_secure_session — Phase 6-9) instead of raw plaintext asyncio
streams. Before this, Phase 6-9 existed as fully-implemented, unit-tested
modules that nothing in the running app actually called — chat.py and
file_transfer.py were sending JSON straight over plaintext TCP.

ConnectionManager's public API (send()/send_binary()/connect_to()/
is_connected(), addr_key-keyed) is unchanged, so chat.py and
file_transfer.py didn't need to change. What's new: every connection is
now backed by a SecureSession, so callers can look up an authenticated
peer_device_id via get_peer_device_id() — previously, the only device_id
in play was self-reported inside application-level message fields, never
cryptographically verified.

my_identity/my_name/trust_store have no defaults on purpose: a
ConnectionManager without a real, persistent Ed25519 identity would
mint a throwaway one and nobody would notice — every caller (including
tests) must be explicit about which identity it's handshaking as.
"""

import asyncio
from typing import Awaitable, Callable, Optional

import protocol
from core.crypto.handshake import HandshakeError
from core.identity.device_identity import DeviceKeypair
from core.transport import (
    SecureSession,
    accept_secure_session,
    initiate_secure_session,
)
from core.transport.timeout import ConnectionClosedError, TransportError
from core.trust.store import TrustDecision, TrustStore

OnMessage = Callable[[str, dict], Awaitable[None]]  # (peer_addr_key, message) -> None

CONNECT_TIMEOUT = 5.0    # seconds to wait for outgoing TCP connect (BUG-014)
MAX_CONNECTIONS = 64     # simultaneous connections, incoming + outgoing (BUG-016)


class ConnectionLimitError(Exception):
    """Raised when accepting/opening a connection would exceed MAX_CONNECTIONS."""


class ConnectionManager:
    """Owns the TCP server and all active secure sessions.

    Sessions are keyed by "ip:port" string (addr_key), same convention as
    before BUG-004 — chat.py/file_transfer.py address peers this way
    throughout. Unlike before, each session now also carries a verified
    peer_device_id (get_peer_device_id()); callers that need the
    authenticated identity rather than just "the connection at this
    address" should use that instead of trusting a message's own
    self-reported sender_id field.
    """

    def __init__(
        self,
        listen_port: int,
        my_identity: DeviceKeypair,
        my_name: str,
        on_message: Optional[OnMessage] = None,
        max_connections: int = MAX_CONNECTIONS,
        event_bus: Optional[object] = None,
        trust_store: Optional[TrustStore] = None,
    ):
        self.listen_port = listen_port
        self.my_identity = my_identity
        self.my_name = my_name
        self.on_message = on_message
        self.max_connections = max_connections
        self.event_bus = event_bus
        self.trust_store = trust_store
        self._connections: dict[str, SecureSession] = {}
        self._server: Optional[asyncio.base_events.Server] = None

    async def start_server(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_incoming, host="0.0.0.0", port=self.listen_port
        )

    async def _handle_incoming(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_addr = writer.get_extra_info("peername")
        addr_key = f"{peer_addr[0]}:{peer_addr[1]}" if peer_addr else "unknown:0"

        # BUG-016: a hostile LAN peer opening unlimited connections is a
        # cheap resource-exhaustion attack. Reject once we're at capacity,
        # before even spending CPU on a handshake.
        if len(self._connections) >= self.max_connections:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return

        try:
            session = await accept_secure_session(
                reader, writer,
                my_identity=self.my_identity,
                my_name=self.my_name,
                trust_store=self.trust_store,
            )
        except (HandshakeError, TransportError, asyncio.TimeoutError, OSError, RuntimeError):
            # Failed handshakes for security-relevant reasons (identity
            # mismatch, REVOKED device, bad signature, replay) already
            # emit a SecurityEvent from inside handshake.py/TrustStore
            # itself (Phase 41) — the app-level SecurityWarning bridge
            # (bridge_security_events in ui.py) surfaces those.
            # RuntimeError covers Phase 39.3: TrustStore detached while
            # the vault is hard-locked (no live conn) — fail closed on
            # new handshakes until re-unlock, without crashing the
            # accept loop. Nothing further to publish here; just clean
            # up the raw socket.
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass
            return

        await self._register_session(session, incoming=True)
        await self._read_loop(session)

    async def connect_to(self, ip: str, port: int) -> str:
        """Open an outgoing secure session. Returns the addr_key for this connection."""
        addr_key = f"{ip}:{port}"
        if addr_key in self._connections:
            return addr_key

        if len(self._connections) >= self.max_connections:
            raise ConnectionLimitError(
                f"at connection limit ({self.max_connections}); refusing to connect to {addr_key}"
            )

        # BUG-014: initiate_secure_session applies its own connect_timeout
        # internally (core/transport/timeout.py's CONNECT_TIMEOUT) — a peer
        # that accepts the TCP handshake but never completes the crypto
        # handshake is separately bounded by handshake_timeout.
        session = await initiate_secure_session(
            ip, port,
            my_identity=self.my_identity,
            my_name=self.my_name,
            trust_store=self.trust_store,
            connect_timeout=CONNECT_TIMEOUT,
        )
        # session.addr_key is derived from the actual connected socket's
        # peer info, which should equal what we dialed — use it as the
        # canonical key regardless, same as the old code implicitly did.
        addr_key = session.addr_key
        await self._register_session(session, incoming=False)
        # Run the read loop in the background so this call returns immediately.
        asyncio.create_task(self._read_loop(session))
        return addr_key

    async def _register_session(self, session: SecureSession, incoming: bool) -> None:
        self._connections[session.addr_key] = session
        if self.event_bus:
            from core.events import PeerConnected, TrustRequired
            await self.event_bus.publish(
                PeerConnected(
                    addr_key=session.addr_key,
                    peer_id=session.peer_device_id,
                    incoming=incoming,
                )
            )
            if session.trust_decision == TrustDecision.PENDING:
                # First time we've ever seen this device_id (TrustStore
                # recorded it as first-seen during the handshake and
                # returned PENDING) — the connection is allowed to
                # proceed (matching handshake.py's own behavior), but the
                # UI should know a trust decision is outstanding. Full
                # approve/reject UX is Phase 36/37, not this bug fix —
                # for now this is surfaced as a notification only.
                await self.event_bus.publish(
                    TrustRequired(
                        peer_id=session.peer_device_id,
                        peer_name=session.peer_name,
                        public_key=session.peer_public_key,
                        addr_key=session.addr_key,
                    )
                )

    async def _read_loop(self, session: SecureSession) -> None:
        try:
            while True:
                kind, payload = await session.receive()
                if kind == "json":
                    protocol.validate_message(payload)  # raises ProtocolError if malformed
                    if self.event_bus:
                        from core.events import NetworkMessageReceived
                        await self.event_bus.publish(
                            NetworkMessageReceived(addr_key=session.addr_key, message=payload, kind="json")
                        )
                    if self.on_message:
                        await self.on_message(session.addr_key, payload)
                elif kind == "binary":
                    # Binary frame: currently only used for file_data
                    # chunks. Decode into a dict shape so the on_message
                    # callback interface doesn't need to change —
                    # FileTransferSession._dispatch treats "file_data"
                    # like any other message type.
                    decoded = protocol.decode_file_data(payload)  # raises ProtocolError if too short
                    decoded["type"] = "file_data"
                    if self.event_bus:
                        from core.events import NetworkMessageReceived
                        await self.event_bus.publish(
                            NetworkMessageReceived(addr_key=session.addr_key, message=decoded, kind="binary")
                        )
                    if self.on_message:
                        await self.on_message(session.addr_key, decoded)
                # else: "raw" frame kind (neither JSON nor binary marker) — drop.
        except (ConnectionClosedError, asyncio.IncompleteReadError, ConnectionResetError):
            pass  # peer disconnected
        except (protocol.ProtocolError, TransportError):
            pass  # malformed frame, or a decryption/replay failure — drop the connection
        finally:
            self._connections.pop(session.addr_key, None)
            await session.close()
            if self.event_bus:
                from core.events import PeerDisconnected
                await self.event_bus.publish(
                    PeerDisconnected(addr_key=session.addr_key, peer_id=session.peer_device_id)
                )

    async def send(self, addr_key: str, message: dict) -> bool:
        """Send a JSON control message on an already-open session. Returns False if not connected."""
        session = self._connections.get(addr_key)
        if session is None:
            return False
        try:
            await session.send(message)
            return True
        except (ConnectionClosedError, ConnectionResetError, BrokenPipeError, TransportError):
            self._connections.pop(addr_key, None)
            return False

    async def send_binary(self, addr_key: str, payload: bytes) -> bool:
        """Send a raw binary frame (Phase 1.3: file_data chunks). Returns False if not connected."""
        session = self._connections.get(addr_key)
        if session is None:
            return False
        try:
            await session.send_binary(payload)
            return True
        except (ConnectionClosedError, ConnectionResetError, BrokenPipeError, TransportError):
            self._connections.pop(addr_key, None)
            return False

    def is_connected(self, addr_key: str) -> bool:
        return addr_key in self._connections

    def get_peer_device_id(self, addr_key: str) -> Optional[str]:
        """The cryptographically authenticated device_id of the peer at
        addr_key, or None if not connected. Unlike a message's own
        self-reported sender_id field, this is verified by the handshake
        (Phase 6) — the peer proved possession of the private key behind
        this device_id."""
        session = self._connections.get(addr_key)
        return session.peer_device_id if session else None

    async def close_all(self) -> None:
        for session in list(self._connections.values()):
            await session.close()
        self._connections.clear()
        if self._server:
            self._server.close()
            # Python 3.12's Server.wait_closed() waits for every accepted
            # connection's handler task to actually finish, not just for
            # close() itself — and a just-closed session's background
            # _read_loop task can take a beat to notice its socket died
            # (it's waiting on the EOF to propagate). We've already
            # closed every known session above; don't block shutdown
            # indefinitely on that last bit of housekeeping.
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass


if __name__ == "__main__":
    # Manual test: run as either "server" or "client" role from two terminals.
    #   python3 peer.py server 5555
    #   python3 peer.py client 5555 <server-ip>
    import sys

    import core.identity as identity
    import discovery as _discovery  # reuse identity loader

    async def _main() -> None:
        role = sys.argv[1]
        port = int(sys.argv[2])
        dev_identity = identity.load_or_create_identity()
        peer_id, name = dev_identity.device_id, dev_identity.name

        async def on_message(addr_key: str, message: dict) -> None:
            if message.get("type") == "chat":
                print(f"\n<{message['sender_name']}> {message['text']}")

        manager = ConnectionManager(
            listen_port=port, my_identity=dev_identity.keypair, my_name=name,
            on_message=on_message,
        )
        await manager.start_server()
        print(f"Listening on port {port} as {name} ({peer_id[:8]})")

        if role == "client":
            target_ip = sys.argv[3]
            addr_key = await manager.connect_to(target_ip, port)
            print(f"Connected to {addr_key}")

        # Simple stdin -> send loop for manual testing
        loop = asyncio.get_event_loop()
        while True:
            text = await loop.run_in_executor(None, input, "")
            if not manager._connections:
                print("(no connection yet)")
                continue
            msg = protocol.make_chat_message(peer_id, name, text)
            for addr_key in list(manager._connections.keys()):
                await manager.send(addr_key, msg)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
