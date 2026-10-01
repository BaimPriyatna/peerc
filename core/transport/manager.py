"""
core/transport/manager.py — direct TCP connections between peers (transport layer).

Phase 38: moved here from the root peer.py, which is now a compatibility
shim. Behavior is unchanged.

Discovery (core/discovery/) tells us WHO is out there and WHERE (ip:tcp_port).
This module handles actually connecting to them and exchanging framed,
authenticated, encrypted messages over TCP.

BUG-004 (v1.15.1): every connection, incoming or outgoing, now goes
through core/transport's mutual authenticated handshake and
ChaCha20-Poly1305 session encryption (initiate_secure_session /
accept_secure_session — Phase 6-9) instead of raw plaintext asyncio
streams. Before this, Phase 6-9 existed as fully-implemented, unit-tested
modules that nothing in the running app actually called — the chat and file-transfer
sessions (then chat.py and file_transfer.py) were sending JSON straight over plaintext TCP.

ConnectionManager's public API (send()/send_binary()/connect_to()/
is_connected(), addr_key-keyed) is unchanged, so the chat and file-transfer
sessions didn't need to change. What's new: every connection is
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
from typing import Awaitable, Callable, List, Optional, Tuple

from core import protocol
from core.crypto.handshake import HANDSHAKE_TIMEOUT, HandshakeError
from core.identity.device_identity import DeviceKeypair
from core.transport import (
    RelayedStreamReader,
    RelayedStreamWriter,
    SecureSession,
    TCPConnection,
    accept_secure_session,
    initiate_secure_session,
    initiate_secure_session_on_connection,
)
from core.transport.timeout import ConnectionClosedError, TransportError
from core.trust.store import TrustDecision, TrustStore
from core.task_registry import TaskRegistry
from core.connection_state import ConnectionState, ConnectionStateMachine, InvalidConnectionTransition
from core.protocol import ErrorCode

OnMessage = Callable[[str, dict], Awaitable[None]]  # (peer_addr_key, message) -> None

CONNECT_TIMEOUT = 5.0    # seconds to wait for outgoing TCP connect (BUG-014)
MAX_CONNECTIONS = 64     # simultaneous connections, incoming + outgoing (BUG-016)


class ConnectionLimitError(Exception):
    """Raised when accepting/opening a connection would exceed MAX_CONNECTIONS."""


class ConnectionManager:
    """Owns the TCP server and all active secure sessions.

    Sessions are keyed by "ip:port" string (addr_key), same convention as
    before BUG-004 — the chat and file-transfer sessions address peers this way
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
        task_registry: Optional[TaskRegistry] = None,
    ):
        self.listen_port = listen_port
        self.my_identity = my_identity
        self.my_name = my_name
        self.on_message = on_message
        self.max_connections = max_connections
        self.event_bus = event_bus
        self.trust_store = trust_store
        # Phase 32.1: optional — falls back to bare asyncio.create_task()
        # so existing callers/tests that don't pass one are unaffected.
        self._task_registry = task_registry
        self._connections: dict[str, SecureSession] = {}
        # Phase 33.1: one ConnectionStateMachine per addr_key currently in
        # _connections (added/removed together). By the time
        # ConnectionManager ever sees a session, accept_secure_session()/
        # initiate_secure_session() has already run the whole handshake
        # atomically -- there's no hook into TCP_CONNECTED/HANDSHAKING as
        # separately-observable steps without instrumenting core.crypto
        # itself, which is out of scope here. _register_session() fast-
        # forwards through them (each still individually validated by the
        # transition table) so the two things that actually matter
        # operationally -- the ESTABLISHED guard before dispatching a
        # frame, and idempotent CLOSING/CLOSED on teardown -- are real.
        self._connection_states: dict[str, ConnectionStateMachine] = {}
        self._server: Optional[asyncio.base_events.Server] = None
        # Phase 46.1: relay-tunnel plumbing. Both dicts are keyed by the
        # addr_key of a real, already-established session — never by a
        # virtual A-B connection, since that one never has a real socket.
        #
        # _relay_pipes: I am R, forwarding for someone else. Bidirectional
        # (addr_key_a -> addr_key_b and back), populated by open_relay_pipe().
        self._relay_pipes: dict[str, str] = {}
        # _relay_tunnels: I am A or B, tunneling my own connection through
        # the session at this addr_key. Populated by register_relay_tunnel().
        self._relay_tunnels: dict[str, RelayedStreamReader] = {}
        # _tunnel_r_keys: maps tunneled session addr_key -> underlying relay r_addr_key.
        # Used to unregister relay tunnel upon session teardown.
        self._tunnel_r_keys: dict[str, str] = {}

    async def send_error(self, addr_key: str, code, *, context=None) -> bool:
        """Phase 35.2: best-effort `error` to a connected, authenticated
        peer. Never raises — this runs in failure paths, where a second
        failure would mask the first — and returns False if it couldn't
        be sent. Callers must not use this to answer an `error` frame.
        Only ever reachable post-handshake: sessions are registered only
        once the handshake has succeeded."""
        try:
            msg = protocol.make_error(code, context=context)
        except ValueError:
            return False
        try:
            return await self.send(addr_key, msg)
        except Exception:
            return False

    async def _report_invalid_frame(self, session: SecureSession, payload) -> None:
        """Tell the peer its authenticated application frame was malformed
        (INVALID_FRAME), just before the read loop drops the connection as
        it always has. Skipped when the bad frame was itself an `error`
        (no error ping-pong), and never for framing/decryption failures —
        those never reach here and stay local-log-only per §7."""
        ctx = None
        if isinstance(payload, dict):
            if payload.get("type") == "error":
                return
            ctx = {k: payload.get(k) for k in ("message_id", "transfer_id", "group_id")}
        await self.send_error(session.addr_key, ErrorCode.INVALID_FRAME, context=ctx)

    def _mark_closing(self, addr_key: str) -> None:
        """Phase 33.1: best-effort, defensive transition to CLOSING from
        a send-path failure. This connection's own _read_loop is what
        does the full CLOSED cleanup (it may already have — .get()
        returning None here just means someone else got there first,
        which is fine)."""
        fsm = self._connection_states.get(addr_key)
        if fsm is not None and not fsm.is_terminal():
            fsm.transition_to(ConnectionState.CLOSING)

    def get_connection_state(self, addr_key: str) -> Optional[ConnectionState]:
        """Introspection/testing hook — the connection lifecycle state
        for addr_key, or None if it was never registered (or has already
        been fully torn down and popped)."""
        fsm = self._connection_states.get(addr_key)
        return fsm.state if fsm is not None else None

    def _spawn(self, coro, *, name: str) -> asyncio.Task:
        """Phase 32.1: tracked task creation — falls back to a bare
        asyncio.create_task() when no registry was supplied."""
        if self._task_registry is not None:
            return self._task_registry.create_task(coro, group="connection", name=name)
        return asyncio.create_task(coro)

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
            # (bridge_security_events in app/ui/app.py) surfaces those.
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
        self._spawn(self._read_loop(session), name=f"read_loop:{addr_key}")
        return addr_key

    async def _register_session(self, session: SecureSession, incoming: bool) -> None:
        self._connections[session.addr_key] = session
        fsm = ConnectionStateMachine()
        for state in (
            ConnectionState.TCP_CONNECTED,
            ConnectionState.HANDSHAKING,
            ConnectionState.AUTHENTICATED,
            ConnectionState.ESTABLISHED,
        ):
            fsm.transition_to(state)
        self._connection_states[session.addr_key] = fsm
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
                # Phase 33.1: a send-path failure elsewhere (send()/
                # send_binary()/send_relay_data()) may have already
                # transitioned this connection to CLOSING while this
                # loop's receive() call was returning one more
                # already-buffered frame -- reject it rather than
                # dispatching against a connection that's on its way out.
                fsm = self._connection_states.get(session.addr_key)
                if fsm is not None:
                    fsm.require_established(f"dispatching a {kind!r} frame")
                if kind == "json":
                    try:
                        protocol.validate_message(payload)  # raises ProtocolError if malformed
                    except protocol.ProtocolError:
                        await self._report_invalid_frame(session, payload)
                        raise
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
                    try:
                        decoded = protocol.decode_file_data(payload)  # raises ProtocolError if too short
                    except protocol.ProtocolError:
                        await self._report_invalid_frame(session, None)
                        raise
                    decoded["type"] = "file_data"
                    if self.event_bus:
                        from core.events import NetworkMessageReceived
                        await self.event_bus.publish(
                            NetworkMessageReceived(addr_key=session.addr_key, message=decoded, kind="binary")
                        )
                    if self.on_message:
                        await self.on_message(session.addr_key, decoded)
                elif kind == "relay":
                    # Phase 46.1: opaque relay-tunnel chunk. Never reaches
                    # on_message/NetworkMessageReceived — it's either
                    # someone else's traffic I'm relaying (pipe) or my
                    # own tunneled connection's bytes (tunnel), and in
                    # both cases the content is meaningless at this
                    # layer.
                    paired_addr_key = self._relay_pipes.get(session.addr_key)
                    if paired_addr_key is not None:
                        await self.send_relay_data(paired_addr_key, payload)
                    else:
                        tunnel_reader = self._relay_tunnels.get(session.addr_key)
                        if tunnel_reader is not None:
                            tunnel_reader.feed_data(payload)
                        elif len(self._connections) < self.max_connections:
                            # Phase 46.3: incoming relayed connection — peer is initiating a handshake via R
                            r_addr_key = session.addr_key
                            reader = RelayedStreamReader()
                            self.register_relay_tunnel(r_addr_key, reader)
                            reader.feed_data(payload)

                            async def _handle_incoming_relay(r_key: str, r_reader: RelayedStreamReader) -> None:
                                async def _send(chunk: bytes) -> None:
                                    await self.send_relay_data(r_key, chunk)
                                writer = RelayedStreamWriter(_send, peer_addr=("relayed-temp", 0))
                                try:
                                    relayed_session = await accept_secure_session(
                                        r_reader, writer,
                                        my_identity=self.my_identity,
                                        my_name=self.my_name,
                                        trust_store=self.trust_store,
                                    )
                                    relayed_session.transport.tcp._peer_ip = f"relay-{relayed_session.peer_device_id[:8]}"
                                    relayed_session.transport.tcp._peer_port = 0
                                    self._tunnel_r_keys[relayed_session.addr_key] = r_key
                                    await self._register_session(relayed_session, incoming=True)
                                    await self._read_loop(relayed_session)
                                except Exception:
                                    self.unregister_relay_tunnel(r_key)

                            self._spawn(
                                _handle_incoming_relay(r_addr_key, reader),
                                name=f"relay_incoming:{r_addr_key}",
                            )
                        # else: relay chunk with no active pipe or tunnel and limit reached — drop
                # else: "raw" frame kind (neither JSON nor binary/relay marker) — drop.
        except (ConnectionClosedError, asyncio.IncompleteReadError, ConnectionResetError):
            pass  # peer disconnected
        except (protocol.ProtocolError, TransportError):
            pass  # malformed frame, or a decryption/replay failure — drop the connection
        except InvalidConnectionTransition:
            pass  # a frame arrived after this connection left ESTABLISHED — drop it
        finally:
            fsm = self._connection_states.pop(session.addr_key, None)
            if fsm is not None:
                fsm.transition_to(ConnectionState.CLOSING)
                fsm.transition_to(ConnectionState.CLOSED)
            self._connections.pop(session.addr_key, None)
            self.close_relay_pipe(session.addr_key)
            r_key = self._tunnel_r_keys.pop(session.addr_key, None)
            if r_key is not None:
                self.unregister_relay_tunnel(r_key)
            tunnel_reader = self._relay_tunnels.pop(session.addr_key, None)
            if tunnel_reader is not None:
                tunnel_reader.feed_eof()
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
            self._mark_closing(addr_key)
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
            self._mark_closing(addr_key)
            return False

    async def send_relay_data(self, addr_key: str, payload: bytes) -> bool:
        """Send a raw relay-tunnel chunk on an already-open session
        (Phase 46.1). Same shape as send_binary(); kept separate so a
        relay chunk never gets decoded as file_data. Returns False if
        not connected."""
        session = self._connections.get(addr_key)
        if session is None:
            return False
        try:
            await session.send_relay(payload)
            return True
        except (ConnectionClosedError, ConnectionResetError, BrokenPipeError, TransportError):
            self._connections.pop(addr_key, None)
            self._mark_closing(addr_key)
            return False

    def open_relay_pipe(self, addr_key_a: str, addr_key_b: str) -> None:
        """I am R: bridge two already-connected sessions. Any `relay`
        chunk arriving on either addr_key gets forwarded verbatim to the
        other, with no decoding — see _read_loop. Caller (Phase 46.2) is
        responsible for having already checked both are actually
        connected and that this bridging is authorized."""
        self._relay_pipes[addr_key_a] = addr_key_b
        self._relay_pipes[addr_key_b] = addr_key_a

    def close_relay_pipe(self, addr_key: str) -> None:
        """Tear down a relay pipe given either side's addr_key. Only
        removes the routing entries — does not close either underlying
        session, which may still be in use for unrelated traffic (e.g.
        R's own group messages with that peer). Safe to call even if no
        pipe is open for this addr_key."""
        paired = self._relay_pipes.pop(addr_key, None)
        if paired is not None:
            self._relay_pipes.pop(paired, None)

    def is_relay_pipe_open(self, addr_key: str) -> bool:
        return addr_key in self._relay_pipes

    def register_relay_tunnel(self, addr_key: str, reader: RelayedStreamReader) -> None:
        """I am A or B: `relay` chunks arriving on the real session at
        addr_key (my connection to R) are bytes of my own tunneled
        connection, not something to forward — feed them to reader
        instead of on_message. See open_relay_tunnel()."""
        self._relay_tunnels[addr_key] = reader

    def unregister_relay_tunnel(self, addr_key: str) -> None:
        self._relay_tunnels.pop(addr_key, None)

    def open_relay_tunnel(
        self,
        r_addr_key: str,
        peer_addr: Tuple[str, int] = ("0.0.0.0", 0),
    ) -> TCPConnection:
        """I am A or B: build a TCPConnection whose bytes tunnel through
        my existing session with R (r_addr_key) as opaque `relay`
        chunks, and register it so incoming `relay` chunks on that
        session feed this tunnel instead of being dropped.

        The returned TCPConnection can be handed straight to
        perform_handshake_initiator/_responder (via its .reader/.writer)
        or wrapped the same way initiate_secure_session/
        accept_secure_session wrap a real one — nothing downstream needs
        to know this isn't a real socket. Caller owns unregistering it
        (unregister_relay_tunnel) once the tunneled connection is done;
        it's also cleaned up automatically if the underlying session
        with R itself closes first (see _read_loop).
        """
        async def _send(chunk: bytes) -> None:
            await self.send_relay_data(r_addr_key, chunk)

        reader = RelayedStreamReader()
        writer = RelayedStreamWriter(_send, peer_addr=peer_addr)
        self.register_relay_tunnel(r_addr_key, reader)
        return TCPConnection(reader, writer)

    async def connect_via_relay_tunnel(
        self,
        r_addr_key: str,
        target_device_id: str,
        timeout: float = HANDSHAKE_TIMEOUT,
    ) -> str:
        """Phase 46.3: establish a SecureSession to target_device_id by
        tunneling a Phase 6 initiator handshake through an existing session
        with relay R (r_addr_key).
        Registers the resulting session into _connections, starts its background
        read loop, and returns the assigned collision-free addr_key.
        """
        existing_key = self.find_addr_key_for_device(target_device_id)
        if existing_key is not None and existing_key in self._connections:
            return existing_key

        if len(self._connections) >= self.max_connections:
            raise ConnectionLimitError(
                f"at connection limit ({self.max_connections}); refusing to connect to {target_device_id[:8]}"
            )

        peer_addr = (f"relay-{target_device_id[:8]}", 0)
        tcp_conn = self.open_relay_tunnel(r_addr_key, peer_addr=peer_addr)
        try:
            session = await initiate_secure_session_on_connection(
                tcp_conn,
                my_identity=self.my_identity,
                my_name=self.my_name,
                trust_store=self.trust_store,
                handshake_timeout=timeout,
            )
            if session.peer_device_id != target_device_id:
                await session.close()
                self.unregister_relay_tunnel(r_addr_key)
                raise HandshakeError(
                    f"Relayed handshake returned unexpected peer_device_id: "
                    f"{session.peer_device_id} (expected {target_device_id})"
                )
            self._tunnel_r_keys[session.addr_key] = r_addr_key
            await self._register_session(session, incoming=False)
            self._spawn(self._read_loop(session), name=f"read_loop:{session.addr_key}")
            return session.addr_key
        except Exception:
            self.unregister_relay_tunnel(r_addr_key)
            raise


    def is_connected(self, addr_key: str) -> bool:
        return addr_key in self._connections

    def list_connected_addr_keys(self) -> List[str]:
        """Snapshot of currently-connected addr_keys. A plain list copy,
        not a live view — safe to iterate even if a connection drops
        mid-loop (e.g. Phase 44.4/45.1's re-announce-on-IP-change)."""
        return list(self._connections.keys())

    def find_addr_key_for_device(self, device_id: str) -> Optional[str]:
        """Reverse of get_peer_device_id(): the addr_key of an
        already-connected session whose authenticated peer is
        device_id, or None if not currently connected to it (Phase
        46.2 needs this — "am I, R, already connected to the relay
        target?"). O(n) in connection count; nothing so far has needed
        this lookup often enough to warrant a second index."""
        for addr_key, session in self._connections.items():
            if session.peer_device_id == device_id:
                return addr_key
        return None

    def get_peer_device_id(self, addr_key: str) -> Optional[str]:
        """The cryptographically authenticated device_id of the peer at
        addr_key, or None if not connected. Unlike a message's own
        self-reported sender_id field, this is verified by the handshake
        (Phase 6) — the peer proved possession of the private key behind
        this device_id."""
        session = self._connections.get(addr_key)
        return session.peer_device_id if session else None

    def get_peer_public_key(self, addr_key: str) -> Optional[bytes]:
        """The peer's raw Ed25519 public key bytes for addr_key, or None
        if not connected — same authentication guarantee as
        get_peer_device_id() (Phase 6 handshake), just the raw key
        instead of its device_id hash. Used to verify things signed by
        the peer after the handshake itself, e.g. an endpoint_update
        (Phase 44.4)."""
        session = self._connections.get(addr_key)
        if session is None:
            return None
        return bytes.fromhex(session.peer_public_key)

    async def close_all(self) -> None:
        for addr_key, session in list(self._connections.items()):
            self._mark_closing(addr_key)
            await session.close()
        # Each session's _read_loop will independently reach its own
        # finally block (session.close() unblocks its pending receive())
        # and finish the CLOSING -> CLOSED transition + dict pop itself;
        # nothing further to do to _connection_states here.
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
    #   python3 -m core.transport.manager server 5555
    #   python3 -m core.transport.manager client 5555 <server-ip>
    import sys

    import core.identity as identity

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
