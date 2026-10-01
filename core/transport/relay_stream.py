"""core/transport/relay_stream.py — Phase 46.1: relay-tunnel stream shim.

A relayed connection between A and B never touches a real socket — every
byte of it travels as opaque `relay` chunks (core/transport/secure.py's
TYPE_RELAY marker) over A's and B's own already-established, already-
authenticated sessions with the relay R. R itself never decodes any of
it; see docs/ROADMAP.md's "Phase 46 design (resolved)" for the full
picture.

RelayedStreamReader/RelayedStreamWriter exist so that code which expects
a real asyncio.StreamReader/StreamWriter pair — most importantly
core/crypto/handshake.py's perform_handshake_initiator/_responder, which
read/write raw length-prefixed frames directly via
core/protocol/frame.py — can run completely unmodified over a relayed
connection. Wrap them in a plain core.transport.tcp.TCPConnection (which
only ever calls the small surface implemented below) and everything
above that layer — SecureSession, EncryptedTransport, the Phase 6
handshake itself — works exactly as it would over a direct TCP
connection.

Only the surface actually exercised by frame.py / tcp.py is implemented:
reader.readexactly(n); writer.write(data), writer.drain(),
writer.get_extra_info(name), writer.is_closing(), writer.close(),
writer.wait_closed(). This is deliberately not a general-purpose asyncio
stream substitute.
"""

import asyncio
from typing import Awaitable, Callable, Optional, Tuple


class RelayedStreamReader:
    """Feeds bytes arriving as `relay` chunks to readexactly() callers.

    feed_data() is called by whatever is pulling `relay` frames off the
    real underlying session (see core/transport/manager.py's ConnectionManager) each time
    one arrives for this tunnel; feed_eof() is called once that
    underlying session itself closes, so a stalled read unblocks with
    the same asyncio.IncompleteReadError a real dead socket would raise.
    """

    def __init__(self):
        self._buffer = bytearray()
        self._eof = False
        self._waiter: Optional[asyncio.Future] = None

    def feed_data(self, data: bytes) -> None:
        if self._eof or not data:
            return
        self._buffer.extend(data)
        self._wake()

    def feed_eof(self) -> None:
        if self._eof:
            return
        self._eof = True
        self._wake()

    def _wake(self) -> None:
        if self._waiter is not None and not self._waiter.done():
            self._waiter.set_result(None)

    async def readexactly(self, n: int) -> bytes:
        """Matches asyncio.StreamReader.readexactly(): returns exactly n
        bytes, or raises asyncio.IncompleteReadError (with whatever
        partial bytes had arrived) if EOF is hit first."""
        while len(self._buffer) < n:
            if self._eof:
                partial = bytes(self._buffer)
                self._buffer.clear()
                raise asyncio.IncompleteReadError(partial, n)
            self._waiter = asyncio.get_event_loop().create_future()
            try:
                await self._waiter
            finally:
                self._waiter = None

        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data


class RelayedStreamWriter:
    """Packages write()+drain() calls into `relay` chunks sent over the
    real session with R, via send_fn (typically
    ConnectionManager.send_relay_data bound to the R-facing addr_key).
    """

    def __init__(
        self,
        send_fn: Callable[[bytes], Awaitable[None]],
        peer_addr: Tuple[str, int] = ("0.0.0.0", 0),
    ):
        self._send_fn = send_fn
        self._pending = bytearray()
        self._closed = False
        self._peer_addr = peer_addr

    def write(self, data: bytes) -> None:
        if self._closed or not data:
            return
        self._pending.extend(data)

    async def drain(self) -> None:
        if self._closed or not self._pending:
            return
        chunk = bytes(self._pending)
        self._pending.clear()
        await self._send_fn(chunk)

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            return self._peer_addr
        return default

    def is_closing(self) -> bool:
        return self._closed

    def close(self) -> None:
        # Nothing to actually tear down here — the real socket is the
        # A/B<->R session, which outlives any one tunnel. This just
        # marks the tunnel itself as done so further write()/drain()
        # calls are no-ops, matching a real StreamWriter's post-close
        # behavior closely enough for TCPConnection's needs.
        self._closed = True

    async def wait_closed(self) -> None:
        return None
