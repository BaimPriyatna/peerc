"""
discovery.py — MNDP-style peer discovery via UDP broadcast.

Each running instance periodically broadcasts a JSON "announce" packet
containing its stable peer_id, display name, and TCP port. Other instances
listen for these broadcasts and maintain a live peer list, evicting peers
that haven't announced within PEER_TIMEOUT seconds (handles DHCP IP changes
and peers going offline).

Phase 3: peer_id is now a device_id derived from an Ed25519 keypair
(core/identity/), not a random UUID — see core/identity/device_identity.py
for why a bare UUID isn't good enough (anyone could claim any UUID; a
device_id is provably tied to the key that backs it). load_or_create_identity()
below keeps its old (peer_id, name) tuple return shape so chat.py/ui.py/
peer.py didn't need to change, but what's inside peer_id changed completely.

Phase 5.1 (IMPLEMENTATION_PLAN.md "Phase 5 — Discovery V2"): the wire
payload now carries a "version" field and the device's raw Ed25519
public_key alongside device_id, and every incoming packet's device_id is
checked for self-consistency against its claimed public_key
(device_id == sha256(public_key)). This is deliberately NOT a trust
decision — discovery only proves "this announcement is internally
consistent", never "this device is trusted" (that's core/trust/'s job,
enforced later at handshake time in Phase 6). A mismatch here means the
packet is lying about its own identity, so it's dropped and logged as a
security event; it says nothing about whether a self-consistent peer
should actually be trusted.

Phase 5.2 (v1.13.1): mDNS via `zeroconf` added as a second discovery
transport alongside UDP broadcast, for environments where UDP broadcast
is blocked (AP isolation, multi-subnet LANs).  mDNS is **optional** —
if the `zeroconf` package is not installed, discovery falls back to UDP
broadcast only (MDNS_AVAILABLE = False, startup logs a warning).

Install mDNS support with:  pip install peerc[mdns]

mDNS service type: _peerc._tcp.local.
TXT record fields (all strings, key-value):
  version=<int>          PROTOCOL_VERSION
  device_id=<hex>        sha256(public_key) hex digest
  public_key=<b64>       raw Ed25519 public key, base64-encoded
  name=<str>             display name (capped at 64 chars)
  tcp_port=<int>         TCP listen port

The same _handle_packet() method parses both UDP broadcast and mDNS
announce packets — no duplicate validation logic.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import core.identity as identity
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

# ---------------------------------------------------------------------------
# Optional mDNS dependency
# ---------------------------------------------------------------------------
try:
    from zeroconf import ServiceInfo, Zeroconf  # noqa: F401 (checked for availability)
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    MDNS_AVAILABLE = True
except ImportError:
    MDNS_AVAILABLE = False

_log = logging.getLogger(__name__)

BROADCAST_PORT = 9999
ANNOUNCE_INTERVAL = 3.0   # seconds between announces
PEER_TIMEOUT = 10.0       # seconds of silence before a peer is considered offline
PROTOCOL_VERSION = 2      # Phase 5.1: discovery payload schema version

MDNS_SERVICE_TYPE = "_peerc._tcp.local."
MDNS_ANNOUNCE_INTERVAL = 10.0  # mDNS re-registration / TTL-refresh interval (seconds)


@dataclass
class Peer:
    peer_id: str
    name: str
    ip: str
    tcp_port: int
    public_key: bytes = b""  # raw Ed25519 public key bytes (Phase 5.1); empty for legacy/unset
    model: str = ""  # self-reported device/platform string (core/device_info.py); "" for legacy/unset, display-only
    last_seen: float = field(default_factory=time.time)


class PeerRegistry:
    """Thread/async-safe-enough store of currently known peers.

    Keyed by peer_id (NOT ip), since IP can change under DHCP or when
    switching between LAN and hotspot.
    """

    def __init__(self, on_peer_new: Optional[Callable[[Peer], None]] = None,
                 on_peer_lost: Optional[Callable[[Peer], None]] = None):
        self._peers: dict[str, Peer] = {}
        self._on_peer_new = on_peer_new
        self._on_peer_lost = on_peer_lost

    def upsert(self, peer_id: str, name: str, ip: str, tcp_port: int,
               public_key: bytes = b"", model: str = "") -> None:
        existing = self._peers.get(peer_id)
        now = time.time()
        if existing is None:
            self._peers[peer_id] = Peer(peer_id, name, ip, tcp_port, public_key, model, now)
            if self._on_peer_new:
                self._on_peer_new(self._peers[peer_id])
        else:
            # Update in place — IP/port may have changed (DHCP renew, network switch)
            existing.name = name
            existing.ip = ip
            existing.tcp_port = tcp_port
            if public_key:
                existing.public_key = public_key
            if model:
                existing.model = model
            existing.last_seen = now

    def prune_stale(self) -> None:
        now = time.time()
        stale_ids = [
            pid for pid, p in self._peers.items()
            if now - p.last_seen > PEER_TIMEOUT
        ]
        for pid in stale_ids:
            peer = self._peers.pop(pid)
            if self._on_peer_lost:
                self._on_peer_lost(peer)

    def list_peers(self) -> list[Peer]:
        return list(self._peers.values())

    def get(self, peer_id: str) -> Optional[Peer]:
        return self._peers.get(peer_id)


def save_identity(peer_id: str, name: str, config_path: str = identity.DEFAULT_IDENTITY_FILE) -> None:
    """Update the display name in the identity file (used by ui.py's /name
    rename command).

    peer_id is accepted for backward compatibility with the pre-Phase-3
    call signature but is no longer something this function can change:
    device_id is derived from the Ed25519 keypair, not freely assignable.
    If the caller's peer_id doesn't match what's on file, that's a sign
    something's out of sync — better to raise than silently ignore it.
    """
    if not os.path.exists(config_path):
        return  # nothing to rename yet — load_or_create_identity() creates it first

    with open(config_path, "r") as f:
        meta = json.load(f)

    if meta.get("device_id") != peer_id:
        raise ValueError(
            f"save_identity called with peer_id={peer_id!r}, but the identity "
            f"file's device_id is {meta.get('device_id')!r} — refusing to "
            "rename what looks like a different identity"
        )

    meta["name"] = name
    with open(config_path, "w") as f:
        json.dump(meta, f, indent=2)


def get_broadcast_targets() -> list[str]:
    """Find all potential IPv4 broadcast and gateway addresses.

    On mobile hotspot tethering (e.g. Android), sending only to 255.255.255.255
    often fails because the mobile kernel routes 255.255.255.255 over cellular
    data rather than the Wi-Fi AP interface. Including subnet broadcast
    (e.g. 10.186.76.255, 192.168.43.255) and the default gateway IP ensures
    packets reach peers across mobile hotspots and complex LANs.
    """
    import struct
    import subprocess

    targets = {"255.255.255.255"}

    # 1. Parse /proc/net/route on Linux/Android for default gateway
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3:
                    dest, gw = fields[1], fields[2]
                    if dest == "00000000" and gw != "00000000":
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
                        targets.add(gw_ip)
    except Exception:
        pass

    # 2. Check `ip` command on Linux / Android Termux for subnet broadcasts
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            text=True, stderr=subprocess.DEVNULL, timeout=1.0
        )
        for line in out.splitlines():
            parts = line.split()
            if "brd" in parts:
                idx = parts.index("brd")
                if idx + 1 < len(parts):
                    targets.add(parts[idx + 1])
    except Exception:
        pass

    # 3. Check default gateway from ip route
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True, stderr=subprocess.DEVNULL, timeout=1.0
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    targets.add(parts[idx + 1])
    except Exception:
        pass

    return sorted(list(targets))


def get_network_info() -> dict:
    """Return local network diagnostics for peer discovery."""
    targets = get_broadcast_targets()
    local_ips = []
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                local_ips.append(ip)
    except Exception:
        pass
    return {
        "local_ips": local_ips,
        "targets": targets,
        "mdns_available": MDNS_AVAILABLE,
    }


def load_or_create_identity(config_path: str = identity.DEFAULT_IDENTITY_FILE) -> tuple[str, str]:
    """Return (peer_id, name).

    peer_id is now an Ed25519-derived device_id (Phase 3) — generated and
    persisted via core.identity on first run, loaded from the same file on
    every run after. Old pre-Phase-3 identity files (a bare
    {"peer_id": <uuid>, "name": ...} at .peerc_identity.json) are not
    migrated: they used a fundamentally different scheme with no keypair
    behind them, so there's nothing to carry forward. A device upgrading
    to this version gets a new device_id the first time it runs.
    """
    dev_identity = identity.load_or_create_identity(
        name=socket.gethostname(), identity_file=config_path,
    )
    return dev_identity.device_id, dev_identity.name


# ---------------------------------------------------------------------------
# mDNS helpers (Phase 5.2)
# ---------------------------------------------------------------------------

def _build_mdns_txt(version: int, device_id: str, public_key: bytes,
                    name: str, tcp_port: int, model: str = "") -> dict[str, str]:
    """Build the TXT record key-value dict for a peerc mDNS service.

    All values are str (zeroconf encodes them as UTF-8 in the TXT record).
    Fields mirror the UDP broadcast JSON payload so _handle_packet() can
    validate both paths identically via _mdns_txt_to_packet().
    """
    return {
        "version": str(version),
        "device_id": device_id,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "name": name[:64],
        "tcp_port": str(tcp_port),
        "model": model[:64],
    }


def _safe_int(v: object) -> int:
    """Convert v to int; return 0 on any failure."""
    try:
        return int(v)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return 0


def _mdns_txt_to_packet(txt: dict, src_ip: str) -> bytes:
    """Convert a received mDNS TXT key-value dict back into the same JSON
    wire format used by UDP broadcast announce packets.

    This lets _handle_packet() validate mDNS peers with exactly the same
    code path as UDP broadcast peers — no duplicate validation logic.
    reply=False tells _handle_packet not to send a UDP unicast reply back
    (mDNS already handles bidirectional discovery).
    """
    try:
        version = int(txt.get("version", 0))
    except (ValueError, TypeError):
        version = 0
    msg = {
        "type": "announce",
        "version": version,
        "device_id": txt.get("device_id", ""),
        "public_key": txt.get("public_key", ""),
        "name": txt.get("name", src_ip),
        "tcp_port": _safe_int(txt.get("tcp_port", "0")),
        "model": txt.get("model", ""),
        "reply": False,
    }
    return json.dumps(msg).encode("utf-8")


# ---------------------------------------------------------------------------
# mDNS transport classes (Phase 5.2) — only active when MDNS_AVAILABLE=True
# ---------------------------------------------------------------------------

class _PeercServiceListener:
    """zeroconf ServiceListener that feeds discovered mDNS peers into
    Discovery._handle_packet() for validation and registry insertion.

    add_service / update_service resolve the ServiceInfo to obtain
    IP + port + TXT, then call on_packet with a synthetic UDP-format packet
    so _handle_packet's validation runs without any duplication.
    """

    def __init__(self, on_packet: Callable[[bytes, tuple[str, int]], None]) -> None:
        self._on_packet = on_packet

    def _handle_info(self, zc: "Zeroconf", name: str) -> None:  # type: ignore[name-defined]
        from zeroconf import ServiceInfo as _SI
        info = _SI(MDNS_SERVICE_TYPE, name)
        if not info.request(zc, timeout=3000):
            return

        # Decode TXT properties (keys and values are bytes in zeroconf)
        txt: dict[str, str] = {}
        for k, v in (info.properties or {}).items():
            key = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8") if isinstance(v, bytes) else (v or "")
            txt[key] = val

        # Determine source IP from the first resolved address
        src_ip = "0.0.0.0"
        if info.addresses:
            try:
                src_ip = socket.inet_ntoa(info.addresses[0])
            except Exception:
                pass

        packet = _mdns_txt_to_packet(txt, src_ip)
        self._on_packet(packet, (src_ip, BROADCAST_PORT))

    def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:  # type: ignore[name-defined]
        self._handle_info(zc, name)

    def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:  # type: ignore[name-defined]
        self._handle_info(zc, name)

    def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:  # type: ignore[name-defined]
        pass  # Stale peer eviction is handled by PeerRegistry.prune_stale()


class MDNSDiscovery:
    """Advertise this device and browse for peers via mDNS (_peerc._tcp.local.).

    Only instantiated when MDNS_AVAILABLE is True.  The caller (Discovery)
    feeds the received packets through _handle_packet() so all validation
    logic is shared with the UDP broadcast path.
    """

    def __init__(self, peer_id: str, name: str, tcp_port: int,
                 public_key: bytes,
                 on_packet: Callable[[bytes, tuple[str, int]], None],
                 model: str = "") -> None:
        self._peer_id = peer_id
        self._name = name
        self._tcp_port = tcp_port
        self._public_key = public_key
        self._model = model
        self._on_packet = on_packet  # == Discovery._handle_packet
        # Service name must be unique per device; use first 16 hex chars of device_id.
        self._service_name = f"{peer_id[:16]}.{MDNS_SERVICE_TYPE}"

    def _make_service_info(self) -> "ServiceInfo":  # type: ignore[name-defined]
        from zeroconf import ServiceInfo as _SI
        txt = _build_mdns_txt(
            PROTOCOL_VERSION, self._peer_id, self._public_key,
            self._name, self._tcp_port, self._model,
        )
        # Advertise all non-loopback local IPv4 addresses
        local_ips: list[bytes] = []
        try:
            hostname = socket.gethostname()
            for ip_str in socket.gethostbyname_ex(hostname)[2]:
                if not ip_str.startswith("127."):
                    local_ips.append(socket.inet_aton(ip_str))
        except Exception:
            pass
        if not local_ips:
            local_ips = [socket.inet_aton("127.0.0.1")]

        return _SI(
            type_=MDNS_SERVICE_TYPE,
            name=self._service_name,
            addresses=local_ips,
            port=self._tcp_port,
            properties=txt,
        )

    async def run(self) -> None:
        """Register this device's mDNS service and browse for peers.

        Runs until cancelled (asyncio.CancelledError propagates up to
        Discovery._mdns_loop, then to the asyncio.gather in Discovery.run).
        """
        azc = AsyncZeroconf()
        info = self._make_service_info()

        try:
            await azc.async_register_service(info, ttl=60)
            _log.info("mDNS: registered %s", self._service_name)
        except Exception as exc:
            _log.warning("mDNS: register failed: %s", exc)

        listener = _PeercServiceListener(self._on_packet)
        _browser = AsyncServiceBrowser(azc.zeroconf, MDNS_SERVICE_TYPE, listener=listener)

        try:
            while True:
                await asyncio.sleep(MDNS_ANNOUNCE_INTERVAL)
                # Refresh TTL so the record doesn't expire during long sessions
                try:
                    updated_info = self._make_service_info()
                    await azc.async_update_service(updated_info)
                except Exception:
                    pass
        except asyncio.CancelledError:
            raise
        finally:
            try:
                await azc.async_unregister_service(info)
                await azc.async_close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main Discovery class — UDP broadcast + optional mDNS (Phase 5.2)
# ---------------------------------------------------------------------------

class Discovery:
    """Runs the broadcast announce loop and the listener loop concurrently.

    Phase 5.2: also runs an mDNS loop in parallel when zeroconf is available
    (MDNS_AVAILABLE is True).  Both transports share the same _handle_packet()
    method for validation — no duplicate security logic.
    """

    def __init__(self, peer_id: str, name: str, tcp_port: int, registry: PeerRegistry,
                 public_key: bytes = b"", model: str = ""):
        self.peer_id = peer_id
        self.name = name
        self.tcp_port = tcp_port
        self.registry = registry
        self.public_key = public_key
        self.model = model
        self._sock: Optional[socket.socket] = None
        self._send_sock: Optional[socket.socket] = None

    def _get_send_socket(self) -> socket.socket:
        if self._send_sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._send_sock = sock
        return self._send_sock

    def _make_broadcast_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", BROADCAST_PORT))
        sock.setblocking(False)
        return sock

    def _build_payload(self, reply: bool = True) -> bytes:
        return json.dumps({
            "type": "announce",
            "version": PROTOCOL_VERSION,
            "device_id": self.peer_id,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "name": self.name,
            "tcp_port": self.tcp_port,
            "model": self.model,
            "reply": reply,
        }).encode("utf-8")

    def probe_peer(self, ip: str, port: int = BROADCAST_PORT) -> None:
        """Send an immediate direct announce packet to a specific IP."""
        payload = self._build_payload(reply=True)
        try:
            send_sock = self._get_send_socket()
            send_sock.sendto(payload, (ip, port))
        except OSError:
            pass

    def broadcast_now(self) -> None:
        """Send an immediate broadcast across all discovered targets."""
        payload = self._build_payload(reply=True)
        send_sock = self._get_send_socket()
        targets = get_broadcast_targets()
        for target in targets:
            try:
                send_sock.sendto(payload, (target, BROADCAST_PORT))
            except OSError:
                pass

    async def _announce_loop(self) -> None:
        try:
            while True:
                targets = get_broadcast_targets()
                payload = self._build_payload(reply=True)
                send_sock = self._get_send_socket()
                for target in targets:
                    try:
                        send_sock.sendto(payload, (target, BROADCAST_PORT))
                    except OSError:
                        pass
                await asyncio.sleep(ANNOUNCE_INTERVAL)
        finally:
            if self._send_sock:
                self._send_sock.close()
                self._send_sock = None

    async def _listen_loop(self) -> None:
        self._sock = self._make_broadcast_socket()
        loop = asyncio.get_event_loop()

        try:
            while True:
                try:
                    data, addr = await loop.sock_recvfrom(self._sock, 4096)
                except OSError:
                    await asyncio.sleep(0.5)
                    continue

                self._handle_packet(data, addr)
        finally:
            if self._sock:
                self._sock.close()
                self._sock = None

    def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            msg = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not isinstance(msg, dict):
            return
        if msg.get("type") != "announce":
            return

        # Phase 5.1: unversioned or wrong-version packets are a different
        # (older/newer) protocol speaker, not an attack — drop quietly,
        # same as any other schema mismatch. The whole network is expected
        # to upgrade together, per BUG_REPORT.md's discovery notes.
        if msg.get("version") != PROTOCOL_VERSION:
            return

        # BUG-023: fields were pulled out with bare .get()/indexing and
        # trusted as-is — a crafted packet with device_id=123 or
        # tcp_port=-999 would sail straight into the registry.
        device_id = msg.get("device_id")
        if not isinstance(device_id, str) or not device_id:
            return

        # Phase 5.1: public_key self-consistency check. This does NOT mean
        # the peer is trusted — it means the packet isn't lying about which
        # key backs its claimed device_id. Actual trust decisions stay with
        # core/trust/ at handshake time (Phase 6).
        public_key_b64 = msg.get("public_key")
        if not isinstance(public_key_b64, str) or not public_key_b64:
            return
        try:
            public_key_bytes = base64.b64decode(public_key_b64, validate=True)
        except (ValueError, TypeError):
            return
        if len(public_key_bytes) != 32:  # raw Ed25519 public key length
            return
        if hashlib.sha256(public_key_bytes).hexdigest() != device_id:
            emit(
                SecurityEvent(
                    event_type=SecurityEventType.AUTH_FAILED,
                    severity=SecuritySeverity.WARNING,
                    description=(
                        f"discovery packet from {addr[0]} claimed device_id "
                        f"{device_id[:16]}... but it doesn't match sha256(public_key) "
                        "— dropping as internally inconsistent"
                    ),
                    device_id=device_id,
                    details={"stage": "discovery", "reason": "device_id_pubkey_mismatch",
                             "source_ip": addr[0]},
                )
            )
            return

        if device_id == self.peer_id:
            return  # ignore our own broadcast

        name = msg.get("name", addr[0])
        if not isinstance(name, str) or not name.strip():
            name = addr[0]
        name = name[:64]  # don't let discovery become an amplified nickname-length bug

        model = msg.get("model", "")
        if not isinstance(model, str):
            model = ""
        model = model[:64]

        tcp_port = msg.get("tcp_port", 0)
        if not isinstance(tcp_port, int) or not (0 < tcp_port < 65536):
            return

        ip = addr[0]
        self.registry.upsert(peer_id=device_id, name=name, ip=ip, tcp_port=tcp_port,
                              public_key=public_key_bytes, model=model)

        # Bi-directional discovery reply:
        # If the incoming announce permits replies, immediately send a unicast announce back.
        # This circumvents AP isolation or broadcast forwarding drops on mobile hotspots.
        # mDNS packets arrive with reply=False so this only triggers for UDP broadcast.
        if msg.get("reply", True):
            reply_payload = self._build_payload(reply=False)
            try:
                self._get_send_socket().sendto(reply_payload, (ip, BROADCAST_PORT))
            except OSError:
                pass

    async def _prune_loop(self) -> None:
        while True:
            self.registry.prune_stale()
            await asyncio.sleep(PEER_TIMEOUT / 2)

    async def _mdns_loop(self) -> None:
        """Phase 5.2: run mDNS browse+advertise loop.

        Only called when MDNS_AVAILABLE is True.  Feeds discovered mDNS
        peers through _handle_packet() so all validation logic is shared.
        Logs a warning on unexpected failure and exits so the UDP broadcast
        path continues unaffected.
        """
        mdns = MDNSDiscovery(
            peer_id=self.peer_id,
            name=self.name,
            tcp_port=self.tcp_port,
            public_key=self.public_key,
            on_packet=self._handle_packet,
            model=self.model,
        )
        try:
            await mdns.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log.warning("mDNS loop exited unexpectedly: %s", exc)

    async def run(self) -> None:
        """Run announce, listen, and prune loops until cancelled.

        Phase 5.2: mDNS loop is added in parallel when zeroconf is available.
        When zeroconf is absent, logs an INFO message and continues with
        UDP broadcast only.
        """
        if not MDNS_AVAILABLE:
            _log.info(
                "mDNS discovery not available (zeroconf not installed). "
                "UDP broadcast only.  Install with: pip install peerc[mdns]"
            )
        tasks = [
            self._announce_loop(),
            self._listen_loop(),
            self._prune_loop(),
        ]
        if MDNS_AVAILABLE:
            tasks.append(self._mdns_loop())
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    # Minimal manual test: run this on two devices on the same LAN/hotspot
    # and watch peers appear/disappear in the console.
    def _on_new(peer: Peer) -> None:
        print(f"[+] Peer online : {peer.name} ({peer.peer_id[:8]}) at {peer.ip}:{peer.tcp_port}")

    def _on_lost(peer: Peer) -> None:
        print(f"[-] Peer offline: {peer.name} ({peer.peer_id[:8]})")

    async def _main() -> None:
        dev_identity = identity.load_or_create_identity()
        peer_id, name = dev_identity.device_id, dev_identity.name
        print(f"Starting as {name} ({peer_id[:8]})")
        print(f"mDNS available: {MDNS_AVAILABLE}")
        registry = PeerRegistry(on_peer_new=_on_new, on_peer_lost=_on_lost)
        disc = Discovery(
            peer_id, name, tcp_port=5555, registry=registry,
            public_key=dev_identity.keypair.public_key_bytes(),
        )
        await disc.run()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass