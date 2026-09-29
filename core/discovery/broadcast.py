"""core/discovery/broadcast.py — MNDP-style peer discovery via UDP broadcast.

Each running instance periodically broadcasts a JSON "announce" packet
containing its stable peer_id, display name, and TCP port. Other instances
listen for these broadcasts and maintain a live peer list (registry.py),
evicting peers that haven't announced within PEER_TIMEOUT seconds (handles
DHCP IP changes and peers going offline).

Phase 5.1 (IMPLEMENTATION_PLAN.md "Phase 5 — Discovery V2"): the wire
payload carries a "version" field and the device's raw Ed25519 public_key
alongside device_id, and every incoming packet's device_id is checked for
self-consistency against its claimed public_key
(device_id == sha256(public_key)). This is deliberately NOT a trust
decision — discovery only proves "this announcement is internally
consistent", never "this device is trusted" (that's core/trust/'s job,
enforced later at handshake time in Phase 6). A mismatch here means the
packet is lying about its own identity, so it's dropped and logged as a
security event; it says nothing about whether a self-consistent peer
should actually be trusted.

The optional mDNS transport (mdns.py) is composed in by Discovery.run(). The
same _handle_packet() method parses both UDP broadcast and mDNS announce
packets — no duplicate validation logic.
"""

import asyncio
import base64
import hashlib
import json
import logging
import socket
from typing import Optional

import core.identity as identity
from core.discovery.constants import BROADCAST_PORT, PROTOCOL_VERSION
from core.discovery.mdns import MDNS_AVAILABLE, MDNSDiscovery
from core.discovery.registry import PEER_TIMEOUT, Peer, PeerRegistry
from core.security import SecurityEvent, SecurityEventType, SecuritySeverity, emit

_log = logging.getLogger("peerc.discovery")

ANNOUNCE_INTERVAL = 3.0   # seconds between announces


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
