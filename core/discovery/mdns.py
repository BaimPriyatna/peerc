"""core/discovery/mdns.py — optional mDNS discovery adapter (Phase 5.2, v1.13.1).

mDNS via `zeroconf` is a second discovery transport alongside UDP broadcast,
for environments where UDP broadcast is blocked (AP isolation, multi-subnet
LANs). It is **optional** — if the `zeroconf` package is not installed,
discovery falls back to UDP broadcast only (MDNS_AVAILABLE = False).

Install mDNS support with:  pip install peerc[mdns]

mDNS service type: _peerc._tcp.local.
TXT record fields (all strings, key-value):
  version=<int>          PROTOCOL_VERSION
  device_id=<hex>        sha256(public_key) hex digest
  public_key=<b64>       raw Ed25519 public key, base64-encoded
  name=<str>             display name (capped at 64 chars)
  tcp_port=<int>         TCP listen port

This adapter never validates packets itself: it converts TXT records back
into the UDP wire format and hands them to Discovery._handle_packet()
(broadcast.py), so broadcast and mDNS cannot drift into accepting different
identity shapes.
"""

import asyncio
import base64
import json
import logging
import socket
from typing import Callable

from core.discovery.constants import BROADCAST_PORT, PROTOCOL_VERSION

# ---------------------------------------------------------------------------
# Optional mDNS dependency
# ---------------------------------------------------------------------------
try:
    from zeroconf import ServiceInfo, Zeroconf  # noqa: F401 (checked for availability)
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
    MDNS_AVAILABLE = True
except ImportError:
    MDNS_AVAILABLE = False

_log = logging.getLogger("peerc.discovery")

MDNS_SERVICE_TYPE = "_peerc._tcp.local."
MDNS_ANNOUNCE_INTERVAL = 10.0  # mDNS re-registration / TTL-refresh interval (seconds)


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
