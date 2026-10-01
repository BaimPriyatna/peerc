"""tests/test_mdns_listener.py — Phase 38.13: the mDNS receive side.

Regression tests for a bug that predates Phase 38. _PeercServiceListener
resolved discovered services with the blocking ServiceInfo.request(), called
straight from AsyncServiceBrowser's callback on the event loop. zeroconf
refuses that ("Use AsyncServiceInfo.async_request from the event loop"), so
mDNS advertised this device but never produced a single peer. Verified on
zeroconf 0.131.0 and 0.151.5.

These tests are deterministic: they replace AsyncServiceInfo with a fake, so
they need neither a network nor the optional `zeroconf` package. A real
two-instance run over mDNS was done by hand when the fix landed.
"""

import asyncio
import logging
import socket

import pytest

import core.discovery.mdns as mdns
from core.discovery.broadcast import Discovery
from core.discovery.constants import BROADCAST_PORT, PROTOCOL_VERSION
from core.discovery.registry import PeerRegistry
from core.identity.device_identity import generate_keypair

pytestmark = pytest.mark.unit

SERVICE_NAME = "bob-service." + mdns.MDNS_SERVICE_TYPE


class _Scenario:
    """What the fake network returns for one service name."""

    def __init__(self, txt, ip="192.0.2.7", resolves=True, gate=None, error=None):
        self.txt, self.ip, self.resolves, self.gate, self.error = txt, ip, resolves, gate, error


def _peer_txt(name="bob", port=5002):
    kp = generate_keypair()
    txt = mdns._build_mdns_txt(PROTOCOL_VERSION, kp.device_id, kp.public_key_bytes(), name, port)
    return kp, txt


def _install_fake(monkeypatch, scenarios):
    requested = []

    class FakeAsyncServiceInfo:
        def __init__(self, type_, name):
            self._sc = scenarios[name]
            self.name = name
            self.properties = {k.encode(): v.encode() for k, v in self._sc.txt.items()}
            self.addresses = [socket.inet_aton(self._sc.ip)]

        async def async_request(self, zc, timeout):
            requested.append((self.name, timeout))
            if self._sc.gate is not None:
                await self._sc.gate.wait()
            else:
                await asyncio.sleep(0)
            if self._sc.error is not None:
                raise self._sc.error
            return self._sc.resolves

    monkeypatch.setattr(mdns, "AsyncServiceInfo", FakeAsyncServiceInfo, raising=False)
    return requested


async def _drain(listener):
    while listener._pending:
        await asyncio.gather(*list(listener._pending), return_exceptions=True)
        await asyncio.sleep(0)


@pytest.fixture
def warnings_logged():
    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _H(level=logging.WARNING)
    old = mdns._log.level
    mdns._log.addHandler(handler)
    mdns._log.setLevel(logging.WARNING)
    yield records
    mdns._log.removeHandler(handler)
    mdns._log.setLevel(old)


# ---------------------------------------------------------------------------

async def test_add_service_returns_immediately_and_delivers_a_valid_packet(monkeypatch):
    _, txt = _peer_txt()
    requested = _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt)})
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append((data, addr)))

    result = listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)

    assert result is None
    assert received == [], "add_service must not resolve synchronously"
    assert len(listener._pending) == 1
    await _drain(listener)
    assert received == [(mdns._mdns_txt_to_packet(txt, "192.0.2.7"), ("192.0.2.7", BROADCAST_PORT))]
    assert requested == [(SERVICE_NAME, mdns._PeercServiceListener.RESOLVE_TIMEOUT_MS)]
    assert not listener._pending


async def test_resolved_peer_reaches_the_registry_through_the_real_validation_path(monkeypatch):
    kp, txt = _peer_txt(name="bob", port=5002)
    _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt)})
    me = generate_keypair()
    registry = PeerRegistry()
    discovery = Discovery(me.device_id, "alice", 5001, registry, public_key=me.public_key_bytes())
    listener = mdns._PeercServiceListener(discovery._handle_packet)

    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)
    await _drain(listener)

    peer = registry.get(kp.device_id)
    assert peer is not None
    assert (peer.name, peer.tcp_port, peer.ip) == ("bob", 5002, "192.0.2.7")


async def test_a_slow_resolution_does_not_block_the_event_loop(monkeypatch):
    _, txt = _peer_txt()
    gate = asyncio.Event()
    _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt, gate=gate)})
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append(data))
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.005)
            ticks += 1

    tick_task = asyncio.ensure_future(ticker())
    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)
    await asyncio.sleep(0.1)
    assert received == [] and len(listener._pending) == 1
    assert ticks >= 5, "the loop stalled while a service was resolving"

    gate.set()
    await _drain(listener)
    tick_task.cancel()
    assert len(received) == 1


async def test_update_service_also_resolves(monkeypatch):
    _, txt = _peer_txt()
    _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt)})
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append(data))

    listener.update_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)
    await _drain(listener)

    assert len(received) == 1


async def test_a_service_that_does_not_resolve_is_ignored_quietly(monkeypatch, warnings_logged):
    _, txt = _peer_txt()
    _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt, resolves=False)})
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append(data))

    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)
    await _drain(listener)

    assert received == [] and not listener._pending
    assert warnings_logged == []


async def test_a_failed_resolution_is_logged_and_later_ones_still_work(monkeypatch, warnings_logged):
    _, good_txt = _peer_txt(name="carol", port=5003)
    bad, good = "bad." + mdns.MDNS_SERVICE_TYPE, "good." + mdns.MDNS_SERVICE_TYPE
    _install_fake(monkeypatch, {
        bad: _Scenario(good_txt, error=RuntimeError("boom")),
        good: _Scenario(good_txt),
    })
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append(data))

    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, bad)
    await _drain(listener)
    assert [r.getMessage() for r in warnings_logged] == ["mDNS: could not resolve peer: boom"]

    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, good)
    await _drain(listener)
    assert len(received) == 1 and not listener._pending


async def test_cancel_pending_cancels_resolutions_still_in_flight(monkeypatch, warnings_logged):
    _, txt = _peer_txt()
    _install_fake(monkeypatch, {SERVICE_NAME: _Scenario(txt, gate=asyncio.Event())})  # never set
    received = []
    listener = mdns._PeercServiceListener(lambda data, addr: received.append(data))

    listener.add_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME)
    assert len(listener._pending) == 1
    listener.cancel_pending()
    await _drain(listener)

    assert not listener._pending and received == []
    assert warnings_logged == [], "a cancelled resolution must not be reported as an error"


def test_remove_service_is_a_no_op():
    listener = mdns._PeercServiceListener(lambda data, addr: pytest.fail("unexpected packet"))
    assert listener.remove_service(object(), mdns.MDNS_SERVICE_TYPE, SERVICE_NAME) is None
    assert not listener._pending
