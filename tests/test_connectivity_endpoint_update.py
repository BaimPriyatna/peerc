"""tests/test_connectivity_endpoint_update.py — Phase 44.2: signed endpoint
announcement + verification tests (core/connectivity/endpoint_update.py).

Covers:
  1. create_endpoint_update validation (bad kind, missing host, bad port).
  2. Happy path: create + verify.
  3. Wrong verifying key rejected.
  4. Tampered payload rejected (host/port/kind changed after signing).
  5. Stale timestamp rejected; future timestamp rejected.
  6. Nonce replay rejected (same update verified twice against the same
     NonceCache); a nonce reused by a DIFFERENT (unsigned/forged) update
     doesn't consume the cache slot, since signature is checked first.
  7. endpoint_update_to_endpoint() shape conversion.
"""

import time

import pytest

from core.connectivity.endpoint_update import (
    EndpointUpdate,
    EndpointUpdateError,
    create_endpoint_update,
    endpoint_update_to_endpoint,
    verify_endpoint_update,
)
from core.connectivity.locator import KIND_DIRECT_V4, KIND_RENDEZVOUS
from core.crypto.handshake import NonceCache
from core.identity.device_identity import generate_keypair


# ---------------------------------------------------------------------------
# 1. Validation
# ---------------------------------------------------------------------------


def test_create_endpoint_update_rejects_invalid_kind():
    device = generate_keypair()
    with pytest.raises(EndpointUpdateError):
        create_endpoint_update(device, "carrier-pigeon", "1.2.3.4", 5656)


def test_create_endpoint_update_rejects_missing_host():
    device = generate_keypair()
    with pytest.raises(EndpointUpdateError):
        create_endpoint_update(device, KIND_DIRECT_V4, "", 5656)


def test_create_endpoint_update_rejects_invalid_port():
    device = generate_keypair()
    with pytest.raises(EndpointUpdateError):
        create_endpoint_update(device, KIND_DIRECT_V4, "1.2.3.4", 0)


# ---------------------------------------------------------------------------
# 2-4. Happy path, wrong key, tampering
# ---------------------------------------------------------------------------


def test_create_and_verify_happy_path():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)

    assert verify_endpoint_update(update, device.public_key_bytes(), cache) is True


def test_verify_rejects_wrong_key():
    device = generate_keypair()
    impostor = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)

    assert verify_endpoint_update(update, impostor.public_key_bytes(), cache) is False


def test_verify_rejects_tampered_host():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    tampered = EndpointUpdate(**{**update.__dict__, "host": "1.2.3.4"})

    assert verify_endpoint_update(tampered, device.public_key_bytes(), cache) is False


def test_verify_rejects_tampered_port():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    tampered = EndpointUpdate(**{**update.__dict__, "port": 9999})

    assert verify_endpoint_update(tampered, device.public_key_bytes(), cache) is False


def test_verify_rejects_tampered_kind():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    tampered = EndpointUpdate(**{**update.__dict__, "kind": KIND_RENDEZVOUS})

    assert verify_endpoint_update(tampered, device.public_key_bytes(), cache) is False


# ---------------------------------------------------------------------------
# 5. Timestamp freshness
# ---------------------------------------------------------------------------


def test_verify_rejects_stale_timestamp():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    stale = EndpointUpdate(**{**update.__dict__, "timestamp": time.time() - 99999})

    # Note: timestamp is part of the signed payload, so mutating it also
    # invalidates the signature — this exercises the freshness check
    # only indirectly. Re-sign with the mutated timestamp to isolate it.
    from core.connectivity.endpoint_update import _update_payload
    import base64

    payload = _update_payload(stale.device_id, stale.kind, stale.host, stale.port, stale.timestamp, stale.nonce)
    stale.signature = base64.b64encode(device.sign(payload)).decode("ascii")

    assert verify_endpoint_update(stale, device.public_key_bytes(), cache, max_age_seconds=300) is False


def test_verify_rejects_future_timestamp():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    future = EndpointUpdate(**{**update.__dict__, "timestamp": time.time() + 99999})

    from core.connectivity.endpoint_update import _update_payload
    import base64

    payload = _update_payload(future.device_id, future.kind, future.host, future.port, future.timestamp, future.nonce)
    future.signature = base64.b64encode(device.sign(payload)).decode("ascii")

    assert verify_endpoint_update(future, device.public_key_bytes(), cache, max_age_seconds=300) is False


# ---------------------------------------------------------------------------
# 6. Nonce replay
# ---------------------------------------------------------------------------


def test_verify_rejects_replayed_nonce():
    device = generate_keypair()
    cache = NonceCache()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)

    assert verify_endpoint_update(update, device.public_key_bytes(), cache) is True
    # Same update, same nonce, verified again against the same cache.
    assert verify_endpoint_update(update, device.public_key_bytes(), cache) is False


def test_forged_update_does_not_consume_nonce_slot():
    device = generate_keypair()
    impostor = generate_keypair()
    cache = NonceCache()
    real_update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)
    # A forged update from an impostor, reusing the SAME nonce value.
    forged = create_endpoint_update(impostor, KIND_DIRECT_V4, "9.9.9.9", 1234)
    forged.nonce = real_update.nonce
    # Forged signature is over forged's own payload (with the swapped
    # nonce) — verifying it against device's key must fail on signature,
    # not consume the nonce cache.

    assert verify_endpoint_update(forged, device.public_key_bytes(), cache) is False
    # The real update with that nonce should still verify fine —
    # proving the forged attempt above never touched the nonce cache.
    assert verify_endpoint_update(real_update, device.public_key_bytes(), cache) is True


# ---------------------------------------------------------------------------
# 7. Shape conversion
# ---------------------------------------------------------------------------


def test_endpoint_update_to_endpoint():
    device = generate_keypair()
    update = create_endpoint_update(device, KIND_DIRECT_V4, "103.20.30.40", 5656)

    endpoint = endpoint_update_to_endpoint(update)

    assert endpoint.device_id == device.device_id
    assert endpoint.kind == KIND_DIRECT_V4
    assert endpoint.host == "103.20.30.40"
    assert endpoint.port == 5656
    assert endpoint.updated_at == update.timestamp
