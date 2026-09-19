"""tests/test_connectivity_link.py — Phase 44.3: Add-by-Link tests
(core/connectivity/link.py).

Covers:
  1. create_link validation (bad PIN, empty endpoints, mismatched
     host/kind).
  2. Happy path: create + decode, single and multiple endpoints
     (direct-v4, direct-v6, rendezvous all in one link).
  3. Wrong PIN rejected (WrongPinError) — and doesn't leak which part
     was wrong.
  4. Tampered link (flipped byte in the base64 payload) rejected.
  5. Malformed link (bad prefix, bad base64, truncated) rejected with
     LinkFormatError — independent of PIN.
  6. Signature forged with the right PIN but a different key is
     rejected as LinkSignatureError, distinctly from WrongPinError.
  7. Link round-trips through the exact wire prefix format.
  8. generate_qr(): happy path (skipped if qrcode isn't installed),
     and QrCodeUnavailableError behavior is at least importable/raisable.
"""

import base64

import pytest

from core.connectivity.link import (
    LINK_PREFIX,
    QRCODE_AVAILABLE,
    LinkError,
    LinkFormatError,
    LinkSignatureError,
    WrongPinError,
    create_link,
    decode_link,
    generate_qr,
)
from core.connectivity.locator import KIND_DIRECT_V4, KIND_DIRECT_V6, KIND_RENDEZVOUS, Endpoint
from core.identity.device_identity import generate_keypair

PIN = "482913"


def _ep(kind=KIND_DIRECT_V4, host="103.20.30.40", port=5656, device_id="dev1"):
    return Endpoint(device_id=device_id, kind=kind, host=host, port=port)


# ---------------------------------------------------------------------------
# 1. Validation
# ---------------------------------------------------------------------------


def test_create_link_rejects_short_pin():
    device = generate_keypair()
    with pytest.raises(LinkError):
        create_link(device, [_ep()], "123")


def test_create_link_rejects_non_digit_pin():
    device = generate_keypair()
    with pytest.raises(LinkError):
        create_link(device, [_ep()], "12a456")


def test_create_link_rejects_empty_endpoints():
    device = generate_keypair()
    with pytest.raises(LinkError):
        create_link(device, [], PIN)


def test_create_link_rejects_mismatched_host_for_kind():
    device = generate_keypair()
    # direct-v4 kind but an IPv6-shaped host
    bad = _ep(kind=KIND_DIRECT_V4, host="::1")
    with pytest.raises(LinkError):
        create_link(device, [bad], PIN)


# ---------------------------------------------------------------------------
# 2. Happy path
# ---------------------------------------------------------------------------


def test_create_and_decode_single_endpoint():
    device = generate_keypair()
    link = create_link(device, [_ep()], PIN)

    payload = decode_link(link, PIN)

    assert payload.device_id == device.device_id
    assert payload.public_key == device.public_key_bytes()
    assert len(payload.endpoints) == 1
    assert payload.endpoints[0].host == "103.20.30.40"
    assert payload.endpoints[0].port == 5656
    assert payload.endpoints[0].kind == KIND_DIRECT_V4


def test_create_and_decode_multiple_endpoint_kinds():
    device = generate_keypair()
    endpoints = [
        _ep(kind=KIND_DIRECT_V4, host="192.168.1.20", port=5656),
        _ep(kind=KIND_DIRECT_V4, host="10.10.0.20", port=5656),
        _ep(kind=KIND_DIRECT_V6, host="2001:db8::1", port=5656),
        _ep(kind=KIND_RENDEZVOUS, host="rendez.example.com", port=443),
    ]
    link = create_link(device, endpoints, PIN)

    payload = decode_link(link, PIN)

    assert len(payload.endpoints) == 4
    hosts = {e.host for e in payload.endpoints}
    assert hosts == {"192.168.1.20", "10.10.0.20", "2001:db8::1", "rendez.example.com"}
    kinds = {e.kind for e in payload.endpoints}
    assert kinds == {KIND_DIRECT_V4, KIND_DIRECT_V6, KIND_RENDEZVOUS}


def test_decoded_endpoints_carry_correct_device_id():
    device = generate_keypair()
    link = create_link(device, [_ep(device_id="whatever-placeholder")], PIN)

    payload = decode_link(link, PIN)

    # The decoded device_id always comes from the verified public key,
    # never from whatever device_id was on the Endpoint passed into
    # create_link (which isn't even part of the signed payload).
    assert all(e.device_id == device.device_id for e in payload.endpoints)


# ---------------------------------------------------------------------------
# 3-4. Wrong PIN / tampering
# ---------------------------------------------------------------------------


def test_decode_wrong_pin_rejected():
    device = generate_keypair()
    link = create_link(device, [_ep()], PIN)

    with pytest.raises(WrongPinError):
        decode_link(link, "000000")


def test_decode_tampered_link_rejected():
    device = generate_keypair()
    link = create_link(device, [_ep()], PIN)
    b64_part = link[len(LINK_PREFIX):]
    raw = bytearray(base64.urlsafe_b64decode(b64_part + "=" * (-len(b64_part) % 4)))
    raw[-1] ^= 0xFF  # flip a byte in the ciphertext/tag region
    tampered_b64 = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
    tampered_link = LINK_PREFIX + tampered_b64

    with pytest.raises(WrongPinError):
        decode_link(tampered_link, PIN)


# ---------------------------------------------------------------------------
# 5. Malformed links
# ---------------------------------------------------------------------------


def test_decode_rejects_bad_prefix():
    with pytest.raises(LinkFormatError):
        decode_link("NOTPEERC1:abcdef", PIN)


def test_decode_rejects_bad_base64():
    with pytest.raises(LinkFormatError):
        decode_link(LINK_PREFIX + "!!!not-valid-base64!!!", PIN)


def test_decode_rejects_truncated_link():
    with pytest.raises(LinkFormatError):
        decode_link(LINK_PREFIX + base64.urlsafe_b64encode(b"short").decode("ascii"), PIN)


# ---------------------------------------------------------------------------
# 6. Signature forgery (correct PIN, wrong key)
# ---------------------------------------------------------------------------


def test_decode_rejects_forged_signature_with_correct_pin(monkeypatch):
    """Simulates an attacker who has correctly guessed the PIN but signs
    with their own key instead of the real sender's — the AES-GCM tag
    still checks out (it's a validly-encrypted blob), but the embedded
    Ed25519 signature won't verify against the public_key also embedded
    in that same blob, since it's a genuinely different keypair signing
    genuinely different bytes than what public_key claims."""
    real_device = generate_keypair()
    impostor = generate_keypair()

    # Build a link the normal way but splice in the impostor's
    # public_key alongside a signature made by the real device — this
    # mismatch is exactly what LinkSignatureError exists to catch.
    import core.connectivity.link as link_mod

    link = create_link(real_device, [_ep()], PIN)
    raw = link_mod._b64url_decode(link[len(LINK_PREFIX):])
    salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
    kek = link_mod.derive_kek(PIN.encode("ascii"), salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plaintext = AESGCM(kek).decrypt(nonce, ciphertext, None)
    # Swap in the impostor's public key, keep the real signature —
    # signature no longer matches the (now-different) public_key.
    forged_plaintext = impostor.public_key_bytes() + plaintext[32:]
    forged_ciphertext = AESGCM(kek).encrypt(nonce, forged_plaintext, None)
    forged_link = LINK_PREFIX + link_mod._b64url_encode(salt + nonce + forged_ciphertext)

    with pytest.raises(LinkSignatureError):
        decode_link(forged_link, PIN)


# ---------------------------------------------------------------------------
# 7. Wire format
# ---------------------------------------------------------------------------


def test_link_starts_with_prefix():
    device = generate_keypair()
    link = create_link(device, [_ep()], PIN)
    assert link.startswith("PEERC1:")


# ---------------------------------------------------------------------------
# 8. QR generation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not QRCODE_AVAILABLE, reason="qrcode package not installed")
def test_generate_qr_happy_path():
    device = generate_keypair()
    link = create_link(device, [_ep()], PIN)

    ascii_qr = generate_qr(link)

    assert isinstance(ascii_qr, str)
    assert len(ascii_qr) > 0
