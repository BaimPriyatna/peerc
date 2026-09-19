"""core/connectivity/link.py — Phase 44.3: Add-by-Link.

See docs/INTERNET_CONNECTIVITY_DESIGN.md §3a "Link Format (Add-by-Link)".
A manual way to add a peer over the Internet without Rendezvous (Phase
45) running yet — sent over any already-trusted channel (WhatsApp,
email, etc.), never over the network peerc itself controls.

Wire format::

    PEERC1:<base64url(salt || nonce || ciphertext)>

    plaintext (never encrypted):
        salt   16 bytes — Scrypt(PIN, salt) -> KEK input
        nonce  12 bytes — AES-256-GCM nonce

    ciphertext (AES-256-GCM(KEK, nonce, plaintext=signed_payload)):
        public_key    32 bytes — sender's Ed25519 public key
        endpoint_count 1 byte
        endpoints[]   variable — tagged direct-v4/direct-v6/rendezvous
        created_at     4 bytes — uint32 Unix timestamp (informational only)
        signature     64 bytes — Ed25519 sig over everything above
        [GCM tag]     16 bytes — appended by AESGCM.encrypt automatically

Sign-then-Encrypt, deliberately (see the design doc for the full
reasoning): the payload is signed first, THEN the whole signed bundle
is encrypted under the PIN-derived key — never the other way around.
Without the PIN, nothing (not even the sender's device_id) is visible
at all. The signature only matters if the PIN is ever brute-forced —
it stops an attacker who has the PIN from forging a link with their
OWN key that would otherwise look completely legitimate.

Reuses core/vault/crypto.py's exact Scrypt(secret, salt) -> KEK and
AES-256-GCM primitives rather than inventing new ones (same RFC 7914
interactive parameters already used for the vault passphrase/recovery
code — the design doc's own reasoning is that Scrypt cost alone can't
be relied on to stop a 6-digit PIN brute force anyway; the signature is
the real defense-in-depth, not a slower KDF).

No expiry by design (§3a "Expiry"): a link stays valid until the
sender's endpoint actually changes, at which point Endpoint Update
(44.2) keeps a verifier's locator current with no new link needed.

A successfully decoded link is NOT automatic trust — approval is still
manual on the receiving side (§3a "Approval"). This module only proves
"this is genuinely device X, reachable here" — see core/trust/store.py
for the separate, manual approval step.
"""

import base64
import io
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import List

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.identity.device_identity import DeviceKeypair, compute_device_id, public_key_from_bytes
from core.vault.crypto import NONCE_LEN, SALT_LEN, derive_kek, new_salt

from .locator import KIND_DIRECT_V4, KIND_DIRECT_V6, KIND_RENDEZVOUS, VALID_KINDS, Endpoint

LINK_PREFIX = "PEERC1:"
PIN_LENGTH = 6

_LINK_SIGN_DOMAIN = b"peerc-add-by-link\x00"

_KIND_TAGS = {KIND_DIRECT_V4: 0, KIND_DIRECT_V6: 1, KIND_RENDEZVOUS: 2}
_TAG_KINDS = {v: k for k, v in _KIND_TAGS.items()}

_PUBLIC_KEY_LEN = 32
_SIGNATURE_LEN = 64
_CREATED_AT_LEN = 4
_MAX_RENDEZVOUS_HOST_LEN = 255  # fits in the 1-byte length prefix

try:
    import qrcode

    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False


class LinkError(Exception):
    """Base class for Add-by-Link errors."""


class LinkFormatError(LinkError):
    """The string isn't a well-formed PEERC1: link (bad prefix, bad
    base64, truncated/malformed structure) — this is independent of the
    PIN, a link can be malformed before decryption is even attempted."""


class WrongPinError(LinkError):
    """AES-GCM authentication failed. Deliberately doesn't distinguish
    "wrong PIN" from "tampered/corrupted link" — same reasoning as
    core/vault/crypto.py's WrongSecretError: that distinction itself
    could leak information to someone probing links."""


class LinkSignatureError(LinkError):
    """The PIN was correct (AES-GCM tag verified) but the Ed25519
    signature inside didn't check out. Per §3a, this specific
    combination is the scenario the signature exists to catch: an
    attacker who has correctly guessed/brute-forced the PIN but doesn't
    have the real sender's private key. Worth surfacing distinctly to
    the user rather than folding into WrongPinError — "the PIN worked
    but the link doesn't check out" is a different, more concerning
    situation than a simple typo'd PIN."""


class QrCodeUnavailableError(LinkError):
    """Raised by generate_qr() when the optional qrcode dependency isn't
    installed. Install with: pip install peerc[qr]"""


@dataclass
class LinkPayload:
    """Everything a successfully-decoded link reveals about its sender."""

    device_id: str
    public_key: bytes
    endpoints: List[Endpoint]
    created_at: float


def create_link(keypair: DeviceKeypair, endpoints: List[Endpoint], pin: str) -> str:
    """Build a PEERC1: link announcing *keypair*'s device at *endpoints*,
    protected by a 6-digit *pin*.

    Raises LinkError if pin isn't exactly 6 ASCII digits, endpoints is
    empty, or an endpoint's host doesn't fit its kind (e.g. a
    direct-v4 endpoint with a non-IPv4 host).
    """
    _validate_pin(pin)
    if not endpoints:
        raise LinkError("at least one endpoint is required")

    public_key = keypair.public_key_bytes()
    created_at = int(time.time())
    endpoints_bytes = _pack_endpoints(endpoints)
    signed_payload = (
        public_key + struct.pack(">B", len(endpoints)) + endpoints_bytes + struct.pack(">I", created_at)
    )
    signature = keypair.sign(_LINK_SIGN_DOMAIN + signed_payload)

    plaintext = signed_payload + signature
    salt = new_salt()
    nonce = _new_nonce()
    kek = derive_kek(pin.encode("ascii"), salt)
    ciphertext = AESGCM(kek).encrypt(nonce, plaintext, None)

    raw = salt + nonce + ciphertext
    return LINK_PREFIX + _b64url_encode(raw)


def decode_link(link: str, pin: str) -> LinkPayload:
    """Decode and verify a PEERC1: link.

    Raises LinkFormatError (malformed, independent of PIN),
    WrongPinError (AES-GCM auth failed — wrong PIN or tampered link,
    deliberately not distinguished), or LinkSignatureError (PIN was
    right but the Ed25519 signature inside didn't verify — see that
    class's docstring for why this is treated as a distinct, more
    serious case).
    """
    _validate_pin(pin)
    if not link.startswith(LINK_PREFIX):
        raise LinkFormatError(f"link must start with {LINK_PREFIX!r}")

    try:
        raw = _b64url_decode(link[len(LINK_PREFIX):])
    except Exception as e:
        raise LinkFormatError(f"invalid base64url payload: {e}") from e

    if len(raw) < SALT_LEN + NONCE_LEN:
        raise LinkFormatError("link too short to contain salt+nonce")
    salt, nonce, ciphertext = raw[:SALT_LEN], raw[SALT_LEN:SALT_LEN + NONCE_LEN], raw[SALT_LEN + NONCE_LEN:]

    kek = derive_kek(pin.encode("ascii"), salt)
    try:
        plaintext = AESGCM(kek).decrypt(nonce, ciphertext, None)
    except InvalidTag as e:
        raise WrongPinError("incorrect PIN or the link has been tampered with/corrupted") from e

    min_len = _PUBLIC_KEY_LEN + 1 + _CREATED_AT_LEN + _SIGNATURE_LEN
    if len(plaintext) < min_len:
        raise LinkFormatError("decrypted payload too short")

    public_key = plaintext[:_PUBLIC_KEY_LEN]
    offset = _PUBLIC_KEY_LEN
    endpoint_count = plaintext[offset]
    offset += 1
    try:
        endpoints_raw, offset = _unpack_endpoints(plaintext, offset, endpoint_count)
    except (struct.error, IndexError, UnicodeDecodeError) as e:
        raise LinkFormatError(f"malformed endpoint data: {e}") from e

    if len(plaintext) < offset + _CREATED_AT_LEN + _SIGNATURE_LEN:
        raise LinkFormatError("decrypted payload truncated before created_at/signature")
    created_at = struct.unpack(">I", plaintext[offset:offset + _CREATED_AT_LEN])[0]
    offset += _CREATED_AT_LEN
    signature = plaintext[offset:offset + _SIGNATURE_LEN]
    signed_payload = plaintext[:offset]  # everything before the signature

    try:
        pub_key_obj = public_key_from_bytes(public_key)
        pub_key_obj.verify(signature, _LINK_SIGN_DOMAIN + signed_payload)
    except (InvalidSignature, Exception) as e:
        raise LinkSignatureError(
            "PIN was correct but the signature inside the link is invalid — "
            "this may mean the PIN was guessed/brute-forced rather than the "
            "link being genuine"
        ) from e

    device_id = compute_device_id(public_key)
    endpoints = [
        Endpoint(device_id=device_id, kind=kind, host=host, port=port, updated_at=created_at)
        for kind, host, port in endpoints_raw
    ]
    return LinkPayload(device_id=device_id, public_key=public_key, endpoints=endpoints, created_at=float(created_at))


def generate_qr(link: str) -> str:
    """Render *link* as an ASCII/ANSI QR code for display in the
    terminal. Raises QrCodeUnavailableError if the optional `qrcode`
    package isn't installed (pip install peerc[qr]) — Add-by-Link's
    copy-paste string form works with or without it; QR is purely an
    additional way to render the same string (§3a), never a separate
    encoding."""
    if not QRCODE_AVAILABLE:
        raise QrCodeUnavailableError(
            "QR code generation requires the optional 'qrcode' package — install with: pip install peerc[qr]"
        )
    qr = qrcode.QRCode(border=1)
    qr.add_data(link)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_pin(pin: str) -> None:
    if not (isinstance(pin, str) and len(pin) == PIN_LENGTH and pin.isascii() and pin.isdigit()):
        raise LinkError(f"PIN must be exactly {PIN_LENGTH} digits")


def _new_nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _pack_endpoints(endpoints: List[Endpoint]) -> bytes:
    return b"".join(_pack_one_endpoint(e) for e in endpoints)


def _pack_one_endpoint(ep: Endpoint) -> bytes:
    if ep.kind not in _KIND_TAGS:
        raise LinkError(f"unsupported endpoint kind {ep.kind!r}")
    tag = _KIND_TAGS[ep.kind]
    if ep.kind == KIND_DIRECT_V4:
        try:
            host_bytes = socket.inet_pton(socket.AF_INET, ep.host)
        except OSError as e:
            raise LinkError(f"endpoint host {ep.host!r} is not a valid IPv4 address for kind {ep.kind!r}") from e
    elif ep.kind == KIND_DIRECT_V6:
        try:
            host_bytes = socket.inet_pton(socket.AF_INET6, ep.host)
        except OSError as e:
            raise LinkError(f"endpoint host {ep.host!r} is not a valid IPv6 address for kind {ep.kind!r}") from e
    else:  # KIND_RENDEZVOUS
        host_utf8 = ep.host.encode("utf-8")
        if len(host_utf8) > _MAX_RENDEZVOUS_HOST_LEN:
            raise LinkError(f"rendezvous host too long ({len(host_utf8)} bytes, max {_MAX_RENDEZVOUS_HOST_LEN})")
        host_bytes = struct.pack(">B", len(host_utf8)) + host_utf8
    return struct.pack(">B", tag) + host_bytes + struct.pack(">H", ep.port)


def _unpack_endpoints(buf: bytes, offset: int, count: int):
    """Returns (list of (kind, host, port) tuples, new offset). Returns
    plain tuples rather than Endpoint objects because device_id isn't
    known yet at this point in decode_link() — it's derived from the
    public_key, which is verified against the signature AFTER endpoints
    are parsed but before any Endpoint gets its final device_id."""
    endpoints = []
    for _ in range(count):
        tag = buf[offset]
        offset += 1
        kind = _TAG_KINDS.get(tag)
        if kind is None:
            raise LinkFormatError(f"unknown endpoint tag {tag!r}")
        if kind == KIND_DIRECT_V4:
            host = socket.inet_ntop(socket.AF_INET, buf[offset:offset + 4])
            offset += 4
        elif kind == KIND_DIRECT_V6:
            host = socket.inet_ntop(socket.AF_INET6, buf[offset:offset + 16])
            offset += 16
        else:  # KIND_RENDEZVOUS
            host_len = buf[offset]
            offset += 1
            host = buf[offset:offset + host_len].decode("utf-8")
            offset += host_len
        port = struct.unpack(">H", buf[offset:offset + 2])[0]
        offset += 2
        endpoints.append((kind, host, port))
    return endpoints, offset
