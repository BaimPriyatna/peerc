"""tests/test_encryption.py — Phase 8 (encrypted channel) tests."""

import os

import pytest

from core.crypto.encryption import (
    DecryptionError,
    EncryptionError,
    ReplayOrReorderError,
    SecureChannel,
    SequenceExhaustedError,
    _construct_nonce,
)
from core.crypto.kdf import SessionKeys

pytestmark = pytest.mark.security



def make_channel_pair():
    """Two SecureChannel instances that are each other's mirror image —
    A's send_key is B's recv_key and vice versa, like two ends of a real
    handshake's directional keys."""
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    channel_a = SecureChannel(SessionKeys(send_key=key_a, recv_key=key_b, session_id="test-a"))
    channel_b = SecureChannel(SessionKeys(send_key=key_b, recv_key=key_a, session_id="test-b"))
    return channel_a, channel_b


def test_roundtrip_encrypt_decrypt():
    a, b = make_channel_pair()
    frame = a.encrypt(b"hello from A")
    plaintext = b.decrypt(frame.sequence, frame.ciphertext)
    assert plaintext == b"hello from A"


def test_sequence_increments_and_matches_on_both_sides():
    a, b = make_channel_pair()
    for i, msg in enumerate([b"one", b"two", b"three"]):
        frame = a.encrypt(msg)
        assert frame.sequence == i
        assert b.decrypt(frame.sequence, frame.ciphertext) == msg


def test_tampered_ciphertext_rejected():
    a, b = make_channel_pair()
    frame = a.encrypt(b"do not tamper with me")
    tampered = bytearray(frame.ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        b.decrypt(frame.sequence, bytes(tampered))


def test_wrong_key_rejected():
    a, _ = make_channel_pair()
    _, other_b = make_channel_pair()  # unrelated pair, different keys
    frame = a.encrypt(b"secret")
    with pytest.raises(DecryptionError):
        other_b.decrypt(frame.sequence, frame.ciphertext)


def test_replayed_frame_rejected():
    a, b = make_channel_pair()
    frame = a.encrypt(b"only once")
    assert b.decrypt(frame.sequence, frame.ciphertext) == b"only once"
    # Replaying the exact same frame a second time must not decrypt again —
    # b's expected sequence has already advanced past it.
    with pytest.raises(ReplayOrReorderError):
        b.decrypt(frame.sequence, frame.ciphertext)


def test_out_of_order_frame_rejected():
    a, b = make_channel_pair()
    frame0 = a.encrypt(b"first")
    frame1 = a.encrypt(b"second")
    # Deliver frame1 before frame0 — must be rejected, not buffered/reordered.
    with pytest.raises(ReplayOrReorderError):
        b.decrypt(frame1.sequence, frame1.ciphertext)
    # frame0 (the actually-expected one) still decrypts fine afterward.
    assert b.decrypt(frame0.sequence, frame0.ciphertext) == b"first"


def test_directions_are_independent():
    """A's send_key != A's recv_key, so encrypting on send and decrypting
    on recv use genuinely different keys — sending never lets you decrypt
    your own traffic back, only the peer's."""
    a, b = make_channel_pair()
    frame = a.encrypt(b"from a to b")
    with pytest.raises(DecryptionError):
        a.decrypt(frame.sequence, frame.ciphertext)  # a decrypting its own send — wrong key


def test_nonce_is_deterministic_from_sequence():
    assert _construct_nonce(0) == (0).to_bytes(12, "big")
    assert _construct_nonce(1) == (1).to_bytes(12, "big")
    assert _construct_nonce(0) != _construct_nonce(1)


def test_sequence_out_of_range_raises():
    with pytest.raises(SequenceExhaustedError):
        _construct_nonce(-1)
    with pytest.raises(SequenceExhaustedError):
        _construct_nonce(1 << 96)


def test_wrong_key_length_rejected():
    with pytest.raises(EncryptionError):
        SecureChannel(SessionKeys(send_key=b"too short", recv_key=os.urandom(32), session_id="x"))


def test_associated_data_mismatch_rejected():
    a, b = make_channel_pair()
    frame = a.encrypt(b"payload", associated_data=b"header-v1")
    with pytest.raises(DecryptionError):
        b.decrypt(frame.sequence, frame.ciphertext, associated_data=b"header-v2-tampered")
