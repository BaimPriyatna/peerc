"""core/crypto/encryption.py — AEAD encryption for the secure session (Phase 8).

Uses ChaCha20-Poly1305 (chosen over AES-256-GCM per IMPLEMENTATION_PLAN.md
Phase 8, for portable/constant-time-without-AES-NI implementation) with a
**sequence-derived nonce**, not a random one:

    nonce = sequence_number, encoded as a 12-byte big-endian integer

This is deliberately deterministic, not random, matching the "nonce/
sequence dikelola oleh session layer secara ketat" guidance in the plan:

    - Nonce uniqueness is *guaranteed by construction* (a monotonically
      incrementing counter can't repeat within a session) rather than
      relying on random-96-bit-value collision odds being merely very low.
    - Free replay/reorder detection: decrypt() enforces that the sequence
      number is exactly the next expected one for that direction, no
      separate bookkeeping needed (mirrors the sequence+offset check
      already used for file_data chunks — see core/transfer/session.py's BUG-008
      handling).
    - No nonce needs to travel on the wire at all — both sides already
      track their own sequence counters, so the frame only needs to carry
      {sequence, ciphertext-with-tag}, saving 12 bytes per frame.

Each session (Phase 7's SessionKeys) has two independent directional
keys, so this counter never needs to be shared or synchronized across
directions — each direction's cipher has its own key and its own
sequence counter, so nonce reuse across directions isn't a concern either.
"""

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .kdf import SessionKeys

NONCE_LEN = 12  # ChaCha20-Poly1305's fixed 96-bit nonce size
KEY_LEN = 32
MAX_SEQUENCE = (1 << (NONCE_LEN * 8)) - 1  # a 12-byte counter effectively never exhausts


class EncryptionError(Exception):
    """Base class for errors from the encrypted channel."""


class DecryptionError(EncryptionError):
    """Raised when a ciphertext fails to authenticate — tampered, corrupt,
    or encrypted under a different key than expected. Never distinguishes
    which of those it was (that distinction itself can leak information
    to an attacker probing the channel)."""


class ReplayOrReorderError(EncryptionError):
    """Raised when a received frame's sequence number isn't exactly the
    next one expected for that direction — covers both a replayed old
    frame and a frame arriving out of order. TCP already gives in-order
    delivery within one connection, so this is a defense-in-depth check,
    not something expected to fire under normal operation."""


class SequenceExhaustedError(EncryptionError):
    """Raised if a direction's sequence counter would overflow its
    12-byte range. Rekeying (a fresh handshake) is required at that
    point — this channel refuses to reuse a nonce under the same key."""


def _construct_nonce(sequence: int) -> bytes:
    if sequence < 0 or sequence > MAX_SEQUENCE:
        raise SequenceExhaustedError(f"sequence {sequence} out of range for a {NONCE_LEN}-byte nonce")
    return sequence.to_bytes(NONCE_LEN, byteorder="big")


@dataclass
class EncryptedFrame:
    sequence: int
    ciphertext: bytes  # includes the 16-byte Poly1305 tag, per cryptography's AEAD API


@dataclass
class SecureChannel:
    """One session's encrypted channel: independent send/recv directions,
    each with its own key (from Phase 7's SessionKeys) and its own
    strictly-monotonic sequence counter.
    """

    session_keys: SessionKeys
    _send_cipher: ChaCha20Poly1305 = field(init=False, repr=False)
    _recv_cipher: ChaCha20Poly1305 = field(init=False, repr=False)
    _send_sequence: int = field(default=0, init=False)
    _expected_recv_sequence: int = field(default=0, init=False)

    def __post_init__(self):
        if len(self.session_keys.send_key) != KEY_LEN or len(self.session_keys.recv_key) != KEY_LEN:
            raise EncryptionError("session keys must be exactly 32 bytes for ChaCha20-Poly1305")
        self._send_cipher = ChaCha20Poly1305(self.session_keys.send_key)
        self._recv_cipher = ChaCha20Poly1305(self.session_keys.recv_key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> EncryptedFrame:
        """Encrypt one message for sending. Sequence auto-increments."""
        nonce = _construct_nonce(self._send_sequence)
        ciphertext = self._send_cipher.encrypt(nonce, plaintext, associated_data or None)
        frame = EncryptedFrame(sequence=self._send_sequence, ciphertext=ciphertext)
        self._send_sequence += 1
        return frame

    def decrypt(self, sequence: int, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt one received message. Enforces strict, gap-free sequence
        order — a replayed, dropped-then-arrived-late, or out-of-order
        frame is rejected rather than silently accepted or reordered."""
        if sequence != self._expected_recv_sequence:
            raise ReplayOrReorderError(
                f"expected sequence {self._expected_recv_sequence}, got {sequence}"
            )
        nonce = _construct_nonce(sequence)
        try:
            plaintext = self._recv_cipher.decrypt(nonce, ciphertext, associated_data or None)
        except InvalidTag as e:
            raise DecryptionError("authentication failed") from e
        self._expected_recv_sequence += 1
        return plaintext
