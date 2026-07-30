"""Cryptographic operations for envelopes.

Two constructions, both standard:

- ``seal`` / ``open_sealed``: anonymous-sender confidentiality to a recipient's
  static X25519 key (ephemeral-static ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305).
  Used for handshake payloads, before a session key exists.
- ``derive_session_key`` + ``encrypt`` / ``decrypt``: ephemeral-ephemeral ECDH
  bound to the handshake transcript, then AEAD for all session traffic.
  Forward secrecy: session keys never touch identity keys' secrecy.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..errors import DecryptionError

_NONCE_SIZE = 12
_KEY_SIZE = 32
_SEAL_INFO = b"amp/0.1/seal"
_SESSION_INFO = b"amp/0.1/session"


def _x25519_exchange(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    """ECDH with an explicit low-order/degenerate-point rejection.

    An all-zero shared secret means the peer sent a low-order point, collapsing
    the classical contribution to a constant. SPEC §8 requires rejecting it; the
    DH ratchet already does (``ratchet._dh``) — this keeps the initial
    session-key and sealed derivations consistent with that rule.
    """
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        # OpenSSL rejects most low-order points at exchange time with a bare
        # ValueError; normalize it to our error taxonomy.
        raise DecryptionError("invalid or low-order X25519 point") from exc
    if shared == b"\x00" * len(shared):
        raise DecryptionError("peer contributed a low-order X25519 point (zero shared secret)")
    return shared


def _hkdf(shared: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=_KEY_SIZE, salt=salt, info=info).derive(shared)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD-encrypt; returns nonce || ciphertext."""
    nonce = os.urandom(_NONCE_SIZE)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(data) < _NONCE_SIZE + 16:
        raise DecryptionError("ciphertext too short")
    try:
        return ChaCha20Poly1305(key).decrypt(data[:_NONCE_SIZE], data[_NONCE_SIZE:], aad)
    except InvalidTag as exc:
        raise DecryptionError("AEAD authentication failed") from exc


def seal(recipient_agreement_public: X25519PublicKey, plaintext: bytes) -> bytes:
    """Seal to a static X25519 key. Returns ephemeral_pub(32) || nonce || ciphertext."""
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes_raw()
    shared = _x25519_exchange(ephemeral, recipient_agreement_public.public_bytes_raw())
    key = _hkdf(shared, salt=ephemeral_pub, info=_SEAL_INFO)
    return ephemeral_pub + encrypt(key, plaintext, aad=ephemeral_pub)


def open_sealed(recipient_agreement_private: X25519PrivateKey, data: bytes) -> bytes:
    if len(data) < 32 + _NONCE_SIZE + 16:
        raise DecryptionError("sealed payload too short")
    ephemeral_pub = data[:32]
    shared = _x25519_exchange(recipient_agreement_private, ephemeral_pub)
    key = _hkdf(shared, salt=ephemeral_pub, info=_SEAL_INFO)
    return decrypt(key, data[32:], aad=ephemeral_pub)


def derive_session_key(
    own_ephemeral: X25519PrivateKey,
    peer_ephemeral_public: bytes,
    handshake_transcript: bytes,
    pq_shared: bytes = b"",
) -> bytes:
    """Both sides derive the same key from ephemeral ECDH + handshake transcript.

    ``pq_shared`` is an optional post-quantum KEM shared secret (ML-KEM-768). When
    present it is concatenated with the X25519 secret as HKDF input keying
    material, giving a *hybrid* key that stays secure if EITHER the classical or
    the post-quantum primitive holds — the defense against harvest-now-
    decrypt-later. Empty (the default) reproduces the classical-only key exactly,
    so classical and hybrid peers interoperate with no wire change when PQ isn't
    negotiated.
    """
    shared = _x25519_exchange(own_ephemeral, peer_ephemeral_public)
    return _hkdf(shared + pq_shared, salt=handshake_transcript, info=_SESSION_INFO)
