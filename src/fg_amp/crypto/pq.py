"""Hybrid post-quantum KEM (ML-KEM-768) for the AMP handshake.

Optional and negotiated. When both peers advertise the PQ capability, the
initiator ships an ML-KEM-768 encapsulation key in its handshake, the responder
encapsulates to it, and the resulting shared secret is mixed (concatenated as
HKDF input keying material) with the classical X25519 secret. The session key is
then secure as long as EITHER primitive is unbroken — the standard defense
against harvest-now-decrypt-later.

If the platform ``cryptography`` build lacks ML-KEM, ``PQ_AVAILABLE`` is False,
the PQ capability is simply not advertised, and peers transparently fall back to
the classical baseline. No wire break either way.

ML-KEM-768 sizes: encapsulation key 1184 B, ciphertext 1088 B, shared secret 32 B.
"""

from __future__ import annotations

import base64
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (
        MLKEM768PrivateKey,
        MLKEM768PublicKey,
    )

    PQ_AVAILABLE = True
except ImportError:  # pragma: no cover - platform without ML-KEM
    MLKEM768PrivateKey = None  # type: ignore[assignment,misc]
    MLKEM768PublicKey = None  # type: ignore[assignment,misc]
    PQ_AVAILABLE = False


def generate_kem() -> Any:
    """Fresh ML-KEM-768 private key (the initiator's per-handshake KEM key)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("ML-KEM is not available in this cryptography build")
    return MLKEM768PrivateKey.generate()


def encapsulation_key_b64(private_key: Any) -> str:
    """Base64 of the public encapsulation key to advertise in the handshake."""
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode()


def encapsulate_to(encapsulation_key_b64: str) -> tuple[bytes, str]:
    """Encapsulate to a peer's advertised key. Returns (shared_secret, ct_b64)."""
    public = MLKEM768PublicKey.from_public_bytes(base64.b64decode(encapsulation_key_b64))
    shared, ciphertext = public.encapsulate()
    return shared, base64.b64encode(ciphertext).decode()


def decapsulate(private_key: Any, ciphertext_b64: str) -> bytes:
    """Recover the shared secret from the responder's ciphertext."""
    return private_key.decapsulate(base64.b64decode(ciphertext_b64))
