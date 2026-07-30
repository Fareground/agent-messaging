"""Double ratchet: per-message forward secrecy + per-turn post-compromise security.

Two ratchets compose:

- **Symmetric (chain-key) ratchet** — each direction runs an HKDF chain; every
  message gets a fresh AEAD key and the chain advances, so compromising the
  state at time T reveals nothing about earlier messages (forward secrecy).
- **Diffie-Hellman ratchet** — each message header carries the sender's current
  X25519 public key. When a party receives a *new* public key (a direction
  turn), it mixes a fresh DH shared secret into the root key and derives new
  chains — so a compromise heals after the next turn (post-compromise security).

AMP variant vs. vanilla Signal: AMP lets *either* party send first (including
simultaneously). We achieve that by seeding the responder→initiator direction
with a symmetric chain-0 at init (so the responder can send immediately) while
the initiator takes an immediate send-side DH step. Crucially, ``DHs`` (our
current DH key) changes ONLY inside a receive-triggered ratchet step — never as
a side effect of sending — which is what makes simultaneous sends safe: two
sends can never independently advance the root key and diverge.

Decode happens in strict sequence order (the session's reorder buffer serializes
it), so no skipped-message-key store is needed: each seq is decoded exactly once,
in order, and a header key-change always aligns with a chain boundary.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_SIZE = 32
_MESSAGE_INFO = b"amp/0.1/ratchet/message"
_ADVANCE_INFO = b"amp/0.1/ratchet/advance"
_ROOT_INFO = b"amp/0.1/ratchet/root"
_SEED_INFO = b"amp/0.1/ratchet/seed/"


def _hkdf(key: bytes, info: bytes, length: int = _KEY_SIZE, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def derive_close_key(root_key: bytes, direction: str) -> bytes:
    """Deterministic key for a direction's close frame, independent of chain
    position so a close always authenticates even if a message was lost."""
    return _hkdf(root_key, b"amp/0.1/close/" + direction.encode())


def _kdf_ck(chain: bytes) -> tuple[bytes, bytes]:
    """Advance a chain key: returns (message_key, next_chain)."""
    return _hkdf(chain, _MESSAGE_INFO), _hkdf(chain, _ADVANCE_INFO)


def _kdf_rk(root: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root step: mix a DH secret into the root key. Returns (new_root, chain)."""
    material = _hkdf(dh_out, _ROOT_INFO, length=2 * _KEY_SIZE, salt=root)
    return material[:_KEY_SIZE], material[_KEY_SIZE:]


def _seed_chain(root_key: bytes, label: bytes) -> bytes:
    return _hkdf(root_key, _SEED_INFO + label)


def _dh(private: X25519PrivateKey, peer_public: bytes) -> bytes:
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    # Reject a low-order/degenerate point: an all-zero shared secret would
    # contribute no entropy to the root step, weakening that turn's PCS. A
    # benign peer never produces this; a malicious authenticated one is refused.
    if shared == b"\x00" * len(shared):
        raise ValueError("peer contributed a low-order X25519 point (zero shared secret)")
    return shared


class DoubleRatchet:
    """One session's double-ratchet state. Not constructed directly — use the
    ``initiator``/``responder`` classmethods built from the handshake ephemerals.
    """

    def __init__(
        self,
        root_key: bytes,
        dhs_private: X25519PrivateKey,
        dhr_public: bytes | None,
        cks: bytes | None,
        ckr: bytes | None,
    ):
        self._rk = root_key
        self._dhs = dhs_private
        self._dhr = dhr_public
        self._cks = cks
        self._ckr = ckr

    @property
    def dh_public(self) -> bytes:
        return self._dhs.public_key().public_bytes_raw()

    @classmethod
    def initiator(cls, session_key: bytes, peer_ephemeral_public: bytes) -> DoubleRatchet:
        """The party that received the accept. Takes an immediate send-side DH
        step so it can send right away, and seeds the r2i chain for receiving."""
        dhs = X25519PrivateKey.generate()
        rk, cks = _kdf_rk(session_key, _dh(dhs, peer_ephemeral_public))
        ckr = _seed_chain(session_key, b"r2i")
        return cls(rk, dhs, peer_ephemeral_public, cks, ckr)

    @classmethod
    def responder(
        cls, session_key: bytes, own_ephemeral_private: X25519PrivateKey
    ) -> DoubleRatchet:
        """The party that sent the accept. Sends on the seeded r2i chain until it
        receives the initiator's first message, then ratchets."""
        cks = _seed_chain(session_key, b"r2i")
        return cls(session_key, own_ephemeral_private, None, cks, None)

    # -- sending -----------------------------------------------------------

    def encrypt_step(self) -> tuple[bytes, bytes]:
        """Advance the sending chain. Returns (dh_public_header, message_key).
        Sending never changes ``DHs`` or the root — only a receive step does."""
        message_key, self._cks = _kdf_ck(self._cks)
        return self.dh_public, message_key

    # -- receiving (peek/commit so a bad frame doesn't desync) --------------

    def decrypt_prepare(self, header_dh: bytes):
        """Compute the message key for an inbound frame WITHOUT mutating state.
        Returns (message_key, apply) where apply() commits the ratchet advance
        (and any DH step). Call apply() only after decrypt+validate succeed."""
        if header_dh != self._dhr:
            # Direction turn: mix a fresh DH into the root for the receiving
            # chain, then take a send-side step so our replies use a new key.
            rk_recv, ckr = _kdf_rk(self._rk, _dh(self._dhs, header_dh))
            message_key, ckr_next = _kdf_ck(ckr)
            new_dhs = X25519PrivateKey.generate()
            rk_send, cks = _kdf_rk(rk_recv, _dh(new_dhs, header_dh))

            def apply() -> None:
                self._rk = rk_send
                self._ckr = ckr_next
                self._cks = cks
                self._dhs = new_dhs
                self._dhr = header_dh

            return message_key, apply

        message_key, ckr_next = _kdf_ck(self._ckr)

        def apply() -> None:
            self._ckr = ckr_next

        return message_key, apply

    def burn(self) -> None:
        self._rk = b"\x00" * _KEY_SIZE
        self._cks = None
        self._ckr = None
