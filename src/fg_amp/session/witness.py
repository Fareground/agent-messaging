"""Witnessed session posture (SPEC §7.1): sealed E2E plus an auditor's copy.

The default AMP posture is **sealed**: only the two session parties can read
traffic. Some deployments need an audit trail without giving the relay (or
anyone else on the path) plaintext. Witnessed posture is the negotiated middle
ground: both parties agree — inside the signed, sealed handshake — on a single
**witness** (an agent address plus its X25519 public key), and every sender
additionally seals a copy of each plaintext body to that witness. The copy
travels as a ``witness.copy`` envelope routed to the witness's mailbox; it is
ciphertext to the relay and to everyone except the witness.

What is cryptographically bound and what is best-effort is spelled out in
SPEC §7.1 — this module implements the binding that IS enforceable: the
witnessed agreement rides the signed handshake (neither side can secretly
enable or disable it), and each copy is bound to ``(session_id, seq, sender)``
both by the signed carrying envelope and by a duplicate of those fields inside
the sealed plaintext, so a copy cannot be replayed against a different frame.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)
from pydantic import BaseModel

from ..envelope.crypto import open_sealed, seal
from ..envelope.envelope import Envelope, EnvelopeType
from ..errors import SessionError, WitnessError
from ..identity.keys import KeyPair, base58_decode


class WitnessSpec(BaseModel):
    """Who witnesses a session: an AMP address plus its X25519 agreement key.

    Rides inside the signed, sealed handshake bodies (initiate and accept), so
    the witnessed agreement is part of the handshake transcript — an on-path
    party cannot add, strip, or swap the witness without breaking the
    handshake. Both sides MUST name the identical witness or the handshake is
    rejected.
    """

    address: str
    agreement_key: str  # base58 raw X25519 public, same encoding as AgentCard

    model_config = {"frozen": True}

    @property
    def agreement_key_bytes(self) -> bytes:
        return base58_decode(self.agreement_key)

    def seal_target(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.agreement_key_bytes)


class WitnessedMessage(BaseModel):
    """A decrypted witness copy: the plaintext body plus its provenance.

    ``session_id``/``seq``/``sender`` are cross-checked against the signed
    carrying envelope before this is yielded, so the provenance is as
    trustworthy as the sender's signature.
    """

    session_id: str
    seq: int
    sender: str
    payload: dict[str, Any]  # the message Payload, as its wire JSON object

    model_config = {"frozen": True}


def build_witness_copy(
    witness: WitnessSpec,
    keys: KeyPair,
    sender: str,
    session_id: str,
    seq: int,
    payload_wire: dict[str, Any],
) -> Envelope:
    """Seal one message's plaintext to the witness and wrap it for the wire.

    The sealed plaintext repeats ``(session_id, seq, sender)`` and the signed
    carrying envelope carries the same values, so the two are cross-checkable
    by the witness: a relay (or anyone without the sender's key) cannot detach
    a copy from its frame or splice one session's copy into another.
    """
    inner = WitnessedMessage(
        session_id=session_id, seq=seq, sender=sender, payload=payload_wire
    )
    sealed = seal(witness.seal_target(), json.dumps(inner.model_dump(mode="json")).encode())
    return Envelope(
        type=EnvelopeType.WITNESS_COPY,
        sender=sender,
        to=witness.address,
        session_id=session_id,
        seq=seq,
        body=Envelope.encode_body(sealed),
    ).signed(keys)


class WitnessReceiver:
    """The witness side: opens ``witness.copy`` envelopes into plaintext.

    Construct with the witness's own key pair (its X25519 agreement private is
    the seal target the parties encrypt to). ``open_copy`` verifies and
    decrypts one envelope; ``handle`` is an ``InboundHandler`` that queues
    decrypted copies for ``receive`` — bind it to a transport or set it as a
    node's ``on_witness_copy`` to collect copies delivered via a relay.
    """

    def __init__(self, keys: KeyPair, address: str):
        import asyncio

        self._keys = keys
        self.address = address
        self._inbox: asyncio.Queue[WitnessedMessage] = asyncio.Queue()

    def spec(self) -> WitnessSpec:
        """The WitnessSpec both session parties must configure to use us."""
        return WitnessSpec(
            address=self.address, agreement_key=self._keys.public.agreement_b58
        )

    def open_copy(self, envelope: Envelope) -> WitnessedMessage:
        """Verify, decrypt, and cross-check one witness copy.

        Raises :class:`WitnessError` on anything inconsistent: bad signature,
        wrong type, undecryptable seal, or an inner record that does not match
        the signed outer envelope (a splicing/replay attempt).
        """
        if envelope.type is not EnvelopeType.WITNESS_COPY:
            raise WitnessError(f"not a witness copy: {envelope.type}")
        try:
            envelope.verify_signature()
        except Exception as exc:
            raise WitnessError(f"witness copy signature invalid: {exc}") from exc
        try:
            plaintext = open_sealed(self._keys.agreement_key, envelope.body_bytes)
        except Exception as exc:
            raise WitnessError(f"witness copy is not sealed to this witness: {exc}") from exc
        message = WitnessedMessage.model_validate(json.loads(plaintext))
        # The sealed inner record must agree with the signed outer envelope:
        # a mismatch means someone re-wrapped a copy around a different frame.
        if (
            message.session_id != (envelope.session_id or "")
            or message.seq != envelope.seq
            or message.sender != envelope.sender
        ):
            raise WitnessError(
                "witness copy inner record does not match its signed envelope "
                f"(inner {message.session_id}:{message.seq} from {message.sender}, "
                f"outer {envelope.session_id}:{envelope.seq} from {envelope.sender})"
            )
        return message

    async def handle(self, envelope: Envelope) -> None:
        """InboundHandler: decrypt and queue. Raises WitnessError on garbage."""
        self._inbox.put_nowait(self.open_copy(envelope))

    async def receive(self, timeout: float | None = None) -> WitnessedMessage:
        import asyncio

        if timeout is None:
            return await self._inbox.get()
        return await asyncio.wait_for(self._inbox.get(), timeout)


def require_witness_match(ours: WitnessSpec | None, theirs: WitnessSpec | None) -> WitnessSpec:
    """Both sides must name the identical witness; anything else is a reject.

    Called only when ``amp.posture.witnessed-v1`` made the negotiated set — a
    negotiated capability with a missing or divergent witness block is a
    protocol violation, never a silent fallback to sealed.
    """
    if ours is None or theirs is None:
        raise SessionError(
            "witnessed posture negotiated but a party sent no witness block"
        )
    if ours != theirs:
        raise SessionError(
            f"witness mismatch: {ours.address} != {theirs.address} "
            "(or their agreement keys differ)"
        )
    return ours
