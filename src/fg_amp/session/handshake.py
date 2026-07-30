"""Handshake payloads: what travels inside handshake envelopes.

The initiate body is sealed to the responder's static agreement key; the
accept body is sealed back to the initiator's. Each side contributes an
ephemeral X25519 key; the session key binds both ephemerals to the initiate
payload (as transcript salt), so neither side can be replayed into a
different session.
"""

from __future__ import annotations

import base64
import hashlib

from pydantic import BaseModel, Field

from ..envelope.canonical import canonical_json
from ..identity.card import AgentCard
from ..identity.delegation import DelegationChain
from .states import SessionMode
from .witness import WitnessSpec


def resume_salt(transcript_head: bytes, nonce: bytes) -> bytes:
    """KDF salt for a resumed session key: the stored transcript head bound to
    this attempt's fresh nonce. Identical on both sides; the nonce makes every
    resume derive a distinct key even though the transcript head is stable."""
    return hashlib.sha256(transcript_head + nonce).digest()


class HandshakeInitiate(BaseModel):
    """Body of a handshake.initiate envelope (sealed to responder)."""

    session_id: str
    card: AgentCard
    delegation_chain: DelegationChain = Field(default_factory=DelegationChain)
    mode: SessionMode = SessionMode.EPHEMERAL
    purpose: str = ""
    payload_types: tuple[str, ...] = ("text/plain", "application/json")
    ttl_ms: int = 3_600_000  # integer on the wire: signed/salt payloads carry no floats
    ephemeral_key: str  # base64 raw x25519 public
    capabilities: tuple[str, ...] = ()  # optional features the initiator supports
    pq_kem_key: str | None = None  # base64 ML-KEM-768 encapsulation key (if PQ offered)
    # Witnessed posture (SPEC §7.1): who this side proposes as witness. Rides
    # the signed, sealed initiate — and therefore the transcript salt — so the
    # witnessed agreement is bound into the session key itself.
    witness: WitnessSpec | None = None

    model_config = {"extra": "allow"}  # preserve unknown future handshake fields

    def model_dump(self, **kwargs):
        # An absent witness is OMITTED from the wire (not emitted as null):
        # the sealed initiate feeds the transcript salt byte-for-byte, so a
        # default-null field would silently change every session key derived
        # by this version against the golden vectors and older peers.
        data = super().model_dump(**kwargs)
        if data.get("witness") is None:
            data.pop("witness", None)
        return data

    @property
    def ttl_seconds(self) -> float:
        return self.ttl_ms / 1000.0

    def transcript_salt(self) -> bytes:
        """Deterministic digest binding the session key to this initiation."""
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).digest()

    @property
    def ephemeral_key_bytes(self) -> bytes:
        return base64.b64decode(self.ephemeral_key)


class HandshakeAccept(BaseModel):
    """Body of a handshake.accept envelope (sealed to initiator).

    Carries the responder's delegation chain too, so identity verification is
    mutual: each side learns the other's owner and effective scopes.
    """

    session_id: str
    card: AgentCard
    delegation_chain: DelegationChain = Field(default_factory=DelegationChain)
    accepted_payload_types: tuple[str, ...]
    ttl_ms: int
    ephemeral_key: str  # base64 raw x25519 public
    capabilities: tuple[str, ...] = ()  # negotiated intersection in force for the session
    pq_ciphertext: str | None = None  # base64 ML-KEM-768 ciphertext (if PQ negotiated)
    # Witnessed posture (SPEC §7.1): the responder's witness. MUST equal the
    # initiate's when the capability was negotiated — the initiator rejects a
    # divergent accept, so neither side can smuggle in a different witness.
    witness: WitnessSpec | None = None

    model_config = {"extra": "allow"}  # preserve unknown future handshake fields

    def model_dump(self, **kwargs):
        # Same wire rule as the initiate: absent witness is omitted, not null.
        data = super().model_dump(**kwargs)
        if data.get("witness") is None:
            data.pop("witness", None)
        return data

    @property
    def ttl_seconds(self) -> float:
        return self.ttl_ms / 1000.0

    @property
    def ephemeral_key_bytes(self) -> bytes:
        return base64.b64decode(self.ephemeral_key)


class HandshakeReject(BaseModel):
    """Body of a handshake.reject envelope (plaintext JSON — no secrets)."""

    session_id: str
    reason: str


class ResumeRequest(BaseModel):
    """Body of a session.resume envelope (sealed to responder's static key).

    Resume re-authenticates with identity keys and mints a *fresh* session key
    (post-compromise recovery). The stored session record contains no key
    material; proving knowledge of the transcript head ties the request to the
    real prior conversation.
    """

    session_id: str
    card: AgentCard
    delegation_chain: DelegationChain = Field(default_factory=DelegationChain)
    transcript_head: str  # base64 — must match the responder's stored head
    send_seq: int
    recv_seq: int
    ephemeral_key: str  # base64 raw x25519 public
    nonce: str  # base64 — fresh per resume attempt; echoed in the accept and
    # mixed into the fresh session key, so a captured resume.accept from a prior
    # attempt (session_id is stable across resumes) cannot be replayed.
    pq_kem_key: str | None = None  # base64 ML-KEM-768 encapsulation key (if PQ offered)

    model_config = {"extra": "allow"}  # preserve unknown future resume fields

    @property
    def ephemeral_key_bytes(self) -> bytes:
        return base64.b64decode(self.ephemeral_key)

    @property
    def transcript_head_bytes(self) -> bytes:
        return base64.b64decode(self.transcript_head)

    @property
    def nonce_bytes(self) -> bytes:
        return base64.b64decode(self.nonce)


class ResumeAccept(BaseModel):
    """Body of a resume.accept envelope (sealed to the resuming party)."""

    session_id: str
    card: AgentCard
    delegation_chain: DelegationChain = Field(default_factory=DelegationChain)
    ephemeral_key: str  # base64 raw x25519 public
    nonce: str  # echoes the ResumeRequest nonce, binding this accept to that
    # specific request
    pq_ciphertext: str | None = None  # base64 ML-KEM-768 ciphertext (if PQ negotiated)

    model_config = {"extra": "allow"}  # preserve unknown future resume fields

    @property
    def ephemeral_key_bytes(self) -> bytes:
        return base64.b64decode(self.ephemeral_key)

    @property
    def nonce_bytes(self) -> bytes:
        return base64.b64decode(self.nonce)
