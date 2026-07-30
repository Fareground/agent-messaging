"""The AMP wire envelope: signed, typed, sequenced.

Every message on the wire is one Envelope. The signature covers a
domain-separated view of all fields except ``sig`` (see
:mod:`fg_amp.signing`), so receivers verify before touching the body
and an envelope signature can never be replayed as another kind of artifact.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from ..errors import SignatureError
from ..identity.keys import KeyPair
from ..signing import CONTEXT_ENVELOPE, sign_payload, verify_by_address
from ..version import PROTOCOL_VERSION


class EnvelopeType(StrEnum):
    HANDSHAKE_INITIATE = "handshake.initiate"
    HANDSHAKE_ACCEPT = "handshake.accept"
    HANDSHAKE_REJECT = "handshake.reject"
    SESSION_MESSAGE = "session.message"
    SESSION_CLOSE = "session.close"
    SESSION_RESUME = "session.resume"
    RESUME_ACCEPT = "resume.accept"
    RESUME_REJECT = "resume.reject"
    RECEIPT = "receipt"
    WITNESS_COPY = "witness.copy"


class Envelope(BaseModel):
    amp: str = PROTOCOL_VERSION
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EnvelopeType
    sender: str  # AMP address; serialized as "from" on the wire
    to: str
    session_id: str | None = None
    seq: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    body: str = ""  # base64 ciphertext, or base64 plaintext JSON for handshake frames
    sig: str = ""

    # extra="allow": unknown fields from a newer peer are PRESERVED (not dropped)
    # and therefore included in the signed canonical payload, so an additive
    # wire-format field never breaks signature agreement between versions.
    model_config = {"frozen": True, "populate_by_name": True, "extra": "allow"}

    def _payload(self) -> dict:
        """The signed view of this envelope: everything except the signature."""
        data = self.model_dump(mode="json")
        data.pop("sig")
        data["from"] = data.pop("sender")
        return data

    def signed(self, keys: KeyPair) -> Envelope:
        return self.model_copy(
            update={"sig": sign_payload(keys, CONTEXT_ENVELOPE, self._payload())}
        )

    def verify_signature(self) -> None:
        """Verify against the sender address's self-certified key."""
        if not self.sig:
            raise SignatureError("envelope is unsigned")
        verify_by_address(self.sender, CONTEXT_ENVELOPE, self._payload(), self.sig)

    @property
    def body_bytes(self) -> bytes:
        return base64.b64decode(self.body)

    @staticmethod
    def encode_body(raw: bytes) -> str:
        return base64.b64encode(raw).decode()

    def to_wire(self) -> dict:
        data = self.model_dump(mode="json")
        data["from"] = data.pop("sender")
        return data

    @classmethod
    def from_wire(cls, data: dict) -> Envelope:
        data = dict(data)
        if "from" in data:
            data["sender"] = data.pop("from")
        return cls.model_validate(data)
