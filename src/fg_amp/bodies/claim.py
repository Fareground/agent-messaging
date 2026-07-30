"""``amp.claim/1`` — a knowledge-claim envelope.

A carriage format only: it moves a claim (statement + confidence + pedigree)
between agents. Whether a claim is believed, promoted, or superseded is
governance and lives in the knowledge layer, not in this protocol.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, Field, field_validator

from .ref import RefBody


class ClaimPedigree(BaseModel):
    """Where a claim came from and what supports it."""

    source: str  # AMP address of the originating agent
    evidence: tuple[RefBody, ...] = ()  # supporting artifacts, as amp.ref bodies
    observed_at: str | None = None  # RFC 3339 timestamp of the observation

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("source")
    @classmethod
    def _source_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pedigree source must be non-empty")
        return v


class ClaimBody(BaseModel):
    """A single knowledge claim with provenance."""

    TYPE: ClassVar[str] = "amp.claim/1"

    claim_id: str
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    pedigree: ClaimPedigree
    supersedes: str | None = None  # claim_id this claim replaces

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("claim_id", "statement")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must be non-empty")
        return v
