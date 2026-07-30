"""``amp.ref/1`` — a pointer to an external artifact.

A ref carries no content, only enough to locate and verify one: a URI, what
kind of thing it points at, an optional version/revision, and an optional
content hash so the receiver can check what it fetched is what was meant.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, field_validator


class RefKind(StrEnum):
    ARTIFACT = "artifact"
    PROPOSAL = "proposal"
    TICKET = "ticket"
    COMMIT = "commit"
    CLAIM = "claim"


class RefBody(BaseModel):
    """A verifiable pointer to something outside the session."""

    TYPE: ClassVar[str] = "amp.ref/1"

    uri: str
    kind: RefKind = RefKind.ARTIFACT
    version: str = ""  # version / revision identifier, format is the target's
    content_hash: str = ""  # e.g. "sha256:<hex>"; empty = unverifiable

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("uri")
    @classmethod
    def _uri_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("uri must be non-empty")
        return v
