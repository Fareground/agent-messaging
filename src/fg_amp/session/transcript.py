"""Tamper-evident transcript: a SHA-256 hash chain over canonical envelopes.

Both parties advance the same chain in the same order; comparing heads proves
they hold identical transcripts without exchanging the transcripts themselves.
"""

from __future__ import annotations

import hashlib

from ..envelope.canonical import canonical_json
from ..envelope.envelope import Envelope

GENESIS = b"\x00" * 32


def advance(head: bytes, envelope: Envelope) -> bytes:
    return hashlib.sha256(head + canonical_json(envelope.to_wire())).digest()


class Transcript:
    """Mutable holder for one session's chain head and entry count."""

    def __init__(self, head: bytes = GENESIS, length: int = 0):
        self._head = head
        self._length = length

    def record(self, envelope: Envelope) -> bytes:
        self._head = advance(self._head, envelope)
        self._length += 1
        return self._head

    @property
    def head(self) -> bytes:
        return self._head

    @property
    def length(self) -> int:
        return self._length

    def matches(self, expected_head: bytes) -> bool:
        """Whether this transcript's head equals a counterpart's — a constant
        proof that both parties hold the identical, untampered message history."""
        return self._head == expected_head
