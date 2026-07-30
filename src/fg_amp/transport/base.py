"""Transport abstraction: carriers of opaque, already-encrypted envelopes.

A transport never inspects bodies — it moves signed envelopes between
addresses. Nodes register an inbound handler; delivery failures raise
TransportError so the caller can retry or fail loudly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from ..envelope.envelope import Envelope

InboundHandler = Callable[[Envelope], Awaitable[None]]


class Transport(ABC):
    @abstractmethod
    async def deliver(self, envelope: Envelope) -> None:
        """Deliver an envelope to its ``to`` address. Raises TransportError."""

    @abstractmethod
    def bind(self, address: str, handler: InboundHandler) -> None:
        """Register the inbound handler for a local agent address."""

    @abstractmethod
    def unbind(self, address: str) -> None:
        """Remove a local agent binding."""
