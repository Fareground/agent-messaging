"""In-memory transport: same-process agent meshes (tests, sims, arena matches).

Includes simple store-and-forward: envelopes for addresses that are not yet
bound are queued and flushed on bind, so offline agents receive initiations.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque

from ..envelope.envelope import Envelope
from ..errors import TransportError
from .base import InboundHandler, Transport

_MAX_QUEUED_PER_ADDRESS = 1024
_log = logging.getLogger("fg_amp.transport.memory")


class InMemoryTransport(Transport):
    """Same-process transport that mirrors network semantics: a delivery
    succeeds once the envelope reaches the recipient's handler; errors raised
    *inside* the recipient's processing are logged, not propagated back to the
    sender (so a receiver-side fault never surfaces as the sender's exception).
    """

    def __init__(self):
        self._handlers: dict[str, InboundHandler] = {}
        self._pending: dict[str, deque[Envelope]] = {}

    async def deliver(self, envelope: Envelope) -> None:
        handler = self._handlers.get(envelope.to)
        if handler is None:
            queue = self._pending.setdefault(envelope.to, deque())
            if len(queue) >= _MAX_QUEUED_PER_ADDRESS:
                raise TransportError(f"mailbox full for unbound address {envelope.to}")
            queue.append(envelope)
            return
        await self._dispatch(handler, envelope)

    async def _dispatch(self, handler: InboundHandler, envelope: Envelope) -> None:
        try:
            await handler(envelope)
        except Exception as exc:  # noqa: BLE001 — receiver faults must not reach the sender
            _log.warning(
                "recipient %s rejected envelope %s (%s): %s",
                envelope.to,
                envelope.id,
                envelope.type,
                exc,
            )

    def bind(self, address: str, handler: InboundHandler) -> None:
        self._handlers[address] = handler
        # Auto-flush anything queued while this address was unbound, so a
        # message sent before the recipient attached is not silently stranded.
        if self._pending.get(address):
            try:
                asyncio.get_running_loop().create_task(self.flush(address))
            except RuntimeError:
                pass  # no running loop; caller can flush() explicitly

    def unbind(self, address: str) -> None:
        self._handlers.pop(address, None)

    async def flush(self, address: str) -> int:
        """Deliver queued envelopes to a now-bound address. Returns count delivered."""
        handler = self._handlers.get(address)
        if handler is None:
            raise TransportError(f"no handler bound for {address}")
        queue = self._pending.pop(address, deque())
        for envelope in queue:
            await self._dispatch(handler, envelope)
        return len(queue)
