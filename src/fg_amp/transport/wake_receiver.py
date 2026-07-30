"""The other half of wake: a listener that turns a ping into action.

:mod:`wake` is the *trigger* — a relay POSTs a content-free ping to the URL an
agent advertised. Something has to be listening at that URL and do the pulling.
That listener is inherently runtime-specific (it might connect a node and pull,
or resume a poll loop, or spawn a whole agent process), so AMP does not force
one shape. This is a small reference implementation that covers the common case
and documents the contract in code.

Contract: the agent advertises ``endpoints.wake = "https://host/path"`` in its
card. A :class:`WakeReceiver` serves that path; on a ping it invokes the
async ``on_wake`` callback the operator supplied. Typically that callback
connects a :class:`RelayTransport` and drains the mailbox — the wake is only a
hint, so the callback, not the ping, is what actually fetches mail.

The ping carries nothing (see :mod:`wake`), so the receiver treats *any* POST to
its path as "there may be mail" and does not parse a body. It answers 204 fast
and runs the callback without blocking the response, so a slow pull cannot hold
the relay's wake request open.

Requires the ``http`` extra: pip install 'fg-amp[http]'.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

WakeCallback = Callable[[], Awaitable[None]]


class WakeReceiver:
    """Serves an agent's advertised wake endpoint and fires a callback on ping.

    ``coalesce`` (default True) collapses a burst of pings that arrive while a
    pull is already running into a single follow-up run, so N pings cause at
    most one in-flight pull plus one queued — a pull fetches *all* waiting mail
    anyway, so running it once per ping would be wasted work.
    """

    def __init__(self, on_wake: WakeCallback, *, path: str = "/wake",
                 coalesce: bool = True):
        self._on_wake = on_wake
        self._path = path
        self._coalesce = coalesce
        self._runner = None
        self._site = None
        self._running_task: asyncio.Task | None = None
        self._pending = False

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        """Start listening. Returns the bound port (useful when port=0).

        In production the agent must front this with TLS at the exact host and
        path it advertised — the wake policy rejects non-https endpoints by
        default, and the certificate has to match the advertised host.
        """
        from aiohttp import web

        app = web.Application()
        app.router.add_post(self._path, self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()
        bound = self._site._server.sockets[0].getsockname()[1]
        logger.info("wake receiver listening on %s:%s%s", host, bound, self._path)
        return bound

    async def _handle(self, request):
        from aiohttp import web

        self._trigger()
        return web.Response(status=204)

    def _trigger(self) -> None:
        if self._running_task is not None and not self._running_task.done():
            # A pull is already running. One follow-up run will fetch anything
            # that arrives in the meantime; more than one would be redundant.
            if self._coalesce:
                self._pending = True
                return
        self._running_task = asyncio.ensure_future(self._run())

    async def _run(self) -> None:
        try:
            await self._on_wake()
        except Exception:
            # A wake is best-effort: a failed pull must not crash the listener,
            # and the poll loop / next ping remains the backstop.
            logger.exception("wake callback failed")
        finally:
            if self._pending:
                self._pending = False
                self._running_task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        """Stop listening and wait for an in-flight callback to finish."""
        if self._running_task is not None and not self._running_task.done():
            try:
                await self._running_task
            except Exception:  # pragma: no cover - already logged in _run
                pass
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
