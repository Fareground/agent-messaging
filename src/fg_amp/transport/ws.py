"""WebSocket relay transport (SPEC §13.4): push delivery instead of polling.

``WsRelayTransport`` is a drop-in replacement for :class:`RelayTransport`:
same constructor shape, same ``connect``/``disconnect``/``deliver`` surface.
Instead of long-polling, it holds one WebSocket per node against the primary
relay, authenticates it with an audience-bound signed frame (single-use,
freshness-windowed — the WS adaptation of the pull credential), and then:

- receives mailbox deliveries pushed in real time, acking them over the
  socket after the node durably handled them;
- submits sends over the same socket (each envelope still carries its own
  signature, verified server-side exactly like an HTTP send);
- re-authenticates when the relay asks (socket sessions expire).

On any WS failure the transport falls back to one HTTP pull round (so no mail
strands while the socket is down) and then retries the socket. The WS client
is aiohttp — already the relay client dependency of the ``http`` extra; there
is no additional dependency.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..envelope.envelope import Envelope
from ..errors import TransportError
from .relay import PULL_PATH, RelayTransport, _pull_payload
from .relay_ws import WS_PATH, ws_auth_payload

if TYPE_CHECKING:
    from ..node.node import AmpNode

logger = logging.getLogger(__name__)

_SEND_TIMEOUT_SECONDS = 30.0
_RECONNECT_DELAY_SECONDS = 1.0


class WsRelayTransport(RelayTransport):
    """RelayTransport whose primary relay is spoken to over one WebSocket.

    Failover relays (positions past the first) are reached over HTTP as in
    the parent — the socket is an optimization on the primary path, and every
    HTTP behavior remains available underneath it.
    """

    def __init__(self, base_url, http_call: Any = None, audience=None, ws_path: str = WS_PATH):
        kwargs = {} if audience is None else {"audience": audience}
        super().__init__(base_url, http_call=http_call, **kwargs)
        self._ws_path = ws_path  # overridable so tests can force WS failure
        self._ws = None  # live aiohttp ClientWebSocketResponse, when connected
        self._ws_session = None
        self._ws_tasks: dict[str, asyncio.Task] = {}
        self._pending_sends: dict[str, asyncio.Future[dict]] = {}

    # -- lifecycle ---------------------------------------------------------

    async def connect(self, node: AmpNode, poll_interval: float = 1.0) -> None:
        """Register the card, then serve the mailbox over WS (HTTP fallback)."""
        await super().connect(node, poll_interval)
        # The parent started an HTTP poll loop; replace it with the WS loop,
        # which itself falls back to HTTP pulls whenever the socket is down.
        old = self._poll_tasks.pop(node.address, None)
        if old is not None:
            old.cancel()
        self._ws_tasks[node.address] = asyncio.create_task(
            self._ws_loop(node, poll_interval)
        )

    async def disconnect(self, node: AmpNode) -> None:
        task = self._ws_tasks.pop(node.address, None)
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self._close_ws()
        await super().disconnect(node)

    async def _close_ws(self) -> None:
        for future in self._pending_sends.values():
            if not future.done():
                future.set_exception(TransportError("websocket closed"))
        self._pending_sends.clear()
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None
        if self._ws_session is not None:
            with contextlib.suppress(Exception):
                await self._ws_session.close()
            self._ws_session = None

    # -- outbound ----------------------------------------------------------

    async def deliver(self, envelope: Envelope) -> None:
        local = self._handlers.get(envelope.to)
        if local is not None:
            await local(envelope)
            return
        ws = self._ws
        if ws is not None and not ws.closed:
            try:
                await self._deliver_over_ws(ws, envelope)
                return
            except TransportError:
                raise  # definitive relay verdict — do not retry over HTTP
            except Exception as exc:  # noqa: BLE001 — socket trouble: use HTTP
                logger.info("WS send failed (%s); falling back to HTTP", exc)
        await super().deliver(envelope)

    async def _deliver_over_ws(self, ws, envelope: Envelope) -> None:
        future: asyncio.Future[dict] = asyncio.get_running_loop().create_future()
        self._pending_sends[envelope.id] = future
        try:
            await ws.send_json({"type": "send", "envelope": envelope.to_wire()})
            verdict = await asyncio.wait_for(future, _SEND_TIMEOUT_SECONDS)
        finally:
            self._pending_sends.pop(envelope.id, None)
        if not verdict.get("accepted"):
            raise TransportError(f"relay send failed: {verdict.get('error', 'rejected')}")

    # -- socket loop -------------------------------------------------------

    def _signed_auth_frame(self, node: AmpNode) -> dict:
        ts = datetime.now(UTC).isoformat()
        sig = base64.b64encode(
            node.identity.keys.sign(ws_auth_payload(node.address, ts, self._audience))
        ).decode()
        return {"type": "auth", "address": node.address, "ts": ts, "sig": sig}

    async def _ws_loop(self, node: AmpNode, poll_interval: float) -> None:
        """Hold the socket open forever; on failure, HTTP-pull once and retry."""
        import aiohttp

        ws_url = self._base.replace("http://", "ws://").replace("https://", "wss://")
        while True:
            try:
                if self._ws_session is None:
                    self._ws_session = aiohttp.ClientSession()
                async with self._ws_session.ws_connect(ws_url + self._ws_path) as ws:
                    self._ws = ws
                    await ws.send_json(self._signed_auth_frame(node))
                    await self._serve_ws(node, ws)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — WS down: fall back, retry
                logger.info("relay WS unavailable (%s); HTTP pull fallback", exc)
            finally:
                self._ws = None
                for future in self._pending_sends.values():
                    if not future.done():
                        future.set_exception(TransportError("websocket closed"))
                self._pending_sends.clear()
            # No socket: one authenticated HTTP pull round so mail keeps
            # flowing (this is the spec'd fallback), then try the WS again.
            try:
                await self._http_pull_once(node)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — transient; the loop retries
                pass
            await asyncio.sleep(max(poll_interval, _RECONNECT_DELAY_SECONDS))

    async def _serve_ws(self, node: AmpNode, ws) -> None:
        import aiohttp

        # Deliveries are dispatched by a worker task, NOT inline in this
        # reader: a node handler frequently *sends* in response to a delivery
        # (e.g. the handshake accept), and that send awaits a `sent` verdict
        # only this reader can consume — inline dispatch would deadlock. One
        # worker keeps deliveries serial; the session layer reorders by seq.
        deliveries: asyncio.Queue[list[dict]] = asyncio.Queue()

        async def _worker() -> None:
            while True:
                envelopes = await deliveries.get()
                try:
                    await self._handle_delivery(node, ws, envelopes)
                except Exception:  # noqa: BLE001 — a bad batch must not kill delivery
                    logger.exception("WS delivery dispatch failed")

        worker = asyncio.create_task(_worker())
        try:
            async for message in ws:
                if message.type != aiohttp.WSMsgType.TEXT:
                    break
                frame = message.json()
                kind = frame.get("type")
                if kind == "ready":
                    pass  # (re-)authenticated; deliveries follow
                elif kind == "auth_required":
                    await ws.send_json(self._signed_auth_frame(node))
                elif kind == "deliver":
                    deliveries.put_nowait(frame.get("envelopes", []))
                elif kind == "sent":
                    future = self._pending_sends.get(frame.get("id") or "")
                    if future is not None and not future.done():
                        future.set_result(frame)
                elif kind == "acked":
                    pass
                elif kind == "error":
                    logger.warning("relay WS error frame: %s", frame.get("error"))
        finally:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        raise ConnectionError("relay websocket closed")

    async def _handle_delivery(self, node: AmpNode, ws, envelopes: list[dict]) -> None:
        """Dispatch pushed envelopes exactly as the HTTP poll loop does, then
        ack the durably-handled ones over the socket (at-least-once holds: an
        unacked lease is reclaimed and redelivered)."""
        handler = self._handlers.get(node.address)
        if handler is None:
            return
        acked: list[str] = []
        for wire in envelopes:
            mid = wire.get("id")
            try:
                parsed = Envelope.from_wire(wire)
            except Exception:  # noqa: BLE001 — malformed: ack to drop
                if mid:
                    acked.append(mid)
                continue
            try:
                await handler(parsed)
            except Exception:  # noqa: BLE001 — leave unacked for redelivery
                continue
            if mid:
                acked.append(mid)
        if acked:
            await ws.send_json({"type": "ack", "ids": acked})

    async def _http_pull_once(self, node: AmpNode) -> None:
        """One signed HTTP pull + dispatch + ack round (the WS-down fallback)."""
        def signed_pull(base: str, audience: str) -> dict:
            ts = datetime.now(UTC).isoformat()
            sig = base64.b64encode(
                node.identity.keys.sign(_pull_payload(node.address, ts, audience))
            ).decode()
            return {"address": node.address, "ts": ts, "sig": sig, "wait_seconds": 0.0}

        status, data = await self._call_failover("POST", PULL_PATH, body_fn=signed_pull)
        if status >= 400:
            return
        handler = self._handlers.get(node.address)
        if handler is None:
            return
        acked: list[str] = []
        for wire in data.get("envelopes", []):
            mid = wire.get("id")
            try:
                parsed = Envelope.from_wire(wire)
            except Exception:  # noqa: BLE001 — malformed: ack to drop
                if mid:
                    acked.append(mid)
                continue
            try:
                await handler(parsed)
            except Exception:  # noqa: BLE001 — leave unacked for redelivery
                continue
            if mid:
                acked.append(mid)
        if acked:
            await self._ack(node, acked)
