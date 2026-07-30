"""HTTP transport (optional extra: ``fg-amp[http]``).

Server side: a FastAPI router exposing ``POST /amp/v0/inbox`` plus the agent
card at ``/.well-known/amp/agent-card.json``. Client side: aiohttp delivery
to the peer's ``http`` endpoint (from its AgentCard).

The transport carries only signed envelopes with encrypted bodies; TLS is
recommended but not load-bearing for confidentiality.
"""

from __future__ import annotations

import logging

from ..envelope.envelope import Envelope
from ..errors import TransportError
from ..identity.card import AgentCard
from .base import InboundHandler, Transport
from .ssrf import SsrfError, SsrfPolicy

_log = logging.getLogger("fg_amp.http")

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None

# Module-level so FastAPI can resolve the `request: Request` annotation under
# `from __future__ import annotations` (get_type_hints reads module globals).
try:
    from starlette.requests import Request
except ImportError:  # pragma: no cover
    Request = None  # only needed when the http extra (FastAPI/Starlette) is installed

INBOX_PATH = "/amp/v0/inbox"
CARD_PATH = "/.well-known/amp/agent-card.json"
_MAX_ENVELOPE_BYTES = 1 << 20  # 1 MiB cap on a single inbound envelope (matches relay)


class HttpTransport(Transport):
    """Delivers envelopes to peers' HTTP endpoints; receives via a FastAPI router."""

    def __init__(self, http_post=None, ssrf_policy: SsrfPolicy | None = None):
        # http_post is injectable for testing (e.g. an ASGI client). Default
        # uses aiohttp; signature: async (url: str, body: dict) -> (status, text)
        if http_post is None and aiohttp is None:
            raise ImportError("HttpTransport requires: pip install 'fg-amp[http]'")
        self._handlers: dict[str, InboundHandler] = {}
        self._endpoints: dict[str, str] = {}  # peer address -> base URL
        self._session: aiohttp.ClientSession | None = None
        self._http_post = http_post or self._aiohttp_post
        # A peer's endpoint URL comes from a card it published — a signed card
        # proves who published it, never that its URL is safe to dial. Guard
        # it exactly as the wake path does. Tests injecting http_post opt out
        # (they dial an in-process ASGI app, not the network).
        self._ssrf = ssrf_policy or SsrfPolicy()
        self._guarded = http_post is None

    async def _aiohttp_post(self, url: str, body: dict) -> tuple[int, str]:
        # Re-check the connected address inside the resolver (DNS-rebinding
        # safe) and never follow redirects (a 302 would re-open every SSRF
        # path the shape check closed). A fresh connector per session carries
        # the guarded resolver.
        if self._session is None:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(resolver=self._ssrf.guarded_resolver())
            )
        async with self._session.post(
            url,
            json=body,
            timeout=aiohttp.ClientTimeout(total=30),
            allow_redirects=False,
        ) as response:
            return response.status, await response.text()

    def register_peer(self, card: AgentCard) -> None:
        """Learn a peer's HTTP endpoint from its card. The endpoint is
        SSRF-validated for shape here (pre-flight); the connect-time resolver
        guard is the actual rebinding defence at delivery."""
        endpoint = card.endpoints.get("http")
        if not endpoint:
            raise TransportError(f"agent card for {card.address} has no http endpoint")
        base = endpoint.rstrip("/")
        if self._guarded:
            try:
                self._ssrf.check_url_shape(base + INBOX_PATH)
            except SsrfError as exc:
                raise TransportError(
                    f"agent card for {card.address} has an unsafe http endpoint: {exc}"
                ) from exc
        self._endpoints[card.address] = base

    async def deliver(self, envelope: Envelope) -> None:
        local = self._handlers.get(envelope.to)
        if local is not None:
            await local(envelope)
            return
        base = self._endpoints.get(envelope.to)
        if base is None:
            raise TransportError(f"no known endpoint for {envelope.to}")
        try:
            status, detail = await self._http_post(base + INBOX_PATH, envelope.to_wire())
        except Exception as exc:  # noqa: BLE001 — normalize client errors
            raise TransportError(f"delivery to {envelope.to} failed: {exc}") from exc
        if status >= 400:
            raise TransportError(
                f"delivery to {envelope.to} failed: HTTP {status} {detail[:200]}"
            )

    def bind(self, address: str, handler: InboundHandler) -> None:
        self._handlers[address] = handler

    def unbind(self, address: str) -> None:
        self._handlers.pop(address, None)

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None


async def read_capped_json(
    request, cap: int = _MAX_ENVELOPE_BYTES, read_timeout: float = 30.0
) -> dict:
    """Read a JSON request body with a hard byte cap enforced BEFORE buffering or
    parsing, so an oversized body can't exhaust memory/CPU. Rejects early on a
    too-large Content-Length, then streams with a running cap in case the header
    is absent or lying, and only then decodes JSON. A wall-clock ``read_timeout``
    bounds the whole read so a slow-drip (Slowloris) body can't pin a connection.

    Raises fastapi.HTTPException(413 too large / 408 too slow / 422 bad JSON).
    """
    import asyncio
    import json as _json

    from fastapi import HTTPException

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > cap:
        raise HTTPException(status_code=413, detail="envelope exceeds size limit")

    async def _read() -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > cap:
                raise HTTPException(status_code=413, detail="envelope exceeds size limit")
            chunks.append(chunk)
        return b"".join(chunks)

    try:
        body = await asyncio.wait_for(_read(), read_timeout)
    except TimeoutError as exc:
        raise HTTPException(status_code=408, detail="request body read timed out") from exc
    try:
        return _json.loads(body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"malformed body: {exc}") from exc


def create_inbox_router(transport: HttpTransport, card: AgentCard):
    """FastAPI router serving this node's inbox and public agent card."""
    from fastapi import APIRouter, HTTPException

    router = APIRouter()

    @router.post(INBOX_PATH)
    async def inbox(request: Request):
        # Enforce the byte cap on the raw body before any buffering/parsing, so a
        # directly-reachable agent can't be exhausted by an oversized payload.
        envelope = await read_capped_json(request)
        try:
            parsed = Envelope.from_wire(envelope)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"malformed envelope: {exc}") from exc
        handler = transport._handlers.get(parsed.to)
        if handler is None:
            raise HTTPException(status_code=404, detail="no such agent at this node")
        try:
            await handler(parsed)
        except Exception as exc:
            # Don't echo internal exception text to an unauthenticated poster — it
            # leaks replay-guard/session-state internals useful for probing. Log
            # the detail server-side; return a generic rejection.
            _log.info("inbox rejected envelope %s: %s", parsed.id, exc)
            raise HTTPException(status_code=400, detail="envelope rejected") from exc
        return {"accepted": True, "id": parsed.id}

    @router.get(CARD_PATH)
    async def agent_card():
        return card.model_dump(mode="json")

    return router
