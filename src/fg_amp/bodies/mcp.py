"""``amp.mcp/1`` — MCP-over-AMP carriage.

Carriage, not an MCP implementation: each body wraps one MCP JSON-RPC
message verbatim under ``payload``, with an opaque ``mcp_session`` string
correlating an MCP session within the AMP session. AMP validates only the
outer frame (the payload must be a JSON object with ``jsonrpc == "2.0"``);
every inner semantic — methods, capabilities, tool schemas — belongs to MCP.

:class:`McpBridge` is a thin helper pair over one session: expose a local
async MCP handler (request → response) to the peer, and call the peer's,
with request/response correlation by JSON-RPC id and a timeout. It is a
profile demo, not a framework — one handler, one pending-call map.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar

from pydantic import BaseModel, field_validator

from ..errors import SessionError

_log = logging.getLogger("fg_amp.mcp")

JSONRPC_VERSION = "2.0"


class McpBody(BaseModel):
    """One MCP JSON-RPC message in flight, direction-neutral."""

    TYPE: ClassVar[str] = "amp.mcp/1"

    payload: dict[str, Any]  # the JSON-RPC message, verbatim and opaque
    mcp_session: str = ""  # opaque MCP-session correlator within the AMP session

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("payload")
    @classmethod
    def _payload_is_jsonrpc(cls, v: dict[str, Any]) -> dict[str, Any]:
        if v.get("jsonrpc") != JSONRPC_VERSION:
            raise ValueError('payload must be a JSON-RPC message with jsonrpc == "2.0"')
        return v


McpHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class McpBridge:
    """Expose a local MCP handler over a session, and call the remote one.

    Feed every received ``amp.mcp/1`` message to :meth:`dispatch` (or run
    :meth:`pump` as a background task to drain the session). Outbound calls
    go through :meth:`call`, which correlates the response by JSON-RPC id.
    """

    def __init__(self, session, handler: McpHandler | None = None, mcp_session: str = ""):
        self._session = session
        self._handler = handler
        self._mcp_session = mcp_session
        self._pending: dict[Any, asyncio.Future[dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self.unmatched_responses = 0  # responses with no pending call (dropped)

    def expose(self, handler: McpHandler) -> None:
        """Set the local handler answering the peer's MCP requests."""
        self._handler = handler

    async def call(self, request: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
        """Send one MCP request to the peer and await its correlated response.

        Assigns a bridge-unique JSON-RPC ``id`` when the request has none.
        Raises :class:`asyncio.TimeoutError` when no response arrives in time.
        """
        request = {"jsonrpc": JSONRPC_VERSION, **request}
        if request.get("id") is None:
            request = {**request, "id": f"amp-{next(self._ids)}"}
        call_id = request["id"]
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[call_id] = future
        try:
            await self._session.send_body(McpBody(payload=request, mcp_session=self._mcp_session))
            return await asyncio.wait_for(future, timeout)
        finally:
            self._pending.pop(call_id, None)

    async def dispatch(self, body: McpBody) -> bool:
        """Route one inbound MCP frame. Returns False for frames this bridge
        does not own (a different ``mcp_session``), so callers can layer
        bridges over one AMP session."""
        if body.mcp_session != self._mcp_session:
            return False
        payload = body.payload
        if "method" in payload:
            await self._handle_request(payload)
            return True
        # A response: correlate by id. An unmatched response (late after a
        # timeout, or never requested) is dropped and counted — inner JSON-RPC
        # bookkeeping is MCP's, so it is not an AMP protocol error.
        future = self._pending.get(payload.get("id"))
        if future is None:
            self.unmatched_responses += 1
            _log.warning(
                "mcp bridge (session %s): dropping unmatched response id %r",
                self._session.session_id,
                payload.get("id"),
            )
            return True
        if not future.done():
            future.set_result(payload)
        return True

    async def _handle_request(self, request: dict[str, Any]) -> None:
        if self._handler is None:
            response: dict[str, Any] = {
                "jsonrpc": JSONRPC_VERSION,
                "id": request.get("id"),
                "error": {"code": -32601, "message": "no MCP handler exposed"},
            }
        else:
            response = await self._handler(request)
        if request.get("id") is None:
            return  # a notification: no response travels back
        response = {"jsonrpc": JSONRPC_VERSION, "id": request.get("id"), **response}
        await self._session.send_body(McpBody(payload=response, mcp_session=self._mcp_session))

    async def pump(self) -> None:
        """Drain the session as a background task, dispatching MCP frames until
        cancelled or the session errors. Non-MCP payloads are ignored (a demo
        pump — a real application routes its own inbox)."""
        while True:
            try:
                message = await self._session.receive()
            except (SessionError, asyncio.CancelledError):
                return
            if message.payload.content_type != McpBody.TYPE:
                continue
            await self.dispatch(McpBody.model_validate(message.payload.content))
