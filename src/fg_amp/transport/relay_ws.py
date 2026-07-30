"""Relay WebSocket endpoint (SPEC §13.4): push delivery + send over one socket.

The HTTP relay is pull-based: a recipient long-polls its mailbox with a fresh
single-use signed credential per pull. The WS endpoint keeps the same security
model but amortizes the credential over a bounded **socket session**: the
client authenticates the socket with an audience-bound, freshness-windowed,
single-use signed frame (context ``relay-ws``), and the relay then pushes
mailbox deliveries as they arrive and accepts sends over the same socket.

Auth is periodic, not eternal: a socket session expires after
``WS_AUTH_SECONDS``; the relay asks for re-auth (``auth_required``) and closes
the socket if no fresh credential arrives within the grace window. Sends need
no per-frame credential — every envelope carries its own signature and is
verified exactly as the HTTP ``send`` endpoint verifies it. Acks ride the
authenticated socket (HTTP acks are signed only because HTTP is stateless).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

# Module-level so FastAPI can resolve the `websocket: WebSocket` annotation
# under `from __future__ import annotations` (get_type_hints reads module
# globals; a function-local import leaves the forward reference unresolvable
# and the route rejects every upgrade with 403).
try:
    from fastapi import WebSocket, WebSocketDisconnect
except ImportError:  # pragma: no cover — requires the http extra
    WebSocket = None
    WebSocketDisconnect = None

from ..envelope.canonical import canonical_json
from ..envelope.envelope import Envelope
from ..errors import TransportError
from ..identity.address import signing_key_from_address
from ..identity.keys import PublicKeys
from ..signing import CONTEXT_RELAY_WS, decode_signature, signing_input

logger = logging.getLogger(__name__)

WS_PATH = "/amp/v0/relay/ws"

# One socket authentication is honored this long; after that the relay asks
# for a fresh signed frame. Matches the operational-assumption clock window.
WS_AUTH_SECONDS = 300.0
# How long past expiry the relay waits for the re-auth before closing.
WS_REAUTH_GRACE_SECONDS = 30.0
_WS_AUTH_MAX_AGE_SECONDS = 120.0  # freshness window for the signed auth frame
_PUSH_POLL_SECONDS = 5.0  # waiter timeout between mailbox checks
_CLOSE_POLICY_VIOLATION = 1008


def ws_auth_payload(address: str, timestamp: str, audience: str) -> bytes:
    """The signed bytes that authenticate one WS session for ``address``."""
    return signing_input(
        CONTEXT_RELAY_WS,
        {"action": "connect", "address": address, "audience": audience, "ts": timestamp},
    )


def _verify_ws_auth(frame: dict, audience: str) -> str:
    """Validate a client auth frame; returns the authenticated address."""
    address, ts, sig = frame.get("address"), frame.get("ts"), frame.get("sig")
    if not (isinstance(address, str) and isinstance(ts, str) and isinstance(sig, str)):
        raise TransportError("auth frame requires address, ts, sig")
    try:
        issued = datetime.fromisoformat(ts)
    except (ValueError, TypeError) as exc:
        raise TransportError("invalid auth timestamp") from exc
    if issued.tzinfo is None:
        raise TransportError("auth timestamp must be timezone-aware")
    if abs((datetime.now(UTC) - issued).total_seconds()) > _WS_AUTH_MAX_AGE_SECONDS:
        raise TransportError("auth credential expired")
    try:
        keys = PublicKeys(signing=signing_key_from_address(address), agreement=b"\x00" * 32)
        keys.verify(decode_signature(sig), ws_auth_payload(address, ts, audience))
    except Exception as exc:
        raise TransportError("auth signature invalid") from exc
    return address


def register_ws_endpoint(app, relay, audience: str, rate_allow, waker=None) -> None:
    """Mount the WS endpoint on a relay app built by ``create_relay_app``.

    ``rate_allow(key) -> bool`` is the app's shared rate limiter;
    ``relay.check_pull_replay`` doubles as the single-use guard for auth
    credentials (same freshness window semantics as pulls).
    """
    if WebSocket is None:  # pragma: no cover — requires the http extra
        raise ImportError("the relay WS endpoint requires: pip install 'fg-amp[http]'")

    _max_frame = 1 << 20  # same 1 MiB cap as the HTTP send endpoint

    async def _authenticate(websocket: WebSocket, frame: dict) -> str:
        address = _verify_ws_auth(frame, audience)
        # Single-use within the freshness window: a captured auth frame cannot
        # open a second socket for the victim's mailbox.
        if not relay.check_pull_replay(frame["sig"], time.monotonic()):
            raise TransportError("auth credential already used")
        if not rate_allow(f"ws:{address}"):
            raise TransportError("rate limit exceeded")
        return address

    async def _handle_send(websocket: WebSocket, raw: dict) -> None:
        wire = raw.get("envelope")
        mid = wire.get("id") if isinstance(wire, dict) else None
        try:
            if not isinstance(wire, dict):
                raise TransportError("send frame requires an envelope object")
            canonical_json(wire)  # reject non-canonical content (e.g. floats)
            parsed = Envelope.from_wire(wire)
            parsed.verify_signature()
            if not rate_allow(f"send:{parsed.sender}"):
                raise TransportError("rate limit exceeded")
            await relay.run(relay.enqueue, parsed)
        except Exception as exc:  # noqa: BLE001 — report to the sender, keep the socket
            await websocket.send_json(
                {"type": "sent", "id": mid, "accepted": False, "error": str(exc)}
            )
            return
        relay._notify(parsed.to)
        if waker is not None and not relay.has_waiter(parsed.to):
            waker.schedule(parsed.to, await relay.run(relay.get_card, parsed.to))
        await websocket.send_json({"type": "sent", "id": parsed.id, "accepted": True})

    @app.websocket(WS_PATH)
    async def relay_ws(websocket: WebSocket):
        await websocket.accept()
        # Bound the very first frame the same way as every later frame: an
        # unauthenticated client must not be able to make the relay buffer and
        # parse an arbitrarily large JSON blob before it has proven anything.
        try:
            raw_first = await websocket.receive_text()
        except WebSocketDisconnect:
            return
        if len(raw_first) > _max_frame:
            await websocket.close(code=_CLOSE_POLICY_VIOLATION, reason="frame too large")
            return
        import json as _first_json

        try:
            first = _first_json.loads(raw_first)
        except ValueError:
            await websocket.close(code=_CLOSE_POLICY_VIOLATION, reason="auth required")
            return
        if not isinstance(first, dict) or first.get("type") != "auth":
            await websocket.close(code=_CLOSE_POLICY_VIOLATION, reason="auth required")
            return
        try:
            address = await _authenticate(websocket, first)
        except TransportError as exc:
            await websocket.send_json({"type": "error", "error": str(exc)})
            await websocket.close(code=_CLOSE_POLICY_VIOLATION, reason=str(exc))
            return
        session = {"authed_until": time.monotonic() + WS_AUTH_SECONDS, "nagged": False}
        await websocket.send_json({"type": "ready", "address": address})

        async def _pusher() -> None:
            """Push mailbox deliveries as they arrive; enforce re-auth."""
            while True:
                now = time.monotonic()
                if now > session["authed_until"]:
                    if now > session["authed_until"] + WS_REAUTH_GRACE_SECONDS:
                        await websocket.close(
                            code=_CLOSE_POLICY_VIOLATION, reason="re-auth timeout"
                        )
                        return
                    if not session["nagged"]:
                        session["nagged"] = True
                        await websocket.send_json({"type": "auth_required"})
                    await asyncio.sleep(1.0)
                    continue
                envelopes = await relay.run(relay.drain, address)
                if envelopes:
                    await websocket.send_json({"type": "deliver", "envelopes": envelopes})
                    continue
                event = relay.register_waiter(address)
                try:
                    # Never sleep past the auth deadline, so the re-auth nag
                    # goes out promptly instead of one poll interval late.
                    until_expiry = max(session["authed_until"] - now, 0.05)
                    await asyncio.wait_for(
                        event.wait(), min(_PUSH_POLL_SECONDS, until_expiry)
                    )
                except TimeoutError:
                    pass
                finally:
                    relay.drop_waiter(address, event)

        pusher = asyncio.create_task(_pusher())
        try:
            while True:
                raw = await websocket.receive_text()
                if len(raw) > _max_frame:
                    await websocket.send_json({"type": "error", "error": "frame too large"})
                    continue
                import json as _json

                try:
                    frame = _json.loads(raw)
                except ValueError:
                    await websocket.send_json({"type": "error", "error": "not JSON"})
                    continue
                kind = frame.get("type") if isinstance(frame, dict) else None
                if kind == "auth":
                    # Periodic re-auth: same verification as the opening frame,
                    # and it MUST authenticate the same address — a socket never
                    # changes hands.
                    try:
                        reauthed = await _authenticate(websocket, frame)
                        if reauthed != address:
                            raise TransportError("re-auth for a different address")
                    except TransportError as exc:
                        await websocket.send_json({"type": "error", "error": str(exc)})
                        continue
                    session["authed_until"] = time.monotonic() + WS_AUTH_SECONDS
                    session["nagged"] = False
                    await websocket.send_json({"type": "ready", "address": address})
                elif kind == "ack":
                    # Rides the authenticated socket; grace matches the pusher's.
                    if time.monotonic() > session["authed_until"] + WS_REAUTH_GRACE_SECONDS:
                        await websocket.send_json({"type": "error", "error": "not authed"})
                        continue
                    ids = [i for i in frame.get("ids", []) if isinstance(i, str)]
                    removed = await relay.run(relay.ack, address, ids)
                    await websocket.send_json({"type": "acked", "count": removed})
                elif kind == "send":
                    await _handle_send(websocket, frame)
                else:
                    await websocket.send_json(
                        {"type": "error", "error": f"unknown frame type {kind!r}"}
                    )
        except WebSocketDisconnect:
            pass
        except RuntimeError:
            pass  # receive after close (e.g. pusher closed on re-auth timeout)
        finally:
            pusher.cancel()
            try:
                await pusher
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 — teardown
                pass
