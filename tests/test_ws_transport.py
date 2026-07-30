"""WebSocket relay transport (SPEC §13.4): auth, push delivery, send, fallback.

These tests run a real uvicorn server on an ephemeral port because the WS
path needs a live socket (httpx's ASGI transport cannot upgrade). They skip
cleanly when the optional http extra (aiohttp/uvicorn) is not installed.
"""

import asyncio
import base64
from datetime import UTC, datetime

import pytest

aiohttp = pytest.importorskip("aiohttp")
uvicorn = pytest.importorskip("uvicorn")

from fg_amp import (  # noqa: E402 — after importorskip by design
    AgentIdentity,
    AmpNode,
    Session,
    WsRelayTransport,
    create_relay_app,
)
from fg_amp.transport.relay_ws import WS_PATH, ws_auth_payload  # noqa: E402

AUDIENCE = "ws-test-relay"


@pytest.fixture
async def relay_server():
    app = create_relay_app(audience=AUDIENCE)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    await task


def auth_frame(identity: AgentIdentity, audience: str = AUDIENCE) -> dict:
    ts = datetime.now(UTC).isoformat()
    sig = base64.b64encode(
        identity.keys.sign(ws_auth_payload(identity.address, ts, audience))
    ).decode()
    return {"type": "auth", "address": identity.address, "ts": ts, "sig": sig}


# -- auth ----------------------------------------------------------------


async def test_ws_auth_accepts_valid_and_rejects_forged(relay_server):
    identity = AgentIdentity.generate("puller")
    ws_url = relay_server.replace("http://", "ws://") + WS_PATH
    async with aiohttp.ClientSession() as http:
        # valid, audience-bound credential
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(auth_frame(identity))
            ready = await ws.receive_json()
            assert ready == {"type": "ready", "address": identity.address}
        # wrong audience: the signature is bound to another relay
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(auth_frame(identity, audience="some-other-relay"))
            reply = await ws.receive_json()
            assert reply["type"] == "error" and "signature" in reply["error"]
        # forged: signed by a different key than the claimed address
        mallory = AgentIdentity.generate("mallory")
        frame = auth_frame(mallory)
        frame["address"] = identity.address
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(frame)
            reply = await ws.receive_json()
            assert reply["type"] == "error"


async def test_ws_auth_credential_is_single_use(relay_server):
    identity = AgentIdentity.generate("replayed")
    frame = auth_frame(identity)
    ws_url = relay_server.replace("http://", "ws://") + WS_PATH
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(frame)
            assert (await ws.receive_json())["type"] == "ready"
        # the captured frame cannot open a second socket
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(frame)
            reply = await ws.receive_json()
            assert reply["type"] == "error" and "already used" in reply["error"]


async def test_ws_periodic_reauth_roundtrip(relay_server, monkeypatch):
    from fg_amp.transport import relay_ws as relay_ws_module

    monkeypatch.setattr(relay_ws_module, "WS_AUTH_SECONDS", 0.2)
    identity = AgentIdentity.generate("longlived")
    ws_url = relay_server.replace("http://", "ws://") + WS_PATH
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(auth_frame(identity))
            assert (await ws.receive_json())["type"] == "ready"
            # the session expires; the relay asks for a fresh credential
            # (the pusher notices at its next waiter timeout, up to ~5 s later)
            nag = await asyncio.wait_for(ws.receive_json(), timeout=10)
            assert nag == {"type": "auth_required"}
            await ws.send_json(auth_frame(identity))
            renewed = await asyncio.wait_for(ws.receive_json(), timeout=5)
            assert renewed == {"type": "ready", "address": identity.address}


async def test_ws_rejects_non_auth_first_frame(relay_server):
    ws_url = relay_server.replace("http://", "ws://") + WS_PATH
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json({"type": "send", "envelope": {}})
            message = await ws.receive()
            assert message.type == aiohttp.WSMsgType.CLOSE


# -- end-to-end over WS --------------------------------------------------


async def make_pair(relay_server, transport_cls=WsRelayTransport, **kwargs):
    inbound: list[Session] = []

    async def on_session(session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    ta = transport_cls(relay_server, audience=AUDIENCE, **kwargs)
    tb = transport_cls(relay_server, audience=AUDIENCE, **kwargs)
    await ta.connect(alice, poll_interval=0.05)
    await tb.connect(bob, poll_interval=0.05)
    return alice, bob, ta, tb, inbound


async def test_push_delivery_and_send_over_ws(relay_server):
    alice, bob, ta, tb, inbound = await make_pair(relay_server)
    try:
        # let both sockets come up so traffic genuinely rides the WS path
        for transport in (ta, tb):
            for _ in range(100):
                if transport._ws is not None:
                    break
                await asyncio.sleep(0.05)
            assert transport._ws is not None, "websocket never connected"
        bob_card = await ta.resolve_card(bob.address)
        session = await alice.initiate(bob_card, timeout=10)
        for _ in range(200):  # accept resolves before bob's on_session fires
            if inbound:
                break
            await asyncio.sleep(0.02)
        await session.send_text("pushed, not polled")
        message = await inbound[0].receive(timeout=10)
        assert message.payload.content == "pushed, not polled"
        # and the reverse direction
        await inbound[0].send_text("push back")
        assert (await session.receive(timeout=10)).payload.content == "push back"
    finally:
        await ta.disconnect(alice)
        await tb.disconnect(bob)


async def test_ws_failure_falls_back_to_http_pull(relay_server):
    # A broken WS path (server closes the upgrade) must not break delivery:
    # the transport serves the mailbox via authenticated HTTP pulls instead.
    alice, bob, ta, tb, inbound = await make_pair(
        relay_server, ws_path="/definitely/not/ws"
    )
    try:
        assert ta._ws is None and tb._ws is None
        bob_card = await ta.resolve_card(bob.address)
        session = await alice.initiate(bob_card, timeout=10)
        await session.send_text("fell back to http")
        message = await inbound[0].receive(timeout=10)
        assert message.payload.content == "fell back to http"
    finally:
        await ta.disconnect(alice)
        await tb.disconnect(bob)


async def test_sent_verdict_rejects_garbage_envelope(relay_server):
    identity = AgentIdentity.generate("sender")
    ws_url = relay_server.replace("http://", "ws://") + WS_PATH
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(ws_url) as ws:
            await ws.send_json(auth_frame(identity))
            assert (await ws.receive_json())["type"] == "ready"
            await ws.send_json({"type": "send", "envelope": {"garbage": True}})
            verdict = await ws.receive_json()
            assert verdict["type"] == "sent" and verdict["accepted"] is False
