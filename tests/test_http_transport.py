"""HTTP transport: FastAPI inbox round-trip + card serving (previously untested)."""

import httpx

from fg_amp import AgentIdentity, AmpNode, Envelope, EnvelopeType
from fg_amp.transport import HttpTransport, create_inbox_router
from fg_amp.transport.http import CARD_PATH, INBOX_PATH


def asgi_client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://node.test")


async def test_inbox_router_delivers_to_node():
    from fastapi import FastAPI

    inbound = []

    async def on_session(s):
        inbound.append(s)

    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = HttpTransport()
    bob.attach(transport)

    app = FastAPI()
    app.include_router(create_inbox_router(transport, bob.card))
    client = asgi_client(app)

    # bob's signed card is served for discovery
    resp = await client.get(CARD_PATH)
    assert resp.status_code == 200
    assert resp.json()["address"] == bob.address

    # a signed envelope posted to the inbox reaches bob's node
    alice = AgentIdentity.generate("alice")
    envelope = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,  # simplest inbound frame
        sender=alice.address,
        to=bob.address,
        session_id="s1",
        body=Envelope.encode_body(b"{}"),
    ).signed(alice.keys)
    resp = await client.post(INBOX_PATH, json=envelope.to_wire())
    assert resp.status_code == 200
    assert resp.json()["accepted"] is True


async def test_inbox_rejects_malformed_and_unknown():
    from fastapi import FastAPI

    node = AmpNode(identity=AgentIdentity.generate("n"))
    transport = HttpTransport()
    node.attach(transport)
    app = FastAPI()
    app.include_router(create_inbox_router(transport, node.card))
    client = asgi_client(app)

    resp = await client.post(INBOX_PATH, json={"garbage": True})
    assert resp.status_code == 422

    # addressed to someone not hosted here
    other = AgentIdentity.generate("other")
    stray = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=other.address,
        to=other.address,
        session_id="s",
        body=Envelope.encode_body(b"{}"),
    ).signed(other.keys)
    resp = await client.post(INBOX_PATH, json=stray.to_wire())
    assert resp.status_code == 404


async def test_http_transport_full_session_over_two_apps():
    """Two nodes, each behind its own FastAPI inbox, complete a real handshake
    and exchange an encrypted message across the HTTP boundary."""
    from fastapi import FastAPI

    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"), endpoints={"http": "http://alice.test"})
    bob = AmpNode(identity=AgentIdentity.generate("bob"), endpoints={"http": "http://bob.test"},
                  on_session=on_session)

    app_a, app_b = FastAPI(), FastAPI()

    clients: dict[str, httpx.AsyncClient] = {}

    async def http_post(url: str, body: dict):
        # Route by host to the right ASGI app, exercising the real inbox path.
        host = url.split("/")[2]
        client = clients[host]
        resp = await client.post("/" + "/".join(url.split("/")[3:]), json=body)
        return resp.status_code, resp.text

    ta = HttpTransport(http_post=http_post)
    tb = HttpTransport(http_post=http_post)
    alice.attach(ta)
    bob.attach(tb)
    ta.register_peer(bob.card)
    tb.register_peer(alice.card)

    app_a.include_router(create_inbox_router(ta, alice.card))
    app_b.include_router(create_inbox_router(tb, bob.card))
    clients["alice.test"] = asgi_client(app_a)
    clients["bob.test"] = asgi_client(app_b)

    session = await alice.initiate(bob.card, purpose="http")
    await session.send_text("hi over http")
    msg = await inbound[0].receive(timeout=2)
    assert msg.payload.content == "hi over http"

    await session.send_text("and again")
    assert (await inbound[0].receive(timeout=2)).payload.content == "and again"


async def test_inbox_rejects_oversized_body():
    """The inbox caps the raw body before parsing, so an oversized payload is
    rejected with 413 rather than being fully buffered and decoded."""
    from fastapi import FastAPI

    node = AmpNode(identity=AgentIdentity.generate("n"))
    transport = HttpTransport()
    node.attach(transport)
    app = FastAPI()
    app.include_router(create_inbox_router(transport, node.card))
    client = asgi_client(app)

    huge = Envelope(
        type=EnvelopeType.SESSION_MESSAGE,
        sender=AgentIdentity.generate("s").address,
        to=node.address,
        session_id="s",
        seq=1,
        body=Envelope.encode_body(b"x" * (2 << 20)),  # 2 MiB > 1 MiB cap
    ).signed(AgentIdentity.generate("s").keys)
    resp = await client.post(INBOX_PATH, json=huge.to_wire())
    assert resp.status_code == 413


def test_register_peer_rejects_private_and_non_https_endpoints():
    """A peer's card is self-certified but its URL is not trusted: the guarded
    transport refuses private/loopback/metadata and non-https endpoints so a
    malicious card can't turn this node into an SSRF proxy."""
    import pytest

    from fg_amp import AgentIdentity, AmpNode
    from fg_amp.errors import TransportError
    from fg_amp.transport import HttpTransport

    transport = HttpTransport()  # default = guarded (no injected http_post)
    for bad in (
        "http://bob.test",                       # not https
        "https://127.0.0.1/inbox",               # loopback
        "https://169.254.169.254/latest/meta",   # cloud metadata
        "https://10.0.0.5",                       # RFC1918
    ):
        node = AmpNode(identity=AgentIdentity.generate("m"), endpoints={"http": bad})
        with pytest.raises(TransportError):
            transport.register_peer(node.card)

    ok = AmpNode(identity=AgentIdentity.generate("ok"), endpoints={"http": "https://peer.example"})
    transport.register_peer(ok.card)  # public https is accepted


def test_ssrf_policy_unwraps_embedded_ipv4():
    """A globally-scoped IPv6 that carries a routable IPv4 (NAT64) is judged
    on the embedded address, not just its own scope."""
    import pytest

    from fg_amp.transport.ssrf import SsrfError, SsrfPolicy

    policy = SsrfPolicy()
    # 64:ff9b::a9fe:a9fe embeds 169.254.169.254 (link-local metadata).
    with pytest.raises(SsrfError):
        policy.check_address("64:ff9b::a9fe:a9fe")
    policy.check_address("2606:4700:4700::1111")  # public v6 is fine
