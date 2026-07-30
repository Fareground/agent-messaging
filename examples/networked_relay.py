"""Two agents talk through a hosted relay — the real networked path, in-process.

Runs the relay as an ASGI app and drives it with an in-memory HTTP client, so
you can see discovery + offline delivery without opening a socket. In
production you'd instead run `amp-relay --port 8404` and point RelayTransport
at its URL.

Run:  python examples/networked_relay.py   (needs the [http] extra)
"""

import asyncio


async def main() -> None:
    import httpx

    from fg_amp import AgentIdentity, AmpNode, OwnerIdentity, create_relay_app
    from fg_amp.transport.relay import RelayTransport

    app = create_relay_app()  # a fresh in-memory relay
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.local"
    )

    async def http_call(method, url, body):
        resp = await client.request(method, url, json=body if body else None)
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, {}

    inbound = []

    async def on_session(session):
        inbound.append(session)

    corp = OwnerIdentity.generate("corp")
    alice = AmpNode(identity=corp.create_agent("alice", {"converse"}))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)

    relay_a = RelayTransport("http://relay.local", http_call=http_call)
    relay_b = RelayTransport("http://relay.local", http_call=http_call)

    # bob registers with the relay and starts pulling its mailbox
    await relay_b.connect(bob, poll_interval=0.05)
    await relay_a.connect(alice, poll_interval=0.05)

    # alice discovers bob's signed card through the relay directory
    bob_card = await relay_a.resolve_card(bob.address)
    print(f"resolved {bob_card.name} @ {bob_card.address[:20]}…")

    session = await alice.initiate(bob_card, purpose="hello over the relay", timeout=10)
    await session.send_text("delivered through an untrusted mailbox")
    message = await inbound[0].receive(timeout=10)
    print(f"bob received: {message.payload.content!r} from {message.sender[:20]}…")

    await session.close()
    await relay_a.disconnect(alice)
    await relay_b.disconnect(bob)
    await client.aclose()
    print("done — the relay only ever saw ciphertext")


if __name__ == "__main__":
    asyncio.run(main())
