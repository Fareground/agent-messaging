"""Two agents talk through a hosted relay — the real networked path.

Serves the relay app on a local port with uvicorn (the same server behind
`amp-relay`), then wires two nodes to it over real HTTP. In production you'd
run `amp-relay --port 8404` somewhere and point at its URL instead.

Run:  python examples/networked_relay.py   (needs the [http] extra)
"""

import asyncio
import socket

from fg_amp import AgentIdentity, AmpNode, ContactPolicy, OwnerIdentity, create_relay_app
from fg_amp.transport.relay import RelayTransport


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def main() -> None:
    import uvicorn

    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_relay_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    server_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    relay_url = f"http://127.0.0.1:{port}"
    print(f"relay listening on {relay_url}")

    async def on_session(session):  # bob answers whoever the policy admits
        message = await session.receive(timeout=10)
        print(f"bob received: {message.payload.content!r} from {message.sender[:20]}…")

    corp = OwnerIdentity.generate("corp")
    alice = AmpNode(identity=corp.create_agent("alice", {"converse"}))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy.open(),
        on_session=on_session,
    )

    relay_a = RelayTransport(relay_url)
    relay_b = RelayTransport(relay_url)

    # bob registers with the relay and starts pulling its mailbox
    await relay_b.connect(bob, poll_interval=0.05)
    await relay_a.connect(alice, poll_interval=0.05)

    # alice discovers bob's signed card through the relay directory
    bob_card = await relay_a.resolve_card(bob.address)
    print(f"resolved {bob_card.name} @ {bob_card.address[:20]}…")

    session = await alice.initiate(bob_card, purpose="hello over the relay", timeout=10)
    await session.send_text("delivered through an untrusted mailbox")
    await asyncio.sleep(0.5)  # let bob's poll loop pull and his callback print

    await session.close()
    await alice.aclose()  # aclose disconnects the relay transport it is attached to
    await bob.aclose()

    server.should_exit = True
    await server_task


if __name__ == "__main__":
    asyncio.run(main())
