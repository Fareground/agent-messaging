"""The shortest possible AMP conversation: two nodes, one encrypted session.

``amp_pair`` wires two open-policy nodes over an in-process transport — no
relay, no network, no extras. Every message below is end-to-end encrypted and
double-ratcheted exactly as it would be over the wire.

Run:  python examples/hello_world.py
"""

import asyncio

from fg_amp.testing import amp_pair


async def main() -> None:
    async def respond(session) -> None:  # b's side: runs as its own task, so receiving is safe
        message = await session.receive()
        print("b received:", message.payload.content)
        await session.send_text("pong")

    a, b = await amp_pair(on_session=respond)

    session = await a.initiate(b.card, purpose="hello")
    await session.send_text("ping")
    print("a received:", (await session.receive(timeout=1)).payload.content)

    await a.aclose()
    await b.aclose()


if __name__ == "__main__":
    asyncio.run(main())
