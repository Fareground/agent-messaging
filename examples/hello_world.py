"""The shortest possible AMP conversation: two nodes, one encrypted session.

``amp_pair`` wires two open-policy nodes over an in-process transport — no
relay, no network, no extras. Every message below is end-to-end encrypted and
double-ratcheted exactly as it would be over the wire.

Run:  python examples/hello_world.py
"""

import asyncio

from fg_amp.testing import amp_pair


async def main() -> None:
    a, b = await amp_pair()

    session = await a.initiate(b.card, purpose="hello")
    await session.send_text("ping")

    echo = b.sessions[session.session_id]  # b's side of the same session
    print("b received:", (await echo.receive(timeout=1)).payload.content)

    await echo.send_text("pong")
    print("a received:", (await session.receive(timeout=1)).payload.content)

    await a.aclose()
    await b.aclose()


if __name__ == "__main__":
    asyncio.run(main())
