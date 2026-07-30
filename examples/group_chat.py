"""Three agents from two owners hold a group conversation.

Demonstrates: owner identities minting agents, group creation, full-mesh
membership, broadcast messaging, and a member leaving.

Run:  python examples/group_chat.py
"""

import asyncio

from fg_amp import AmpNode, GroupMessage, InMemoryTransport, OwnerIdentity


async def main() -> None:
    acme = OwnerIdentity.generate("acme-corp")
    globex = OwnerIdentity.generate("globex")

    groups = {}

    def collector(name):
        async def on_group(group):
            groups[name] = group

        return on_group

    analyst = AmpNode(
        identity=acme.create_agent("analyst", {"converse"}), on_group=collector("analyst")
    )
    trader = AmpNode(
        identity=acme.create_agent("trader", {"converse"}), on_group=collector("trader")
    )
    broker = AmpNode(
        identity=globex.create_agent("broker", {"converse"}), on_group=collector("broker")
    )

    transport = InMemoryTransport()
    for node in (analyst, trader, broker):
        node.attach(transport)

    group = await analyst.create_group([trader.card, broker.card], purpose="deal room")
    await asyncio.sleep(0.05)  # let invites + mesh settle
    print(f"group {group.group_id[:8]} roster: {[a[:16] + '…' for a in group.roster]}")

    await group.send_text("Proposal: 500 units at $3.90, settles Friday.")
    for name in ("trader", "broker"):
        message = await groups[name].receive(timeout=2)
        assert isinstance(message, GroupMessage)
        print(f"{name} received from {message.sender[:16]}…: {message.payload.content}")

    await groups["broker"].send_json({"vote": "accept"})
    print("founder received:", (await group.receive(timeout=2)).payload.content)
    print("trader received:", (await groups['trader'].receive(timeout=2)).payload.content)

    await groups["trader"].leave()
    event = await group.receive(timeout=2)
    print(f"membership event: {event.kind} — {event.member[:16]}…")


if __name__ == "__main__":
    asyncio.run(main())
