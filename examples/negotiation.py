"""Two agents negotiate a price over an ephemeral AMP session.

Demonstrates: credentialed contact policy, delegation chains, initiation,
bidirectional encrypted messaging, transcript verification, and close.

Run:  python examples/negotiation.py
"""

import asyncio

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    Delegation,
    DelegationChain,
    InMemoryTransport,
)


async def main() -> None:
    # A principal (the human/org) delegates 'negotiate' authority to the buyer agent.
    principal = AgentIdentity.generate("acme-corp")
    buyer_id = AgentIdentity.generate("acme-buyer")
    chain = DelegationChain(
        links=(
            Delegation.grant(
                principal.keys,
                principal.address,
                buyer_id.address,
                scopes={"converse", "negotiate"},
                ttl_seconds=3600,
            ),
        )
    )

    seller_sessions = []

    async def on_session(session):
        seller_sessions.append(session)

    buyer = AmpNode(identity=buyer_id.with_delegation(chain))
    seller = AmpNode(
        identity=AgentIdentity.generate("widget-seller"),
        # Pin the trusted owner: only agents whose authority traces back to
        # acme-corp may negotiate. Without trusted_issuers, scopes are advisory.
        policy=ContactPolicy.credentialed({"negotiate"}, trusted_issuers={principal.address}),
        on_session=on_session,
    )

    transport = InMemoryTransport()
    buyer.attach(transport)
    seller.attach(transport)

    session = await buyer.initiate(seller.card, purpose="bulk widget pricing")
    print(f"session established: {session.session_id} (mode={session.mode})")

    await session.send_text("Looking for 500 widgets. What's your best price?")
    inquiry = await seller_sessions[0].receive(timeout=1)
    print(f"seller received: {inquiry.payload.content}")

    await seller_sessions[0].send_json({"quote": {"quantity": 500, "unit_price": 3.80}})
    quote = await session.receive(timeout=1)
    print(f"buyer received quote: {quote.payload.content}")

    assert session.transcript.head == seller_sessions[0].transcript.head
    print(f"transcripts match: {session.transcript.head.hex()[:16]}…")

    await session.close("deal reached")
    print("session closed")


if __name__ == "__main__":
    asyncio.run(main())
