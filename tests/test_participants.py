"""Any-participant messaging: agent<->human, kind-gated policies."""

import pytest

from fg_amp import (
    AmpNode,
    ContactPolicy,
    InMemoryTransport,
    OwnerIdentity,
    ParticipantKind,
    PolicyRejection,
    SessionState,
)


async def test_human_endpoint_talks_to_agent():
    sandro = OwnerIdentity.generate("sandro")
    corp = OwnerIdentity.generate("corp")
    inbound = []

    async def on_session(s):
        inbound.append(s)

    human = AmpNode(identity=sandro.create_endpoint())
    agent = AmpNode(
        identity=corp.create_agent("support-bot", {"converse"}), on_session=on_session
    )
    transport = InMemoryTransport()
    human.attach(transport)
    agent.attach(transport)

    assert human.card.kind is ParticipantKind.HUMAN
    session = await human.initiate(agent.card, purpose="support request")
    assert session.state is SessionState.ESTABLISHED

    # the agent can verify it's talking to a human owned by sandro
    agent_side = inbound[0]
    assert agent_side.peer_card.kind is ParticipantKind.HUMAN
    assert agent_side.peer_owner == sandro.address

    await agent_side.send_text("How can I help?")
    message = await session.receive(timeout=1)
    assert message.payload.content == "How can I help?"


async def test_policy_gates_by_participant_kind():
    sandro = OwnerIdentity.generate("sandro")
    human = AmpNode(identity=sandro.create_endpoint())
    bot_owner = OwnerIdentity.generate("botfarm")
    bot = AmpNode(identity=bot_owner.create_agent("bot", {"converse"}))

    # this agent only accepts humans
    humans_only = AmpNode(
        identity=OwnerIdentity.generate("gallery").create_agent("curator", {"converse"}),
        policy=ContactPolicy(allow_kinds=frozenset({ParticipantKind.HUMAN})),
    )
    transport = InMemoryTransport()
    for node in (human, bot, humans_only):
        node.attach(transport)

    session = await human.initiate(humans_only.card)
    assert session.state is SessionState.ESTABLISHED
    with pytest.raises(PolicyRejection, match="participant kind"):
        await bot.initiate(humans_only.card)


async def test_kind_is_signed_into_card():
    """A node cannot lie about its kind without breaking its card signature."""
    from fg_amp import AgentIdentity, SignatureError

    agent = AgentIdentity.generate("bot")
    card = agent.card()
    forged = card.model_copy(update={"kind": ParticipantKind.HUMAN})
    with pytest.raises(SignatureError):
        forged.verify()


async def test_mixed_group_humans_and_agents():
    import asyncio

    sandro = OwnerIdentity.generate("sandro")
    corp = OwnerIdentity.generate("corp")
    groups = {}

    def collector(name):
        async def on_group(g):
            groups[name] = g

        return on_group

    human = AmpNode(identity=sandro.create_endpoint(), on_group=collector("human"))
    analyst = AmpNode(
        identity=corp.create_agent("analyst", {"converse"}), on_group=collector("analyst")
    )
    trader = AmpNode(
        identity=corp.create_agent("trader", {"converse"}), on_group=collector("trader")
    )
    transport = InMemoryTransport()
    for node in (human, analyst, trader):
        node.attach(transport)

    group = await human.create_group([analyst.card, trader.card], purpose="oversight")
    await asyncio.sleep(0.05)
    await group.send_text("status report, please")
    for name in ("analyst", "trader"):
        message = await groups[name].receive(timeout=2)
        assert message.payload.content == "status report, please"
        assert message.sender == human.address
