"""Agent identity-key revocation: cut off a compromised agent entirely."""

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    InMemoryTransport,
    KeyRevocation,
    OwnerIdentity,
)


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def test_self_revocation_blocks_all_sessions_even_under_open_policy():
    """A revoked key can't open a session even against an OPEN policy — this is
    the gap plain delegation revocation left."""
    agent = AmpNode(identity=AgentIdentity.generate("agent"))
    target = AmpNode(identity=AgentIdentity.generate("target"), policy=ContactPolicy.open())
    connect(agent, target)

    # works before revocation
    session = await agent.initiate(target.card)
    assert session.state.value == "established"

    # agent self-revokes; target learns of it
    target.revocations.revoke_key(agent.identity.revoke_own_key())
    # The target drops the revoked agent's frames; the initiate can't complete.
    with pytest.raises(Exception):  # noqa: B017 — TimeoutError, establishment fails
        await agent.initiate(target.card, timeout=0.3)


async def test_owner_revokes_compromised_agent_key():
    owner = OwnerIdentity.generate("acme")
    agent_id = owner.create_agent("worker", {"converse"})
    agent = AmpNode(identity=agent_id)
    target = AmpNode(identity=AgentIdentity.generate("target"))
    connect(agent, target)
    assert (await agent.initiate(target.card)).state.value == "established"

    revocation = owner.revoke_agent_key(agent_id)
    target.revocations.revoke_key(revocation)
    with pytest.raises(Exception):  # noqa: B017
        await agent.initiate(target.card, timeout=0.3)


async def test_owner_cannot_revoke_key_it_did_not_delegate():
    owner = OwnerIdentity.generate("acme")
    stranger = OwnerIdentity.generate("stranger")
    agent_id = owner.create_agent("worker", {"converse"})
    with pytest.raises(ValueError, match="not the root"):
        stranger.revoke_agent_key(agent_id)


async def test_forged_key_revocation_rejected():
    """An owner-revocation without a valid proof chain, or a mismatched issuer,
    fails verification and never enters a registry."""
    attacker = OwnerIdentity.generate("attacker")
    victim = AgentIdentity.generate("victim")
    node = AmpNode(identity=AgentIdentity.generate("node"))

    # attacker tries to revoke victim's key with no proof chain
    forged = KeyRevocation.create(attacker.keys, attacker.address, victim.address)
    with pytest.raises(Exception, match="must include a proof chain"):
        node.revocations.revoke_key(forged)


async def test_key_revocation_distributes_via_relay():
    import httpx

    from fg_amp import create_relay_app
    from fg_amp.transport.relay import RelayTransport

    app = create_relay_app()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://r")

    async def http_call(method, url, body):
        resp = await client.request(method, url, json=body if body else None)
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, {}

    relay = RelayTransport("http://r", http_call=http_call)
    compromised = AgentIdentity.generate("compromised")
    await relay.publish_key_revocation(compromised.revoke_own_key())

    verifier = AmpNode(identity=AgentIdentity.generate("verifier"))
    assert await relay.sync_key_revocations(verifier) == 1
    assert verifier.revocations.is_key_revoked(compromised.address)


async def test_revocation_registry_snapshot_restore_is_durable_and_additive():
    """A revocation registry must survive restart and never un-revoke."""
    owner = OwnerIdentity.generate("acme")
    agent_id = owner.create_agent("worker", {"trade"})

    node = AmpNode(identity=AgentIdentity.generate("node"))
    node.revocations.revoke_key(owner.revoke_agent_key(agent_id))
    node.revocations.add(owner.revoke(agent_id.delegation_chain.links[0]))

    snap = node.revocations.snapshot()
    assert agent_id.address in snap["revoked_keys"]
    assert len(snap["digests"]) == 1

    # a fresh node (simulating a restart) restores the snapshot
    restarted = AmpNode(identity=AgentIdentity.generate("node2"))
    # it also has a pre-existing local revocation that restore must preserve
    stray = AgentIdentity.generate("stray")
    restarted.revocations.revoke_key(stray.revoke_own_key())
    restarted.revocations.restore(snap)

    assert restarted.revocations.is_key_revoked(agent_id.address)   # restored
    assert restarted.revocations.is_key_revoked(stray.address)      # local preserved
    grant = agent_id.delegation_chain.links[0]
    assert grant.digest in restarted.revocations.digests            # delegation revocation restored

    # restore is additive — an empty snapshot removes nothing
    restarted.revocations.restore({"digests": [], "revoked_keys": []})
    assert restarted.revocations.is_key_revoked(agent_id.address)


async def test_revocation_does_not_affect_other_agents():
    a = AmpNode(identity=AgentIdentity.generate("a"))
    b = AmpNode(identity=AgentIdentity.generate("b"))
    target = AmpNode(identity=AgentIdentity.generate("target"))
    connect(a, b, target)
    target.revocations.revoke_key(a.identity.revoke_own_key())
    # a is blocked, b is unaffected
    with pytest.raises(Exception):  # noqa: B017
        await a.initiate(target.card, timeout=0.3)
    assert (await b.initiate(target.card)).state.value == "established"
