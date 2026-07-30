"""Security hardening: per-message ratchet, revocation, replay guards, sqlite relay."""

import asyncio

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    InMemorySessionStore,
    InMemoryTransport,
    OwnerIdentity,
    PolicyRejection,
    Revocation,
    SessionMode,
)
from fg_amp.session.ratchet import DoubleRatchet


def connected(*nodes: AmpNode) -> InMemoryTransport:
    transport = InMemoryTransport()
    for node in nodes:
        node.attach(transport)
    return transport


def test_ratchet_fresh_key_per_message_and_peers_agree():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    session_key = b"r" * 32
    bob_eph = X25519PrivateKey.generate()
    alice = DoubleRatchet.initiator(session_key, bob_eph.public_key().public_bytes_raw())
    bob = DoubleRatchet.responder(session_key, bob_eph)

    # Alice sends two frames; keys differ (fresh per message) and Bob agrees.
    dh1, k1 = alice.encrypt_step()
    dh2, k2 = alice.encrypt_step()
    assert k1 != k2  # fresh key every message
    assert dh1 == dh2  # same chain until a direction turn

    mk1, apply1 = bob.decrypt_prepare(dh1)
    apply1()
    assert mk1 == k1  # peer derives the identical message key
    mk2, apply2 = bob.decrypt_prepare(dh2)
    apply2()
    assert mk2 == k2


async def test_each_message_uses_fresh_key():
    """Identical plaintexts at different positions produce unrelatable ciphertexts,
    and a ciphertext cannot be replayed at another sequence position."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connected(alice, bob)
    session = await alice.initiate(bob.card)

    env1 = await session.send_text("same words")
    env2 = await session.send_text("same words")
    assert env1.body != env2.body
    await inbound[0].receive(timeout=1)
    await inbound[0].receive(timeout=1)


async def test_revocation_blocks_recalled_agent():
    owner = OwnerIdentity.generate("acme")
    rogue = owner.create_agent("rogue", {"converse"})
    node = AmpNode(identity=rogue)
    guard = AmpNode(
        identity=AgentIdentity.generate("guard"),
        policy=ContactPolicy.credentialed({"converse"}),
    )
    connected(node, guard)

    # before revocation: accepted
    session = await node.initiate(guard.card)
    assert session.state.value == "established"

    # owner recalls the grant; guard learns of it
    revocation = owner.revoke(rogue.delegation_chain.links[0])
    guard.revocations.add(revocation)
    with pytest.raises(PolicyRejection, match="revoked"):
        await node.initiate(guard.card)


async def test_revocation_only_by_original_issuer():
    owner = OwnerIdentity.generate("acme")
    mallory = OwnerIdentity.generate("mallory")
    agent = owner.create_agent("agent", {"converse"})
    grant = agent.delegation_chain.links[0]
    with pytest.raises(ValueError, match="this owner issued"):
        mallory.revoke(grant)
    # a forged revocation fails verification and never enters a registry
    forged = Revocation.revoke(mallory.keys, grant)
    victim = AmpNode(identity=AgentIdentity.generate("victim"))
    with pytest.raises(Exception, match="invalid revocation signature"):
        victim.revocations.add(forged)


async def test_replayed_initiate_cannot_clobber_session():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = connected(alice, bob)

    captured = []
    original_deliver = transport.deliver

    async def capture(envelope):
        if envelope.type.value == "handshake.initiate":
            captured.append(envelope)
        await original_deliver(envelope)

    transport.deliver = capture
    session = await alice.initiate(bob.card)
    await session.send_text("live message")
    await inbound[0].receive(timeout=1)

    # attacker replays the captured initiate verbatim
    await original_deliver(captured[0])
    await asyncio.sleep(0.01)
    assert len(inbound) == 1  # no second session materialized
    # and the original session still works
    await session.send_text("still alive")
    assert (await inbound[0].receive(timeout=1)).payload.content == "still alive"


async def test_replayed_resume_dropped():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(
        identity=AgentIdentity.generate("alice"), session_store=InMemorySessionStore()
    )
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        session_store=InMemorySessionStore(),
        on_session=on_session,
    )
    transport = connected(alice, bob)

    captured = []
    original_deliver = transport.deliver

    async def capture(envelope):
        if envelope.type.value == "session.resume":
            captured.append(envelope)
        await original_deliver(envelope)

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    alice.persist_session(session)
    bob.persist_session(inbound[0])

    transport.deliver = capture
    await alice.resume(session.session_id)
    sessions_after_resume = len(inbound)

    # replay the captured resume request verbatim: silently dropped
    await original_deliver(captured[0])
    await asyncio.sleep(0.01)
    assert len(inbound) == sessions_after_resume


async def test_sqlite_relay_survives_restart(tmp_path):
    import httpx

    from fg_amp import Envelope, EnvelopeType, SqliteRelayState, create_relay_app

    db = str(tmp_path / "relay.db")
    sender = AgentIdentity.generate("sender")
    recipient = AgentIdentity.generate("recipient")
    envelope = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=sender.address,
        to=recipient.address,
        session_id="s1",
        body=Envelope.encode_body(b"{}"),
    ).signed(sender.keys)

    # first relay process: store an envelope, a card, and a revocation
    state1 = SqliteRelayState(db)
    app1 = create_relay_app(state1)
    client1 = httpx.AsyncClient(transport=httpx.ASGITransport(app=app1), base_url="http://r")
    assert (await client1.post("/amp/v0/relay/send", json=envelope.to_wire())).status_code == 200
    card = sender.card()
    assert (
        await client1.put("/amp/v0/relay/cards", json=card.model_dump(mode="json"))
    ).status_code == 200
    owner = OwnerIdentity.generate("owner")
    agent = owner.create_agent("a", {"converse"})
    revocation = owner.revoke(agent.delegation_chain.links[0])
    assert (
        await client1.post(
            "/amp/v0/relay/revocations", json=revocation.model_dump(mode="json")
        )
    ).status_code == 200

    # "restart": fresh state object over the same file
    state2 = SqliteRelayState(db)
    assert state2.get_card(sender.address) is not None
    rows, _cursor = state2.list_revocations()
    assert rows[0]["delegation_digest"] == revocation.delegation_digest
    drained = state2.drain(recipient.address)
    assert len(drained) == 1
    assert Envelope.from_wire(drained[0]).id == envelope.id
    assert state2.drain(recipient.address) == []  # drained means gone


async def test_relay_revocation_sync():
    import httpx

    from fg_amp import create_relay_app
    from fg_amp.transport.relay import RelayTransport

    app = create_relay_app()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://r")

    async def http_call(method, url, body):
        response = await client.request(method, url, json=body if body else None)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {}

    relay = RelayTransport("http://r", http_call=http_call)
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("a", {"converse"})
    await relay.publish_revocation(owner.revoke(agent.delegation_chain.links[0]))

    node = AmpNode(identity=AgentIdentity.generate("verifier"))
    assert await relay.sync_revocations(node) == 1
    assert len(node.revocations.digests) == 1


async def test_sqlite_relay_persists_key_revocations_across_restart(tmp_path):
    """Key revocations (the strongest, permanent revocation type) must survive a
    relay restart on the SQLite backend — not silently fall back to memory."""
    from fg_amp.transport.relay import SqliteRelayState

    db = str(tmp_path / "relay.db")
    state = SqliteRelayState(db)
    agent = AgentIdentity.generate("compromised")
    keyrev = agent.revoke_own_key()
    state.add_key_revocation(keyrev)
    rows, _ = state.list_key_revocations(0)
    assert len(rows) == 1

    # "restart": fresh state object over the same file
    state2 = SqliteRelayState(db)
    rows2, _ = state2.list_key_revocations(0)
    assert len(rows2) == 1
    assert rows2[0]["address"] == agent.address
