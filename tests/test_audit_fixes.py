"""Regression tests for the audit findings (crypto/security round)."""

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
    SessionError,
    SessionMode,
)


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


# -- CREDENTIALED trust-anchor bypass (crypto CRITICAL) --------------------


async def test_credentialed_without_trusted_issuers_is_not_a_gate():
    """Documented weak mode: a self-signed chain still satisfies scopes."""
    attacker_owner = OwnerIdentity.generate("attacker")
    attacker = AmpNode(identity=attacker_owner.create_agent("rogue", {"admin"}))
    target = AmpNode(
        identity=AgentIdentity.generate("t"),
        policy=ContactPolicy.credentialed({"admin"}),
    )
    connect(attacker, target)
    # Without trusted_issuers this is only advisory — it connects (and logs a warning).
    session = await attacker.initiate(target.card)
    assert session.state.value == "established"


def signed_lying_card(identity, operator_address):
    """A validly-signed card whose operator field lies (the attacker signs a
    card claiming an operator it was never delegated by)."""
    from fg_amp.identity.card import AgentCard

    return AgentCard.create(
        keys=identity.keys,
        address=identity.address,
        name=identity.name,
        operator=operator_address,
    )


async def test_trusted_issuers_blocks_self_signed_chain():
    """The real gate: pin the owner, and a self-signed chain is rejected."""
    real_owner = OwnerIdentity.generate("real")
    attacker_owner = OwnerIdentity.generate("attacker")
    target = AmpNode(
        identity=AgentIdentity.generate("t"),
        policy=ContactPolicy.credentialed({"admin"}, trusted_issuers={real_owner.address}),
    )
    attacker = AmpNode(identity=attacker_owner.create_agent("rogue", {"admin"}))
    legit = AmpNode(identity=real_owner.create_agent("legit", {"admin"}))
    connect(attacker, legit, target)

    # attacker self-signs admin from an untrusted owner: rejected
    with pytest.raises(PolicyRejection, match="not a trusted issuer"):
        await attacker.initiate(target.card)
    # a genuinely delegated agent from the trusted owner is accepted
    session = await legit.initiate(target.card)
    assert session.state.value == "established"


async def test_card_operator_must_match_verified_chain():
    """A validly-signed card claiming an operator not in its chain is rejected."""
    owner = OwnerIdentity.generate("owner")
    liar = OwnerIdentity.generate("liar")
    agent = owner.create_agent("agent", {"converse"})
    node = AmpNode(identity=agent)
    node._card = signed_lying_card(agent, liar.address)  # lies about operator
    target = AmpNode(identity=AgentIdentity.generate("t"))
    connect(node, target)
    with pytest.raises(PolicyRejection, match="operator does not match"):
        await node.initiate(target.card)


async def test_allowlist_uses_verified_owner_not_card_field():
    """Operator-allowlist must consult the verified chain root, not card.operator."""
    trusted = OwnerIdentity.generate("trusted")
    attacker_owner = OwnerIdentity.generate("attacker")
    target = AmpNode(
        identity=AgentIdentity.generate("t"),
        policy=ContactPolicy.allowlist(operators={trusted.address}),
    )
    attacker = AmpNode(identity=attacker_owner.create_agent("rogue", {"converse"}))
    attacker._card = signed_lying_card(attacker.identity, trusted.address)
    legit = AmpNode(identity=trusted.create_agent("legit", {"converse"}))
    connect(attacker, legit, target)
    with pytest.raises(PolicyRejection):  # operator-mismatch or allowlist
        await attacker.initiate(target.card)
    # the genuinely-trusted owner's agent gets in
    assert (await legit.initiate(target.card)).state.value == "established"


# -- Revocation/expiry bypass on resume (crypto HIGH) ----------------------


async def test_resume_reverifies_authority_and_honors_revocation():
    owner = OwnerIdentity.generate("owner")
    agent_id = owner.create_agent("agent", {"trade"})
    inbound = []

    async def on_session(s):
        inbound.append(s)

    agent = AmpNode(identity=agent_id, session_store=InMemorySessionStore())
    counterparty = AmpNode(
        identity=AgentIdentity.generate("cp"),
        session_store=InMemorySessionStore(),
        policy=ContactPolicy.credentialed({"trade"}, trusted_issuers={owner.address}),
        on_session=on_session,
    )
    connect(agent, counterparty)

    session = await agent.initiate(counterparty.card, mode=SessionMode.PERSISTENT)
    assert inbound[0].has_scope("trade")
    agent.persist_session(session)
    counterparty.persist_session(inbound[0])

    # owner revokes the 'trade' delegation; counterparty learns of it
    revocation = owner.revoke(agent_id.delegation_chain.links[0])
    counterparty.revocations.add(revocation)

    # resume must now fail authority re-verification (revocation survives resume)
    with pytest.raises(SessionError, match="no longer valid"):
        await agent.resume(session.session_id)


# -- Group roster confidentiality (crypto HIGH) ----------------------------


async def test_non_roster_peer_not_joined_to_group_fanout():
    from fg_amp.session.group import GROUP_PURPOSE_PREFIX

    groups = {}

    def collector(name):
        async def cb(g):
            groups[name] = g

        return cb

    founder = AmpNode(identity=AgentIdentity.generate("founder"), on_group=collector("f"))
    member = AmpNode(identity=AgentIdentity.generate("member"), on_group=collector("m"))
    outsider = AmpNode(identity=AgentIdentity.generate("outsider"))
    connect(founder, member, outsider)

    group = await founder.create_group([member.card], purpose="private")
    await asyncio.sleep(0.05)

    # outsider learns the group_id and opens a group-purpose session to the member
    await outsider.initiate(
        member.card, purpose=GROUP_PURPOSE_PREFIX + group.group_id
    )
    await asyncio.sleep(0.05)

    member_group = groups["m"]
    # the outsider was NOT joined to the member's fan-out set
    assert outsider.address not in member_group.sessions
    # and a broadcast does not reach the outsider (no group on its side)
    await member_group.send_text("members only")
    assert not outsider.sessions or all(
        s.receive_nowait() is None for s in outsider.sessions.values()
    )


# -- require_scope with expected owner (defense in depth) ------------------


async def test_require_scope_with_expected_owner():
    owner = OwnerIdentity.generate("owner")
    other = OwnerIdentity.generate("other")
    inbound = []

    async def on_session(s):
        inbound.append(s)

    agent = AmpNode(identity=owner.create_agent("a", {"trade"}))
    target = AmpNode(identity=AgentIdentity.generate("t"), on_session=on_session)
    connect(agent, target)
    await agent.initiate(target.card)
    peer = inbound[0]
    peer.require_scope("trade", owner=owner.address)  # matches
    with pytest.raises(SessionError, match="expected"):
        peer.require_scope("trade", owner=other.address)


# -- resume force-close regression (verification round) --------------------


async def test_third_party_resume_cannot_close_live_session():
    """A party who merely knows a session_id (cleartext routing metadata) must
    not be able to force-close a victim's established session via resume."""
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
    mallory = AmpNode(
        identity=AgentIdentity.generate("mallory"), session_store=InMemorySessionStore()
    )
    connect(alice, bob, mallory)

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    bob_session = inbound[0]
    bob.persist_session(bob_session)

    # mallory forges a resume for the known session_id against bob
    import base64

    from fg_amp.envelope.envelope import EnvelopeType
    from fg_amp.session.handshake import ResumeRequest

    forged = ResumeRequest(
        session_id=session.session_id,
        card=mallory.card,
        transcript_head=base64.b64encode(b"\x00" * 32).decode(),
        send_seq=0,
        recv_seq=0,
        ephemeral_key=base64.b64encode(b"\x01" * 32).decode(),
        nonce=base64.b64encode(b"\x02" * 16).decode(),
    )
    envelope = mallory._sealed_envelope(
        EnvelopeType.SESSION_RESUME, bob.card, session.session_id, forged
    )
    await mallory._require_transport().deliver(envelope)
    await asyncio.sleep(0.01)

    # bob's real session with alice is untouched
    assert bob_session.state.value == "established"
    await bob_session.send_text("still here")
    assert (await session.receive(timeout=1)).payload.content == "still here"


# -- graceful shutdown -----------------------------------------------------


async def test_aclose_closes_sessions_and_fails_pending():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    await alice.aclose()
    assert session.state.value == "closed"
    await asyncio.sleep(0)
    assert inbound[0].state.value == "closed"  # close frame propagated


# -- protocol version guard ------------------------------------------------


async def test_incompatible_version_rejected():
    from fg_amp import Envelope, EnvelopeType, ProtocolVersionError

    alice = AgentIdentity.generate("alice")
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(bob)
    envelope = Envelope(
        amp="9.9",
        type=EnvelopeType.SESSION_MESSAGE,
        sender=alice.address,
        to=bob.address,
        session_id="x",
        seq=1,
        body=Envelope.encode_body(b"z"),
    ).signed(alice.keys)
    with pytest.raises(ProtocolVersionError):
        await bob._on_envelope(envelope)
