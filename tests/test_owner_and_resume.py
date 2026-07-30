"""Owner identity, mutual verification, and persistent session resume."""

import asyncio

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    InMemorySessionStore,
    InMemoryTransport,
    OwnerIdentity,
    SessionMode,
    SessionState,
)
from fg_amp.envelope.envelope import EnvelopeType
from fg_amp.errors import SessionError


async def test_owner_mints_authorized_agent():
    owner = OwnerIdentity.generate("acme-corp")
    agent = owner.create_agent("acme-buyer", scopes={"converse", "negotiate"})
    assert agent.operator == owner.address
    scopes = agent.delegation_chain.verify(agent.address)
    assert scopes == frozenset({"converse", "negotiate"})


async def test_mutual_identity_verification_on_session():
    """Both sides learn the other's verified owner and scopes."""
    alice_owner = OwnerIdentity.generate("alice-org")
    bob_owner = OwnerIdentity.generate("bob-org")
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=alice_owner.create_agent("alice", {"converse", "negotiate"}))
    bob = AmpNode(
        identity=bob_owner.create_agent("bob", {"converse"}),
        policy=ContactPolicy.credentialed({"converse"}),
        on_session=on_session,
    )
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card)

    # initiator's view of the responder
    assert session.peer_owner == bob_owner.address
    assert session.peer_scopes == frozenset({"converse"})
    # responder's view of the initiator
    bob_session = inbound[0]
    assert bob_session.peer_owner == alice_owner.address
    assert bob_session.peer_scopes == frozenset({"converse", "negotiate"})

    bob_session.require_scope("negotiate")  # alice holds it
    with pytest.raises(SessionError, match="does not hold required scope"):
        session.require_scope("negotiate")  # bob does not
    assert session.has_scope("converse")


async def test_persist_and_resume_rotates_key_and_keeps_transcript():
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
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT, ttl_seconds=3600)
    await session.send_text("before restart")
    await inbound[0].receive(timeout=1)
    old_head = session.transcript.head
    assert old_head == inbound[0].transcript.head

    # both sides snapshot, then "restart" (records survive; keys do not)
    alice.persist_session(session)
    bob.persist_session(inbound[0])

    resumed = await alice.resume(session.session_id)
    assert resumed.state is SessionState.ESTABLISHED
    assert resumed.transcript.head == old_head  # transcript position carried over
    assert resumed.peer_card.address == bob.address

    # conversation continues where it left off, over the fresh key
    bob_resumed = inbound[1]
    await resumed.send_text("after restart")
    message = await bob_resumed.receive(timeout=1)
    assert message.payload.content == "after restart"
    assert message.seq == 2  # sequence numbers continued, not reset
    assert resumed.transcript.head == bob_resumed.transcript.head


async def test_stale_resume_accept_is_rejected_by_nonce(caplog):
    """A resume.accept captured from a prior attempt cannot be replayed into a
    later resume of the same session (session_id is stable): the fresh per-attempt
    nonce must match, so the replay is dropped and the pending resume stays open
    instead of resolving into a dead session key (audit blocker #2)."""
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
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    # Capture every resume.accept bob emits.
    captured_accepts = []
    real_deliver = transport.deliver

    async def capture(env):
        if env.type is EnvelopeType.RESUME_ACCEPT:
            captured_accepts.append(env)
        await real_deliver(env)

    transport.deliver = capture

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT, ttl_seconds=3600)
    alice.persist_session(session)
    bob.persist_session(inbound[0])

    # Attempt #1 completes normally; we now hold its genuine resume.accept.
    resumed1 = await alice.resume(session.session_id)
    assert resumed1.state is SessionState.ESTABLISHED
    stale_accept = captured_accepts[-1]

    # Set up attempt #2 with bob silenced, so alice has a fresh pending resume
    # (a new nonce) awaiting an accept.
    bob.detach()
    task2 = asyncio.create_task(alice.resume(session.session_id, timeout=1))
    await asyncio.sleep(0.05)
    assert session.session_id in alice._pending_resumes  # pending, awaiting accept

    # Replay attempt #1's accept into attempt #2: the nonce no longer matches.
    await alice._on_envelope(stale_accept)
    await asyncio.sleep(0.05)
    assert not task2.done()  # the replay did NOT resolve the resume

    task2.cancel()
    with pytest.raises((asyncio.CancelledError, SessionError, asyncio.TimeoutError)):
        await task2


async def test_duplicate_resume_accept_does_not_supersede_live_session():
    """A duplicated GENUINE resume-accept (same nonce — e.g. an at-least-once
    relay redelivering the same envelope) must not rebuild and supersede the
    already-resumed live session. The pending entry is consumed on the first
    nonce-matching accept, so the duplicate is a no-op (M6, resume path)."""
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
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    # Capture bob's resume.accept AND suppress its delivery, so alice keeps a
    # live pending resume awaiting the accept we now inject by hand.
    captured = []
    real_deliver = transport.deliver

    async def capture(env):
        if env.type is EnvelopeType.RESUME_ACCEPT:
            captured.append(env)
            return
        await real_deliver(env)

    transport.deliver = capture

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT, ttl_seconds=3600)
    alice.persist_session(session)
    bob.persist_session(inbound[0])

    task = asyncio.create_task(alice.resume(session.session_id, timeout=1))
    await asyncio.sleep(0.05)
    assert captured, "bob should have produced a resume-accept"
    assert session.session_id in alice._pending_resumes
    accept = captured[-1]

    # Deliver the genuine accept synchronously (no await lets resume()'s finally
    # interleave), so this exercises the handler's own consume, not the caller's.
    alice._handle_resume_accept(accept)
    assert session.session_id not in alice._pending_resumes  # consumed on nonce match
    live = alice.sessions[session.session_id]
    assert live.state is SessionState.ESTABLISHED

    # The duplicate must find no pending entry and change nothing.
    alice._handle_resume_accept(accept)
    assert alice.sessions[session.session_id] is live
    assert live.state is SessionState.ESTABLISHED

    resumed = await task
    assert resumed is live


async def test_resume_rejected_for_wrong_peer_or_state():
    alice = AmpNode(
        identity=AgentIdentity.generate("alice"), session_store=InMemorySessionStore()
    )
    bob = AmpNode(identity=AgentIdentity.generate("bob"), session_store=InMemorySessionStore())
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    record = alice.persist_session(session)
    # bob never persisted his side -> resume must be refused
    with pytest.raises(SessionError, match="no stored session"):
        await alice.resume(record.session_id)


async def test_persist_requires_persistent_mode():
    alice = AmpNode(
        identity=AgentIdentity.generate("alice"), session_store=InMemorySessionStore()
    )
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)
    session = await alice.initiate(bob.card)  # ephemeral
    with pytest.raises(ValueError, match="persistent"):
        alice.persist_session(session)


async def test_file_session_store_roundtrip(tmp_path):
    from fg_amp import FileSessionStore

    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(
        identity=AgentIdentity.generate("alice"),
        session_store=FileSessionStore(tmp_path / "alice"),
    )
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        session_store=FileSessionStore(tmp_path / "bob"),
        on_session=on_session,
    )
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    alice.persist_session(session)
    bob.persist_session(inbound[0])
    assert alice.session_store.list_ids() == [session.session_id]

    resumed = await alice.resume(session.session_id)
    assert resumed.state is SessionState.ESTABLISHED
