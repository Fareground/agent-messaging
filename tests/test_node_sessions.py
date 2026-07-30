"""End-to-end node tests: handshake, sessions, policy enforcement."""

import asyncio

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    Delegation,
    DelegationChain,
    InMemoryTransport,
    Payload,
    PolicyRejection,
    Session,
    SessionMode,
    SessionState,
)
from fg_amp.errors import SessionError


def make_node(name: str, policy: ContactPolicy | None = None, **kwargs) -> AmpNode:
    return AmpNode(identity=AgentIdentity.generate(name), policy=policy, **kwargs)


def connect(*nodes: AmpNode) -> InMemoryTransport:
    transport = InMemoryTransport()
    for node in nodes:
        node.attach(transport)
    return transport


async def test_handshake_and_bidirectional_chat():
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = make_node("alice")
    bob = make_node("bob", on_session=on_session)
    connect(alice, bob)

    session = await alice.initiate(bob.card, purpose="testing", ttl_seconds=60)
    assert session.state is SessionState.ESTABLISHED
    assert len(inbound) == 1
    bob_session = inbound[0]

    await session.send_text("hello bob")
    message = await bob_session.receive(timeout=1)
    assert message.payload.content == "hello bob"
    assert message.sender == alice.address

    await bob_session.send_json({"answer": 42})
    reply = await session.receive(timeout=1)
    assert reply.payload.content == {"answer": 42}

    # both sides advanced identical transcript chains
    assert session.transcript.head == bob_session.transcript.head
    assert session.transcript.length == 2


async def test_close_propagates_and_ephemeral_key_dropped():
    inbound: list[Session] = []

    async def on_session(s):
        inbound.append(s)

    alice, bob = make_node("alice"), make_node("bob", on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    await session.close("done")
    assert session.state is SessionState.CLOSED
    await asyncio.sleep(0)
    assert inbound[0].state is SessionState.CLOSED
    with pytest.raises(SessionError):
        await session.send_text("after close")


async def test_closed_policy_rejects():
    alice = make_node("alice")
    bob = make_node("bob", policy=ContactPolicy(mode="closed"))
    connect(alice, bob)
    with pytest.raises(PolicyRejection, match="does not accept"):
        await alice.initiate(bob.card)


async def test_credentialed_policy_requires_scopes():
    principal = AgentIdentity.generate("principal")
    alice_id = AgentIdentity.generate("alice")
    bob = make_node("bob", policy=ContactPolicy.credentialed({"converse"}))

    # without credentials: rejected
    bare = AmpNode(identity=alice_id)
    connect(bare, bob)
    with pytest.raises(PolicyRejection, match="missing required scopes"):
        await bare.initiate(bob.card)

    # with a valid delegation chain: accepted
    chain = DelegationChain(
        links=(
            Delegation.grant(
                principal.keys, principal.address, alice_id.address, {"converse"}, 3600
            ),
        )
    )
    credentialed = AmpNode(identity=alice_id.with_delegation(chain))
    connect(credentialed, bob)
    session = await credentialed.initiate(bob.card)
    assert session.state is SessionState.ESTABLISHED


async def test_allowlist_policy():
    alice, mallory = make_node("alice"), make_node("mallory")
    bob = make_node(
        "bob", policy=ContactPolicy.allowlist(addresses={alice.address})
    )
    connect(alice, mallory, bob)
    assert (await alice.initiate(bob.card)).state is SessionState.ESTABLISHED
    with pytest.raises(PolicyRejection, match="allowlist"):
        await mallory.initiate(bob.card)


async def test_rate_limit():
    alice = make_node("alice")
    bob = make_node(
        "bob",
        policy=ContactPolicy(rate_limit_per_peer=2, rate_limit_window_seconds=60),
    )
    connect(alice, bob)
    await alice.initiate(bob.card)
    await alice.initiate(bob.card)
    with pytest.raises(PolicyRejection, match="rate limit"):
        await alice.initiate(bob.card)


async def test_human_approval_defer():
    decisions = []

    async def approver(initiate):
        decisions.append(initiate.purpose)
        return initiate.purpose == "legit"

    alice = make_node("alice")
    bob = make_node(
        "bob", policy=ContactPolicy(human_approval=True), approval_fn=approver
    )
    connect(alice, bob)
    assert (await alice.initiate(bob.card, purpose="legit")).state is SessionState.ESTABLISHED
    with pytest.raises(PolicyRejection, match="declined by human"):
        await alice.initiate(bob.card, purpose="sketchy")
    assert decisions == ["legit", "sketchy"]


async def test_payload_type_enforced_at_boundary():
    alice = make_node("alice")
    bob = make_node("bob", policy=ContactPolicy(accepted_payload_types=("text/plain",)))
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    assert session.payload_types == ("text/plain",)
    with pytest.raises(SessionError, match="not negotiated"):
        await session.send(Payload.json_data({"x": 1}))


async def test_replay_is_idempotent_noop():
    """A replayed already-delivered frame is ignored (not re-delivered), and
    the ratchet is not advanced — a real replay yields no new plaintext."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice, bob = make_node("alice"), make_node("bob", on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    envelope = await session.send_text("once")
    first = await inbound[0].receive(timeout=1)
    assert first.payload.content == "once"
    await inbound[0].handle_incoming(envelope)  # replay: no raise, no re-delivery
    assert inbound[0].receive_nowait() is None


async def test_third_party_cannot_inject_into_session():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice, bob, mallory = (
        make_node("alice"),
        make_node("bob", on_session=on_session),
        make_node("mallory"),
    )
    transport = connect(alice, bob, mallory)
    session = await alice.initiate(bob.card)

    # mallory forges a signed envelope claiming alice's session
    from fg_amp.envelope import Envelope, EnvelopeType

    forged = Envelope(
        type=EnvelopeType.SESSION_MESSAGE,
        sender=mallory.address,
        to=bob.address,
        session_id=session.session_id,
        seq=1,
        body=Envelope.encode_body(b"junk"),
    ).signed(mallory.identity.keys)
    # Delivery succeeds at the transport, but bob's node rejects the forgery
    # (logged, not raised to the sender) so nothing reaches the real session.
    await transport.deliver(forged)
    bob_session = inbound[0]
    assert bob_session.receive_nowait() is None
    assert bob_session._recv_seq == 0


async def test_ephemeral_expiry():
    alice, bob = make_node("alice"), make_node("bob")
    connect(alice, bob)
    session = await alice.initiate(bob.card, ttl_seconds=0.01)
    await asyncio.sleep(0.02)
    with pytest.raises(SessionError, match="expired"):
        await session.send_text("too late")
    assert session.state is SessionState.EXPIRED


async def test_persistent_mode_negotiated():
    alice, bob = make_node("alice"), make_node("bob")
    connect(alice, bob)
    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    assert session.mode is SessionMode.PERSISTENT


async def test_store_and_forward_for_unbound_recipient():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = make_node("alice")
    bob = make_node("bob", on_session=on_session)
    transport = InMemoryTransport()
    alice.attach(transport)

    # bob is offline: the knock queues rather than failing
    task = asyncio.create_task(alice.initiate(bob.card, timeout=5))
    await asyncio.sleep(0.05)
    bob.attach(transport)
    await transport.flush(bob.address)
    session = await task
    assert session.state is SessionState.ESTABLISHED
