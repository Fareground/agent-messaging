"""Witnessed session posture (SPEC §7.1): negotiation, copies, sealed default."""

import base64

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    InMemoryTransport,
    PolicyRejection,
    Session,
    WitnessedMessage,
    WitnessError,
    WitnessReceiver,
    WitnessSpec,
)
from fg_amp.capabilities import CAP_WITNESSED_V1
from fg_amp.envelope.envelope import Envelope, EnvelopeType
from fg_amp.errors import ConfigurationError, SessionError
from fg_amp.session.witness import build_witness_copy


def make_node(name: str, **kwargs) -> AmpNode:
    return AmpNode(identity=AgentIdentity.generate(name), **kwargs)


def make_witness(name: str = "auditor") -> tuple[AgentIdentity, WitnessReceiver]:
    identity = AgentIdentity.generate(name)
    return identity, WitnessReceiver(identity.keys, identity.address)


def connect(*nodes: AmpNode) -> InMemoryTransport:
    transport = InMemoryTransport()
    for node in nodes:
        node.attach(transport)
    return transport


async def establish(alice: AmpNode, bob_kwargs: dict, witness_node: AmpNode | None = None):
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    bob = make_node("bob", on_session=on_session, **bob_kwargs)
    nodes = [alice, bob] + ([witness_node] if witness_node else [])
    connect(*nodes)
    session = await alice.initiate(bob.card, ttl_seconds=60)
    return session, inbound[0], bob


# -- negotiation ---------------------------------------------------------


async def test_both_offer_same_witness_activates_witnessed_mode():
    _, receiver = make_witness()
    spec = receiver.spec()
    alice = make_node("alice", witness=spec)
    session, bob_session, _ = await establish(alice, {"witness": spec})
    assert CAP_WITNESSED_V1 in session.capabilities
    assert CAP_WITNESSED_V1 in bob_session.capabilities
    assert session.witness == spec
    assert bob_session.witness == spec


async def test_one_sided_offer_falls_back_to_sealed():
    _, receiver = make_witness()
    alice = make_node("alice", witness=receiver.spec())
    session, bob_session, _ = await establish(alice, {})
    assert CAP_WITNESSED_V1 not in session.capabilities
    assert session.witness is None
    assert bob_session.witness is None
    # sealed behavior is exactly today's: sends emit no witness copy
    transport_deliveries: list[Envelope] = []
    original = session._send_fn

    async def spy(envelope):
        transport_deliveries.append(envelope)
        await original(envelope)

    session._send_fn = spy
    await session.send_text("plain sealed message")
    assert [e.type for e in transport_deliveries] == [EnvelopeType.SESSION_MESSAGE]


async def test_witness_mismatch_rejects_handshake():
    _, receiver_a = make_witness("auditor-a")
    _, receiver_b = make_witness("auditor-b")
    alice = make_node("alice", witness=receiver_a.spec())
    bob = make_node("bob", witness=receiver_b.spec())
    connect(alice, bob)
    with pytest.raises(PolicyRejection, match="witness mismatch"):
        await alice.initiate(bob.card, ttl_seconds=60)


async def test_capability_without_witness_config_is_refused():
    with pytest.raises(ConfigurationError, match="requires a witness"):
        make_node("alice", capabilities=("amp.ratchet.dh-v1", CAP_WITNESSED_V1))


# -- witness copies ------------------------------------------------------


async def test_witness_copy_decryptable_by_witness_and_bound_to_seq():
    witness_node = make_node("carol")
    receiver = WitnessReceiver(witness_node.identity.keys, witness_node.address)
    spec = receiver.spec()
    # route copies delivered to the witness's address into the receiver
    witness_node.on_witness_copy = receiver.handle

    alice = make_node("alice", witness=spec)
    session, bob_session, _ = await establish(alice, {"witness": spec}, witness_node)

    await session.send_text("audited hello")
    await bob_session.send_json({"reply": True})

    first = await receiver.receive(timeout=1)
    second = await receiver.receive(timeout=1)
    assert first.session_id == session.session_id
    assert first.seq == 1 and first.sender == alice.address
    assert first.payload["content"] == "audited hello"
    assert second.seq == 1  # per-sender seq: bob's first frame
    assert second.payload["content"] == {"reply": True}
    # the receiving peer still got the message normally
    assert (await bob_session.receive(timeout=1)).payload.content == "audited hello"


async def test_witness_copy_rejects_spliced_seq():
    witness_identity, receiver = make_witness()
    spec = receiver.spec()
    sender = AgentIdentity.generate("mallory-relay-victim")
    copy = build_witness_copy(
        spec, sender.keys, sender.address, "session-1", 3,
        {"content_type": "text/plain", "content": "hi", "metadata": {}},
    )
    # a relay re-wrapping the sealed body under different routing metadata
    # cannot re-sign, and a re-signed envelope no longer matches the inner
    forged = copy.model_copy(update={"seq": 4}).signed(sender.keys)
    with pytest.raises(WitnessError, match="does not match its signed envelope"):
        receiver.open_copy(forged)
    # untampered copy opens fine
    opened = receiver.open_copy(copy)
    assert isinstance(opened, WitnessedMessage)
    assert (opened.session_id, opened.seq) == ("session-1", 3)


async def test_witness_copy_not_decryptable_by_others():
    _, receiver = make_witness()
    spec = receiver.spec()
    sender = AgentIdentity.generate("sender")
    copy = build_witness_copy(
        spec, sender.keys, sender.address, "s", 1,
        {"content_type": "text/plain", "content": "secret", "metadata": {}},
    )
    # ciphertext to everyone but the witness: another identity cannot open it
    _, other_receiver = make_witness("not-the-witness")
    with pytest.raises(WitnessError, match="not sealed to this witness"):
        other_receiver.open_copy(copy)
    # and the wire body carries no plaintext
    assert b"secret" not in base64.b64decode(copy.body)


async def test_refuses_to_send_when_copy_cannot_be_produced():
    _, receiver = make_witness()
    spec = receiver.spec()
    alice = make_node("alice", witness=spec)
    session, bob_session, _ = await establish(alice, {"witness": spec})
    # sabotage the witness key so sealing fails
    session.witness = WitnessSpec(address=spec.address, agreement_key="3")  # 1 byte
    with pytest.raises(SessionError, match="cannot produce its witness copy"):
        await session.send_text("must not leave")
    # nothing reached the peer, and seq was not burned: a later good send works
    session.witness = spec
    await session.send_text("after recovery")
    message = await bob_session.receive(timeout=1)
    assert message.payload.content == "after recovery"
    assert message.seq == 1


async def test_witnessed_posture_survives_resume():
    from fg_amp import InMemorySessionStore, SessionMode, SessionState

    _, receiver = make_witness()
    spec = receiver.spec()
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = make_node("alice", witness=spec, session_store=InMemorySessionStore())
    bob = make_node(
        "bob", witness=spec, on_session=on_session, session_store=InMemorySessionStore()
    )
    connect(alice, bob)
    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT, ttl_seconds=60)
    await session.send_text("before resume")
    await inbound[0].receive(timeout=1)
    alice.persist_session(session)
    bob.persist_session(inbound[0])
    session.cancel_maintenance()
    inbound[0].cancel_maintenance()
    session.state = inbound[0].state = SessionState.CLOSED

    resumed = await alice.resume(session.session_id)
    assert resumed.witness == spec
    assert CAP_WITNESSED_V1 in resumed.capabilities
    assert inbound[-1].witness == spec


async def test_node_without_handler_refuses_witness_copies():
    node = make_node("not-a-witness")
    policy_ok_node = make_node("sender")
    connect(node, policy_ok_node)
    copy = build_witness_copy(
        WitnessSpec(
            address=node.address,
            agreement_key=node.identity.keys.public.agreement_b58,
        ),
        policy_ok_node.identity.keys,
        policy_ok_node.address,
        "s",
        1,
        {"content_type": "text/plain", "content": "x", "metadata": {}},
    )
    with pytest.raises(SessionError, match="no witness handler"):
        await node._on_envelope(copy)


async def test_sealed_default_unchanged_without_witness_anywhere():
    alice = make_node("alice")
    session, bob_session, _ = await establish(alice, {})
    assert session.witness is None
    assert CAP_WITNESSED_V1 not in session.capabilities
    await session.send_text("no auditors here")
    assert (await bob_session.receive(timeout=1)).payload.content == "no auditors here"
