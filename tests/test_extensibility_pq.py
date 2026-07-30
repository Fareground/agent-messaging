"""Wire extensibility (unknown-field-preserving signatures + capability
negotiation) and the hybrid post-quantum handshake."""


import pytest

from fg_amp import AgentIdentity, AmpNode, Envelope, EnvelopeType, InMemoryTransport
from fg_amp.capabilities import CAP_PQ_ML_KEM_768, CAP_RATCHET_DH_V1, negotiate
from fg_amp.crypto.pq import PQ_AVAILABLE
from fg_amp.errors import SignatureError

pytestmark = pytest.mark.skipif(not PQ_AVAILABLE, reason="ML-KEM not available")


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def _establish(a_caps=None, b_caps=None):
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"), capabilities=a_caps)
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"), on_session=on_session, capabilities=b_caps
    )
    connect(alice, bob)
    session = await alice.initiate(bob.card, ttl_seconds=60)
    return alice, bob, session, inbound[0]


# -- capability negotiation ------------------------------------------------


async def test_pq_negotiated_by_default_and_messages_flow():
    _, _, s, bs = await _establish()
    assert CAP_PQ_ML_KEM_768 in s.capabilities
    assert s.capabilities == bs.capabilities  # both sides agree on the set
    await s.send_text("hybrid hello")
    assert (await bs.receive(timeout=1)).payload.content == "hybrid hello"


async def test_classical_fallback_when_one_peer_lacks_pq():
    # bob only supports the baseline ratchet; PQ must NOT be negotiated.
    _, _, s, bs = await _establish(b_caps=(CAP_RATCHET_DH_V1,))
    assert CAP_PQ_ML_KEM_768 not in s.capabilities
    assert CAP_PQ_ML_KEM_768 not in bs.capabilities
    await s.send_text("classical still works")
    assert (await bs.receive(timeout=1)).payload.content == "classical still works"


async def test_negotiate_is_sorted_intersection():
    assert negotiate(("b", "a", "z"), ("a", "b")) == ("a", "b")
    assert negotiate(("a",), ("b",)) == ()


def test_with_pq_gate_reflects_actual_exchange():
    """`session.capabilities` gate: the PQ token is present iff a KEM secret was
    really exchanged, never merely because both peers advertised the token."""
    from fg_amp.node.node import _with_pq

    assert CAP_PQ_ML_KEM_768 in _with_pq((CAP_RATCHET_DH_V1, CAP_PQ_ML_KEM_768), True)
    # advertised but not exchanged -> token dropped
    assert CAP_PQ_ML_KEM_768 not in _with_pq((CAP_RATCHET_DH_V1, CAP_PQ_ML_KEM_768), False)
    assert _with_pq((CAP_RATCHET_DH_V1,), True)[:1] == (CAP_RATCHET_DH_V1,)


async def test_pq_capability_not_claimed_without_key_material(monkeypatch):
    """Both peers advertise the PQ token but no KEM secret is exchanged (no
    backend / no key): neither session may claim PQ is in force, or an app gating
    on it gets a false 'hybrid-secure' signal over a purely-classical key."""
    import fg_amp.crypto.pq as pqmod
    import fg_amp.node.node as nodemod

    # Force the token to be advertised while KEM material is never produced.
    monkeypatch.setattr(nodemod.pqkem, "PQ_AVAILABLE", False)
    monkeypatch.setattr(pqmod, "PQ_AVAILABLE", False)

    inbound = []

    async def on_session(s):
        inbound.append(s)

    caps = (CAP_RATCHET_DH_V1, CAP_PQ_ML_KEM_768)
    alice = AmpNode(identity=AgentIdentity.generate("alice"), capabilities=caps)
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session, capabilities=caps)
    connect(alice, bob)

    session = await alice.initiate(bob.card, ttl_seconds=60)
    bob_session = inbound[0]
    assert CAP_PQ_ML_KEM_768 not in session.capabilities
    assert CAP_PQ_ML_KEM_768 not in bob_session.capabilities


async def test_pq_survives_resume():
    from fg_amp import InMemorySessionStore, SessionMode

    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"), session_store=InMemorySessionStore())
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        session_store=InMemorySessionStore(),
        on_session=on_session,
    )
    connect(alice, bob)
    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT, ttl_seconds=3600)
    alice.persist_session(session)
    bob.persist_session(inbound[0])

    assert CAP_PQ_ML_KEM_768 in session.capabilities  # original was hybrid
    resumed = await alice.resume(session.session_id)
    bob_resumed = inbound[1]
    # The resumed session key is hybrid too: messages still decrypt across it,
    # AND session.capabilities correctly reports PQ (re-derived at resume) rather
    # than blanking to frozenset().
    assert CAP_PQ_ML_KEM_768 in resumed.capabilities
    assert CAP_PQ_ML_KEM_768 in bob_resumed.capabilities
    await resumed.send_text("after resume, still hybrid")
    assert (await bob_resumed.receive(timeout=1)).payload.content == "after resume, still hybrid"


# -- unknown-field-preserving signatures -----------------------------------


async def test_additive_envelope_field_preserves_signature():
    """A newer peer that signs an envelope carrying an unknown field verifies on
    an older parser (the field is preserved and included in canonicalization),
    and tampering after signing is still detected."""
    alice = AgentIdentity.generate("alice")
    env = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=alice.address,
        to=alice.address,
        session_id="s",
        body=Envelope.encode_body(b"{}"),
    )
    wire = env.to_wire()
    wire["future_ext"] = {"feature": "x"}  # a field this version doesn't know
    signed = Envelope.from_wire(wire).signed(alice.keys)  # newer signer includes it

    parsed = Envelope.from_wire(signed.to_wire())
    parsed.verify_signature()  # older parser verifies despite the unknown field
    assert parsed.model_dump().get("future_ext") == {"feature": "x"}

    # Tamper: add a field AFTER signing -> canonicalization differs -> rejected.
    tampered = dict(signed.to_wire())
    tampered["injected"] = "evil"
    with pytest.raises(SignatureError):
        Envelope.from_wire(tampered).verify_signature()


async def test_additive_card_field_preserves_signature():
    """A card signed by a newer peer with an extra field verifies on an older
    parser, because the signature covers the full canonical model including
    unknown fields (extra='allow')."""
    from fg_agent_id.signing import CONTEXT_AGENT_CARD, sign_payload

    from fg_amp.identity.card import AgentCard

    ident = AgentIdentity.generate("carol")
    base_card = AgentCard.create(ident.keys, ident.address, "carol")

    # Newer signer: inject an unknown field and re-sign over the full payload.
    fields = {k: v for k, v in base_card.model_dump().items() if k != "signature"}
    fields["future_meta"] = "some-new-field"
    unsigned = AgentCard.model_validate(fields)
    sig = sign_payload(ident.keys, CONTEXT_AGENT_CARD, unsigned._payload())
    newer = unsigned.model_copy(update={"signature": sig})

    parsed = AgentCard.model_validate(newer.model_dump())
    parsed.verify()  # older parser verifies despite the unknown field
    assert parsed.model_dump().get("future_meta") == "some-new-field"
