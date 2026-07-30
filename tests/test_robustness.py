"""Robustness hardening from the scored production audit."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    InMemorySessionStore,
    InMemoryTransport,
    SessionError,
    SessionMode,
)


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def test_out_of_order_frames_are_buffered_and_reordered():
    """A frame that arrives ahead of its predecessor is buffered, then both are
    delivered in order once the gap fills — instead of bricking the session."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card, ttl_seconds=60)
    bob_session = inbound[0]

    # capture the two ciphertext envelopes without delivering
    captured = []
    session._send_fn = lambda e: captured.append(e) or asyncio.sleep(0)
    await session.send_text("one")
    await session.send_text("two")
    assert [e.seq for e in captured] == [1, 2]

    # deliver seq 2 first (out of order), then seq 1
    await bob_session.handle_incoming(captured[1])
    assert bob_session.receive_nowait() is None  # buffered, nothing yet
    await bob_session.handle_incoming(captured[0])

    got = [bob_session.receive_nowait(), bob_session.receive_nowait()]
    assert [m.payload.content for m in got] == ["one", "two"]  # delivered in order


async def test_lost_frame_recovers_via_retransmit():
    """A frame dropped by the transport is recovered: the receiver NACKs the
    gap, the sender retransmits from its buffer, and delivery completes in order."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = InMemoryTransport()

    from fg_amp.envelope.envelope import EnvelopeType

    real_deliver = transport.deliver
    drop = {"done": False}

    async def lossy(envelope):
        # drop the FIRST delivery of message seq 1 to bob; pass retransmits
        if (
            envelope.to == bob.address
            and envelope.type is EnvelopeType.SESSION_MESSAGE
            and envelope.seq == 1
            and not drop["done"]
        ):
            drop["done"] = True
            return
        await real_deliver(envelope)

    transport.deliver = lossy
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, ttl_seconds=60)
    await session.send_text("one")  # dropped in flight
    await session.send_text("two")  # arrives, bob detects the gap and NACKs
    await asyncio.sleep(0.02)  # let the NACK + retransmit round-trip settle

    got = [inbound[0].receive_nowait(), inbound[0].receive_nowait()]
    assert [m.payload.content for m in got] == ["one", "two"]
    assert drop["done"] is True  # the drop really happened


def _receipt(sender_node, to_addr, session_id, rseq, ack, missing):
    from fg_amp.envelope.envelope import Envelope, EnvelopeType

    body = f'{{"rseq": {rseq}, "ack": {ack}, "missing": {missing}}}'.encode()
    return Envelope(
        type=EnvelopeType.RECEIPT,
        sender=sender_node.address,
        to=to_addr,
        session_id=session_id,
        body=Envelope.encode_body(body),
    ).signed(sender_node.identity.keys)


async def test_tail_loss_recovers_via_rto_timer():
    """A lone message lost in flight (no following frame to reveal the gap) is
    recovered by the sender's retransmit-on-timeout timer, not by a NACK."""
    from fg_amp.envelope.envelope import EnvelopeType

    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = InMemoryTransport()
    real = transport.deliver
    drop = {"done": False}

    async def lossy(envelope):
        if (
            envelope.to == bob.address
            and envelope.type is EnvelopeType.SESSION_MESSAGE
            and envelope.seq == 1
            and not drop["done"]
        ):
            drop["done"] = True
            return  # tail loss: the only message is dropped
        await real(envelope)

    transport.deliver = lossy
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, ttl_seconds=60)
    session.set_retransmit_interval(0.05)  # fast RTO for the test
    await session.send_text("lonely")  # dropped; no later frame to NACK it

    message = await inbound[0].receive(timeout=2)  # RTO fires, retransmits
    assert message.payload.content == "lonely"
    assert drop["done"] is True
    assert session.stats.retransmitted >= 1
    await session.close()


async def test_lost_ack_self_heals():
    """If a cumulative ACK is lost, a retransmit of the already-delivered frame
    re-triggers an ACK (rather than the sender retransmitting forever)."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    session.set_retransmit_interval(None)
    env = await session.send_text("m1")
    bob_session = inbound[0]
    await bob_session.receive(timeout=1)

    acks = []
    orig = bob_session._send_fn
    bob_session._send_fn = lambda e: acks.append(e) or orig(e)
    # simulate the sender's RTO replaying the frame after its ACK was lost
    await bob_session.handle_incoming(env)  # duplicate of delivered seq 1
    assert len(acks) == 1  # bob re-ACKs instead of ignoring silently


async def test_abandoned_session_expires_via_rto():
    """A session whose peer vanishes after a send is reaped by the RTO loop at
    TTL — the task and node reference don't leak."""
    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(alice, bob)
    session = await alice.initiate(bob.card, ttl_seconds=0.05)
    session.set_retransmit_interval(0.02)
    session._send_fn = lambda e: asyncio.sleep(0)  # peer vanished: sends go nowhere
    await session.send_text("into the void")  # arms the RTO loop
    assert session.session_id in alice.sessions

    # Past TTL the RTO loop reaps the session. Poll rather than sleeping a fixed
    # span: under full-suite CPU load the reaper's wakeups can be delayed, so a
    # single sleep(0.15) flakes while the eventual outcome is deterministic.
    for _ in range(200):
        await asyncio.sleep(0.02)
        if session.state.value == "expired":
            break
    assert session.state.value == "expired"
    assert session.session_id not in alice.sessions  # on_closed pruned it


async def test_never_sent_abandoned_session_is_reaped():
    """A session that establishes and then never sends or receives is still
    reaped at TTL by the maintenance loop armed at establishment."""
    reaped = []

    async def on_session(s):
        # short TTL + fast maintenance so the reaper fires quickly
        s.expires_at = s.created_at  # already at TTL
        s.set_retransmit_interval(0.02)
        reaped.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    await alice.initiate(bob.card)  # bob's side never sends/receives after this
    bob_session = reaped[0]
    await asyncio.sleep(0.1)
    assert bob_session.state.value == "expired"
    assert bob_session.session_id not in bob.sessions


async def test_replayed_receipt_dropped():
    """A captured RECEIPT replayed by the transport is dropped (monotonic rseq),
    so it cannot re-drive retransmit amplification."""
    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    session.set_retransmit_interval(None)  # no background timer

    # Capture sends so bob never receives/acks — the frame stays in the buffer.
    retransmits = []
    session._send_fn = lambda e: retransmits.append(e) or asyncio.sleep(0)
    await session.send_text("m1")  # seq 1 buffered, not delivered
    baseline = len(retransmits)

    receipt = _receipt(bob, alice.address, session.session_id, rseq=1, ack=0, missing=[1])
    await session.handle_incoming(receipt)  # processed: retransmits seq 1
    assert len(retransmits) == baseline + 1
    await session.handle_incoming(receipt)  # replay of rseq 1: dropped
    assert len(retransmits) == baseline + 1  # no additional retransmit
    assert session.stats.receipts_dropped == 1


async def test_unrecoverable_gap_closes_session():
    """A NACK for a frame already evicted from the send buffer closes the
    session deterministically instead of silently wedging the peer."""
    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    session.set_retransmit_interval(None)

    session._send_fn = lambda e: asyncio.sleep(0)  # capture: no acks come back
    await session.send_text("m1")
    await session.send_text("m2")
    session._send_buffer.clear()  # simulate eviction of old frames

    receipt = _receipt(bob, alice.address, session.session_id, rseq=1, ack=0, missing=[1])
    await session.handle_incoming(receipt)
    assert session.state.value == "closed"
    assert session.stats.unrecoverable_closes == 1


async def test_replayed_stale_seq_is_idempotent_noop():
    """A redelivered already-seen frame (at-least-once transport / ARQ) is a
    silent no-op, not an error and not a duplicate delivery."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card)
    env = await session.send_text("hi")
    await inbound[0].receive(timeout=1)
    await inbound[0].handle_incoming(env)  # replay of seq 1: no raise
    assert inbound[0].receive_nowait() is None  # not delivered twice


async def test_stale_handshake_rejected_by_freshness_window():
    from fg_amp.envelope.envelope import EnvelopeType
    from fg_amp.session.handshake import HandshakeInitiate

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(alice, bob)

    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    eph = X25519PrivateKey.generate()
    initiate = HandshakeInitiate(
        session_id="s",
        card=alice.card,
        ttl_ms=60_000,
        ephemeral_key=base64.b64encode(eph.public_key().public_bytes_raw()).decode(),
    )
    envelope = alice._sealed_envelope(EnvelopeType.HANDSHAKE_INITIATE, bob.card, "s", initiate)
    # backdate the signed envelope beyond the freshness window
    stale = envelope.model_copy(
        update={"created_at": datetime.now(UTC) - timedelta(seconds=600)}
    ).signed(alice.identity.keys)
    with pytest.raises(SessionError, match="freshness window"):
        await bob._on_envelope(stale)


async def test_duplicate_handshake_id_rejected_after_forget():
    """A captured initiate replayed verbatim is rejected even after the
    responder no longer holds the session (seen-envelope-id guard)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from fg_amp.envelope.envelope import EnvelopeType
    from fg_amp.session.handshake import HandshakeInitiate

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    connect(alice, bob)

    eph = X25519PrivateKey.generate()
    initiate = HandshakeInitiate(
        session_id="dup",
        card=alice.card,
        ttl_ms=60_000,
        ephemeral_key=base64.b64encode(eph.public_key().public_bytes_raw()).decode(),
    )
    envelope = alice._sealed_envelope(EnvelopeType.HANDSHAKE_INITIATE, bob.card, "dup", initiate)
    await bob._on_envelope(envelope)
    bob.sessions.clear()  # simulate the session being forgotten
    with pytest.raises(SessionError, match="replayed envelope id"):
        await bob._on_envelope(envelope)


def test_canonical_json_forbids_floats():
    from fg_amp.envelope.canonical import canonical_json

    canonical_json({"a": 1, "b": "x", "c": [1, 2]})  # ints/strings fine
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"ttl": 3600.0})
    with pytest.raises(ValueError, match="floats are not allowed"):
        canonical_json({"nested": [{"x": 1.5}]})


async def test_ttl_is_integer_on_the_wire():
    """The handshake carries ttl as integer milliseconds (no float in signed
    or salt-relevant payloads)."""
    from fg_amp.session.handshake import HandshakeInitiate

    init = HandshakeInitiate(session_id="s", card=AgentIdentity.generate("a").card(),
                             ttl_ms=1500, ephemeral_key="AA==")
    assert isinstance(init.model_dump()["ttl_ms"], int)
    assert init.ttl_seconds == 1.5
    init.transcript_salt()  # must not raise (no floats inside)


async def test_persistent_session_still_resumes_after_hardening():
    """Sanity: the salt-binding + ttl changes didn't break resume."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"), session_store=InMemorySessionStore())
    bob = AmpNode(identity=AgentIdentity.generate("bob"), session_store=InMemorySessionStore(),
                  on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card, mode=SessionMode.PERSISTENT)
    await session.send_text("before")
    await inbound[0].receive(timeout=1)
    alice.persist_session(session)
    bob.persist_session(inbound[0])
    resumed = await alice.resume(session.session_id)
    await resumed.send_text("after")
    assert (await inbound[1].receive(timeout=1)).payload.content == "after"
