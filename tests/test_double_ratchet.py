"""Double-ratchet: DH rotation (post-compromise security), many-turn sync,
both-can-send-first, and bidirectional adversarial delivery."""

from __future__ import annotations

import asyncio

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def _pair():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    a = await alice.initiate(bob.card, ttl_seconds=300)
    a.set_retransmit_interval(None)
    b = inbound[0]
    b.set_retransmit_interval(None)
    return a, b


async def test_dh_key_rotates_on_direction_turn():
    """The header DH public key advances after a direction turn — proof that a
    fresh DH secret is mixed into the root (post-compromise security)."""
    a, b = await _pair()

    env1 = await a.send_text("a1")
    dh_a1 = env1.body_bytes[:32]
    await b.receive(timeout=1)

    # b replies (direction turn) then a replies again — a's DH key must change.
    await b.send_text("b1")
    await a.receive(timeout=1)
    env2 = await a.send_text("a2")
    dh_a2 = env2.body_bytes[:32]
    assert dh_a2 != dh_a1  # a ratcheted its DH key after receiving from b


async def test_same_chain_keeps_dh_until_turn():
    """Consecutive sends without an intervening receive keep the same DH key
    (chain-key ratchet), so we don't pay a DH per message."""
    a, b = await _pair()
    e1 = await a.send_text("m1")
    e2 = await a.send_text("m2")
    assert e1.body_bytes[:32] == e2.body_bytes[:32]  # same chain, same DH header
    m1 = await b.receive(timeout=1)
    m2 = await b.receive(timeout=1)
    assert (m1.payload.content, m2.payload.content) == ("m1", "m2")


async def test_responder_can_send_first():
    """AMP allows the responder to speak first — the double ratchet must not
    block that (vanilla Signal would)."""
    a, b = await _pair()
    await b.send_text("greetings from the responder")
    msg = await a.receive(timeout=1)
    assert msg.payload.content == "greetings from the responder"
    # and the conversation continues normally afterward
    await a.send_text("hello back")
    assert (await b.receive(timeout=1)).payload.content == "hello back"


async def test_many_turn_pingpong_stays_in_sync():
    a, b = await _pair()
    for i in range(25):
        sender, receiver, label = (a, b, f"a{i}") if i % 2 == 0 else (b, a, f"b{i}")
        await sender.send_text(label)
        got = await receiver.receive(timeout=1)
        assert got.payload.content == label


async def test_simultaneous_first_sends_both_deliver():
    """Both sides send before receiving — the ratchet must not diverge."""
    a, b = await _pair()
    await a.send_text("from-a")
    await b.send_text("from-b")
    assert (await b.receive(timeout=1)).payload.content == "from-a"
    assert (await a.receive(timeout=1)).payload.content == "from-b"
    # keep going after the simultaneous open
    await a.send_text("a-again")
    assert (await b.receive(timeout=1)).payload.content == "a-again"


def _ratchet_pair():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from fg_amp.session.ratchet import DoubleRatchet

    session_key = b"S" * 32
    bob_eph = X25519PrivateKey.generate()
    alice = DoubleRatchet.initiator(session_key, bob_eph.public_key().public_bytes_raw())
    bob = DoubleRatchet.responder(session_key, bob_eph)
    return alice, bob


def _xfer(sender, receiver):
    """One message sender->receiver at the raw ratchet layer; assert keys agree."""
    dh, mk = sender.encrypt_step()
    mk2, apply = receiver.decrypt_prepare(dh)
    apply()
    assert mk2 == mk
    return mk


def test_ratchet_simultaneous_first_sends_no_divergence():
    """Both encrypt from initial state before either receives; each side then
    decrypts the other's first frame with a matching key (root doesn't diverge)."""
    alice, bob = _ratchet_pair()
    dh_a, mk_a = alice.encrypt_step()   # a's first, before receiving
    dh_b, mk_b = bob.encrypt_step()     # b's first, before receiving
    mk_a2, apply_a = bob.decrypt_prepare(dh_a)
    apply_a()
    mk_b2, apply_b = alice.decrypt_prepare(dh_b)
    apply_b()
    assert mk_a2 == mk_a and mk_b2 == mk_b
    # continue several turns, keys must keep agreeing
    for _ in range(6):
        _xfer(alice, bob)
        _xfer(bob, alice)


def test_ratchet_same_direction_burst_shares_chain():
    """A burst of same-direction sends stays on one DH key (chain-key ratchet);
    the receiver decrypts them all in order with matching keys."""
    alice, bob = _ratchet_pair()
    headers = []
    keys = []
    for _ in range(5):
        dh, mk = alice.encrypt_step()
        headers.append(dh)
        keys.append(mk)
    assert len(set(headers)) == 1        # one DH key for the whole burst
    assert len(set(keys)) == 5           # but a fresh message key each
    for dh, mk in zip(headers, keys, strict=True):
        mk2, apply = bob.decrypt_prepare(dh)
        apply()
        assert mk2 == mk


def test_ratchet_rejects_low_order_point():
    import pytest

    alice, _ = _ratchet_pair()
    # An all-zero X25519 point yields a degenerate/zero shared secret; it must be
    # rejected (either by the library's own low-order guard or our zero-output
    # check), never mixed into the root.
    with pytest.raises(ValueError):
        alice.decrypt_prepare(b"\x00" * 32)


@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    turns=st.lists(
        st.tuples(st.sampled_from(["a", "b"]), st.integers(min_value=1, max_value=3)),
        min_size=1,
        max_size=25,
    )
)
def test_bidirectional_ratchet_property(turns):
    """Random interleaving of who-sends and how-many: every message decrypts to
    the exact plaintext in order on the receiving side."""
    asyncio.run(_run_bidirectional(turns))


async def _run_bidirectional(turns) -> None:
    a, b = await _pair()
    a_expect: list[str] = []  # what b should receive from a
    b_expect: list[str] = []  # what a should receive from b
    counter = 0
    for who, n in turns:
        for _ in range(n):
            text = f"{who}{counter}"
            counter += 1
            if who == "a":
                await a.send_text(text)
                a_expect.append(text)
            else:
                await b.send_text(text)
                b_expect.append(text)
        await asyncio.sleep(0)

    got_from_a = []
    while (m := b.receive_nowait()) is not None:
        got_from_a.append(m.payload.content)
    got_from_b = []
    while (m := a.receive_nowait()) is not None:
        got_from_b.append(m.payload.content)

    assert got_from_a == a_expect
    assert got_from_b == b_expect
