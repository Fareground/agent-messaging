"""The critical seam: DH ratchet turns UNDER loss/reorder/duplication.

The ARQ fuzzer is one-directional (no DH turns) and the ratchet fuzzer runs
over an in-order FIFO. This joins them: both parties send (so direction turns
happen), an adversarial transport drops/reorders/duplicates message frames in
BOTH directions, and ARQ (NACK + manual retransmit) must still deliver every
message exactly once, in order, on each side — or the session closes
deterministically. This is where a subtle ratchet-vs-reorder bug would live.
"""

from __future__ import annotations

import asyncio

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport
from fg_amp.envelope.envelope import EnvelopeType


class BiAdversarialTransport(InMemoryTransport):
    """Holds SESSION_MESSAGE frames (both directions) in a controllable queue;
    control frames (handshake/receipt/close) pass through so ARQ still works."""

    def __init__(self):
        super().__init__()
        self.held: list = []

    async def deliver(self, envelope) -> None:
        if envelope.type is EnvelopeType.SESSION_MESSAGE:
            self.held.append(envelope)
            return
        await super().deliver(envelope)

    async def release(self, idx: int) -> None:
        if 0 <= idx < len(self.held):
            await super().deliver(self.held.pop(idx))

    async def duplicate(self, idx: int) -> None:
        if 0 <= idx < len(self.held):
            env = self.held[idx]
            await super()._dispatch(self._handlers[env.to], env)

    def drop(self, idx: int) -> None:
        if 0 <= idx < len(self.held):
            self.held.pop(idx)


async def test_explicit_dh_turn_with_dropped_frame_straddling_it():
    """Concrete seam: a lost frame from the OLD chain, retransmitted after the
    receiver already holds a NEW-chain (post-turn) frame, must still decode in
    order — the ratchet must not have advanced past the gap."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = BiAdversarialTransport()
    alice.attach(transport)
    bob.attach(transport)

    a = await alice.initiate(bob.card, ttl_seconds=600)
    a.set_retransmit_interval(None)
    b = inbound[0]
    b.set_retransmit_interval(None)

    # a sends a1, a2 (chain A). Deliver a1 only so bob can reply (a turn).
    await a.send_text("a1")
    await a.send_text("a2")
    a1 = transport.held[0]
    dh_a = a1.body_bytes[:32]
    await transport.release(0)  # deliver a1
    await b.receive(timeout=1)
    transport.held.clear()  # drop a2 for now (still in a's send buffer)

    # bob replies b1 (its send triggers/uses a chain); deliver it so ALICE turns
    await b.send_text("b1")
    while transport.held:
        await transport.release(0)
    await a.receive(timeout=1)

    # a sends a3 AFTER receiving b1 → a ratchets to a NEW DH key (post-turn)
    await a.send_text("a3")
    a3 = transport.held[-1]
    assert a3.body_bytes[:32] != dh_a  # confirms a genuine DH turn happened

    # Bob currently expects a2 (old chain). Deliver a3 (new chain) FIRST — it must
    # buffer (gap at a2), not decode ahead of the turn.
    await transport.release(len(transport.held) - 1)
    assert b.receive_nowait() is None  # a3 buffered, ratchet NOT advanced

    # retransmit the dropped a2 (old chain) — must still decode, then a3 follows
    await a._retransmit_unacked()
    while transport.held:
        await transport.release(0)

    got = []
    while (m := b.receive_nowait()) is not None:
        got.append(m.payload.content)
    assert got == ["a2", "a3"]  # old-chain a2 then new-chain a3, in order


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    ops=st.lists(
        st.one_of(
            st.tuples(st.just("send_a"), st.none()),
            st.tuples(st.just("send_b"), st.none()),
            st.tuples(st.just("release"), st.integers(0, 999)),
            st.tuples(st.just("reorder_release"), st.integers(0, 999)),
            st.tuples(st.just("duplicate"), st.integers(0, 999)),
            st.tuples(st.just("drop"), st.integers(0, 999)),
        ),
        min_size=1,
        max_size=40,
    )
)
def test_ratchet_survives_loss_and_reorder_both_directions(ops):
    asyncio.run(_run(ops))


async def _run(ops) -> None:
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = BiAdversarialTransport()
    alice.attach(transport)
    bob.attach(transport)

    a = await alice.initiate(bob.card, ttl_seconds=600)
    a.set_retransmit_interval(None)  # drive retransmit deterministically
    b = inbound[0]
    b.set_retransmit_interval(None)

    a_sent: list[str] = []  # what bob should receive
    b_sent: list[str] = []  # what alice should receive
    counter = 0

    for kind, arg in ops:
        if kind == "send_a":
            text = f"a{counter}"
            counter += 1
            await a.send_text(text)
            a_sent.append(text)
        elif kind == "send_b":
            text = f"b{counter}"
            counter += 1
            await b.send_text(text)
            b_sent.append(text)
        elif kind == "release" and transport.held:
            await transport.release(arg % len(transport.held))
        elif kind == "reorder_release" and transport.held:
            # release the most-recently-held frame to force out-of-order arrival
            await transport.release(len(transport.held) - 1)
        elif kind == "duplicate" and transport.held:
            await transport.duplicate(arg % len(transport.held))
        elif kind == "drop" and transport.held:
            transport.drop(arg % len(transport.held))
        await asyncio.sleep(0)

    # Drain: release everything, fire both sides' retransmit (recovers tail loss
    # + NACK-driven gaps), repeat until quiescent or a session closes.
    for _ in range(len(ops) * 3 + 8):
        while transport.held:
            await transport.release(0)
        await a._retransmit_unacked()
        await b._retransmit_unacked()
        while transport.held:
            await transport.release(0)
        await asyncio.sleep(0)
        if a.state.value != "established" or b.state.value != "established":
            break

    got_by_bob = []
    while (m := b.receive_nowait()) is not None:
        got_by_bob.append(m.payload.content)
    got_by_alice = []
    while (m := a.receive_nowait()) is not None:
        got_by_alice.append(m.payload.content)

    if a.state.value == "established" and b.state.value == "established":
        assert got_by_bob == a_sent, f"a->b mismatch: {got_by_bob} vs {a_sent}"
        assert got_by_alice == b_sent, f"b->a mismatch: {got_by_alice} vs {b_sent}"
    else:
        # deterministic close is acceptable; whatever was delivered must be a
        # correct in-order prefix (no dup, no reorder, no corruption)
        assert got_by_bob == a_sent[: len(got_by_bob)]
        assert got_by_alice == b_sent[: len(got_by_alice)]
