"""Property-based fuzzing of the reorder + ARQ delivery state machine.

Invariant under an adversarial transport (arbitrary drop / reorder / duplicate,
with NACK-driven retransmit): the receiver delivers every message exactly once,
in the original order — or the session closes deterministically. It must never
deliver out of order, duplicate, or corrupt.
"""

from __future__ import annotations

import asyncio

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport
from fg_amp.envelope.envelope import EnvelopeType


class AdversarialTransport(InMemoryTransport):
    """Delays every message frame to the receiver into a controllable queue so
    the test can release them in any order, drop some, and duplicate some.
    Handshake, receipt, and close frames pass through immediately so the
    control loop (NACK/retransmit/close) still works."""

    def __init__(self, victim: str):
        super().__init__()
        self.victim = victim
        self.held: list = []  # queued SESSION_MESSAGE frames to the victim

    async def deliver(self, envelope) -> None:
        if envelope.to == self.victim and envelope.type is EnvelopeType.SESSION_MESSAGE:
            self.held.append(envelope)
            return
        await super().deliver(envelope)

    async def flush_one(self, index: int) -> None:
        if 0 <= index < len(self.held):
            env = self.held.pop(index)
            await super().deliver(env)


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    n_messages=st.integers(min_value=1, max_value=12),
    # a schedule of actions over the held queue: (kind, index_seed)
    schedule=st.lists(
        st.tuples(
            st.sampled_from(["release", "release", "release", "duplicate", "drop"]),
            st.integers(min_value=0, max_value=1000),
        ),
        min_size=0,
        max_size=60,
    ),
)
def test_arq_delivers_exactly_once_in_order(n_messages, schedule):
    asyncio.run(_run(n_messages, schedule))


async def _run(n_messages: int, schedule: list) -> None:
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = AdversarialTransport(victim="")
    # victim is bob's address; set after we know it
    transport.victim = bob.address
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, ttl_seconds=300)
    bob_session = inbound[0]
    # Drive retransmit deterministically instead of via the wall-clock timer.
    session.set_retransmit_interval(None)
    bob_session.set_retransmit_interval(None)

    expected = [f"m{i}" for i in range(n_messages)]
    for text in expected:
        await session.send_text(text)  # all held by the adversarial transport

    # Execute the adversarial schedule over the held queue.
    for kind, seed in schedule:
        if not transport.held:
            break
        idx = seed % len(transport.held)
        if kind == "release":
            await transport.flush_one(idx)
        elif kind == "duplicate":
            env = transport.held[idx]
            await transport._dispatch(transport._handlers[bob.address], env)  # deliver a copy
        elif kind == "drop":
            transport.held.pop(idx)  # transport loses it; ARQ must recover via NACK
        await asyncio.sleep(0)

    # Drain: release whatever remains, fire the sender's retransmit (recovers
    # tail loss that produces no NACK), and let acks settle. Dropped frames are
    # recovered because alice still holds them in her send buffer.
    for _ in range(n_messages * 4 + 4):
        while transport.held:
            await transport.flush_one(0)
        await session._retransmit_unacked()  # simulate the RTO timer firing
        while transport.held:
            await transport.flush_one(0)
        await asyncio.sleep(0)
        if bob_session.state.value != "established":
            break

    got = []
    while True:
        m = bob_session.receive_nowait()
        if m is None:
            break
        got.append(m.payload.content)

    if bob_session.state.value == "established":
        # No duplicates, correct order, and a prefix (or all) of expected —
        # everything delivered must match expected exactly at its position.
        assert got == expected[: len(got)], f"out-of-order/dup: {got} vs {expected}"
        # With retransmit and full drain, all should arrive.
        assert got == expected, f"incomplete: {got} vs {expected}"
    else:
        # Deterministic close is the only acceptable alternative to full delivery.
        assert got == expected[: len(got)], f"corrupt on close: {got}"
