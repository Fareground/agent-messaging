"""Regression tests for concurrency/correctness bugs found in audit."""

import asyncio

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport


def make_node(name, **kw):
    return AmpNode(identity=AgentIdentity.generate(name), **kw)


async def test_concurrent_send_delivery_reorder_bricks_session():
    """Two concurrent send() calls: seq assigned under lock, but the actual
    wire delivery happens OUTSIDE the lock. If the transport yields, the
    higher-seq envelope can hit the receiver first -> SequenceError."""
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = make_node("alice")
    bob = make_node("bob", on_session=on_session)
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, ttl_seconds=60)
    bob_session = inbound[0]

    # Make delivery of the FIRST envelope slow, the second fast, so ordering
    # inverts on the wire even though seq was assigned in order under the lock.
    real_deliver = transport.deliver
    calls = {"n": 0}

    async def slow_first(envelope):
        calls["n"] += 1
        if calls["n"] == 1:
            await asyncio.sleep(0.05)  # first send lags
        await real_deliver(envelope)

    # patch the session's send_fn
    session._send_fn = slow_first

    # fire two sends concurrently
    await asyncio.gather(
        session.send_text("first"),
        session.send_text("second"),
        return_exceptions=True,
    )
    await asyncio.sleep(0.1)

    # If ordering held, bob receives seq1 then seq2. If reordered, the second
    # envelope (seq2) arrived first and was rejected -> only 1 message queued
    # and session desynced.
    got = []
    while True:
        m = bob_session.receive_nowait()
        if m is None:
            break
        got.append(m.payload.content)
    assert got == ["first", "second"], f"reordered/lost: {got}"
