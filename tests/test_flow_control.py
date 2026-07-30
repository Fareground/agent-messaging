"""Windowed flow control: a bounded consumer applies real backpressure and no
acknowledged message is ever decoded-then-dropped (audit blocker #1)."""

import asyncio

import pytest

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def _establish():
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)
    session = await alice.initiate(bob.card, ttl_seconds=60)
    bob_session = inbound[0]
    # Deterministic: disable RTO so recovery is driven only by the flow-control
    # paths under test, not the background retransmit timer.
    session.set_retransmit_interval(None)
    bob_session.set_retransmit_interval(None)
    return session, bob_session


async def _wait_until(predicate, timeout=1.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met within timeout")


async def test_overcapacity_frame_is_held_not_dropped():
    """The receiver decode-gate holds an over-capacity in-order frame undecoded
    (and unacked) instead of decoding-then-dropping it; draining recovers it in
    order with nothing lost. Sender-side capture bypasses the window stall so the
    receiver gate is exercised directly."""
    session, bob_session = await _establish()
    bob_session.max_inflight = 2

    # Capture ciphertext without delivering, so the sender never sees a receipt
    # and never stalls — isolating the receiver's decode-gate.
    captured = []
    session._send_fn = lambda e: captured.append(e) or asyncio.sleep(0)
    for text in ("one", "two", "three"):
        await session.send_text(text)
    assert [e.seq for e in captured] == [1, 2, 3]

    for env in captured:
        await bob_session.handle_incoming(env)

    # Only two decoded; the third is held under backpressure, not decoded.
    assert bob_session._inbox.qsize() == 2
    assert bob_session.stats.backpressure_holds == 1
    assert 3 in bob_session._reorder  # held in-order frame, undecoded
    # The sender still holds seq 3 as retransmittable — it was never acknowledged.
    assert 3 in session._send_buffer

    got = [await bob_session.receive(timeout=1) for _ in range(3)]
    assert [m.payload.content for m in got] == ["one", "two", "three"]
    assert bob_session.stats.received == 3


async def test_sender_stalls_on_zero_window_then_resumes():
    """When the peer window reaches zero the sender blocks; draining the consumer
    reopens the window and the stalled send completes — end-to-end over the real
    transport."""
    session, bob_session = await _establish()
    bob_session.max_inflight = 1

    await session.send_text("first")
    # First receipt advertises window 0 (inbox full).
    await _wait_until(lambda: session._peer_recv_window == 0)

    send_task = asyncio.create_task(session.send_text("second"))
    await asyncio.sleep(0.05)
    assert not send_task.done()  # stalled on the exhausted window
    assert session.stats.send_stalls >= 1

    # Consumer drains → window reopens → the stalled send unblocks and delivers.
    assert (await bob_session.receive(timeout=1)).payload.content == "first"
    await asyncio.wait_for(send_task, timeout=1)
    assert (await bob_session.receive(timeout=1)).payload.content == "second"


async def test_max_inflight_validation():
    """max_inflight is bounded by the reorder window and rejects 0, so a held
    frame can never overflow the reorder buffer into unrecoverable loss."""
    session, _ = await _establish()
    session.max_inflight = 256  # upper bound OK
    session.max_inflight = None  # unbounded OK
    session.max_inflight = 1  # lower bound OK
    for bad in (0, -1, 257, 100_000):
        with pytest.raises(ValueError, match="max_inflight"):
            session.max_inflight = bad


async def test_unbounded_receiver_never_stalls_sender():
    """Default (max_inflight=None) advertises an unbounded window, so the sender
    never stalls and behavior is unchanged."""
    session, bob_session = await _establish()
    for i in range(20):
        await session.send_text(f"m{i}")
    assert session._peer_recv_window is None
    assert session.stats.send_stalls == 0
    got = [await bob_session.receive(timeout=1) for _ in range(20)]
    assert [m.payload.content for m in got] == [f"m{i}" for i in range(20)]
