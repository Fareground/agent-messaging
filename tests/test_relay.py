"""Relay server + relay transport: hosted mailboxes, card directory, auth."""

import asyncio
import base64
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from fg_amp import AgentIdentity, AmpNode, RelayTransport, create_relay_app
from fg_amp.transport.relay import (
    CARDS_PATH,
    DEFAULT_RELAY_AUDIENCE,
    PULL_PATH,
    SEND_PATH,
    _pull_payload,
)


def make_relay_transport(app) -> RelayTransport:
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )

    async def http_call(method: str, url: str, json_body: dict):
        response = await client.request(method, url, json=json_body if json_body else None)
        try:
            data = response.json()
        except ValueError:
            data = {}
        return response.status_code, data

    return RelayTransport("http://relay.test", http_call=http_call)


async def test_end_to_end_session_via_relay():
    app = create_relay_app()
    inbound = []

    async def on_session(s):
        inbound.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)

    relay_a, relay_b = make_relay_transport(app), make_relay_transport(app)
    await relay_a.connect(alice, poll_interval=0.05)
    await relay_b.connect(bob, poll_interval=0.05)
    try:
        # discovery through the relay's card directory
        bob_card = await relay_a.resolve_card(bob.address)
        session = await alice.initiate(bob_card, purpose="via relay", timeout=10)
        await session.send_text("hello through the mailbox")
        message = await inbound[0].receive(timeout=10)
        assert message.payload.content == "hello through the mailbox"
        # relay only ever saw ciphertext bodies; check a mailbox drain is empty now
        leftover = app.state.relay.mailboxes.get(bob.address)
        assert not leftover
    finally:
        await relay_a.disconnect(alice)
        await relay_b.disconnect(bob)


async def test_relay_rejects_unsigned_envelope_and_unknown_card():
    app = create_relay_app()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )
    response = await client.post(SEND_PATH, json={"garbage": True})
    assert response.status_code == 422
    response = await client.get(f"{CARDS_PATH}/amp:key:nonsense")
    assert response.status_code == 404
    # a forged card (signature mismatch) is refused
    identity = AgentIdentity.generate("real")
    card = identity.card().model_copy(update={"name": "forged"})
    response = await client.put(CARDS_PATH, json=card.model_dump(mode="json"))
    assert response.status_code == 422


async def test_pull_replay_rejected():
    """A captured, valid pull cannot be replayed to drain-and-delete mail."""
    app = create_relay_app()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )
    owner = AgentIdentity.generate("owner")
    ts = datetime.now(UTC).isoformat()
    payload = _pull_payload(owner.address, ts, DEFAULT_RELAY_AUDIENCE)
    sig = base64.b64encode(owner.keys.sign(payload)).decode()
    body = {"address": owner.address, "ts": ts, "sig": sig}

    first = await client.post(PULL_PATH, json=body)
    assert first.status_code == 200
    # replay the exact same signed request: rejected as already-used
    replay = await client.post(PULL_PATH, json=body)
    assert replay.status_code == 401


async def test_per_sender_mailbox_quota():
    """One sender cannot fill a victim's whole mailbox and starve others."""
    from fg_amp.transport.relay import _MAX_PER_SENDER, RelayState

    state = RelayState()
    victim = AgentIdentity.generate("victim")
    spammer = AgentIdentity.generate("spammer")

    def env(sender):
        from fg_amp import Envelope, EnvelopeType

        return Envelope(
            type=EnvelopeType.HANDSHAKE_REJECT,
            sender=sender.address,
            to=victim.address,
            session_id="s",
            body=Envelope.encode_body(b"{}"),
        ).signed(sender.keys)

    for _ in range(_MAX_PER_SENDER):
        state.enqueue(env(spammer))
    # spammer is now capped
    with pytest.raises(Exception, match="per-sender quota"):
        state.enqueue(env(spammer))
    # but a different sender still gets through
    state.enqueue(env(AgentIdentity.generate("legit")))


async def test_envelope_size_limit():
    app = create_relay_app()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )
    sender = AgentIdentity.generate("s")
    recipient = AgentIdentity.generate("r")
    from fg_amp import Envelope, EnvelopeType

    huge = Envelope(
        type=EnvelopeType.SESSION_MESSAGE,
        sender=sender.address,
        to=recipient.address,
        session_id="s",
        seq=1,
        body=Envelope.encode_body(b"x" * (2 << 20)),  # 2 MiB > 1 MiB cap
    ).signed(sender.keys)
    resp = await client.post(SEND_PATH, json=huge.to_wire())
    assert resp.status_code == 413


@pytest.mark.parametrize("tamper", ["signature", "stale", "wrong-signer"])
async def test_pull_authentication(tamper):
    app = create_relay_app()
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )
    owner = AgentIdentity.generate("owner")
    attacker = AgentIdentity.generate("attacker")

    ts = datetime.now(UTC)
    if tamper == "stale":
        ts = ts - timedelta(seconds=600)
    ts_text = ts.isoformat()
    signer = attacker if tamper == "wrong-signer" else owner
    payload = _pull_payload(owner.address, ts_text, DEFAULT_RELAY_AUDIENCE)
    sig = base64.b64encode(signer.keys.sign(payload)).decode()
    if tamper == "signature":
        sig = base64.b64encode(b"\x00" * 64).decode()

    response = await client.post(
        PULL_PATH, json={"address": owner.address, "ts": ts_text, "sig": sig}
    )
    assert response.status_code == 401

    # and the legitimate owner can pull
    good_ts = datetime.now(UTC).isoformat()
    good_payload = _pull_payload(owner.address, good_ts, DEFAULT_RELAY_AUDIENCE)
    good_sig = base64.b64encode(owner.keys.sign(good_payload)).decode()
    response = await client.post(
        PULL_PATH, json={"address": owner.address, "ts": good_ts, "sig": good_sig}
    )
    assert response.status_code == 200
    assert response.json() == {"envelopes": []}


async def test_offline_agent_is_woken_by_a_relay_send():
    """The headline promise: mail for an agent that is NOT polling triggers a
    real HTTP ping to the wake endpoint advertised in its card. This exercises
    the relay send -> waker.schedule wiring end to end, not the notifier alone.
    """
    from fg_amp.envelope.envelope import Envelope, EnvelopeType
    from fg_amp.transport.relay import CARDS_PATH, SEND_PATH
    from fg_amp.transport.wake import WakeNotifier, WakePolicy

    pings = []

    async def http_post(url, body):
        pings.append((url, body))

    waker = WakeNotifier(
        policy=WakePolicy(allow_private=True,
                          allowed_schemes=frozenset({"http"})),
        http_post=http_post,
    )
    app = create_relay_app(audience="relay-x", waker=waker)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test")
    try:
        sleeper = AgentIdentity.generate("sleepy")
        card = sleeper.card(endpoints={"wake": "http://127.0.0.1:9/wake"})
        r = await client.put(CARDS_PATH, json=card.model_dump(mode="json"))
        assert r.status_code == 200

        sender = AgentIdentity.generate("sender")
        env = Envelope(
            type=EnvelopeType.HANDSHAKE_INITIATE, sender=sender.address,
            to=sleeper.address, session_id="s1",
            body=Envelope.encode_body(b"{}")).signed(sender.keys)
        r = await client.post(SEND_PATH, json=env.to_wire())
        assert r.json()["accepted"] is True

        for _ in range(100):
            if pings:
                break
            await asyncio.sleep(0.02)

        assert pings == [("http://127.0.0.1:9/wake", {})], pings
    finally:
        await client.aclose()


async def test_no_wake_ping_when_the_recipient_is_polling():
    """A live poller is reached directly; waking it too would be redundant and
    would leak an online/offline signal to the wake endpoint."""
    from fg_amp.envelope.envelope import Envelope, EnvelopeType
    from fg_amp.transport.relay import CARDS_PATH, SEND_PATH
    from fg_amp.transport.wake import WakeNotifier, WakePolicy

    pings = []

    async def http_post(url, body):
        pings.append((url, body))

    waker = WakeNotifier(
        policy=WakePolicy(allow_private=True,
                          allowed_schemes=frozenset({"http"})),
        http_post=http_post,
    )
    app = create_relay_app(audience=DEFAULT_RELAY_AUDIENCE, waker=waker)
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    card = bob.identity.card(endpoints={"wake": "http://127.0.0.1:9/wake"})

    relay_b = make_relay_transport(app)
    await relay_b.connect(bob, poll_interval=0.05)
    try:
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://relay.test")
        await client.put(CARDS_PATH, json=card.model_dump(mode="json"))
        # connect() starts the poll task but does not wait for its long-poll to
        # reach the relay; send before that and a wake fires by design (mail
        # with nobody waiting). Sync on the exact condition under test.
        for _ in range(200):
            if app.state.relay.has_waiter(bob.address):
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("poller never registered as a waiter")
        sender = AgentIdentity.generate("sender")
        env = Envelope(
            type=EnvelopeType.HANDSHAKE_INITIATE, sender=sender.address,
            to=bob.address, session_id="s1",
            body=Envelope.encode_body(b"{}")).signed(sender.keys)
        await client.post(SEND_PATH, json=env.to_wire())
        await asyncio.sleep(0.3)
        assert pings == [], "a polling agent should not be pinged"
        await client.aclose()
    finally:
        await relay_b.disconnect(bob)
