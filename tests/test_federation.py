"""Federation-lite (SPEC §13.3): multi-relay failover + cross-relay dir sync."""

import httpx
import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    RelaySyncer,
    RelayTransport,
    Session,
    create_relay_app,
)
from fg_amp.errors import TransportError
from fg_amp.identity.delegation import KeyRevocation
from fg_amp.transport.relay import CARDS_PATH, relay_endpoints


def asgi_call(app):
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )

    async def http_call(method: str, url: str, json_body: dict):
        # strip whatever fake base the transport prepended; route by path
        path = url.split("://", 1)[1].split("/", 1)[1]
        response = await client.request(
            method, f"/{path}", json=json_body if json_body else None
        )
        try:
            data = response.json()
        except ValueError:
            data = {}
        return response.status_code, data

    return http_call


def multi_relay_call(routes: dict[str, object]):
    """One http_call that dispatches to different ASGI apps by URL prefix.
    A None app simulates an unreachable relay."""
    clients = {
        base: httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)
        for base, app in routes.items()
        if app is not None
    }

    async def http_call(method: str, url: str, json_body: dict):
        for base, client in clients.items():
            if url.startswith(base):
                response = await client.request(
                    method, url.removeprefix(base), json=json_body if json_body else None
                )
                try:
                    data = response.json()
                except ValueError:
                    data = {}
                return response.status_code, data
        raise ConnectionError(f"relay unreachable: {url}")

    return http_call


# -- card relay-endpoint convention --------------------------------------


def test_relay_endpoints_ordered_failover_list():
    identity = AgentIdentity.generate("multi")
    card = identity.card(
        endpoints={
            "relay.2": "https://c.example",
            "relay": "https://a.example",
            "wake": "https://wake.example/hook",
            "relay.1": "https://b.example",
            "relay.x": "https://ignored.example",
        }
    )
    assert relay_endpoints(card) == [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ]
    for_card = RelayTransport.for_card(card)
    assert [base for base, _ in for_card._targets] == [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ]


def test_for_card_without_relay_endpoint_raises():
    card = AgentIdentity.generate("norelay").card()
    with pytest.raises(TransportError, match="advertises no relay endpoint"):
        RelayTransport.for_card(card)


# -- ordered failover ----------------------------------------------------


async def test_send_fails_over_to_second_relay():
    app_b = create_relay_app(audience="http://b.test")
    call = multi_relay_call({"http://a.test": None, "http://b.test": app_b})
    transport = RelayTransport(
        ["http://a.test", "http://b.test"],
        http_call=call,
        audience=["http://a.test", "http://b.test"],
    )
    inbound: list[Session] = []

    async def on_session(session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    bob_transport = RelayTransport(
        ["http://a.test", "http://b.test"],
        http_call=call,
        audience=["http://a.test", "http://b.test"],
    )
    await transport.connect(alice, poll_interval=0.05)
    await bob_transport.connect(bob, poll_interval=0.05)
    try:
        # relay A is down for everyone; the whole flow rides relay B
        bob_card = await transport.resolve_card(bob.address)
        session = await alice.initiate(bob_card, timeout=10)
        await session.send_text("survived a dead primary")
        message = await inbound[0].receive(timeout=10)
        assert message.payload.content == "survived a dead primary"
    finally:
        await transport.disconnect(alice)
        await bob_transport.disconnect(bob)


async def test_definitive_4xx_does_not_fail_over():
    """A real rejection from a healthy relay is a verdict, not an outage."""
    seen: list[str] = []
    app = create_relay_app(audience="http://b.test")
    inner = multi_relay_call({"http://b.test": app})

    async def recording_call(method, url, body):
        seen.append(url)
        if url.startswith("http://a.test"):
            return 422, {"detail": "invalid envelope"}
        return await inner(method, url, body)

    transport = RelayTransport(
        ["http://a.test", "http://b.test"], http_call=recording_call
    )
    status, _ = await transport._call_failover("POST", "/amp/v0/relay/send", {"x": 1})
    assert status == 422
    assert all(u.startswith("http://a.test") for u in seen)  # never tried B


async def test_all_relays_unreachable_raises_transport_error():
    call = multi_relay_call({"http://a.test": None, "http://b.test": None})
    transport = RelayTransport(["http://a.test", "http://b.test"], http_call=call)
    with pytest.raises(TransportError, match="no relay reachable"):
        await transport._call_failover("GET", CARDS_PATH + "/amp:key:x")


def test_audience_count_must_match_relay_count():
    with pytest.raises(ValueError, match="audiences for"):
        RelayTransport(["http://a", "http://b"], http_call=object(), audience=["only-one"])


# -- RelaySyncer ---------------------------------------------------------


async def test_syncer_pulls_cards_and_revocations_delta():
    app_a = create_relay_app(audience="a")
    app_b = create_relay_app(audience="b")
    state_a, state_b = app_a.state.relay, app_b.state.relay

    agent = AgentIdentity.generate("published-on-a")
    state_a.put_card(agent.card())
    revoker = AgentIdentity.generate("revoker")
    state_a.add_key_revocation(
        KeyRevocation.create(revoker.keys, revoker.address, revoker.address)
    )

    syncer = RelaySyncer(state_b, "http://a.test", http_call=asgi_call(app_a))
    counts = await syncer.sync_once()
    assert counts["cards"] == 1
    assert counts["key_revocations"] == 1
    assert counts["rejected"] == 0
    assert state_b.get_card(agent.address) is not None
    assert revoker.address in state_b.key_revocations

    # delta: a second round with nothing new transfers nothing
    counts = await syncer.sync_once()
    assert counts == {"cards": 0, "revocations": 0, "key_revocations": 0, "rejected": 0}

    # a re-registration reappears after the cursor
    state_a.put_card(agent.card(policy_summary="updated"))
    counts = await syncer.sync_once()
    assert counts["cards"] == 1


async def test_syncer_rejects_hostile_records():
    app_a = create_relay_app(audience="a")
    state_a = app_a.state.relay
    real = AgentIdentity.generate("real")
    # inject a forged card and a garbage record directly into the peer's store
    forged = real.card().model_copy(update={"name": "forged"})
    state_a.cards[forged.address] = forged.model_dump(mode="json")
    state_a._card_seq += 1
    state_a._card_seqs[forged.address] = state_a._card_seq
    state_a.cards["amp:key:garbage"] = {"not": "a card"}
    state_a._card_seq += 1
    state_a._card_seqs["amp:key:garbage"] = state_a._card_seq

    target = create_relay_app(audience="b").state.relay
    syncer = RelaySyncer(target, "http://a.test", http_call=asgi_call(app_a))
    counts = await syncer.sync_once()
    assert counts["cards"] == 0
    assert counts["rejected"] == 2
    assert target.get_card(forged.address) is None
    # the cursor still advanced: a poisonous record cannot wedge the sync
    counts = await syncer.sync_once()
    assert counts["rejected"] == 0


async def test_cards_since_endpoint_paginates_by_cursor():
    app = create_relay_app(audience="a")
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://relay.test"
    )
    first = AgentIdentity.generate("one")
    app.state.relay.put_card(first.card())
    response = await client.get(CARDS_PATH)
    body = response.json()
    assert len(body["cards"]) == 1
    cursor = body["cursor"]
    second = AgentIdentity.generate("two")
    app.state.relay.put_card(second.card())
    response = await client.get(f"{CARDS_PATH}?since={cursor}")
    body = response.json()
    assert [c["address"] for c in body["cards"]] == [second.address]


async def test_sqlite_state_lists_cards_since(tmp_path):
    from fg_amp import SqliteRelayState

    state = SqliteRelayState(str(tmp_path / "relay.db"))
    a, b = AgentIdentity.generate("a"), AgentIdentity.generate("b")
    state.put_card(a.card())
    rows, cursor = state.list_cards()
    assert [r["address"] for r in rows] == [a.address]
    state.put_card(b.card())
    rows, cursor2 = state.list_cards(since=cursor)
    assert [r["address"] for r in rows] == [b.address]
    assert cursor2 > cursor
