"""Relay directory/revocation hardening: bounded stores + delta revocation sync."""

from fg_amp.identity import OwnerIdentity
from fg_amp.transport import relay as relay_mod
from fg_amp.transport.relay import RelayState


def test_revocation_delta_cursor_returns_only_new_entries():
    state = RelayState()
    owner = OwnerIdentity.generate("o")
    a1 = owner.create_agent("a1", {"converse"})
    a2 = owner.create_agent("a2", {"converse"})
    r1 = owner.revoke(a1.delegation_chain.links[0])
    r2 = owner.revoke(a2.delegation_chain.links[0])

    state.add_revocation(r1)
    rows, cursor1 = state.list_revocations(0)
    assert len(rows) == 1  # only r1 so far

    state.add_revocation(r2)
    rows2, cursor2 = state.list_revocations(cursor1)  # delta since first sync
    assert len(rows2) == 1  # only the NEW one, not the whole table
    assert cursor2 > cursor1

    # a fully caught-up client gets nothing new
    rows3, cursor3 = state.list_revocations(cursor2)
    assert rows3 == []
    assert cursor3 == cursor2


def test_card_directory_is_bounded(monkeypatch):
    monkeypatch.setattr(relay_mod, "_MAX_CARDS", 3)
    state = RelayState()
    addrs = []
    for i in range(5):
        ident = OwnerIdentity.generate(f"o{i}").create_agent(f"a{i}", {"converse"})
        card = ident.card()
        state.put_card(card)
        addrs.append(card.address)
    assert len(state.cards) == 3  # capped
    # the three most-recently-registered survive; the first two were evicted
    assert state.get_card(addrs[0]) is None
    assert state.get_card(addrs[-1]) is not None


def test_revocations_fail_closed_never_evict_existing(monkeypatch):
    """A revocation store at capacity rejects NEW writes rather than silently
    evicting an existing (possibly critical) revocation — so a spam flood can't
    make a real revocation disappear from a fresh client's `since=0` sync."""
    from fg_amp.errors import TransportError

    monkeypatch.setattr(relay_mod, "_MAX_REVOCATIONS", 2)
    state = RelayState()
    owner = OwnerIdentity.generate("victim")
    agent = owner.create_agent("compromised", {"converse"})
    real = owner.revoke(agent.delegation_chain.links[0])
    state.add_revocation(real)  # the legitimate one, registered first

    spam_owner = OwnerIdentity.generate("attacker")
    filled = 1
    for i in range(5):
        a = spam_owner.create_agent(f"junk{i}", {"converse"})
        r = spam_owner.revoke(a.delegation_chain.links[0])
        try:
            state.add_revocation(r)
            filled += 1
        except TransportError:
            break  # fail-closed: store full, new writes rejected
    assert filled == 2  # cap reached, further writes rejected loudly

    rows, _ = state.list_revocations(0)
    digests = {r["delegation_digest"] for r in rows}
    assert real.delegation_digest in digests  # legit revocation survives the flood


def test_rate_limiter_bounds_requests_and_map():
    limiter = relay_mod._RateLimiter(max_requests=3, window=60.0, max_tracked=10)
    # First 3 allowed within the window (fixed clock), 4th refused.
    assert [limiter.allow("k", now=100.0) for _ in range(4)] == [True, True, True, False]
    # Window slides: far-future request is allowed again.
    assert limiter.allow("k", now=200.0) is True
    # Tracking map is bounded under key churn.
    for i in range(100):
        limiter.allow(f"peer{i}", now=100.0)
    assert len(limiter._hits) <= 10


async def _asgi_client():
    import httpx

    from fg_amp import create_relay_app

    app = create_relay_app()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://r")


async def test_pull_naive_timestamp_is_422_not_500():
    from fg_amp import AgentIdentity

    client = await _asgi_client()
    agent = AgentIdentity.generate("a")
    # A tz-less timestamp used to raise TypeError deep in the handler -> 500.
    resp = await client.post(
        "/amp/v0/relay/pull",
        json={"address": agent.address, "ts": "2026-01-01T00:00:00", "sig": ""},
    )
    assert resp.status_code == 422
    await client.aclose()


async def test_send_endpoint_rate_limits(monkeypatch):
    from fg_amp import AgentIdentity
    from fg_amp.envelope.envelope import Envelope, EnvelopeType

    monkeypatch.setattr(relay_mod, "_RATE_MAX_REQUESTS", 2)
    client = await _asgi_client()
    sender = AgentIdentity.generate("s")
    to = AgentIdentity.generate("t")

    def wire():
        return Envelope(
            type=EnvelopeType.HANDSHAKE_INITIATE,
            sender=sender.address,
            to=to.address,
            session_id="s1",
            body=Envelope.encode_body(b"x"),
        ).signed(sender.keys).to_wire()

    codes = []
    for _ in range(3):
        r = await client.post("/amp/v0/relay/send", json=wire())
        codes.append(r.status_code)
    assert codes[:2] == [200, 200]
    assert codes[2] == 429
    await client.aclose()


# -- H1: at-least-once delivery via leases ------------------------------------


def _env(to, sender="amp:key:s", mid=None):
    from fg_amp.envelope.envelope import Envelope, EnvelopeType

    kw = {"id": mid} if mid else {}
    return Envelope(
        type=EnvelopeType.HANDSHAKE_INITIATE, sender=sender, to=to,
        session_id="s", body=Envelope.encode_body(b"x"), **kw,
    )


def test_drain_leases_and_ack_removes():
    state = RelayState()
    state.enqueue(_env("amp:key:bob", mid="m1"))
    # Drain leases the message (returns it, holds it in-flight).
    got = state.drain("amp:key:bob", now=0.0)
    assert [w["id"] for w in got] == ["m1"]
    # A second drain before the lease expires returns nothing (still in-flight).
    assert state.drain("amp:key:bob", now=1.0) == []
    # Ack removes it permanently.
    assert state.ack("amp:key:bob", ["m1"]) == 1
    # After ack, even past lease expiry there is nothing to redeliver.
    assert state.drain("amp:key:bob", now=10_000.0) == []


def test_unacked_lease_is_redelivered():
    state = RelayState()
    state.enqueue(_env("amp:key:bob", mid="m1"))
    assert [w["id"] for w in state.drain("amp:key:bob", now=0.0)] == ["m1"]
    # Puller "crashes" (never acks). After the lease lapses the message is
    # reclaimed and redelivered — at-least-once, not at-most-once.
    redelivered = state.drain("amp:key:bob", now=_relay_lease() + 1.0)
    assert [w["id"] for w in redelivered] == ["m1"]


def test_ack_is_idempotent_and_ignores_unknown():
    state = RelayState()
    state.enqueue(_env("amp:key:bob", mid="m1"))
    state.drain("amp:key:bob", now=0.0)
    assert state.ack("amp:key:bob", ["m1"]) == 1
    assert state.ack("amp:key:bob", ["m1"]) == 0        # already gone
    assert state.ack("amp:key:bob", ["nope"]) == 0      # unknown id


def test_sqlite_lease_survives_restart(tmp_path):
    from fg_amp.transport.relay import SqliteRelayState

    db = str(tmp_path / "relay.db")
    state = SqliteRelayState(db)
    state.enqueue(_env("amp:key:bob", mid="m1"))
    assert [w["id"] for w in state.drain("amp:key:bob", now=0.0)] == ["m1"]
    state._db.close()

    # Relay restarts before the puller acked: the in-flight message must persist
    # and be reclaimed for redelivery, not silently lost.
    restarted = SqliteRelayState(db)
    redelivered = restarted.drain("amp:key:bob", now=_relay_lease() + 1.0)
    assert [w["id"] for w in redelivered] == ["m1"]
    assert restarted.ack("amp:key:bob", ["m1"]) == 1


def _relay_lease() -> float:
    return relay_mod._LEASE_SECONDS


# -- H2: sqlite storage runs off the event loop -------------------------------


async def test_inmemory_run_is_inline_sqlite_offloads(tmp_path):
    import threading

    from fg_amp.transport.relay import SqliteRelayState

    loop_thread = threading.get_ident()

    mem = RelayState()
    # In-memory ops are event-loop-safe: run inline on the loop thread.
    assert await mem.run(threading.get_ident) == loop_thread

    sql = SqliteRelayState(str(tmp_path / "r.db"))
    # Sqlite ops are offloaded so a blocking fsync can't stall the loop.
    assert await sql.run(threading.get_ident) != loop_thread
    sql._db.close()


def test_poison_message_is_dead_lettered_after_attempt_cap():
    """A message that is never acked (handler keeps failing) is redelivered a
    bounded number of times, then dropped — it can't pin a mailbox forever."""
    from fg_amp.transport.relay import _MAX_DELIVERY_ATTEMPTS

    state = RelayState()
    state.enqueue(_env("amp:key:bob", mid="poison"))
    lease = _relay_lease()
    seen = 0
    now = 0.0
    for _ in range(_MAX_DELIVERY_ATTEMPTS + 5):
        got = state.drain("amp:key:bob", now=now)
        if not got:
            break
        seen += 1
        now += lease + 1.0  # puller never acks; lease lapses each round
    assert seen == _MAX_DELIVERY_ATTEMPTS  # delivered exactly the cap, then dead-lettered
    assert state.drain("amp:key:bob", now=now + 1_000_000) == []  # gone for good


def test_sqlite_poison_message_is_dead_lettered(tmp_path):
    from fg_amp.transport.relay import _MAX_DELIVERY_ATTEMPTS, SqliteRelayState

    state = SqliteRelayState(str(tmp_path / "relay.db"))
    state.enqueue(_env("amp:key:bob", mid="poison"))
    lease = _relay_lease()
    seen = 0
    now = 1_000.0  # wall-clock-ish base for the sqlite path
    for _ in range(_MAX_DELIVERY_ATTEMPTS + 5):
        got = state.drain("amp:key:bob", now=now)
        if not got:
            break
        seen += 1
        now += lease + 1.0
    assert seen == _MAX_DELIVERY_ATTEMPTS
    assert state.drain("amp:key:bob", now=now + 1_000_000) == []
