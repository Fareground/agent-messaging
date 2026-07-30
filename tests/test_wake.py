"""Wake notifications: reaching an agent that is not currently connected."""

from __future__ import annotations

import asyncio

import pytest

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport, SessionMode
from fg_amp.transport.wake import (
    WakeError,
    WakeNotifier,
    WakePolicy,
)


def card_with_wake(url: str | None) -> dict:
    endpoints = {"wake": url} if url else {}
    return {"address": "amp:key:x", "endpoints": endpoints}


class TestWakePolicy:
    def test_https_public_host_allowed(self):
        WakePolicy().validate("https://example.com/wake/abc")

    def test_http_rejected_by_default(self):
        with pytest.raises(WakeError, match="scheme"):
            WakePolicy().validate("http://example.com/wake")

    def test_http_allowed_when_configured(self):
        policy = WakePolicy(allowed_schemes=frozenset({"http", "https"}))
        policy.validate("http://example.com/wake")

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/wake",
            "https://localhost/wake",
            "https://10.0.0.5/wake",
            "https://192.168.1.1/wake",
            "https://169.254.169.254/latest/meta-data",  # cloud metadata
            "https://[::1]/wake",
        ],
    )
    def test_ssrf_targets_are_refused(self, url):
        """A card is attacker-controlled, so the relay must not be turned into
        an SSRF proxy into its own network."""
        with pytest.raises(WakeError, match="non-public|does not resolve"):
            WakePolicy().validate(url)

    def test_private_allowed_when_explicitly_enabled(self):
        WakePolicy(allow_private=True).validate("https://127.0.0.1/wake")

    def test_empty_url_rejected(self):
        with pytest.raises(WakeError, match="missing or too long"):
            WakePolicy().validate("")

    def test_overlong_url_rejected(self):
        with pytest.raises(WakeError, match="missing or too long"):
            WakePolicy().validate("https://example.com/" + "a" * 5000)

    def test_url_without_host_rejected(self):
        with pytest.raises(WakeError):
            WakePolicy().validate("https:///wake")

    def test_unresolvable_host_rejected(self):
        with pytest.raises(WakeError, match="does not resolve"):
            WakePolicy().validate("https://nonexistent.invalid/wake")


class TestWakeNotifier:
    def test_reads_wake_url_from_card(self):
        notifier = WakeNotifier()
        assert notifier.wake_url(card_with_wake("https://a.example/w")) == "https://a.example/w"

    def test_no_wake_url_when_absent(self):
        notifier = WakeNotifier()
        assert notifier.wake_url(card_with_wake(None)) is None
        assert notifier.wake_url(None) is None
        assert notifier.wake_url({"endpoints": "not-a-dict"}) is None

    async def test_ping_is_content_free(self):
        """The ping must reveal nothing — no sender, no message id, no counts."""
        sent = []

        async def post(url, body):
            sent.append((url, body))

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http", "https"})),
            http_post=post,
        )
        task = notifier.schedule("amp:key:x", card_with_wake("http://127.0.0.1/w"))
        await task

        assert sent == [("http://127.0.0.1/w", {})]

    async def test_debounced_per_address(self):
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=1000,
        )
        card = card_with_wake("http://127.0.0.1/w")
        first = notifier.schedule("amp:key:x", card)
        second = notifier.schedule("amp:key:x", card)

        assert first is not None
        assert second is None, "a burst of messages must not become a burst of pings"
        await first
        assert len(sent) == 1

    async def test_debounce_expires(self):
        sent = []
        clock = {"t": 0.0}

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=30,
            clock=lambda: clock["t"],
        )
        card = card_with_wake("http://127.0.0.1/w")
        await notifier.schedule("amp:key:x", card)
        clock["t"] = 31.0
        second = notifier.schedule("amp:key:x", card)
        assert second is not None
        await second
        assert len(sent) == 2

    async def test_separate_wake_hosts_are_not_debounced_together(self):
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=1000,
        )
        a = notifier.schedule("amp:key:a", card_with_wake("http://127.0.0.1/a"))
        b = notifier.schedule("amp:key:b", card_with_wake("http://127.0.0.2/b"))
        await asyncio.gather(a, b)
        assert len(sent) == 2

    async def test_many_addresses_cannot_flood_one_victim_url(self):
        """Debouncing per recipient address protected the wrong party:
        addresses are free to mint, so N cards pointing at one victim URL got
        N pings through. The debounce is keyed on the wake host."""
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=1000,
        )
        victim = card_with_wake("http://127.0.0.1/victim")
        tasks = [notifier.schedule(f"amp:key:attacker{i}", victim)
                 for i in range(200)]
        await asyncio.gather(*[t for t in tasks if t is not None])

        assert len(sent) == 1, f"victim received {len(sent)} pings"

    async def test_debounce_state_is_bounded(self):
        """The debounce map must not be a memory vector in its own right."""
        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=lambda url, body: asyncio.sleep(0),
            debounce_seconds=1000,
            max_tracked=10,
        )
        for i in range(100):
            notifier.schedule("amp:key:x", card_with_wake(f"http://10.0.0.{i % 250}/w"))
        await notifier.drain()
        assert len(notifier._last_sent) <= 10

    async def test_saturation_drops_rather_than_queues(self):
        """A semaphore bounds sockets but not tasks; a flood must not park
        unbounded pending work on the event loop."""
        started = asyncio.Event()

        async def post(url, body):
            started.set()
            await asyncio.sleep(5)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=0,
            max_concurrency=2,
        )
        scheduled = [notifier.schedule("amp:key:x", card_with_wake(f"http://10.1.0.{i}/w"))
                     for i in range(50)]
        live = [t for t in scheduled if t is not None]
        assert len(live) <= 2, f"{len(live)} tasks created despite a cap of 2"
        for t in live:
            t.cancel()

    async def test_ssrf_url_is_not_posted_to(self):
        """Policy runs before the request, so a blocked target is never hit."""
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(http_post=post)  # default policy: public https only
        task = notifier.schedule("amp:key:x", card_with_wake("https://127.0.0.1/w"))
        await task
        assert sent == []

    async def test_failing_ping_never_raises(self):
        """A wake is a hint; its failure must not disturb the relay."""

        async def post(url, body):
            raise RuntimeError("network down")

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
        )
        task = notifier.schedule("amp:key:x", card_with_wake("http://127.0.0.1/w"))
        await task  # must not raise

    async def test_slow_ping_times_out(self):
        async def post(url, body):
            await asyncio.sleep(10)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
            timeout_seconds=0.05,
        )
        task = notifier.schedule("amp:key:x", card_with_wake("http://127.0.0.1/w"))
        await asyncio.wait_for(task, timeout=2)  # returns rather than hanging

    async def test_no_card_means_no_ping(self):
        notifier = WakeNotifier()
        assert notifier.schedule("amp:key:x", None) is None


class TestRelayIntegration:
    async def test_wake_fires_when_nobody_is_listening(self):
        pytest.importorskip("fastapi")
        from fg_amp.transport.relay import RelayState

        relay = RelayState()
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True, allowed_schemes=frozenset({"http"})),
            http_post=post,
        )
        address = "amp:key:sleepy"
        assert not relay.has_waiter(address)

        task = notifier.schedule(address, {"endpoints": {"wake": "http://127.0.0.1/w"}})
        await task
        assert sent == ["http://127.0.0.1/w"]

    async def test_no_wake_while_a_puller_is_connected(self):
        from fg_amp.transport.relay import RelayState

        relay = RelayState()
        address = "amp:key:awake"
        event = relay.register_waiter(address)
        try:
            assert relay.has_waiter(address) is True
        finally:
            relay.drop_waiter(address, event)
        assert relay.has_waiter(address) is False


class TestDeferredInitiation:
    async def test_wait_false_returns_a_handle_without_blocking(self):
        """Contacting an offline peer must not fail just because it is asleep."""
        alice = AgentIdentity.generate("alice")
        bob = AgentIdentity.generate("bob")
        node_a = AmpNode(identity=alice)
        transport = InMemoryTransport()
        node_a.attach(transport)

        # Bob's node does not exist yet — nobody will answer.
        pending = await node_a.initiate(
            bob.card(), mode=SessionMode.EPHEMERAL, ttl_seconds=60, wait=False
        )
        assert pending.session_id
        assert not pending.done

        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await pending.wait(timeout=0.05)

        # Crucially, the handshake is still live after the timeout.
        assert pending.session_id in node_a._pending
        pending.cancel()
        assert pending.session_id not in node_a._pending

    async def test_late_peer_still_completes_the_handshake(self):
        """The knock waits in the mailbox; the session materializes when the
        peer finally connects."""
        inbound = []

        async def on_session(session):
            inbound.append(session)

        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        bob_identity = AgentIdentity.generate("bob")
        transport = InMemoryTransport()
        alice.attach(transport)

        pending = await alice.initiate(
            bob_identity.card(), ttl_seconds=60, wait=False
        )
        assert not pending.done

        # Bob wakes up and binds — InMemoryTransport flushes his queued mail.
        bob = AmpNode(identity=bob_identity, on_session=on_session)
        bob.attach(transport)

        session = await pending.wait(timeout=5)
        assert session.session_id == pending.session_id
        assert inbound and inbound[0].session_id == pending.session_id

    async def test_wait_true_is_unchanged(self):
        inbound = []

        async def on_session(session):
            inbound.append(session)

        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
        transport = InMemoryTransport()
        alice.attach(transport)
        bob.attach(transport)

        session = await alice.initiate(bob.card, ttl_seconds=60)
        assert session.session_id
        assert not isinstance(session, type(None))


class TestPendingInitiationLifetime:
    async def test_expired_initiations_are_reclaimed(self):
        """Deferred knocks outlive their caller, so they must expire on their
        own or a node that contacts sleeping peers leaks handshake state."""
        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        alice.attach(InMemoryTransport())
        bob = AgentIdentity.generate("bob")

        pending = await alice.initiate(bob.card(), ttl_seconds=0.0, wait=False)
        assert pending.session_id in alice._pending

        reclaimed = alice.forget_expired_initiations()
        assert reclaimed == 1
        assert pending.session_id not in alice._pending

    async def test_expired_initiation_reports_a_clear_error(self):
        from fg_amp.errors import SessionError

        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        alice.attach(InMemoryTransport())
        pending = await alice.initiate(
            AgentIdentity.generate("bob").card(), ttl_seconds=0.0, wait=False
        )
        alice.forget_expired_initiations()

        with pytest.raises(SessionError, match="expired before the peer answered"):
            await pending.wait(timeout=1)

    async def test_live_initiations_are_not_reclaimed(self):
        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        alice.attach(InMemoryTransport())
        pending = await alice.initiate(
            AgentIdentity.generate("bob").card(), ttl_seconds=600, wait=False
        )
        assert alice.forget_expired_initiations() == 0
        assert pending.session_id in alice._pending


class TestSsrfHardening:
    """Regressions for the 2026-07-19 audit: the original policy validated the
    first URL once and let the HTTP client do everything else."""

    def test_cgnat_is_refused(self):
        """100.64.0.0/10 is not `is_private`, so enumerating flags silently
        allowed carrier-grade NAT — reachable internal space in many clouds."""
        with pytest.raises(WakeError, match="non-public"):
            WakePolicy().check_address("100.64.0.1")

    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
        "169.254.169.254", "::1", "fc00::1", "fe80::1",
        "0.0.0.0", "100.64.0.1", "224.0.0.1", "240.0.0.1",
    ])
    def test_non_public_addresses_refused(self, addr):
        with pytest.raises(WakeError):
            WakePolicy().check_address(addr)

    def test_ipv4_mapped_ipv6_is_judged_on_the_ipv4_value(self):
        """::ffff:127.0.0.1 must be read as 127.0.0.1, not as an opaque v6."""
        with pytest.raises(WakeError, match="non-public"):
            WakePolicy().check_address("::ffff:127.0.0.1")

    def test_public_addresses_allowed(self):
        WakePolicy().check_address("93.184.216.34")
        WakePolicy().check_address("2606:2800:220:1:248:1893:25c8:1946")

    async def test_redirects_are_not_followed(self):
        """A public host that 302s into loopback re-opened every path the
        policy closed, because only the first URL was ever checked."""
        pytest.importorskip("aiohttp")
        import inspect

        from fg_amp.transport import wake

        source = inspect.getsource(wake.WakeNotifier._aiohttp_post)
        assert "allow_redirects=False" in source

    async def test_addresses_are_validated_at_connection_time(self):
        """Validating a hostname then letting the client re-resolve it is a
        race a low-TTL attacker wins; the check must sit in the resolver."""
        pytest.importorskip("aiohttp")
        import inspect

        from fg_amp.transport import wake

        source = inspect.getsource(wake.WakeNotifier._aiohttp_post)
        assert "resolver=" in source
        assert "policy.check_address" in source

    def test_preflight_still_rejects_static_private_targets(self):
        with pytest.raises(WakeError):
            WakePolicy().validate("https://127.0.0.1/wake")


class TestPendingWaitDeadline:
    async def test_wait_without_timeout_still_ends(self):
        """An unanswered knock must not hang forever past its own deadline."""
        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        alice.attach(InMemoryTransport())
        pending = await alice.initiate(
            AgentIdentity.generate("bob").card(), ttl_seconds=0.2, wait=False)

        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await asyncio.wait_for(pending.wait(), timeout=5)

    async def test_wait_without_timeout_still_resolves_on_accept(self):
        inbound = []

        async def on_session(session):
            inbound.append(session)

        transport = InMemoryTransport()
        alice = AmpNode(identity=AgentIdentity.generate("alice"))
        alice.attach(transport)
        bob_identity = AgentIdentity.generate("bob")

        pending = await alice.initiate(bob_identity.card(), ttl_seconds=60,
                                       wait=False)
        AmpNode(identity=bob_identity, on_session=on_session).attach(transport)

        session = await asyncio.wait_for(pending.wait(), timeout=10)
        assert session.session_id == pending.session_id


class TestEmbeddedIpv4:
    """IPv6 can carry an IPv4 the network actually routes to, while passing
    every scope rule that judges the IPv6 address alone."""

    @pytest.mark.parametrize("addr,why", [
        ("64:ff9b::a9fe:a9fe", "NAT64 -> 169.254.169.254 cloud metadata"),
        ("64:ff9b::7f00:1", "NAT64 -> 127.0.0.1"),
        ("2002:7f00:1::", "6to4 -> 127.0.0.1"),
        ("2002:a00:1::", "6to4 -> 10.0.0.1"),
        ("::7f00:1", "IPv4-compatible -> 127.0.0.1"),
        ("192.88.99.1", "6to4 relay anycast"),
    ])
    def test_tunnelled_internal_addresses_refused(self, addr, why):
        with pytest.raises(WakeError, match="non-public"):
            WakePolicy().check_address(addr)

    def test_genuinely_public_ipv6_still_allowed(self):
        WakePolicy().check_address("2606:2800:220:1:248:1893:25c8:1946")
        WakePolicy().check_address("2002:5db8:d822::")  # 6to4 of a public v4


class TestDebounceUnderChurn:
    async def test_churn_cannot_reset_a_victims_debounce(self):
        """Pure LRU eviction let an attacker cycle throwaway hosts through the
        cap to force the victim's entry out and win another ping."""
        sent = []

        async def post(url, body):
            sent.append(url)

        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True,
                              allowed_schemes=frozenset({"http"})),
            http_post=post,
            debounce_seconds=1000,
            max_tracked=8,
        )
        victim = card_with_wake("http://10.9.9.9/victim")
        first = notifier.schedule("amp:key:a", victim)
        assert first is not None
        await first

        # Churn far past the cap with unrelated hosts, then retry the victim.
        for i in range(200):
            notifier.schedule(f"amp:key:x{i}",
                              card_with_wake(f"http://10.8.0.{i % 250}/w"))
        await notifier.drain()

        again = notifier.schedule("amp:key:b", victim)
        assert again is None, "churn evicted the victim and reset its debounce"
        assert sent.count("http://10.9.9.9/victim") == 1

    async def test_expired_entries_are_reclaimed(self):
        clock = {"t": 0.0}
        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True,
                              allowed_schemes=frozenset({"http"})),
            http_post=lambda url, body: asyncio.sleep(0),
            debounce_seconds=10,
            max_tracked=4,
            clock=lambda: clock["t"],
        )
        for i in range(4):
            notifier.schedule("amp:key:x", card_with_wake(f"http://10.7.0.{i}/w"))
        assert len(notifier._last_sent) == 4  # full

        clock["t"] = 100.0  # everything is now past its window
        notifier.schedule("amp:key:x", card_with_wake("http://10.7.1.1/w"))
        await notifier.drain()

        assert len(notifier._last_sent) == 1
        assert "10.7.1.1" in notifier._last_sent

    async def test_a_full_table_of_live_entries_does_not_displace_anyone(self):
        """Under pressure a new host goes untracked rather than knocking an
        existing one out — being tracked must not depend on other traffic."""
        notifier = WakeNotifier(
            policy=WakePolicy(allow_private=True,
                              allowed_schemes=frozenset({"http"})),
            http_post=lambda url, body: asyncio.sleep(0),
            debounce_seconds=1000,
            max_tracked=3,
        )
        for i in range(3):
            notifier.schedule("amp:key:x", card_with_wake(f"http://10.6.0.{i}/w"))
        tracked = set(notifier._last_sent)

        for i in range(50):
            notifier.schedule("amp:key:y", card_with_wake(f"http://10.5.0.{i}/w"))
        await notifier.drain()

        assert set(notifier._last_sent) == tracked
        assert len(notifier._last_sent) == 3


class TestWakeReceiver:
    """The listener half: a ping must drive an actual pull, closing the loop
    from 'mail arrived for an offline agent' to 'the agent has its mail'."""

    async def test_ping_fires_the_callback(self):
        import aiohttp

        from fg_amp import WakeReceiver

        fired = asyncio.Event()

        async def on_wake():
            fired.set()

        receiver = WakeReceiver(on_wake, path="/wake")
        port = await receiver.start(host="127.0.0.1", port=0)
        try:
            async with aiohttp.ClientSession() as s:
                r = await s.post(f"http://127.0.0.1:{port}/wake", json={})
                assert r.status == 204
            await asyncio.wait_for(fired.wait(), 2)
        finally:
            await receiver.stop()

    async def test_bursts_coalesce(self):
        """A pull fetches all waiting mail, so N rapid pings should not launch N
        pulls — one in flight plus at most one queued."""
        import aiohttp

        from fg_amp import WakeReceiver

        runs = 0
        gate = asyncio.Event()

        async def on_wake():
            nonlocal runs
            runs += 1
            await gate.wait()  # hold the first run open while pings pile up

        receiver = WakeReceiver(on_wake, path="/wake", coalesce=True)
        port = await receiver.start(host="127.0.0.1", port=0)
        try:
            async with aiohttp.ClientSession() as s:
                for _ in range(10):
                    await s.post(f"http://127.0.0.1:{port}/wake", json={})
            await asyncio.sleep(0.05)
            assert runs == 1  # only the first is running; the rest coalesced
            gate.set()
            await asyncio.sleep(0.05)
            assert runs == 2  # exactly one coalesced follow-up
        finally:
            gate.set()
            await receiver.stop()

    async def test_full_loop_offline_agent_gets_its_mail(self):
        """End to end on real sockets: mail for a sleeping agent pings its
        receiver, whose callback connects a node and drains the mailbox."""
        import aiohttp
        import uvicorn

        from fg_amp import (
            AgentIdentity,
            AmpNode,
            RelayTransport,
            WakeReceiver,
        )
        from fg_amp.envelope.envelope import Envelope, EnvelopeType
        from fg_amp.transport.relay import (
            CARDS_PATH,
            SEND_PATH,
            create_relay_app,
        )
        from fg_amp.transport.wake import WakeNotifier, WakePolicy

        waker = WakeNotifier(
            policy=WakePolicy(allow_private=True,
                              allowed_schemes=frozenset({"http"})))
        app = create_relay_app(audience="relay-x", waker=waker)

        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
        serve_task = asyncio.ensure_future(server.serve())
        while not server.started:
            await asyncio.sleep(0.01)
        base = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"

        sleeper = AgentIdentity.generate("sleepy")
        drained = asyncio.Event()
        received = []

        async def on_wake():
            # The operator's hook: a ping means "connect and pull".
            node = AmpNode(identity=sleeper,
                           on_session=lambda s: received.append(s))
            transport = RelayTransport(base, audience="relay-x")
            await transport.connect(node, poll_interval=0.05)
            await asyncio.sleep(0.3)
            await transport.disconnect(node)
            drained.set()

        receiver = WakeReceiver(on_wake, path="/wake")
        wake_port = await receiver.start(host="127.0.0.1", port=0)

        try:
            async with aiohttp.ClientSession() as s:
                card = sleeper.card(
                    endpoints={"wake": f"http://127.0.0.1:{wake_port}/wake"})
                r = await s.put(f"{base}{CARDS_PATH}",
                                json=card.model_dump(mode="json"))
                assert r.status == 200

                sender = AgentIdentity.generate("sender")
                env = Envelope(
                    type=EnvelopeType.HANDSHAKE_INITIATE, sender=sender.address,
                    to=sleeper.address, session_id="s1",
                    body=Envelope.encode_body(b"{}")).signed(sender.keys)
                r = await s.post(f"{base}{SEND_PATH}", json=env.to_wire())
                assert r.status == 200

                # The ping -> receiver -> connect -> pull chain must run without
                # us ever polling on the sleeper's behalf.
                await asyncio.wait_for(drained.wait(), 5)
        finally:
            await receiver.stop()
            server.should_exit = True
            await serve_task
