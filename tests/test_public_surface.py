"""The documented public surface: top-level exports, lifecycle ergonomics,
and the fg_amp.testing helpers consumers build their own tests on."""

import asyncio

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    KeyPair,
    PendingInitiation,
    PublicKeys,
    Session,
    SessionState,
)
from fg_amp.errors import ConfigurationError, PolicyRejection
from fg_amp.node import PendingInitiation as NodePendingInitiation
from fg_amp.testing import InMemoryTransport, amp_pair, connect


def test_pending_initiation_reexported_from_node_package():
    assert NodePendingInitiation is PendingInitiation


def test_identity_key_types_exported_top_level():
    assert KeyPair is not None and PublicKeys is not None


async def test_async_context_manager_closes_node():
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy.open(),
        on_session=on_session,
    )
    connect(alice, bob)

    async with alice as node:
        assert node is alice
        session = await node.initiate(bob.card, purpose="ctx test")
        assert session.state is SessionState.ESTABLISHED

    # exiting the context closed live sessions and detached the transport
    assert session.state is SessionState.CLOSED
    assert alice._transport is None


async def test_testing_connect_wires_nodes_over_in_memory_transport():
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy.open(),
        on_session=on_session,
    )
    transport = connect(alice, bob)
    assert isinstance(transport, InMemoryTransport)

    session = await alice.initiate(bob.card, purpose="testing helper")
    await session.send_text("hello")
    message = await inbound[0].receive(timeout=1)
    assert message.payload.content == "hello"
    await session.close()


# -- AmpNode.create -----------------------------------------------------------


async def test_create_defaults_to_memory_transport_and_closed_policy():
    async with await AmpNode.create(AgentIdentity.generate("solo")) as node:
        assert isinstance(node._transport, InMemoryTransport)
        # Safe default: an unknown peer initiating toward us is rejected.
        stranger = AmpNode(identity=AgentIdentity.generate("stranger"))
        stranger.attach(node._transport)
        with pytest.raises(PolicyRejection):
            await stranger.initiate(node.card, purpose="cold call")
    assert node._transport is None  # async with closed it


async def test_create_accepts_explicit_transport_and_opt_in_policy():
    transport = InMemoryTransport()
    a = await AmpNode.create(AgentIdentity.generate("a"), transport=transport)
    b = await AmpNode.create(
        AgentIdentity.generate("b"), transport=transport, policy=ContactPolicy.open()
    )
    session = await a.initiate(b.card, purpose="hello")
    await session.send_text("ping")
    echo = b.sessions[session.session_id]
    assert (await echo.receive(timeout=1)).payload.content == "ping"
    await a.aclose()
    await b.aclose()


async def test_create_rejects_relay_and_transport_together():
    with pytest.raises(ConfigurationError):
        await AmpNode.create(
            AgentIdentity.generate("x"), relay="http://r", transport=InMemoryTransport()
        )


async def test_create_builds_relay_transport_from_url(monkeypatch):
    import fg_amp.transport.relay as relay_mod
    import fg_amp.transport.ws as ws_mod

    connected: list[tuple[type, tuple[str, ...], str]] = []

    async def fake_connect(self, node, poll_interval=1.0):
        connected.append((type(self), tuple(base for base, _ in self._targets), node.address))
        node.attach(self)

    monkeypatch.setattr(relay_mod.RelayTransport, "connect", fake_connect)
    monkeypatch.setattr(ws_mod.WsRelayTransport, "connect", fake_connect)

    http_node = await AmpNode.create(
        AgentIdentity.generate("h"), relay=["http://r1.test", "http://r2.test"]
    )
    ws_node = await AmpNode.create(AgentIdentity.generate("w"), relay="wss://relay.test")

    (http_cls, http_bases, _), (ws_cls, ws_bases, _) = connected
    assert http_cls is relay_mod.RelayTransport
    assert http_bases == ("http://r1.test", "http://r2.test")
    assert ws_cls is ws_mod.WsRelayTransport
    assert ws_bases == ("https://relay.test",)  # ws scheme normalized to the http base
    await http_node.aclose()
    await ws_node.aclose()


# -- amp_pair -----------------------------------------------------------------


async def test_amp_pair_round_trip_both_directions():
    a, b = await amp_pair()
    session = await a.initiate(b.card, purpose="hello")
    await session.send_text("ping")
    echo = b.sessions[session.session_id]
    assert (await echo.receive(timeout=1)).payload.content == "ping"
    await echo.send_text("pong")
    assert (await session.receive(timeout=1)).payload.content == "pong"
    # either side may initiate — both run an open policy by default
    reverse = await b.initiate(a.card, purpose="reverse")
    assert reverse.state is SessionState.ESTABLISHED
    await a.aclose()
    await b.aclose()


# -- on_session runs as a task, not inline in the dispatch loop ---------------


async def test_on_session_responder_can_receive_without_deadlock():
    """The obvious responder pattern — await receive() inside on_session —
    must complete a full round trip instead of deadlocking dispatch."""

    async def respond(session: Session):
        message = await session.receive()
        await session.send_text(f"pong ({message.payload.content})")

    a, b = await amp_pair(on_session=respond)
    session = await a.initiate(b.card, purpose="hello")
    await session.send_text("ping")
    reply = await asyncio.wait_for(session.receive(), timeout=2)
    assert reply.payload.content == "pong (ping)"
    await a.aclose()
    await b.aclose()


async def test_aclose_cancels_stuck_on_session_callback():
    started = asyncio.Event()

    async def hang(session: Session):
        started.set()
        await session.receive()  # never satisfied — aclose must cancel us

    a, b = await amp_pair(on_session=hang)
    await a.initiate(b.card, purpose="hang")
    await asyncio.wait_for(started.wait(), timeout=2)
    assert b._callback_tasks
    await asyncio.wait_for(b.aclose(), timeout=2)  # must not hang on the callback
    assert not b._callback_tasks
    await a.aclose()


async def test_on_session_callback_exception_is_logged_not_fatal(caplog):
    async def boom(session: Session):
        raise RuntimeError("callback bug")

    a, b = await amp_pair(on_session=boom)
    session = await a.initiate(b.card, purpose="boom")
    await asyncio.sleep(0)  # let the callback task run
    with caplog.at_level("ERROR", logger="fg_amp.node"):
        await asyncio.sleep(0.05)
        await session.send_text("still alive")  # node keeps working
    assert any("on_session callback failed" in r.message for r in caplog.records)
    await a.aclose()
    await b.aclose()


# -- aclose disconnects connection-oriented transports ------------------------


async def test_aclose_disconnects_relay_style_transport():
    calls: list[str] = []

    class FakeRelay(InMemoryTransport):
        async def connect(self, node, poll_interval=1.0):
            calls.append("connect")
            node.attach(self)

        async def disconnect(self, node):
            calls.append("disconnect")
            node.detach()

    node = await AmpNode.create(AgentIdentity.generate("n"), transport=FakeRelay())
    await node.aclose()
    assert calls == ["connect", "disconnect"]
    assert node._transport is None


async def test_create_cleans_up_when_connect_fails():
    calls: list[str] = []

    class BrokenRelay(InMemoryTransport):
        async def connect(self, node, poll_interval=1.0):
            calls.append("connect")
            raise ConnectionError("relay unreachable")

        async def disconnect(self, node):
            calls.append("disconnect")

    with pytest.raises(ConnectionError):
        await AmpNode.create(AgentIdentity.generate("n"), transport=BrokenRelay())
    assert calls == ["connect", "disconnect"]


async def test_create_rejects_unrecognized_relay_scheme():
    with pytest.raises(ConfigurationError, match="scheme"):
        await AmpNode.create(AgentIdentity.generate("n"), relay="not-a-url")


async def test_receive_timeout_names_session_and_timeout():
    a, b = await amp_pair()
    session = await a.initiate(b.card, purpose="quiet")
    with pytest.raises(TimeoutError, match=f"{session.session_id}.*0.05"):
        await session.receive(timeout=0.05)
    await a.aclose()
    await b.aclose()
