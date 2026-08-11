"""The documented public surface: top-level exports, lifecycle ergonomics,
and the fg_amp.testing helpers consumers build their own tests on."""

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
from fg_amp.node import PendingInitiation as NodePendingInitiation
from fg_amp.testing import InMemoryTransport, connect


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
