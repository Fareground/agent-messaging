"""amp.mcp/1: outer-frame validation only, and the McpBridge helper pair —
expose a local MCP handler over a session, call the remote one with
correlation and timeouts."""

import asyncio

import pytest
from pydantic import ValidationError

from fg_amp import (
    AgentIdentity,
    AmpNode,
    InMemoryTransport,
    McpBody,
    McpBridge,
    Session,
    default_registry,
)


async def make_pair() -> tuple[Session, Session]:
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)
    session = await alice.initiate(bob.card, purpose="mcp", ttl_seconds=60)
    assert len(inbound) == 1
    return session, inbound[0]


async def echo_tool(request: dict) -> dict:
    """A stand-in MCP server: echoes the tool arguments as the result."""
    return {"result": {"echo": request.get("params", {}), "method": request.get("method")}}


# -- frame validation -------------------------------------------------------


def test_payload_must_be_a_jsonrpc_object():
    with pytest.raises(ValidationError, match='jsonrpc == "2.0"'):
        McpBody(payload={"method": "tools/list"})  # missing jsonrpc
    with pytest.raises(ValidationError):
        McpBody(payload={"jsonrpc": "1.0", "method": "tools/list"})
    body = McpBody(payload={"jsonrpc": "2.0", "method": "tools/list", "id": 1})
    assert body.mcp_session == ""  # single-session default


def test_inner_semantics_are_opaque():
    # Anything valid-JSON-RPC-shaped passes, however nonsensical to MCP itself.
    weird = {"jsonrpc": "2.0", "id": None, "result": {"???": [1, {"deep": True}]}}
    parsed = default_registry().parse("amp.mcp/1", {"payload": weird, "mcp_session": "s"})
    assert parsed.payload == weird


def test_registered_as_builtin():
    assert "amp.mcp/1" in default_registry()


# -- bridge over a real session ---------------------------------------------


async def test_e2e_call_with_correlation():
    alice_session, bob_session = await make_pair()
    bob_bridge = McpBridge(bob_session, handler=echo_tool)
    alice_bridge = McpBridge(alice_session)
    pumps = [asyncio.ensure_future(b.pump()) for b in (bob_bridge, alice_bridge)]
    try:
        # Two concurrent calls: responses must land on their own futures.
        first, second = await asyncio.gather(
            alice_bridge.call({"method": "tools/call", "params": {"name": "a"}}, timeout=2),
            alice_bridge.call({"method": "tools/call", "params": {"name": "b"}}, timeout=2),
        )
        assert first["result"]["echo"] == {"name": "a"}
        assert second["result"]["echo"] == {"name": "b"}
        assert {first["id"], second["id"]} == {"amp-1", "amp-2"}
    finally:
        for pump in pumps:
            pump.cancel()


async def test_call_times_out_without_a_responder():
    alice_session, _bob_session = await make_pair()  # nobody pumps bob's inbox
    bridge = McpBridge(alice_session)
    with pytest.raises(TimeoutError):
        await bridge.call({"method": "tools/list"}, timeout=0.05)
    assert not bridge._pending  # the timed-out call is cleaned up


async def test_peer_without_handler_answers_method_not_found():
    alice_session, bob_session = await make_pair()
    bob_bridge = McpBridge(bob_session)  # nothing exposed
    alice_bridge = McpBridge(alice_session)
    pumps = [asyncio.ensure_future(b.pump()) for b in (bob_bridge, alice_bridge)]
    try:
        response = await alice_bridge.call({"method": "tools/list"}, timeout=2)
        assert response["error"]["code"] == -32601
    finally:
        for pump in pumps:
            pump.cancel()


async def test_unmatched_response_is_dropped_and_counted():
    alice_session, _ = await make_pair()
    bridge = McpBridge(alice_session)
    handled = await bridge.dispatch(
        McpBody(payload={"jsonrpc": "2.0", "id": "never-asked", "result": {}})
    )
    assert handled is True
    assert bridge.unmatched_responses == 1


async def test_bridge_ignores_other_mcp_sessions():
    alice_session, _ = await make_pair()
    bridge = McpBridge(alice_session, mcp_session="mine")
    other = McpBody(payload={"jsonrpc": "2.0", "id": 1, "result": {}}, mcp_session="theirs")
    assert await bridge.dispatch(other) is False
