"""End-to-end typed bodies over real sessions: validation at both ends of the
pipe, task lifecycle enforcement, receipts, criticality, opaque fallback."""

import asyncio
from typing import ClassVar

import pytest
from pydantic import BaseModel

from fg_amp import (
    AgentIdentity,
    AmpNode,
    BodyValidationError,
    ClaimBody,
    ClaimPedigree,
    InMemoryTransport,
    Payload,
    ReceiptBody,
    ReceiptStatus,
    RefBody,
    RefKind,
    Session,
    SessionState,
    TaskBody,
    TaskKind,
    TaskLifecycleError,
    TaskState,
    default_registry,
)

CUSTOM_TYPE = "myapp.widget/1"
EXTRA_TYPES = ("text/plain", "application/json", "amp.task/1", "amp.receipt/1", CUSTOM_TYPE)


def extra_kwargs() -> dict:
    """Node kwargs that offer AND accept the custom (unregistered) type."""
    from fg_amp import ContactPolicy

    return {
        "payload_types": EXTRA_TYPES,
        "policy": ContactPolicy(accepted_payload_types=EXTRA_TYPES),
    }


async def make_pair(**node_kwargs) -> tuple[Session, Session]:
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"), **node_kwargs)
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"), on_session=on_session, **node_kwargs
    )
    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)
    session = await alice.initiate(bob.card, purpose="typed bodies", ttl_seconds=60)
    assert len(inbound) == 1
    return session, inbound[0]


async def test_builtins_negotiated_by_default():
    alice_session, _ = await make_pair()
    for name in ("amp.task/1", "amp.receipt/1", "amp.ref/1", "amp.claim/1"):
        assert name in alice_session.payload_types


async def test_task_lifecycle_end_to_end():
    alice, bob = await make_pair()

    await alice.send_body(
        TaskBody(task_id="t1", kind=TaskKind.REQUEST, title="summarize", inputs={"n": 1})
    )
    message = await bob.receive(timeout=1)
    task = bob.body_registry.parse(message.payload.content_type, message.payload.content)
    assert task.kind is TaskKind.REQUEST and task.title == "summarize"
    assert bob.tasks.state_of("t1") is TaskState.REQUESTED

    await bob.send_body(TaskBody(task_id="t1", kind=TaskKind.ACCEPT))
    await alice.receive(timeout=1)
    assert alice.tasks.state_of("t1") is TaskState.ACCEPTED
    assert bob.tasks.state_of("t1") is TaskState.ACCEPTED

    await bob.send_body(
        TaskBody(task_id="t1", kind=TaskKind.COMPLETE, outputs={"summary": "done"})
    )
    reply = await alice.receive(timeout=1)
    assert reply.payload.content["outputs"] == {"summary": "done"}
    assert alice.tasks.state_of("t1") is None  # terminal on both sides
    assert bob.tasks.state_of("t1") is None
    assert alice.state is SessionState.ESTABLISHED


async def test_illegal_outbound_task_transition_raises_before_send():
    alice, bob = await make_pair()
    with pytest.raises(TaskLifecycleError):  # accept for a task nobody requested
        await alice.send_body(TaskBody(task_id="ghost", kind=TaskKind.ACCEPT))
    # nothing reached the wire
    assert alice.stats.sent == 0
    assert alice.state is SessionState.ESTABLISHED


async def test_invalid_outbound_body_raises_before_send():
    alice, _ = await make_pair()
    with pytest.raises(BodyValidationError):
        await alice.send(
            Payload(content_type="amp.task/1", content={"task_id": "t1", "kind": "explode"})
        )
    assert alice.stats.sent == 0


async def test_receipts_flow():
    alice, bob = await make_pair()
    envelope = await alice.send_body(
        TaskBody(task_id="t9", kind=TaskKind.REQUEST, title="fetch")
    )
    await bob.receive(timeout=1)

    await bob.send_body(ReceiptBody(status=ReceiptStatus.REJECTED, task_id="t9", reason="busy"))
    receipt_message = await alice.receive(timeout=1)
    receipt = alice.body_registry.parse(
        receipt_message.payload.content_type, receipt_message.payload.content
    )
    assert receipt.status is ReceiptStatus.REJECTED
    assert receipt.reason == "busy"

    # message-ref receipts point at the envelope id of any body
    await bob.send_body(ReceiptBody(status=ReceiptStatus.ACCEPTED, message_id=envelope.id))
    by_message = await alice.receive(timeout=1)
    assert by_message.payload.content["message_id"] == envelope.id


async def test_ref_and_claim_end_to_end():
    alice, bob = await make_pair()
    ref = RefBody(
        uri="https://git.example/repo/commit/abc",
        kind=RefKind.COMMIT,
        version="abc",
        content_hash="sha256:" + "11" * 32,
    )
    await alice.send_body(ref)
    got_ref = bob.body_registry.parse("amp.ref/1", (await bob.receive(timeout=1)).payload.content)
    assert got_ref == ref

    claim = ClaimBody(
        claim_id="c1",
        statement="the relay enforces quotas",
        confidence=0.75,
        pedigree=ClaimPedigree(source=alice.peer_card.address, evidence=(ref,)),
    )
    await bob.send_body(claim)
    got_claim = alice.body_registry.parse(
        "amp.claim/1", (await alice.receive(timeout=1)).payload.content
    )
    assert got_claim.pedigree.evidence == (ref,)
    assert got_claim.confidence == 0.75


async def test_unknown_noncritical_typed_body_delivered_opaque():
    alice, bob = await make_pair(**extra_kwargs())
    assert CUSTOM_TYPE in alice.payload_types  # negotiated, but in no registry
    await alice.send(Payload(content_type=CUSTOM_TYPE, content={"anything": [1, 2]}))
    message = await bob.receive(timeout=1)
    assert message.payload.content == {"anything": [1, 2]}
    assert bob.state is SessionState.ESTABLISHED


async def test_unknown_critical_typed_body_rejected():
    alice, bob = await make_pair(**extra_kwargs())
    await alice.send(
        Payload(content_type=CUSTOM_TYPE, content={"x": 1}, metadata={"critical": True})
    )
    await asyncio.sleep(0)  # let the inbound dispatch run
    assert bob.state is SessionState.CLOSED
    assert bob.receive_nowait() is None  # never delivered
    # the close propagated back to the sender too
    assert alice.state is SessionState.CLOSED


async def test_invalid_inbound_body_is_protocol_error():
    # A registry mismatch: alice knows a custom type, bob does not... but for a
    # *known* type with a bad body we must bypass alice's outbound validation,
    # so craft the payload against bob's schema via a permissive local type.
    class Widget(BaseModel):
        TYPE: ClassVar[str] = CUSTOM_TYPE
        count: int

    alice, bob = await make_pair(**extra_kwargs())
    bob.body_registry = default_registry().copy()
    bob.body_registry.register(Widget)
    # alice's registry doesn't know the type -> sends opaque; bob validates and
    # finds it violates the schema -> protocol error, session closes.
    await alice.send(Payload(content_type=CUSTOM_TYPE, content={"count": "not-an-int"}))
    await asyncio.sleep(0)
    assert bob.state is SessionState.CLOSED
    assert bob.receive_nowait() is None


async def test_inbound_illegal_task_transition_closes_session():
    alice, bob = await make_pair()
    # bypass alice's outbound tracker by wiping it between sends
    await alice.send_body(TaskBody(task_id="t1", kind=TaskKind.REQUEST, title="x"))
    await bob.receive(timeout=1)
    alice.tasks._tasks.clear()
    alice.tasks.apply(TaskBody(task_id="t1", kind=TaskKind.REQUEST, title="x"), actor="peer")
    alice.tasks.apply(TaskBody(task_id="t1", kind=TaskKind.ACCEPT), actor="local")
    # alice's local view is now consistent (it "accepted" a peer request), so
    # its outbound screen passes — but on bob's side the task is still merely
    # requested and the complete arrives from the requester: illegal.
    await alice.send_body(TaskBody(task_id="t1", kind=TaskKind.COMPLETE))
    await asyncio.sleep(0)
    assert bob.state is SessionState.CLOSED
