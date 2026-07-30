"""Typed-body layer: registry, schema validation, task lifecycle legality."""

from typing import ClassVar

import pytest
from pydantic import BaseModel

from fg_amp import (
    BodyRegistry,
    BodyValidationError,
    ClaimBody,
    ClaimPedigree,
    ReceiptBody,
    ReceiptStatus,
    RefBody,
    RefKind,
    TaskBody,
    TaskKind,
    TaskLifecycleError,
    TaskState,
    TaskTracker,
    UnknownBodyTypeError,
    default_registry,
)
from fg_amp.bodies import BUILTIN_BODY_TYPES, is_typed_name

# -- registry ---------------------------------------------------------------


def test_typed_name_detection():
    assert is_typed_name("amp.task/1")
    assert is_typed_name("myapp.thing/12")
    assert not is_typed_name("text/plain")  # MIME subtype, not an int version
    assert not is_typed_name("application/json")
    assert not is_typed_name("amp.task")  # no version
    assert not is_typed_name("amp.task/0")  # versions start at 1
    assert not is_typed_name("amp/group")  # group frame types stay untyped


def test_builtins_registered():
    registry = default_registry()
    assert set(BUILTIN_BODY_TYPES) <= set(registry.names())
    for name in BUILTIN_BODY_TYPES:
        assert name in registry
        assert registry.get(name).version == 1


def test_register_custom_type_and_copy_isolation():
    class PingBody(BaseModel):
        TYPE: ClassVar[str] = "myapp.ping/1"
        nonce: str

    registry = default_registry().copy()
    registry.register(PingBody)
    parsed = registry.parse("myapp.ping/1", {"nonce": "abc"})
    assert parsed.nonce == "abc"
    # the shared default registry is untouched
    assert "myapp.ping/1" not in default_registry()
    # double registration rejected
    with pytest.raises(ValueError, match="already registered"):
        registry.register(PingBody)


def test_register_requires_wellformed_type_name():
    class Bad(BaseModel):
        TYPE: ClassVar[str] = "not-a-typed-name"

    with pytest.raises(ValueError, match="TYPE class attribute"):
        BodyRegistry().register(Bad)


def test_parse_unknown_type_raises():
    with pytest.raises(UnknownBodyTypeError):
        default_registry().parse("nope.nope/1", {})


def test_parse_non_object_content_rejected():
    with pytest.raises(BodyValidationError, match="JSON object"):
        default_registry().parse("amp.task/1", "just a string")


def test_unknown_fields_preserved():
    parsed = default_registry().parse(
        "amp.ref/1", {"uri": "https://x.example/a", "future_field": 7}
    )
    assert parsed.model_dump()["future_field"] == 7


# -- schemas ----------------------------------------------------------------


def test_task_schema_valid_and_invalid():
    registry = default_registry()
    task = registry.parse(
        "amp.task/1",
        {"task_id": "t1", "kind": "request", "title": "do it", "inputs": {"a": 1}},
    )
    assert task.kind is TaskKind.REQUEST
    with pytest.raises(BodyValidationError):  # request without title
        registry.parse("amp.task/1", {"task_id": "t1", "kind": "request"})
    with pytest.raises(BodyValidationError):  # empty task_id
        registry.parse("amp.task/1", {"task_id": " ", "kind": "cancel"})
    with pytest.raises(BodyValidationError):  # unknown kind
        registry.parse("amp.task/1", {"task_id": "t1", "kind": "explode"})


def test_receipt_schema_exactly_one_ref():
    ReceiptBody(status=ReceiptStatus.ACCEPTED, task_id="t1")
    ReceiptBody(status="rejected", message_id="m1", reason="nope")
    with pytest.raises(BodyValidationError, match="exactly one"):
        default_registry().parse("amp.receipt/1", {"status": "accepted"})
    with pytest.raises(BodyValidationError, match="exactly one"):
        default_registry().parse(
            "amp.receipt/1", {"status": "accepted", "task_id": "t", "message_id": "m"}
        )


def test_ref_schema():
    ref = RefBody(uri="https://x.example/c", kind=RefKind.COMMIT, version="abc")
    assert ref.kind is RefKind.COMMIT
    with pytest.raises(BodyValidationError):
        default_registry().parse("amp.ref/1", {"uri": "   "})
    with pytest.raises(BodyValidationError):
        default_registry().parse("amp.ref/1", {"uri": "x", "kind": "meme"})


def test_claim_schema_confidence_bounds_and_pedigree():
    claim = ClaimBody(
        claim_id="c1",
        statement="water is wet",
        confidence=0.9,
        pedigree=ClaimPedigree(source="amp:key:abc"),
    )
    assert claim.supersedes is None
    for bad_confidence in (-0.1, 1.1):
        with pytest.raises(BodyValidationError):
            default_registry().parse(
                "amp.claim/1",
                {
                    "claim_id": "c1",
                    "statement": "s",
                    "confidence": bad_confidence,
                    "pedigree": {"source": "amp:key:abc"},
                },
            )
    with pytest.raises(BodyValidationError):  # empty pedigree source
        default_registry().parse(
            "amp.claim/1",
            {"claim_id": "c1", "statement": "s", "confidence": 1, "pedigree": {"source": ""}},
        )


# -- task lifecycle ---------------------------------------------------------


def _task(kind: TaskKind, tid: str = "t1", **kw) -> TaskBody:
    if kind is TaskKind.REQUEST:
        kw.setdefault("title", "work")
    return TaskBody(task_id=tid, kind=kind, **kw)


def test_task_happy_path_request_accept_complete():
    tracker = TaskTracker()
    tracker.apply(_task(TaskKind.REQUEST), actor="local")
    assert tracker.state_of("t1") is TaskState.REQUESTED
    tracker.apply(_task(TaskKind.ACCEPT), actor="peer")
    assert tracker.state_of("t1") is TaskState.ACCEPTED
    tracker.apply(_task(TaskKind.PROGRESS), actor="peer")
    tracker.apply(_task(TaskKind.COMPLETE), actor="peer")
    assert tracker.state_of("t1") is None  # terminal


def test_task_reject_and_fail_and_cancel():
    tracker = TaskTracker()
    tracker.apply(_task(TaskKind.REQUEST), actor="peer")
    tracker.apply(_task(TaskKind.REJECT), actor="local")
    assert tracker.state_of("t1") is None

    tracker.apply(_task(TaskKind.REQUEST, tid="t2"), actor="peer")
    tracker.apply(_task(TaskKind.ACCEPT, tid="t2"), actor="local")
    tracker.apply(_task(TaskKind.FAIL, tid="t2"), actor="local")
    assert tracker.state_of("t2") is None

    tracker.apply(_task(TaskKind.REQUEST, tid="t3"), actor="local")
    tracker.apply(_task(TaskKind.CANCEL, tid="t3"), actor="local")  # requester cancels
    assert tracker.state_of("t3") is None


@pytest.mark.parametrize(
    "setup, kind, actor",
    [
        ([], TaskKind.ACCEPT, "peer"),  # accept for unknown task
        ([], TaskKind.COMPLETE, "peer"),  # complete for unknown task
        ([("request", "local")], TaskKind.ACCEPT, "local"),  # requester self-accepts
        ([("request", "local")], TaskKind.COMPLETE, "peer"),  # complete before accept
        ([("request", "local")], TaskKind.PROGRESS, "peer"),  # progress before accept
        ([("request", "local")], TaskKind.CANCEL, "peer"),  # non-requester cancels
        ([("request", "local")], TaskKind.REQUEST, "local"),  # duplicate request
        (
            [("request", "local"), ("accept", "peer")],
            TaskKind.ACCEPT,
            "peer",
        ),  # double accept
        (
            [("request", "local"), ("accept", "peer")],
            TaskKind.COMPLETE,
            "local",
        ),  # requester completes
        (
            [("request", "local"), ("accept", "peer"), ("complete", "peer")],
            TaskKind.FAIL,
            "peer",
        ),  # fail after terminal
    ],
)
def test_task_invalid_transitions_raise(setup, kind, actor):
    tracker = TaskTracker()
    for step_kind, step_actor in setup:
        tracker.apply(_task(TaskKind(step_kind)), actor=step_actor)
    before = tracker.state_of("t1")
    with pytest.raises(TaskLifecycleError):
        tracker.apply(_task(kind), actor=actor)
    assert tracker.state_of("t1") == before  # failed transition mutates nothing
