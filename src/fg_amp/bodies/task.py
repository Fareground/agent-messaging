"""``amp.task/1`` — work lifecycle bodies and the per-session state machine.

A task is created by a ``request``, answered by the peer with ``accept`` or
``reject``, driven by the acceptor with ``progress`` and closed with
``complete``/``fail``, and cancellable by its requester at any point before a
terminal kind. ``TaskTracker`` enforces that legality per session; the session
applies it to outbound tasks before encrypt and inbound tasks after decrypt.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, Field, field_validator, model_validator

from ..errors import TaskLifecycleError
from .ref import RefBody


class TaskKind(StrEnum):
    REQUEST = "request"
    ACCEPT = "accept"
    REJECT = "reject"
    PROGRESS = "progress"
    COMPLETE = "complete"
    FAIL = "fail"
    CANCEL = "cancel"


class TaskState(StrEnum):
    REQUESTED = "requested"
    ACCEPTED = "accepted"


class TaskBody(BaseModel):
    """One event in a task's lifecycle, keyed by a sender-unique ``task_id``."""

    TYPE: ClassVar[str] = "amp.task/1"

    task_id: str
    kind: TaskKind
    title: str = ""
    body: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    deadline: str | None = None  # RFC 3339
    refs: tuple[RefBody, ...] = ()

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("task_id")
    @classmethod
    def _task_id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("task_id must be non-empty")
        return v

    @model_validator(mode="after")
    def _request_has_title(self) -> TaskBody:
        if self.kind is TaskKind.REQUEST and not self.title.strip():
            raise ValueError("a task request must carry a title")
        return self


class _Task:
    __slots__ = ("state", "requester")

    def __init__(self, requester: str) -> None:
        self.state = TaskState.REQUESTED
        self.requester = requester  # "local" | "peer"


class TaskTracker:
    """Per-session task lifecycle legality (SPEC §16.1).

    ``apply`` is called for every ``amp.task/1`` body crossing the session —
    ``actor="local"`` for outbound (before encrypt), ``actor="peer"`` for
    inbound (after decrypt). An illegal transition raises
    :class:`TaskLifecycleError` and MUST NOT mutate tracker state.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, _Task] = {}

    def state_of(self, task_id: str) -> TaskState | None:
        task = self._tasks.get(task_id)
        return task.state if task else None

    def apply(self, body: TaskBody, *, actor: str) -> None:
        kind, tid = body.kind, body.task_id
        task = self._tasks.get(tid)
        if kind is TaskKind.REQUEST:
            if task is not None:
                raise TaskLifecycleError(f"task {tid!r} already exists")
            self._tasks[tid] = _Task(requester=actor)
            return
        if task is None:
            raise TaskLifecycleError(f"{kind} for unknown task {tid!r}")
        if kind in (TaskKind.ACCEPT, TaskKind.REJECT):
            if actor == task.requester:
                raise TaskLifecycleError(f"requester cannot {kind} its own task {tid!r}")
            if task.state is not TaskState.REQUESTED:
                raise TaskLifecycleError(f"{kind} on task {tid!r} in state {task.state}")
            if kind is TaskKind.ACCEPT:
                task.state = TaskState.ACCEPTED
            else:
                del self._tasks[tid]
            return
        if kind in (TaskKind.PROGRESS, TaskKind.COMPLETE, TaskKind.FAIL):
            if actor == task.requester:
                raise TaskLifecycleError(f"requester cannot send {kind} for task {tid!r}")
            if task.state is not TaskState.ACCEPTED:
                raise TaskLifecycleError(
                    f"{kind} on task {tid!r} requires an accepted task (state: {task.state})"
                )
            if kind is not TaskKind.PROGRESS:
                del self._tasks[tid]
            return
        if kind is TaskKind.CANCEL:
            if actor != task.requester:
                raise TaskLifecycleError(f"only the requester may cancel task {tid!r}")
            del self._tasks[tid]
            return
        raise TaskLifecycleError(f"unhandled task kind {kind!r}")  # pragma: no cover
