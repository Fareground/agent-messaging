"""``amp.receipt/1`` — application-level acknowledgement.

Distinct from the transport ``receipt`` envelope (SPEC §10), which only says
"frame N arrived". An application receipt says what the *application* did with
a specific body: accepted it, completed it, or rejected it. It references the
acknowledged body by task id or by message (envelope) id — exactly one.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, model_validator


class ReceiptStatus(StrEnum):
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    REJECTED = "rejected"


class ReceiptBody(BaseModel):
    """Acknowledges a specific previously-received body."""

    TYPE: ClassVar[str] = "amp.receipt/1"

    status: ReceiptStatus
    task_id: str | None = None  # acknowledges an amp.task/1 by its task_id
    message_id: str | None = None  # acknowledges any body by its envelope id
    reason: str = ""

    model_config = {"extra": "allow", "frozen": True}

    @model_validator(mode="after")
    def _exactly_one_ref(self) -> ReceiptBody:
        if bool(self.task_id) == bool(self.message_id):
            raise ValueError("receipt must reference exactly one of task_id or message_id")
        return self
