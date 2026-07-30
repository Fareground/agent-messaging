"""Typed bodies: AMP's MIME layer.

A typed body is a schema-validated payload carried inside a session message.
Its ``content_type`` is a registry name of the form ``<name>/<version>``
(e.g. ``amp.task/1``); the registry maps that name to a validating model.
Free-form ``text/plain`` / ``application/json`` remain the untyped fallback
tier. See SPEC §16.
"""

from .claim import ClaimBody, ClaimPedigree
from .mcp import McpBody, McpBridge, McpHandler
from .payment import PaymentBody, PaymentKind, PaymentState, PaymentTracker, SpendLedger
from .receipt import ReceiptBody, ReceiptStatus
from .ref import RefBody, RefKind
from .registry import (
    BUILTIN_BODY_TYPES,
    BodyRegistry,
    BodyType,
    default_registry,
    is_typed_name,
)
from .task import TaskBody, TaskKind, TaskState, TaskTracker

__all__ = [
    "BUILTIN_BODY_TYPES",
    "BodyRegistry",
    "BodyType",
    "ClaimBody",
    "ClaimPedigree",
    "McpBody",
    "McpBridge",
    "McpHandler",
    "PaymentBody",
    "PaymentKind",
    "PaymentState",
    "PaymentTracker",
    "ReceiptBody",
    "ReceiptStatus",
    "RefBody",
    "RefKind",
    "SpendLedger",
    "TaskBody",
    "TaskKind",
    "TaskState",
    "TaskTracker",
    "default_registry",
    "is_typed_name",
]
