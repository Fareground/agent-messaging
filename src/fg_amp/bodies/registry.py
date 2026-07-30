"""The payload-type registry: versioned, schema-validated body types.

A body type name is ``<dotted-name>/<integer-version>`` (``amp.task/1``).
The integer version segment is what distinguishes a typed name from a MIME
type — ``text/plain`` has no integer version, so it stays in the untyped
fallback tier and is never routed through the registry.

Validation uses the same pydantic models the rest of the codebase uses for
wire structures (``extra="allow"`` so unknown future fields are preserved,
matching the envelope's forward-compatibility rule). Applications extend the
registry with their own types; the ``amp.*`` built-ins ship registered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from ..errors import BodyValidationError, UnknownBodyTypeError

_TYPED_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*/[1-9][0-9]*")


def is_typed_name(content_type: str) -> bool:
    """Whether a content type names a registry body type (``name/version``
    with an integer version) rather than a free-form/MIME type."""
    return _TYPED_NAME.fullmatch(content_type) is not None


@dataclass(frozen=True)
class BodyType:
    """A registered body type: its wire name, version, and validating model."""

    name: str  # full wire name, e.g. "amp.task/1"
    version: int
    model: type[BaseModel]
    description: str = ""

    def validate(self, content: Any) -> BaseModel:
        """Parse and validate raw content against this type's schema."""
        if not isinstance(content, dict):
            raise BodyValidationError(
                f"{self.name} body must be a JSON object, got {type(content).__name__}"
            )
        try:
            return self.model.model_validate(content)
        except ValidationError as exc:
            raise BodyValidationError(f"invalid {self.name} body: {exc}") from exc


class BodyRegistry:
    """Maps typed content-type names to their validating body types.

    Immutable-by-copy extension: ``register`` mutates only this instance, and
    ``copy()`` gives an application its own registry without touching the
    shared default.
    """

    def __init__(self) -> None:
        self._types: dict[str, BodyType] = {}

    def register(self, model: type[BaseModel], *, description: str = "") -> BodyType:
        """Register a body model. The model MUST carry a ``TYPE`` class
        attribute naming its wire type (``<name>/<version>``)."""
        name = getattr(model, "TYPE", None)
        if not isinstance(name, str) or not is_typed_name(name):
            raise ValueError(
                f"body model {model.__name__} needs a TYPE class attribute of the "
                f"form '<name>/<version>' with an integer version, got {name!r}"
            )
        if name in self._types:
            raise ValueError(f"body type {name!r} is already registered")
        body_type = BodyType(
            name=name,
            version=int(name.rsplit("/", 1)[1]),
            model=model,
            description=description,
        )
        self._types[name] = body_type
        return body_type

    def get(self, name: str) -> BodyType | None:
        return self._types.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._types))

    def __contains__(self, name: str) -> bool:
        return name in self._types

    def parse(self, content_type: str, content: Any) -> BaseModel:
        """Validate content against the registered schema for its type."""
        body_type = self._types.get(content_type)
        if body_type is None:
            raise UnknownBodyTypeError(f"unknown body type {content_type!r}")
        return body_type.validate(content)

    def copy(self) -> BodyRegistry:
        clone = BodyRegistry()
        clone._types = dict(self._types)
        return clone


def _builtin_registry() -> BodyRegistry:
    from .claim import ClaimBody
    from .mcp import McpBody
    from .payment import PaymentBody
    from .receipt import ReceiptBody
    from .ref import RefBody
    from .task import TaskBody

    registry = BodyRegistry()
    registry.register(TaskBody, description="work lifecycle (request→accept→complete)")
    registry.register(ReceiptBody, description="application-level acknowledgement")
    registry.register(RefBody, description="pointer to an external artifact")
    registry.register(ClaimBody, description="knowledge claim with pedigree")
    registry.register(PaymentBody, description="x402 payment carriage (quote→authorize→settle)")
    registry.register(McpBody, description="MCP JSON-RPC carriage")
    return registry


_default: BodyRegistry | None = None


def default_registry() -> BodyRegistry:
    """The shared registry with the ``amp.*`` built-ins. Applications MAY
    register additional types here (process-wide) or work on a ``copy()``."""
    global _default
    if _default is None:
        _default = _builtin_registry()
    return _default


# Wire names of the built-in body types, advertised in the default
# payload_types offer so they participate in handshake negotiation.
BUILTIN_BODY_TYPES: tuple[str, ...] = (
    "amp.task/1",
    "amp.receipt/1",
    "amp.ref/1",
    "amp.claim/1",
    "amp.payment/1",
    "amp.mcp/1",
)
