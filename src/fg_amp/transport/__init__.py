"""Transport layer: carriers for signed, encrypted envelopes."""

from .base import InboundHandler, Transport
from .federation import RelaySyncer
from .memory import InMemoryTransport
from .relay import (
    DEFAULT_RELAY_AUDIENCE,
    RelayState,
    RelayTransport,
    SqliteRelayState,
    create_relay_app,
    relay_endpoints,
)
from .wake import WakeError, WakeNotifier, WakePolicy
from .wake_receiver import WakeReceiver
from .ws import WsRelayTransport

__all__ = [
    "DEFAULT_RELAY_AUDIENCE",
    "RelaySyncer",
    "WsRelayTransport",
    "relay_endpoints",
    "InMemoryTransport",
    "InboundHandler",
    "RelayState",
    "RelayTransport",
    "SqliteRelayState",
    "Transport",
    "WakeError",
    "WakeNotifier",
    "WakePolicy",
    "WakeReceiver",
    "create_relay_app",
]


def __getattr__(name: str):
    # HttpTransport / create_inbox_router require the optional [http] extra;
    # import lazily so the core stays web-dependency-free.
    if name in ("HttpTransport", "create_inbox_router"):
        from . import http

        return getattr(http, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
