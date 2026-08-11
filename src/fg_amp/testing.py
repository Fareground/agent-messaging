"""Test helpers for consumers of fg-amp.

Wire nodes together over the in-process :class:`InMemoryTransport` so
integration code can be unit-tested with no relay, no network, and no
optional dependencies:

    from fg_amp import AgentIdentity, AmpNode, ContactPolicy
    from fg_amp.testing import connect

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), policy=ContactPolicy.open())
    connect(alice, bob)
    session = await alice.initiate(bob.card, purpose="test")
"""

from __future__ import annotations

from .node import AmpNode
from .transport import InMemoryTransport

__all__ = ["InMemoryTransport", "connect"]


def connect(*nodes: AmpNode) -> InMemoryTransport:
    """Attach every node to one shared in-memory transport and return it.

    This is the same wiring the package's own test suite uses: after this
    call any node can ``initiate`` toward any other node's card, entirely
    in-process.
    """
    transport = InMemoryTransport()
    for node in nodes:
        node.attach(transport)
    return transport
