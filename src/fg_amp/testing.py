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

from typing import Any

from .identity import AgentIdentity
from .node import AmpNode
from .policy import ContactPolicy
from .transport import InMemoryTransport

__all__ = ["InMemoryTransport", "amp_pair", "connect"]


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


async def amp_pair(
    names: tuple[str, str] = ("a", "b"),
    *,
    policy: ContactPolicy | None = None,
    **kwargs: Any,
) -> tuple[AmpNode, AmpNode]:
    """Two fresh nodes wired over one in-memory transport, ready to talk.

    Both run ``ContactPolicy.open()`` by default so either side can initiate —
    the right default for a test double, and exactly why this helper lives in
    ``fg_amp.testing`` rather than shipping as a production constructor
    (``AmpNode.create`` defaults closed). Extra keyword arguments go to both
    ``AmpNode`` constructors.

        a, b = await amp_pair()
        session = await a.initiate(b.card, purpose="hello")
        await session.send_text("ping")
        echo = b.sessions[session.session_id]   # b's side of the same session
    """
    policy = policy or ContactPolicy.open()
    a = AmpNode(identity=AgentIdentity.generate(names[0]), policy=policy, **kwargs)
    b = AmpNode(identity=AgentIdentity.generate(names[1]), policy=policy, **kwargs)
    connect(a, b)
    return a, b
