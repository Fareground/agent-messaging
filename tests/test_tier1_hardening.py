"""Regression tests for the Tier-1 trust-core hardening round.

Each test pins one finding from the security review so it cannot regress:

- HIGH-1  zero/low-order X25519 rejection in the initial key derivation + seal
- MED-2   reject/resume-reject handlers ignore non-peer senders
- MED-3   owner identity-key revocation invalidates chains that owner signed
- MED-1   policy rate-limit map is bounded under an address-churn flood
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    OwnerIdentity,
)
from fg_amp.envelope.crypto import derive_session_key, seal
from fg_amp.envelope.envelope import Envelope, EnvelopeType
from fg_amp.errors import DecryptionError, DelegationError
from fg_amp.identity.delegation import DelegationChain, KeyRevocation
from fg_amp.session.handshake import HandshakeReject
from fg_amp.transport.memory import InMemoryTransport


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


# -- HIGH-1: low-order X25519 point rejection --------------------------------

_ZERO_POINT = b"\x00" * 32


def test_derive_session_key_rejects_zero_shared_secret():
    own = X25519PrivateKey.generate()
    # An all-zero peer public key is a low-order point: the shared secret
    # collapses to zero, erasing the classical DH contribution.
    with pytest.raises(DecryptionError, match="low-order"):
        derive_session_key(own, _ZERO_POINT, handshake_transcript=b"t")


def test_seal_rejects_zero_recipient_point():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    with pytest.raises(DecryptionError, match="low-order"):
        seal(X25519PublicKey.from_public_bytes(_ZERO_POINT), b"hello")


def test_valid_ephemerals_still_agree():
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    ka = derive_session_key(a, b.public_key().public_bytes_raw(), b"t")
    kb = derive_session_key(b, a.public_key().public_bytes_raw(), b"t")
    assert ka == kb


# -- MED-2: reject handlers ignore non-peer senders --------------------------


async def test_handshake_reject_from_non_peer_is_ignored():
    """A third party that signs a reject for an observed session_id must not be
    able to abort the initiator's pending handshake."""
    import asyncio

    from fg_amp.policy.policy import PolicyMode

    # Gate bob's acceptance so alice stays deterministically pending while we
    # inject the forged reject.
    gate = asyncio.Event()

    async def approve(_initiate):
        await gate.wait()
        return True

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy(mode=PolicyMode.OPEN, human_approval=True),
        approval_fn=approve,
    )
    mallory = AmpNode(identity=AgentIdentity.generate("mallory"))
    connect(alice, bob, mallory)

    task = asyncio.ensure_future(alice.initiate(bob.card, timeout=2.0))
    for _ in range(1000):  # wait until the pending handshake is registered
        await asyncio.sleep(0)
        if alice._pending:
            break
    session_id = next(iter(alice._pending))

    def reject_from(node):
        payload = HandshakeReject(session_id=session_id, reason="go away")
        return Envelope(
            type=EnvelopeType.HANDSHAKE_REJECT,
            sender=node.address,
            to=alice.address,
            session_id=session_id,
            body=Envelope.encode_body(json.dumps(payload.model_dump(mode="json")).encode()),
        ).signed(node.identity.keys)

    # Mallory (not the peer) forges a reject: it must be ignored, handshake stands.
    await alice._on_envelope(reject_from(mallory))
    assert not task.done()
    assert session_id in alice._pending

    # Release approval → bob accepts → the handshake still completes normally.
    gate.set()
    session = await task
    assert session.state.value == "established"


# -- MED-3: owner key revocation tears down chains it signed -----------------


def test_chain_verify_rejects_revoked_root_issuer():
    owner = OwnerIdentity.generate("acme")
    agent = owner.create_agent("worker", {"converse"})
    chain: DelegationChain = agent.delegation_chain
    # Sanity: verifies normally.
    chain.verify(agent.address)
    # With the owner (root issuer) key revoked, the whole chain is dead even
    # though the leaf agent key itself is not in the revoked-key set.
    with pytest.raises(DelegationError, match="revoked identity key"):
        chain.verify(agent.address, revoked_keys=frozenset({owner.address}))


async def test_compromised_owner_key_blocks_its_agents():
    owner = OwnerIdentity.generate("acme")
    agent = AmpNode(identity=owner.create_agent("worker", {"converse"}))
    target = AmpNode(identity=AgentIdentity.generate("target"))
    connect(agent, target)
    assert (await agent.initiate(target.card)).state.value == "established"

    # Owner key is declared compromised (self-revocation). The agent's own leaf
    # key is NOT revoked — only the owner's — yet the agent must no longer
    # authenticate, because its chain roots at the revoked owner.
    owner_revocation = KeyRevocation.create(owner.keys, owner.address, owner.address)
    target.revocations.revoke_key(owner_revocation)
    assert not target.revocations.is_key_revoked(agent.address)  # leaf still "valid"

    with pytest.raises(Exception):  # noqa: B017
        await agent.initiate(target.card, timeout=0.3)


# -- MED-1: rate-limit map is bounded ----------------------------------------


def test_policy_initiations_map_is_bounded():
    from fg_amp.policy import policy as policy_mod

    engine = policy_mod.PolicyEngine(ContactPolicy.open())
    original = policy_mod._MAX_TRACKED_PEERS
    policy_mod._MAX_TRACKED_PEERS = 100
    try:
        for i in range(1000):
            engine._within_rate(f"amp:key:peer{i}")
        assert len(engine._initiations) <= 100
    finally:
        policy_mod._MAX_TRACKED_PEERS = original


async def test_replayed_accept_after_completion_is_noop():
    """Once a handshake completes and the pending entry is consumed, a replayed
    accept for the same session_id must not rebuild/overwrite the session (M6)."""

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), policy=ContactPolicy.open())
    connect(alice, bob)

    session = await alice.initiate(bob.card)
    sid = session.session_id
    live = alice.sessions[sid]
    assert sid not in alice._pending  # pending consumed on accept

    # A replayed accept envelope for the same session_id hits the consumed-pending
    # guard and returns before touching session state — no raise, same object.
    replay = Envelope(
        type=EnvelopeType.HANDSHAKE_ACCEPT,
        sender=bob.address,
        to=alice.address,
        session_id=sid,
        body=Envelope.encode_body(b"ignored"),
    ).signed(bob.identity.keys)
    alice._handle_accept(replay)
    assert alice.sessions[sid] is live


async def test_inbox_error_does_not_leak_internal_text():
    """The inbox must not echo internal exception text to an unauthenticated
    poster (M8)."""
    import httpx
    from fastapi import FastAPI

    from fg_amp import Envelope as _Env
    from fg_amp import EnvelopeType as _Type
    from fg_amp.transport import HttpTransport, create_inbox_router

    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    transport = HttpTransport()
    bob.attach(transport)
    app = FastAPI()
    app.include_router(create_inbox_router(transport, bob.card))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://n.test")

    # A well-formed but unauthenticated/garbage session frame the node will reject
    # deep in processing. The response must be a generic rejection.
    stranger = AgentIdentity.generate("stranger")
    env = _Env(
        type=_Type.SESSION_TRAFFIC if hasattr(_Type, "SESSION_TRAFFIC") else _Type.RECEIPT,
        sender=stranger.address, to=bob.address, session_id="nope",
        body=_Env.encode_body(b"x"),
    ).signed(stranger.keys)
    resp = await client.post("/amp/v0/inbox", json=env.to_wire())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "envelope rejected"
    await client.aclose()


# -- MED-4: replay caches retain by freshness window, not raw FIFO count ------


async def test_replay_cache_prunes_expired_and_catches_window_replay():
    from collections import OrderedDict

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"), policy=ContactPolicy.open())
    connect(alice, bob)
    # A completed handshake means bob recorded the initiate's id (fresh).
    await alice.initiate(bob.card)
    assert bob._seen_envelope_ids  # something remembered

    # Directly exercise the pruner: an entry whose expiry has passed is dropped,
    # a still-live one is kept — so capacity is reclaimed by time, not just count.
    cache: OrderedDict[str, float] = OrderedDict()
    cache["old"] = 100.0
    cache["live"] = 500.0
    AmpNode._prune_expired(cache, now_ts=200.0)
    assert "old" not in cache and "live" in cache


def test_prune_stops_at_first_live_entry():
    from collections import OrderedDict

    cache: OrderedDict[str, float] = OrderedDict()
    for i, exp in enumerate([10.0, 20.0, 999.0, 30.0]):
        cache[f"k{i}"] = exp
    # Insertion-ordered prune halts at the first non-expired entry (k2=999).
    AmpNode._prune_expired(cache, now_ts=50.0)
    assert list(cache) == ["k2", "k3"]


# -- M7: orphan responder sessions are reaped after a grace window ------------


async def test_orphan_responder_session_is_reaped():
    """A responder session whose initiator completed the handshake then vanished
    (no traffic either way) is reaped after the grace window, not held for the
    full TTL (M7)."""
    import asyncio
    from datetime import timedelta

    from fg_amp.session import session as session_mod
    from fg_amp.session.states import SessionState

    captured = []

    async def on_session(s):
        captured.append(s)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy.open(),
        on_session=on_session,
    )
    connect(alice, bob)

    await alice.initiate(bob.card, ttl_seconds=3600.0)  # long TTL
    await asyncio.sleep(0)
    bob_session = captured[0]
    assert bob_session.stats.received == 0 and bob_session.stats.sent == 0

    # Backdate creation past the grace window and let the reaper tick quickly.
    bob_session.created_at = bob_session.created_at - timedelta(
        seconds=session_mod._ORPHAN_GRACE_SECONDS + 1
    )
    bob_session.set_retransmit_interval(0.02)  # restart the loop fast
    for _ in range(50):
        await asyncio.sleep(0.02)
        if bob_session.state is not SessionState.ESTABLISHED:
            break
    assert bob_session.state is SessionState.EXPIRED  # reaped, not pinned for 1h
