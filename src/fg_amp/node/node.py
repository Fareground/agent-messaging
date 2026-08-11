"""AmpNode: one agent's presence on the network.

Composes identity, policy, transport, sessions, groups, and resume. Owns the
full handshake on both sides:

    initiator                                    responder
    ---------                                    ---------
    initiate() ── handshake.initiate (sealed) ──▶ verify sig + card + chain
                                                  policy engine
              ◀── handshake.accept (sealed) ───── derive session key
    verify responder card + chain                 session established
    session established

Identity verification is mutual: both sides walk the other's delegation chain,
so every session knows the peer agent, its owner (chain root), and its
verified scopes. Persistent sessions can be exported to a SessionStore
(no key material persisted) and resumed later with a fresh key.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..bodies import BUILTIN_BODY_TYPES
from ..capabilities import (
    CAP_PQ_ML_KEM_768,
    CAP_RATCHET_DH_V1,
    CAP_WITNESSED_V1,
    default_capabilities,
    negotiate,
)
from ..crypto import pq as pqkem
from ..envelope.crypto import derive_session_key, open_sealed, seal
from ..envelope.envelope import Envelope, EnvelopeType
from ..errors import (
    ConfigurationError,
    DelegationError,
    PolicyRejection,
    ProtocolVersionError,
    ResumeError,
    SessionError,
    SessionNotFoundError,
    SignatureError,
)
from ..identity import AgentIdentity
from ..identity.card import AgentCard
from ..identity.delegation import RevocationRegistry
from ..identity.keys import base58_encode
from ..policy.policy import ApprovalFn, ContactPolicy, Decision, PolicyEngine, PolicyMode
from ..session.group import GROUP_PAYLOAD_TYPES, GroupSession
from ..session.handshake import (
    HandshakeAccept,
    HandshakeInitiate,
    HandshakeReject,
    ResumeAccept,
    ResumeRequest,
    resume_salt,
)
from ..session.session import RestoredState, Session
from ..session.states import SessionMode, SessionState
from ..session.store import SessionRecord, SessionStore
from ..session.witness import WitnessSpec, require_witness_match
from ..transport.base import Transport
from ..version import PROTOCOL_VERSION
from .groups import GroupCallback, GroupManager

SessionCallback = Callable[[Session], Awaitable[None]]

_HANDSHAKE_TIMEOUT_SECONDS = 30.0
# Ceiling on handshakes awaiting an answer. Deferred initiations outlive their
# caller, so this bounds a node that knocks on many peers that never wake.
_MAX_PENDING_INITIATIONS = 1024
_MAX_SEEN_RESUME_KEYS = 8192
_MAX_SEEN_ENVELOPE_IDS = 8192
_MAX_CLOCK_SKEW_SECONDS = 300.0  # freshness window for establishing frames
DEFAULT_PAYLOAD_TYPES = (
    "text/plain",
    "application/json",
    *BUILTIN_BODY_TYPES,
    *GROUP_PAYLOAD_TYPES,
)

_log = logging.getLogger("fg_amp.node")


def _session_salt(initiate_salt: bytes, responder_ephemeral_pub: bytes) -> bytes:
    """KDF salt binding both handshake ephemerals: the initiate transcript
    digest plus the responder's ephemeral public key."""
    import hashlib

    return hashlib.sha256(initiate_salt + responder_ephemeral_pub).digest()


def _with_pq(capabilities: tuple[str, ...], pq_active: bool) -> tuple[str, ...]:
    """Strip the PQ token unless a KEM secret was actually exchanged, so
    session.capabilities never overstates PQ protection. Never fabricates the
    token — callers only pass pq_active=True when PQ was genuinely negotiated."""
    if pq_active:
        return tuple(sorted(capabilities))
    return tuple(c for c in capabilities if c != CAP_PQ_ML_KEM_768)


def _resume_capabilities(pq_active: bool, witness: WitnessSpec | None = None) -> frozenset[str]:
    """Capabilities in force on a resumed session: the baseline ratchet plus PQ
    iff a KEM secret was actually re-derived at resume time. (Resume re-runs the
    KEM rather than restoring a persisted set, so this reflects the live key.)
    Witnessed posture is restored from the session record — the agreement was
    handshake-bound and survives resume."""
    caps = {CAP_RATCHET_DH_V1}
    if pq_active:
        caps.add(CAP_PQ_ML_KEM_768)
    if witness is not None:
        caps.add(CAP_WITNESSED_V1)
    return frozenset(caps)


@dataclass
class _PendingInitiation:
    ephemeral: X25519PrivateKey
    initiate: HandshakeInitiate
    future: asyncio.Future[Session]
    peer_address: str
    pq_private: object | None = None  # ML-KEM-768 private key if PQ was offered
    # Monotonic deadline. Deferred initiations (wait=False) outlive the call
    # that made them, so without a deadline a node that knocks on many sleeping
    # peers would accumulate handshake state forever.
    expires_at: float = 0.0


class PendingInitiation:
    """A handshake sent to a peer that has not answered yet.

    Returned by :meth:`AmpNode.initiate` with ``wait=False``. The initiate
    envelope is already in the peer's mailbox; this handle lets the caller stop
    blocking on a peer that may be asleep, and collect the session whenever it
    wakes up — minutes or hours later.

    Without this, contacting an offline agent is impossible in practice: the
    knock is delivered and stored, but the caller has already given up.
    """

    def __init__(self, node: AmpNode, session_id: str, future: asyncio.Future[Session]):
        self._node = node
        self.session_id = session_id
        self._future = future

    @property
    def done(self) -> bool:
        return self._future.done()

    async def wait(self, timeout: float | None = None) -> Session:
        """Block until the peer accepts. Raises TimeoutError if it doesn't.

        Timing out does NOT abandon the handshake — the pending state survives,
        so a later call can still collect the session.

        A wait with no timeout still ends: the handshake's own deadline is
        enforced here, so an unanswered knock raises rather than hanging past
        the point where it could ever be accepted.
        """
        if timeout is None:
            deadline = self._node._pending.get(self.session_id)
            if deadline is not None:
                remaining = deadline.expires_at - time.monotonic()
                if remaining <= 0:
                    self._node.forget_expired_initiations()
                session = await asyncio.wait_for(
                    asyncio.shield(self._future), max(remaining, 0.0)
                )
            else:
                session = await asyncio.shield(self._future)
        else:
            session = await asyncio.wait_for(asyncio.shield(self._future), timeout)
        # Same ordering contract as AmpNode.initiate: yield once so the
        # acceptor's on_session task (queued before the accept was sent) has
        # started before we hand the session back.
        await asyncio.sleep(0)
        return session

    def cancel(self) -> None:
        """Give up on this handshake and release its pending state."""
        self._node._pending.pop(self.session_id, None)
        if not self._future.done():
            self._future.cancel()


@dataclass
class _PendingResume:
    ephemeral: X25519PrivateKey
    record: SessionRecord
    future: asyncio.Future[Session]
    nonce: str  # fresh per attempt; the accept must echo it
    pq_private: object | None = None  # ML-KEM-768 private key if PQ was offered


class AmpNode:
    """An agent's messaging endpoint: address, inbox, policy, sessions, groups.

    **on_session ordering contract.** The ``on_session`` callback runs as its
    own task, so it may freely await ``session.receive()`` without deadlocking
    inbound dispatch. What a caller may assume: by the time the *initiating*
    peer's ``initiate()`` / ``PendingInitiation.wait()`` / ``resume()``
    returns, the acceptor's callback has **started** — executed up to its
    first suspension point. It has NOT necessarily completed; anything after
    the callback's first ``await`` is unordered relative to the initiator's
    next step. This holds deterministically (not by racing): the callback task
    is queued before the accept frame is sent, the initiator cannot proceed
    before that accept is processed, and the initiator yields to the event
    loop once before returning — asyncio's documented FIFO callback ordering
    then guarantees the earlier-queued task ran first.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        policy: ContactPolicy | None = None,
        payload_types: tuple[str, ...] = DEFAULT_PAYLOAD_TYPES,
        endpoints: dict[str, str] | None = None,
        approval_fn: ApprovalFn | None = None,
        on_session: SessionCallback | None = None,
        on_group: GroupCallback | None = None,
        session_store: SessionStore | None = None,
        capabilities: tuple[str, ...] | None = None,
        witness: WitnessSpec | None = None,
    ):
        self.identity = identity
        # Capabilities this node advertises. Defaults to the reference set plus
        # PQ if a KEM backend is installed; overridable for testing/opt-out.
        self.capabilities = capabilities if capabilities is not None else default_capabilities()
        # Witnessed posture (SPEC §7.1): configuring a witness makes this node
        # OFFER witnessed sessions; the posture activates only when the peer
        # offers it too and names the identical witness. The token is derived
        # from the config (never passed bare) so a node can't advertise a
        # posture it cannot honor.
        self.witness = witness
        if witness is not None and CAP_WITNESSED_V1 not in self.capabilities:
            self.capabilities = (*self.capabilities, CAP_WITNESSED_V1)
        if witness is None and CAP_WITNESSED_V1 in self.capabilities:
            raise ConfigurationError(
                f"{CAP_WITNESSED_V1} requires a witness: pass witness=WitnessSpec(...)"
            )
        # Handler for inbound witness.copy envelopes when THIS node is the
        # witness (e.g. WitnessReceiver.handle). Unset = not a witness.
        self.on_witness_copy: Callable[[Envelope], Awaitable[None]] | None = None
        self.revocations = RevocationRegistry()
        self.policy_engine = PolicyEngine(
            policy or ContactPolicy.open(),
            approval_fn,
            revoked_digests=lambda: self.revocations.digests,
            revoked_keys=lambda: self.revocations.revoked_keys,
        )
        self.payload_types = payload_types
        self.on_session = on_session
        self.session_store = session_store
        self.sessions: dict[str, Session] = {}
        # Live on_session callback tasks. Callbacks run as tasks, NOT inline in
        # the inbound dispatch loop: a callback that awaits session.receive()
        # (the obvious responder pattern) would otherwise deadlock the very
        # loop that has to deliver the message it is waiting for.
        self._callback_tasks: set[asyncio.Task] = set()
        self.groups = GroupManager(self, on_group)
        self._endpoints = endpoints
        # Rotatable agreement prekey ring for forward-secret initiates: initiators
        # seal the first knock to the current prekey; we keep the previous one for
        # a grace period so a card that raced a rotation still opens. Rotating and
        # dropping the old private makes past knocks unrecoverable (FS).
        self._prekey_ring: list[X25519PrivateKey] = [X25519PrivateKey.generate()]
        self._card = identity.card(
            payload_types=payload_types,
            endpoints=endpoints,
            policy_summary=self.policy_engine.policy.mode.value,
            agreement_prekey=self._prekey_public_b58(),
        )
        self._transport: Transport | None = None
        self._pending: dict[str, _PendingInitiation] = {}
        self._pending_resumes: dict[str, _PendingResume] = {}
        # Replay guard for resume requests, bounded FIFO so it can't grow without limit.
        # Replay guards map key -> expiry (epoch seconds). Entries need only be
        # retained for the freshness window; pruning expired entries first means
        # the FIFO count cap binds only under a genuine flood of >cap *unexpired*
        # frames, not merely a high cumulative volume over time.
        self._seen_resume_keys: OrderedDict[str, float] = OrderedDict()
        # Replay guard for establishing envelope ids (handshake.initiate / resume).
        self._seen_envelope_ids: OrderedDict[str, float] = OrderedDict()

    @property
    def address(self) -> str:
        return self.identity.address

    @property
    def owner(self) -> str | None:
        """This agent's own verified owner (root of its delegation chain)."""
        return self.identity.delegation_chain.root_issuer

    @property
    def card(self) -> AgentCard:
        return self._card

    @classmethod
    async def create(
        cls,
        identity: AgentIdentity,
        *,
        relay: str | Sequence[str] | None = None,
        transport: Transport | None = None,
        poll_interval: float = 1.0,
        policy: ContactPolicy | None = None,
        **kwargs: Any,
    ) -> AmpNode:
        """Construct a node and put it on the wire in one call.

        The transport comes from whichever argument is given (at most one):

        - ``relay=`` — one or more relay URLs. ``http(s)://`` speaks HTTP
          (``RelayTransport``); ``ws(s)://`` speaks WebSocket with HTTP
          fallback (``WsRelayTransport``). The card is registered and the
          mailbox served immediately.
        - ``transport=`` — an explicit ``Transport`` instance (attached; relay
          transports are also connected).
        - neither — a fresh private ``InMemoryTransport``, useful alone only
          for tests; to wire several in-process nodes together, share one
          transport or use ``fg_amp.testing.amp_pair``.

        Unlike the bare constructor (which historically defaults to
        ``ContactPolicy.open()``), ``create`` defaults to a **closed** policy:
        the node can initiate outward but accepts no inbound initiations until
        you opt in — pass ``policy=ContactPolicy.open()`` (or an allowlist /
        credentialed policy) to be reachable.

        Remaining keyword arguments go to ``AmpNode(...)`` unchanged. The
        returned node works with ``async with``.
        """
        if relay is not None and transport is not None:
            raise ConfigurationError("pass either relay= or transport=, not both")
        node = cls(
            identity=identity,
            policy=policy or ContactPolicy(mode=PolicyMode.CLOSED),
            **kwargs,
        )
        if relay is not None:
            # Imported here: transport.relay/.ws sit above the node layer.
            from ..transport.relay import RelayTransport
            from ..transport.ws import WsRelayTransport

            urls = [relay] if isinstance(relay, str) else list(relay)
            bad = [u for u in urls if not u.startswith(("http://", "https://", "ws://", "wss://"))]
            if bad:
                raise ConfigurationError(
                    f"relay URL(s) {bad} have no recognized scheme; "
                    "use http(s):// for HTTP polling or ws(s):// for WebSocket"
                )
            use_ws = any(u.startswith(("ws://", "wss://")) for u in urls)
            # Relay base URLs are HTTP; the WS transport derives its socket
            # URL from them, so normalize ws(s):// schemes back to http(s).
            bases = [
                u.replace("ws://", "http://", 1).replace("wss://", "https://", 1) for u in urls
            ]
            transport = WsRelayTransport(bases) if use_ws else RelayTransport(bases)
        if transport is None:
            from ..transport.memory import InMemoryTransport

            transport = InMemoryTransport()
        connect = getattr(transport, "connect", None)
        if connect is not None:
            try:
                await connect(node, poll_interval)  # registers card + serves mailbox
            except BaseException:
                # Don't leak the transport we just built (poll tasks, aiohttp
                # client) when the connect itself fails.
                disconnect = getattr(transport, "disconnect", None)
                if disconnect is not None:
                    try:
                        await disconnect(node)
                    except Exception:  # noqa: BLE001 — cleanup is best-effort
                        _log.debug("transport cleanup after failed connect", exc_info=True)
                raise
        else:
            node.attach(transport)
        return node

    def attach(self, transport: Transport) -> None:
        self._transport = transport
        transport.bind(self.address, self._on_envelope)

    def detach(self) -> None:
        if self._transport is not None:
            self._transport.unbind(self.address)
            self._transport = None

    async def __aenter__(self) -> AmpNode:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    def _spawn_session_callback(self, session: Session) -> None:
        """Run on_session as a tracked task so a callback may itself await
        session.receive() without deadlocking the inbound dispatch loop.

        Must be called BEFORE the accept frame is delivered — that ordering,
        plus the single yield in initiate()/wait()/resume(), is what makes the
        class-level on_session ordering contract deterministic."""
        if self.on_session is None:
            return
        task = asyncio.create_task(self._run_session_callback(session))
        self._callback_tasks.add(task)
        task.add_done_callback(self._callback_tasks.discard)

    async def _run_session_callback(self, session: Session) -> None:
        try:
            await self.on_session(session)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — application callback, log don't crash the node
            _log.exception("on_session callback failed for session %s", session.session_id)

    async def aclose(self, reason: str = "node shutting down") -> None:
        """Gracefully shut the node down: cancel outstanding on_session
        callbacks, send best-effort close frames for all live sessions, fail
        any in-flight handshakes/resumes, and take the node off the wire.

        If the attached transport is connection-oriented (exposes
        ``disconnect``, e.g. the relay transports), it is disconnected for
        this node — stopping the poll/WS task and, when this was the last
        connected node, closing the underlying HTTP client. Plain transports
        are simply detached.
        """
        # Cancel callbacks FIRST: one may be blocked in session.receive(),
        # which closing the session would not unblock.
        for task in list(self._callback_tasks):
            task.cancel()
        if self._callback_tasks:
            await asyncio.gather(*self._callback_tasks, return_exceptions=True)
        self._callback_tasks.clear()
        for session in list(self.sessions.values()):
            if session.state is SessionState.ESTABLISHED:
                try:
                    await session.close(reason)
                except Exception:  # noqa: BLE001 — shutdown is best-effort
                    _log.debug("close frame failed for session %s", session.session_id)
        for pending in list(self._pending.values()):
            if not pending.future.done():
                pending.future.set_exception(SessionError("node closed"))
        for presume in list(self._pending_resumes.values()):
            if not presume.future.done():
                presume.future.set_exception(SessionError("node closed"))
        self._pending.clear()
        self._pending_resumes.clear()
        transport = self._transport
        disconnect = getattr(transport, "disconnect", None)
        if disconnect is not None:
            try:
                await disconnect(self)  # also detaches
            except Exception:  # noqa: BLE001 — shutdown is best-effort
                _log.debug("transport disconnect failed during aclose", exc_info=True)
                self.detach()
        else:
            self.detach()

    @staticmethod
    def _prune_expired(cache: OrderedDict[str, float], now_ts: float) -> None:
        # Entries are inserted in roughly expiry order, so drop from the front
        # until the first still-live entry.
        while cache:
            key = next(iter(cache))
            if cache[key] > now_ts:
                break
            del cache[key]

    def _guard_replay(self, envelope: Envelope) -> None:
        """Reject a stale-timestamped or already-seen establishing frame."""
        now = datetime.now(UTC)
        skew = abs((now - envelope.created_at).total_seconds())
        if skew > _MAX_CLOCK_SKEW_SECONDS:
            raise SessionError(
                f"envelope {envelope.id} timestamp is {skew:.0f}s outside the "
                f"{_MAX_CLOCK_SKEW_SECONDS:.0f}s freshness window"
            )
        self._prune_expired(self._seen_envelope_ids, now.timestamp())
        if envelope.id in self._seen_envelope_ids:
            raise SessionError(f"replayed envelope id {envelope.id}")
        # Remember until a replay could no longer pass the freshness check above.
        self._seen_envelope_ids[envelope.id] = (
            envelope.created_at.timestamp() + _MAX_CLOCK_SKEW_SECONDS
        )
        while len(self._seen_envelope_ids) > _MAX_SEEN_ENVELOPE_IDS:
            self._seen_envelope_ids.popitem(last=False)

    def _supersede_session(self, session_id: str) -> None:
        """Retire a live session object being replaced by a resume, so a single
        session id never maps to two live sessions."""
        existing = self.sessions.get(session_id)
        if existing is not None and existing.state is SessionState.ESTABLISHED:
            existing.state = SessionState.CLOSED
            existing.cancel_maintenance()  # cancel its orphan RTO task now

    def metrics(self) -> dict[str, int]:
        """Aggregate operational counters across this node's live sessions
        (sent/received/retransmitted/nacks/reorder/receipts_dropped/…)."""
        totals: dict[str, int] = {}
        for session in self.sessions.values():
            for key, value in session.stats.model_dump().items():
                totals[key] = totals.get(key, 0) + value
        totals["live_sessions"] = len(self.sessions)
        return totals

    def forget_expired_initiations(self) -> int:
        """Drop handshakes whose peer never answered in time. Returns the count.

        Deferred initiations survive the call that created them, so this is what
        keeps a node that knocks on sleeping peers from growing without bound.
        Called automatically before each new initiation.
        """
        now = time.monotonic()
        stale = [
            sid for sid, pending in self._pending.items() if pending.expires_at <= now
        ]
        for sid in stale:
            pending = self._pending.pop(sid, None)
            if pending and not pending.future.done():
                pending.future.set_exception(
                    SessionError(f"handshake {sid} expired before the peer answered")
                )
                # Nobody may be awaiting a deferred future; retrieving the
                # exception here keeps asyncio from logging it as unhandled.
                pending.future.exception()
        return len(stale)

    def forget_closed_sessions(self) -> int:
        """Drop references to sessions that are no longer established. Returns
        the number pruned. Called automatically as sessions close; exposed for
        callers that want to reclaim eagerly."""
        stale = [
            sid
            for sid, s in self.sessions.items()
            if s.state is not SessionState.ESTABLISHED
        ]
        for sid in stale:
            self.sessions.pop(sid, None)
        return len(stale)

    # -- initiating ---------------------------------------------------------

    async def initiate(
        self,
        peer_card: AgentCard,
        purpose: str = "",
        mode: SessionMode = SessionMode.EPHEMERAL,
        payload_types: tuple[str, ...] | None = None,
        ttl_seconds: float = 3600.0,
        timeout: float = _HANDSHAKE_TIMEOUT_SECONDS,
        wait: bool = True,
    ) -> Session | PendingInitiation:
        """Open a session with a peer. Resolves on accept; raises PolicyRejection on refusal.

        With ``wait=False`` this returns a :class:`PendingInitiation` as soon as
        the handshake is delivered, instead of blocking for an answer. Use it to
        contact a peer that may be offline: the relay holds the knock in its
        mailbox, and the session materializes whenever the peer connects and
        replies. Blocking would otherwise fail after ``timeout`` even though the
        knock was delivered perfectly well.
        """
        transport = self._require_transport()
        peer_card.verify()
        session_id = str(uuid.uuid4())
        ephemeral = X25519PrivateKey.generate()
        # Offer a fresh ML-KEM-768 encapsulation key when we advertise PQ, so the
        # responder can contribute a post-quantum secret to the session key.
        pq_private = None
        pq_kem_key = None
        if CAP_PQ_ML_KEM_768 in self.capabilities and pqkem.PQ_AVAILABLE:
            pq_private = pqkem.generate_kem()
            pq_kem_key = pqkem.encapsulation_key_b64(pq_private)
        initiate = HandshakeInitiate(
            session_id=session_id,
            card=self.card,
            delegation_chain=self.identity.delegation_chain,
            mode=mode,
            purpose=purpose,
            payload_types=payload_types or self.payload_types,
            ttl_ms=round(ttl_seconds * 1000),
            ephemeral_key=base64.b64encode(ephemeral.public_key().public_bytes_raw()).decode(),
            capabilities=self.capabilities,
            pq_kem_key=pq_kem_key,
            witness=self.witness,
        )
        envelope = self._sealed_envelope(
            EnvelopeType.HANDSHAKE_INITIATE, peer_card, session_id, initiate
        )
        future: asyncio.Future[Session] = asyncio.get_running_loop().create_future()
        self.forget_expired_initiations()
        if len(self._pending) >= _MAX_PENDING_INITIATIONS:
            raise SessionError(
                f"too many handshakes in flight ({_MAX_PENDING_INITIATIONS}); "
                "cancel deferred initiations that will never be answered"
            )
        # A deferred knock stays valid for as long as the session it offers.
        lifetime = ttl_seconds if not wait else timeout
        self._pending[session_id] = _PendingInitiation(
            ephemeral,
            initiate,
            future,
            peer_card.address,
            pq_private=pq_private,
            expires_at=time.monotonic() + max(lifetime, 0.0),
        )
        if not wait:
            # Deliver and hand back a handle. The pending entry deliberately
            # stays alive so a late accept still resolves; the caller owns its
            # lifetime via PendingInitiation.cancel().
            try:
                await transport.deliver(envelope)
            except Exception:
                self._pending.pop(session_id, None)
                raise
            return PendingInitiation(self, session_id, future)

        try:
            await transport.deliver(envelope)
            session = await asyncio.wait_for(future, timeout)
        finally:
            self._pending.pop(session_id, None)
        # Over an in-process transport the whole handshake can unwind
        # synchronously, and on 3.12+ wait_for on an already-done future
        # returns without touching the event loop — so the acceptor's spawned
        # on_session task would not have run yet. One explicit yield restores
        # the guarantee callers have always had: by the time initiate()
        # returns, the peer's on_session callback has at least started.
        await asyncio.sleep(0)
        return session

    async def create_group(
        self,
        member_cards: list[AgentCard],
        purpose: str = "",
        mode: SessionMode = SessionMode.EPHEMERAL,
        ttl_seconds: float = 3600.0,
    ) -> GroupSession:
        """Found a multi-agent group: pairwise sessions to every member, full mesh."""
        return await self.groups.create(member_cards, purpose, mode, ttl_seconds)

    # -- persistence & resume -------------------------------------------------

    def persist_session(self, session: Session) -> SessionRecord:
        """Snapshot a persistent session into the store (no key material)."""
        if self.session_store is None:
            raise ConfigurationError("node has no session_store configured")
        record = SessionRecord.from_session(session)
        self.session_store.save(record)
        return record

    async def resume(
        self,
        session_id: str,
        timeout: float = _HANDSHAKE_TIMEOUT_SECONDS,
    ) -> Session:
        """Resume a stored persistent session with a fresh session key."""
        transport = self._require_transport()
        if self.session_store is None:
            raise ConfigurationError("node has no session_store configured")
        record = self.session_store.load(session_id)
        if record is None:
            raise SessionNotFoundError(f"no stored session {session_id}")
        if datetime.now(UTC) >= record.expires_at:
            raise SessionError(f"stored session {session_id} has expired")
        ephemeral = X25519PrivateKey.generate()
        nonce = base64.b64encode(os.urandom(16)).decode()
        pq_private = None
        pq_kem_key = None
        if CAP_PQ_ML_KEM_768 in self.capabilities and pqkem.PQ_AVAILABLE:
            pq_private = pqkem.generate_kem()
            pq_kem_key = pqkem.encapsulation_key_b64(pq_private)
        request = ResumeRequest(
            session_id=session_id,
            card=self.card,
            delegation_chain=self.identity.delegation_chain,
            transcript_head=record.transcript_head,
            send_seq=record.send_seq,
            recv_seq=record.recv_seq,
            ephemeral_key=base64.b64encode(ephemeral.public_key().public_bytes_raw()).decode(),
            nonce=nonce,
            pq_kem_key=pq_kem_key,
        )
        envelope = self._sealed_envelope(
            EnvelopeType.SESSION_RESUME, record.peer_card, session_id, request
        )
        future: asyncio.Future[Session] = asyncio.get_running_loop().create_future()
        self._pending_resumes[session_id] = _PendingResume(
            ephemeral, record, future, nonce, pq_private=pq_private
        )
        try:
            await transport.deliver(envelope)
            session = await asyncio.wait_for(future, timeout)
        finally:
            self._pending_resumes.pop(session_id, None)
        await asyncio.sleep(0)  # let the peer's on_session task start — see initiate()
        return session

    # -- inbound routing ------------------------------------------------------

    async def _on_envelope(self, envelope: Envelope) -> None:
        envelope.verify_signature()
        # Reject an incompatible protocol major version rather than
        # mis-processing it. Same major = wire-compatible by policy.
        if envelope.amp.split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
            _log.warning(
                "dropping envelope %s: unsupported protocol version %s (this node speaks %s)",
                envelope.id,
                envelope.amp,
                PROTOCOL_VERSION,
            )
            raise ProtocolVersionError(
                f"unsupported protocol version {envelope.amp}; this node speaks {PROTOCOL_VERSION}"
            )
        if envelope.to != self.address:
            raise SessionError("envelope not addressed to this node")
        # A revoked identity key is refused outright — regardless of contact
        # policy — so a compromised agent can be cut off entirely, not just
        # stripped of delegated authority.
        if self.revocations.is_key_revoked(envelope.sender):
            _log.warning("dropping envelope from key-revoked agent %s", envelope.sender)
            raise SessionError(f"agent identity key {envelope.sender} is revoked")
        # Session-establishing frames must be fresh and not previously seen, so a
        # captured handshake/resume cannot be replayed after the session is gone
        # to spawn a spurious responder session. In-session frames are already
        # replay-protected by the per-session sequence + ratchet.
        if envelope.type in (EnvelopeType.HANDSHAKE_INITIATE, EnvelopeType.SESSION_RESUME):
            self._guard_replay(envelope)
        match envelope.type:
            case EnvelopeType.HANDSHAKE_INITIATE:
                await self._handle_initiate(envelope)
            case EnvelopeType.HANDSHAKE_ACCEPT:
                self._handle_accept(envelope)
            case EnvelopeType.HANDSHAKE_REJECT:
                self._handle_reject(envelope)
            case EnvelopeType.SESSION_RESUME:
                await self._handle_resume(envelope)
            case EnvelopeType.RESUME_ACCEPT:
                self._handle_resume_accept(envelope)
            case EnvelopeType.RESUME_REJECT:
                self._handle_resume_reject(envelope)
            case EnvelopeType.WITNESS_COPY:
                await self._handle_witness_copy(envelope)
            case _:
                await self._handle_session_traffic(envelope)

    async def _handle_initiate(self, envelope: Envelope) -> None:
        plaintext = self._open_sealed(envelope.body_bytes)
        initiate = HandshakeInitiate.model_validate(json.loads(plaintext))
        initiate.card.verify()
        if initiate.card.address != envelope.sender:
            raise SignatureError("handshake card address does not match envelope sender")
        if initiate.session_id != envelope.session_id:
            raise SessionError("handshake session_id does not match envelope")
        if initiate.session_id in self.sessions:
            return  # replayed initiate: never clobber an existing session

        try:
            peer_scopes = initiate.delegation_chain.verify(
                initiate.card.address,
                revoked=self.revocations.digests,
                revoked_keys=self.revocations.revoked_keys,
            )
        except DelegationError as exc:
            await self._send_reject(initiate, f"invalid delegation chain: {exc}")
            return

        active = sum(
            1 for s in self.sessions.values() if s.state is SessionState.ESTABLISHED
        )
        result = await self.policy_engine.evaluate(initiate, active_sessions=active)
        if result.decision is not Decision.ACCEPT:
            await self._send_reject(initiate, result.reason)
            return

        ephemeral = X25519PrivateKey.generate()
        # Negotiate capabilities (intersection). If PQ is agreed and the peer
        # sent an encapsulation key, encapsulate to it and mix the PQ secret into
        # the session key. capabilities/pq_kem_key are integrity-protected: they
        # ride inside the signed, sealed initiate, so a MITM can't strip PQ.
        negotiated = negotiate(self.capabilities, initiate.capabilities)
        pq_shared = b""
        pq_ciphertext = None
        if CAP_PQ_ML_KEM_768 in negotiated and initiate.pq_kem_key and pqkem.PQ_AVAILABLE:
            pq_shared, pq_ciphertext = pqkem.encapsulate_to(initiate.pq_kem_key)
        # session.capabilities must reflect what ACTUALLY happened: only claim PQ
        # if a KEM secret was really exchanged, so an app that gates on
        # CAP_PQ_ML_KEM_768 to decide "harvest-now-decrypt-later safe" isn't lied
        # to when a peer advertised the token but sent no key material.
        negotiated = _with_pq(negotiated, pq_ciphertext is not None)
        # Witnessed posture: when negotiated, both sides MUST name the same
        # witness. A missing or divergent witness block is a handshake reject,
        # never a silent fallback to sealed (SPEC §7.1).
        witness_spec = None
        if CAP_WITNESSED_V1 in negotiated:
            try:
                witness_spec = require_witness_match(self.witness, initiate.witness)
            except SessionError as exc:
                await self._send_reject(initiate, str(exc))
                return
        # Bind BOTH ephemerals into the KDF salt (initiate digest + responder's
        # ephemeral public), so the session key commits to the full handshake,
        # not just the initiator's contribution.
        salt = _session_salt(
            initiate.transcript_salt(), ephemeral.public_key().public_bytes_raw()
        )
        session_key = derive_session_key(
            ephemeral, initiate.ephemeral_key_bytes, salt, pq_shared=pq_shared
        )
        session = self._build_session(
            initiate.session_id,
            initiate.mode,
            initiate.card,
            session_key,
            result.accepted_payload_types,
            initiate.ttl_seconds,
            initiator=False,
            purpose=initiate.purpose,
            peer_owner=initiate.delegation_chain.root_issuer,
            peer_scopes=peer_scopes,
            peer_chain=initiate.delegation_chain,
            dh_ratchet_initiator=False,  # accept-sender = ratchet responder
            dh_own_private=ephemeral,
            capabilities=frozenset(negotiated),
            witness=witness_spec,
        )
        accept = HandshakeAccept(
            session_id=initiate.session_id,
            card=self.card,
            delegation_chain=self.identity.delegation_chain,
            accepted_payload_types=result.accepted_payload_types,
            ttl_ms=initiate.ttl_ms,
            ephemeral_key=base64.b64encode(ephemeral.public_key().public_bytes_raw()).decode(),
            capabilities=negotiated,
            pq_ciphertext=pq_ciphertext,
            witness=witness_spec,
        )
        response = self._sealed_envelope(
            EnvelopeType.HANDSHAKE_ACCEPT, initiate.card, initiate.session_id, accept
        )
        # Spawn the on_session task BEFORE delivering the accept: the task is
        # then queued ahead of the initiator's wakeup, so the callback's first
        # synchronous segment always runs before the peer's initiate() returns
        # — the ordering the inline call used to guarantee.
        if not await self.groups.claim_inbound_session(session):
            self._spawn_session_callback(session)
        await self._require_transport().deliver(response)

    def _handle_accept(self, envelope: Envelope) -> None:
        # Consume the pending entry so a duplicated/replayed accept can't rebuild
        # a second session and overwrite the live one's seq/ratchet state.
        pending = self._pending.pop(envelope.session_id or "", None)
        if pending is None:
            return  # stale, duplicate, or replayed accept
        plaintext = self._open_sealed(envelope.body_bytes)
        accept = HandshakeAccept.model_validate(json.loads(plaintext))
        try:
            accept.card.verify()
            if accept.card.address != envelope.sender:
                raise SignatureError("accept card address does not match envelope sender")
            if envelope.sender != pending.peer_address:
                raise SignatureError("accept came from a different peer than addressed")
            if accept.session_id != pending.initiate.session_id:
                raise SessionError("accept session_id does not match initiation")
            peer_scopes = accept.delegation_chain.verify(
                accept.card.address,
                revoked=self.revocations.digests,
                revoked_keys=self.revocations.revoked_keys,
            )
            # Witnessed posture: an accept claiming the capability MUST echo
            # exactly the witness WE proposed; a divergent (or unsolicited)
            # witness fails the handshake rather than binding us to an
            # auditor we never agreed to.
            witness_spec = None
            if CAP_WITNESSED_V1 in accept.capabilities:
                witness_spec = require_witness_match(
                    pending.initiate.witness, accept.witness
                )
        except Exception as exc:
            if not pending.future.done():
                pending.future.set_exception(exc)
            return
        # Recover the PQ secret if the responder encapsulated to our KEM key.
        pq_shared = b""
        if (
            CAP_PQ_ML_KEM_768 in accept.capabilities
            and accept.pq_ciphertext
            and pending.pq_private is not None
        ):
            pq_shared = pqkem.decapsulate(pending.pq_private, accept.pq_ciphertext)
        salt = _session_salt(
            pending.initiate.transcript_salt(), accept.ephemeral_key_bytes
        )
        session_key = derive_session_key(
            pending.ephemeral, accept.ephemeral_key_bytes, salt, pq_shared=pq_shared
        )
        # Record PQ as in force only if we actually derived a KEM secret.
        capabilities = frozenset(_with_pq(tuple(accept.capabilities), bool(pq_shared)))
        session = self._build_session(
            accept.session_id,
            pending.initiate.mode,
            accept.card,
            session_key,
            accept.accepted_payload_types,
            accept.ttl_seconds,
            initiator=True,
            purpose=pending.initiate.purpose,
            peer_owner=accept.delegation_chain.root_issuer,
            peer_scopes=peer_scopes,
            peer_chain=accept.delegation_chain,
            dh_ratchet_initiator=True,  # accept-receiver = ratchet initiator
            dh_peer_public=accept.ephemeral_key_bytes,
            capabilities=capabilities,
            witness=witness_spec,
        )
        if not pending.future.done():
            pending.future.set_result(session)

    def _handle_reject(self, envelope: Envelope) -> None:
        pending = self._pending.get(envelope.session_id or "")
        if pending is None:
            return
        # Only the addressed peer may abort our pending handshake. session_id
        # rides in cleartext routing metadata, so without this any on-path party
        # (or malicious relay) could sign a reject for an observed session_id and
        # deny the handshake.
        if envelope.sender != pending.peer_address:
            _log.warning(
                "dropping handshake.reject for %s from non-peer %s",
                envelope.session_id,
                envelope.sender,
            )
            return
        reject = HandshakeReject.model_validate(json.loads(envelope.body_bytes))
        if not pending.future.done():
            pending.future.set_exception(PolicyRejection(reject.reason))

    # -- resume protocol ---------------------------------------------------------

    async def _handle_resume(self, envelope: Envelope) -> None:
        plaintext = self._open_sealed(envelope.body_bytes)
        request = ResumeRequest.model_validate(json.loads(plaintext))
        request.card.verify()

        async def reject(reason: str) -> None:
            response = Envelope(
                type=EnvelopeType.RESUME_REJECT,
                sender=self.address,
                to=envelope.sender,
                session_id=request.session_id,
                body=Envelope.encode_body(json.dumps({"reason": reason}).encode()),
            ).signed(self.identity.keys)
            await self._require_transport().deliver(response)

        if request.card.address != envelope.sender:
            raise SignatureError("resume card address does not match envelope sender")
        now_ts = datetime.now(UTC).timestamp()
        self._prune_expired(self._seen_resume_keys, now_ts)
        # Key on the DECODED key, not its base64 text. One 32-byte key has
        # several valid base64 spellings, so a text key would let the same
        # resume request slip past this guard once per spelling.
        try:
            replay_key = base64.b64decode(request.ephemeral_key, validate=True)
        except Exception as exc:
            raise SignatureError("resume ephemeral_key is not valid base64") from exc
        if replay_key in self._seen_resume_keys:
            return  # replayed resume request: drop silently
        # The carrying envelope was already freshness-checked in _guard_replay, so
        # remembering this key for one freshness window suffices to block replays.
        self._seen_resume_keys[replay_key] = now_ts + _MAX_CLOCK_SKEW_SECONDS
        while len(self._seen_resume_keys) > _MAX_SEEN_RESUME_KEYS:
            self._seen_resume_keys.popitem(last=False)
        record = self.session_store.load(request.session_id) if self.session_store else None
        if record is None:
            await reject("no stored session")
            return
        if record.peer_card.address != envelope.sender:
            await reject("stored session belongs to a different peer")
            return
        if datetime.now(UTC) >= record.expires_at:
            await reject("stored session has expired")
            return
        # Mirrored view must line up: their transcript head equals ours, and
        # their counters are the mirror of ours.
        if (
            request.transcript_head != record.transcript_head
            or request.send_seq != record.recv_seq
            or request.recv_seq != record.send_seq
        ):
            await reject("resume state does not match stored session")
            return
        # Re-verify authority FRESH: a delegation that expired or was revoked
        # since the session was stored must not be reinstated. Scopes are
        # recomputed from the current chain, never restored from the record.
        try:
            peer_scopes = request.delegation_chain.verify(
                request.card.address,
                revoked=self.revocations.digests,
                revoked_keys=self.revocations.revoked_keys,
            )
        except DelegationError as exc:
            await reject(f"delegation no longer valid: {exc}")
            return

        # Only now — after the request is fully validated as coming from the
        # real peer with matching state — retire any prior live session for this
        # id. Doing this earlier would let anyone who knows a session_id (it is
        # cleartext routing metadata) force-close a victim's session.
        self._supersede_session(request.session_id)
        ephemeral = X25519PrivateKey.generate()
        pq_shared = b""
        pq_ciphertext = None
        if request.pq_kem_key and pqkem.PQ_AVAILABLE:
            pq_shared, pq_ciphertext = pqkem.encapsulate_to(request.pq_kem_key)
        session_key = derive_session_key(
            ephemeral,
            request.ephemeral_key_bytes,
            resume_salt(record.transcript_head_bytes, request.nonce_bytes),
            pq_shared=pq_shared,
        )
        ttl_remaining = (record.expires_at - datetime.now(UTC)).total_seconds()
        session = self._build_session(
            record.session_id,
            SessionMode.PERSISTENT,
            record.peer_card,
            session_key,
            record.payload_types,
            ttl_remaining,
            initiator=record.initiator,
            peer_owner=request.delegation_chain.root_issuer,
            peer_scopes=peer_scopes,
            peer_chain=request.delegation_chain,
            restored=RestoredState(
                transcript_head=record.transcript_head_bytes,
                transcript_length=record.transcript_length,
                send_seq=record.send_seq,
                recv_seq=record.recv_seq,
            ),
            dh_ratchet_initiator=False,  # resume-accept sender = ratchet responder
            dh_own_private=ephemeral,
            capabilities=_resume_capabilities(bool(pq_shared), record.witness),
            witness=record.witness,
        )
        accept = ResumeAccept(
            session_id=record.session_id,
            card=self.card,
            delegation_chain=self.identity.delegation_chain,
            ephemeral_key=base64.b64encode(ephemeral.public_key().public_bytes_raw()).decode(),
            nonce=request.nonce,  # bind the accept to this specific request
            pq_ciphertext=pq_ciphertext,
        )
        response = self._sealed_envelope(
            EnvelopeType.RESUME_ACCEPT, record.peer_card, record.session_id, accept
        )
        # Spawned before deliver — see _handle_initiate for the ordering rationale.
        self._spawn_session_callback(session)
        await self._require_transport().deliver(response)

    def _handle_resume_accept(self, envelope: Envelope) -> None:
        # Peek (not pop) here: a stale-nonce replay of a *prior* resume attempt
        # must not consume the current attempt's pending entry — it's dropped on
        # the nonce check below, leaving the genuine accept still awaited. Only a
        # nonce-matching accept consumes the entry, so a duplicated genuine accept
        # (same nonce, e.g. at-least-once relay redelivery) can't rebuild and
        # supersede the live resumed session.
        pending = self._pending_resumes.get(envelope.session_id or "")
        if pending is None:
            return
        if envelope.sender != pending.record.peer_card.address:
            return
        plaintext = self._open_sealed(envelope.body_bytes)
        accept = ResumeAccept.model_validate(json.loads(plaintext))
        record = pending.record
        # Replay guard: the accept must echo THIS attempt's fresh nonce. A
        # captured accept from a prior resume of the same session (session_id is
        # stable across resumes) carries a stale nonce — drop it silently and
        # keep waiting for the genuine accept, rather than resolving the resume
        # into a dead session key that can never decrypt.
        if not hmac.compare_digest(accept.nonce, pending.nonce):
            _log.warning(
                "session %s: dropping resume-accept with mismatched nonce (replay?)",
                envelope.session_id,
            )
            return
        # Nonce matches: this is the genuine accept for the current attempt.
        # Consume the pending entry so a duplicate can't re-run supersede/build.
        self._pending_resumes.pop(envelope.session_id or "", None)
        try:
            accept.card.verify()
            if accept.card.address != envelope.sender:
                raise SignatureError("resume-accept card does not match envelope sender")
            peer_scopes = accept.delegation_chain.verify(
                accept.card.address,
                revoked=self.revocations.digests,
                revoked_keys=self.revocations.revoked_keys,
            )
        except Exception as exc:
            if not pending.future.done():
                pending.future.set_exception(exc)
            return
        pq_shared = b""
        if accept.pq_ciphertext and pending.pq_private is not None:
            pq_shared = pqkem.decapsulate(pending.pq_private, accept.pq_ciphertext)
        session_key = derive_session_key(
            pending.ephemeral,
            accept.ephemeral_key_bytes,
            resume_salt(record.transcript_head_bytes, base64.b64decode(pending.nonce)),
            pq_shared=pq_shared,
        )
        self._supersede_session(record.session_id)
        ttl_remaining = (record.expires_at - datetime.now(UTC)).total_seconds()
        session = self._build_session(
            record.session_id,
            SessionMode.PERSISTENT,
            record.peer_card,
            session_key,
            record.payload_types,
            ttl_remaining,
            initiator=record.initiator,
            peer_owner=accept.delegation_chain.root_issuer,
            peer_scopes=peer_scopes,
            peer_chain=accept.delegation_chain,
            restored=RestoredState(
                transcript_head=record.transcript_head_bytes,
                transcript_length=record.transcript_length,
                send_seq=record.send_seq,
                recv_seq=record.recv_seq,
            ),
            dh_ratchet_initiator=True,  # resume-accept receiver = ratchet initiator
            dh_peer_public=accept.ephemeral_key_bytes,
            capabilities=_resume_capabilities(bool(pq_shared), record.witness),
            witness=record.witness,
        )
        if not pending.future.done():
            pending.future.set_result(session)

    def _handle_resume_reject(self, envelope: Envelope) -> None:
        pending = self._pending_resumes.get(envelope.session_id or "")
        if pending is None:
            return
        # Same guard as _handle_reject: only the session's known peer may abort a
        # pending resume, else any on-path party could deny it via a signed reject.
        if envelope.sender != pending.record.peer_card.address:
            _log.warning(
                "dropping resume.reject for %s from non-peer %s",
                envelope.session_id,
                envelope.sender,
            )
            return
        reason = json.loads(envelope.body_bytes).get("reason", "resume rejected")
        if not pending.future.done():
            pending.future.set_exception(ResumeError(reason))

    async def _handle_witness_copy(self, envelope: Envelope) -> None:
        """Route a witness copy to this node's witness handler, if it has one.

        The copy is addressed to us because two OTHER parties named us their
        witness; without a configured handler we are not acting as one, and the
        copy is refused loudly rather than dropped into a void.
        """
        if self.on_witness_copy is None:
            raise SessionError(
                "received a witness.copy but this node has no witness handler "
                "(set node.on_witness_copy, e.g. to a WitnessReceiver.handle)"
            )
        await self.on_witness_copy(envelope)

    async def _handle_session_traffic(self, envelope: Envelope) -> None:
        session = self.sessions.get(envelope.session_id or "")
        if session is None:
            raise SessionNotFoundError(f"no session {envelope.session_id} on this node")
        if envelope.sender != session.peer_card.address:
            raise SignatureError("envelope sender is not the session peer")
        await session.handle_incoming(envelope)

    # -- internals -------------------------------------------------------------

    def _build_session(
        self,
        session_id: str,
        mode: SessionMode,
        peer_card: AgentCard,
        session_key: bytes,
        payload_types: tuple[str, ...],
        ttl_seconds: float,
        initiator: bool,
        purpose: str = "",
        peer_owner: str | None = None,
        peer_scopes: frozenset[str] = frozenset(),
        peer_chain=None,
        restored: RestoredState | None = None,
        dh_ratchet_initiator: bool = True,
        dh_own_private=None,
        dh_peer_public: bytes | None = None,
        capabilities: frozenset[str] = frozenset(),
        witness: WitnessSpec | None = None,
    ) -> Session:
        transport = self._require_transport()
        session = Session(
            session_id=session_id,
            mode=mode,
            own_keys=self.identity.keys,
            own_address=self.address,
            peer_card=peer_card,
            session_key=session_key,
            payload_types=payload_types,
            ttl_seconds=ttl_seconds,
            send_fn=transport.deliver,
            initiator=initiator,
            purpose=purpose,
            peer_owner=peer_owner,
            peer_scopes=peer_scopes,
            restored=restored,
            dh_ratchet_initiator=dh_ratchet_initiator,
            dh_own_private=dh_own_private,
            dh_peer_public=dh_peer_public,
            capabilities=capabilities,
            own_chain=self.identity.delegation_chain,
            peer_chain=peer_chain,
            witness=witness,
        )
        session.on_payload = self.groups.dispatch
        session.on_closed = lambda s: self.sessions.pop(s.session_id, None)
        self.sessions[session_id] = session
        # Arm the maintenance loop at establishment (not lazily on first send),
        # so it also reaps a never-sent session whose peer vanishes — otherwise
        # its TTL is only checked on send/receive, which never happen. The loop
        # no-ops the retransmit branch when the send buffer is empty.
        session.arm_maintenance()
        return session

    def _prekey_public_b58(self) -> str:
        return base58_encode(self._prekey_ring[0].public_key().public_bytes_raw())

    def rotate_prekey(self) -> AgentCard:
        """Rotate the forward-secrecy prekey: mint a new one, retain the previous
        for a grace window, and reissue the (re-signed) card. Callers should
        re-register the returned card wherever it is published (relay/well-known).
        Dropping the previous key on the next rotation makes knocks sealed to it
        unrecoverable — that is the forward-secrecy gain."""
        new_key = X25519PrivateKey.generate()
        self._prekey_ring = [new_key, self._prekey_ring[0]]  # keep one previous
        self._card = self.identity.card(
            payload_types=self.payload_types,
            endpoints=self._endpoints,
            policy_summary=self.policy_engine.policy.mode.value,
            agreement_prekey=self._prekey_public_b58(),
        )
        return self._card

    def _open_sealed(self, data: bytes) -> bytes:
        """Open a sealed payload, trying the current+previous prekeys first (the
        forward-secret targets) then the static agreement key (back-compat with
        an initiator that sealed to the static key)."""
        from ..errors import DecryptionError

        for private in (*self._prekey_ring, self.identity.keys.agreement_key):
            try:
                return open_sealed(private, data)
            except Exception:  # noqa: BLE001 — try the next candidate key
                continue
        raise DecryptionError("could not open sealed payload with any current key")

    def _sealed_envelope(
        self,
        envelope_type: EnvelopeType,
        peer_card: AgentCard,
        session_id: str,
        payload,
    ) -> Envelope:
        sealed = seal(
            peer_card.seal_target(),
            json.dumps(payload.model_dump(mode="json")).encode(),
        )
        return Envelope(
            type=envelope_type,
            sender=self.address,
            to=peer_card.address,
            session_id=session_id,
            body=Envelope.encode_body(sealed),
        ).signed(self.identity.keys)

    async def _send_reject(self, initiate: HandshakeInitiate, reason: str) -> None:
        reject = HandshakeReject(session_id=initiate.session_id, reason=reason)
        envelope = Envelope(
            type=EnvelopeType.HANDSHAKE_REJECT,
            sender=self.address,
            to=initiate.card.address,
            session_id=initiate.session_id,
            body=Envelope.encode_body(json.dumps(reject.model_dump(mode="json")).encode()),
        ).signed(self.identity.keys)
        await self._require_transport().deliver(envelope)

    def _require_transport(self) -> Transport:
        if self._transport is None:
            raise ConfigurationError("node is not attached to a transport")
        return self._transport
