"""The Session: an established, encrypted conversation between two agents."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fg_agent_id import DelegationChain
from fg_agent_id.errors import SpendScopeError
from fg_agent_id.spend import SpendAuthority
from pydantic import BaseModel, Field

from ..bodies import (
    BodyRegistry,
    PaymentBody,
    PaymentKind,
    PaymentTracker,
    SpendLedger,
    TaskBody,
    TaskTracker,
    default_registry,
    is_typed_name,
)
from ..bodies.payment import Quote
from ..envelope.crypto import decrypt, encrypt
from ..envelope.envelope import Envelope, EnvelopeType
from ..errors import (
    BodyError,
    SequenceError,
    SessionError,
    SessionStateError,
    SpendRejectedError,
)
from ..identity.card import AgentCard
from ..identity.keys import KeyPair
from .ratchet import DoubleRatchet, derive_close_key
from .states import SessionMode, SessionState
from .transcript import Transcript
from .witness import WitnessSpec, build_witness_copy

_log = logging.getLogger("fg_amp.session")

_MAX_REORDER_WINDOW = 256  # future-seq frames buffered while waiting for a gap to fill
_MAX_SEND_BUFFER = 512  # retransmittable recently-sent frames
_MAX_MISSING_PER_RECEIPT = 64  # cap gap size reported in one NACK
# A responder that established a session but has neither received nor sent any
# frame past this window is treated as orphaned: its initiator completed the
# handshake and vanished (e.g. its own initiate timed out after we accepted).
# Reaping these bounds an attacker's ability to pin capacity to the grace window
# rather than the full (possibly hour-long) session TTL.
_ORPHAN_GRACE_SECONDS = 120.0


class Payload(BaseModel):
    """A decrypted application message."""

    content_type: str = "text/plain"
    content: Any = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def text(cls, text: str, **metadata: Any) -> Payload:
        return cls(content_type="text/plain", content=text, metadata=metadata)

    @classmethod
    def json_data(cls, data: Any, **metadata: Any) -> Payload:
        return cls(content_type="application/json", content=data, metadata=metadata)

    @classmethod
    def body(cls, model: Any, **metadata: Any) -> Payload:
        """Wrap a typed body model (anything with a ``TYPE`` wire name, e.g.
        ``TaskBody``) as a payload with its registry content type."""
        return cls(
            content_type=model.TYPE,
            content=model.model_dump(mode="json"),
            metadata=metadata,
        )


class ReceivedMessage(BaseModel):
    """A payload plus its verified provenance."""

    payload: Payload
    sender: str
    session_id: str
    seq: int
    received_at: datetime

    model_config = {"frozen": True}


SendFn = Callable[[Envelope], Awaitable[None]]


class SessionStats(BaseModel):
    """Per-session operational counters — snapshot with ``model_dump()``."""

    sent: int = 0
    received: int = 0
    retransmitted: int = 0       # frames we replayed on a peer NACK
    nacks_sent: int = 0          # gap reports we emitted
    reorder_buffered: int = 0    # frames held awaiting an earlier one
    receipts_dropped: int = 0    # replayed/stale receipts ignored
    backpressure_holds: int = 0  # in-order frames held undecoded while inbox full
    send_stalls: int = 0         # sends blocked on an exhausted peer window
    unrecoverable_closes: int = 0  # sessions closed for an unfillable gap


class RestoredState(BaseModel):
    """Counters and transcript position carried across a resume."""

    transcript_head: bytes
    transcript_length: int
    send_seq: int
    recv_seq: int

    model_config = {"frozen": True}


class Session:
    """One side of an established AMP session.

    Created by the node after a successful handshake; not constructed directly.
    Thread of trust: every inbound envelope was signature-verified by the node,
    sequence-checked and AEAD-decrypted here.
    """

    def __init__(
        self,
        session_id: str,
        mode: SessionMode,
        own_keys: KeyPair,
        own_address: str,
        peer_card: AgentCard,
        session_key: bytes,
        payload_types: tuple[str, ...],
        ttl_seconds: float,
        send_fn: SendFn,
        initiator: bool,
        purpose: str = "",
        peer_owner: str | None = None,
        peer_scopes: frozenset[str] = frozenset(),
        restored: RestoredState | None = None,
        retransmit_interval: float | None = 5.0,
        dh_ratchet_initiator: bool = True,
        dh_own_private=None,
        dh_peer_public: bytes | None = None,
        capabilities: frozenset[str] = frozenset(),
        body_registry: BodyRegistry | None = None,
        own_chain: DelegationChain | None = None,
        peer_chain: DelegationChain | None = None,
        witness: WitnessSpec | None = None,
    ):
        self.purpose = purpose
        # Typed-body layer: validates registry-typed payloads at both ends of
        # the pipe and tracks task/payment lifecycle legality for this session.
        self.body_registry = body_registry if body_registry is not None else default_registry()
        self.tasks = TaskTracker()
        self.payments = PaymentTracker()
        # Spend enforcement (SPEC §16.5): our own chain caps what we may
        # authorize; the peer's handshake-verified chain caps what we accept
        # from it. A None chain skips that side's check (direct construction
        # without identity plumbing) — node-built sessions always carry both.
        self._own_chain = own_chain
        self._peer_chain = peer_chain
        self.spend = SpendLedger()  # amounts we have authorized, per asset
        self.peer_spend = SpendLedger()  # amounts the peer has authorized, per asset
        # Witnessed posture (SPEC §7.1): when set, every send additionally
        # seals a copy of the plaintext to this witness and MUST NOT put the
        # message on the wire unless the copy could be produced.
        self.witness = witness
        self.session_id = session_id
        self.mode = mode
        self.peer_card = peer_card
        self.payload_types = payload_types
        # Negotiated capability set in force for this session (handshake
        # intersection of both peers' offers). Empty = baseline only.
        self.capabilities = capabilities
        self.state = SessionState.ESTABLISHED
        self.created_at = datetime.now(UTC)
        self.expires_at = self.created_at + timedelta(seconds=ttl_seconds)
        self.initiator = initiator
        self.peer_owner = peer_owner  # verified root issuer of the peer's chain
        self.peer_scopes = peer_scopes  # verified effective scopes of the peer
        self.transcript = Transcript(
            head=restored.transcript_head if restored else Transcript().head,
            length=restored.transcript_length if restored else 0,
        )
        self._own_keys = own_keys
        self._own_address = own_address
        # Double ratchet: per-message forward secrecy + per-turn post-compromise
        # security. Built from the handshake ephemerals — the accept-receiver is
        # the ratchet initiator, the accept-sender the responder.
        if dh_ratchet_initiator:
            if dh_peer_public is None:
                raise ValueError("ratchet initiator requires the peer ephemeral public key")
            self._ratchet = DoubleRatchet.initiator(session_key, dh_peer_public)
        else:
            if dh_own_private is None:
                raise ValueError("ratchet responder requires its own ephemeral private key")
            self._ratchet = DoubleRatchet.responder(session_key, dh_own_private)
        # Close keys stay derived from the initial root (both sides share it),
        # so a close authenticates regardless of ratchet position.
        send_dir, recv_dir = ("i2r", "r2i") if initiator else ("r2i", "i2r")
        self._close_send_key = derive_close_key(session_key, send_dir)
        self._close_recv_key = derive_close_key(session_key, recv_dir)
        self._send_fn = send_fn
        self._send_seq = restored.send_seq if restored else 0
        self._recv_seq = restored.recv_seq if restored else 0
        self._inbox: asyncio.Queue[ReceivedMessage] = asyncio.Queue()
        self._lock = asyncio.Lock()
        # Inbound is decoded under its own lock so concurrent delivery (e.g. the
        # HTTP inbox dispatching POSTs in parallel) can't interleave ratchet/seq
        # mutation. Out-of-order frames within a bounded window are buffered and
        # decoded once their turn comes (the ratchet must advance in seq order).
        self._recv_lock = asyncio.Lock()
        self._reorder: dict[int, Envelope] = {}
        # Retransmit buffer: recently sent frames kept so a peer that detects a
        # gap (via a RECEIPT/NACK) can ask us to replay them — delivery survives
        # a lossy transport. Bounded FIFO; beyond it, loss needs a resume.
        self._send_buffer: OrderedDict[int, Envelope] = OrderedDict()
        # Monotonic receipt counters: we number the receipts we send, and track
        # the highest we've accepted, so replayed receipts are dropped.
        self._receipt_send_seq = 0
        self._receipt_recv_seq = 0
        # Windowed flow control. The receiver advertises remaining inbox capacity
        # in every receipt; the sender mirrors it here and stalls when it hits
        # zero, so a slow consumer applies real backpressure instead of the
        # sender overrunning it. None = the peer is unbounded (never stall). The
        # value is absolute (receipts carry remaining capacity, not deltas), so
        # each receipt re-syncs any local drift from per-send decrements.
        self._peer_recv_window: int | None = None
        self._window_event = asyncio.Event()
        self._window_event.set()
        # Last window we advertised, so a drain that reopens a previously-zero
        # window proactively re-advertises even without an inbound frame.
        self._last_recv_window_sent: int | None = None
        # Lightweight operational counters (loss/recovery visibility) so callers
        # can alarm on retransmit/reorder/eviction rates.
        self.stats = SessionStats()
        # Retransmit-on-timeout: pure NACK can't recover *tail* loss (a lost
        # frame with nothing after it produces no gap signal), so the sender
        # periodically replays unacked frames until the peer's cumulative ack
        # clears them. None disables the timer (e.g. for deterministic tests).
        self.retransmit_interval = retransmit_interval
        self._rto_task: asyncio.Task | None = None
        # Optional interceptor (set by the node for e.g. group routing).
        # Return True to consume the message instead of queueing it.
        self.on_payload: Callable[[Session, ReceivedMessage], Awaitable[bool]] | None = None
        # Called once when the session leaves ESTABLISHED (close/expire), so the
        # owning node can drop its reference and reclaim memory.
        self.on_closed: Callable[[Session], None] | None = None
        # Backpressure: if set, the unread inbox is capped at this many frames.
        # Enforced by windowed flow control — the sender stalls on the advertised
        # window, and a decode-gate backstop holds any frame that would overflow
        # undecoded (and unacked) so it is recovered by retransmit rather than
        # decoded-then-dropped. No acknowledged message is ever lost.
        # None = unbounded (default). Set via the validated `max_inflight`
        # property (bounded by the reorder window; see the property).
        self._max_inflight: int | None = None
        # Live references to fire-and-forget drain tasks spawned by
        # receive_nowait(), so the event loop can't GC them mid-run.
        self._drain_tasks: set[asyncio.Task] = set()

    @property
    def max_inflight(self) -> int | None:
        return self._max_inflight

    @max_inflight.setter
    def max_inflight(self, value: int | None) -> None:
        # A backpressure-held in-order frame plus the frames still in flight when
        # the window=0 receipt reaches the sender all land in the bounded reorder
        # buffer. Capping the window at _MAX_REORDER_WINDOW keeps that within the
        # buffer, so the guarantee "no acknowledged message is lost" holds — a
        # larger cap could overflow the reorder buffer into an unrecoverable
        # SequenceError. Reject 0 (would stall the peer forever).
        if value is not None and not (1 <= value <= _MAX_REORDER_WINDOW):
            raise ValueError(
                f"max_inflight must be None or 1..{_MAX_REORDER_WINDOW}, got {value}"
            )
        self._max_inflight = value

    # -- outbound ---------------------------------------------------------

    async def send(self, payload: Payload) -> Envelope:
        self._require_open()
        if payload.content_type not in self.payload_types:
            raise SessionError(
                f"payload type {payload.content_type!r} not negotiated for this session "
                f"(allowed: {self.payload_types})"
            )
        # Typed bodies are validated before encrypt (and task lifecycle applied)
        # so an illegal body never reaches the wire. Raises BodyError.
        self._screen_outbound(payload)
        # The whole send — seq assignment, ratchet advance, transcript, AND
        # delivery — is serialized. Releasing the lock before delivery would let
        # a concurrent send() reach the wire out of seq order, which the strict
        # receiver rejects and never recovers from. Ordering is a protocol
        # requirement here, so per-session send latency serializes deliberately.
        async with self._lock:
            # Windowed flow control: block while the peer's advertised receive
            # window is exhausted. The window reopens via a receipt (handled
            # without this lock, so no deadlock) or on finalize (which sets the
            # event so a stalled sender wakes and errors via _require_open).
            while self._peer_recv_window is not None and self._peer_recv_window <= 0:
                self.stats.send_stalls += 1
                self._window_event.clear()
                await self._window_event.wait()
                self._require_open()
            seq = self._send_seq + 1
            payload_wire = payload.model_dump(mode="json")
            # Witnessed posture: produce the witness copy BEFORE anything is
            # committed or delivered — a party that cannot seal to the agreed
            # witness MUST refuse to send (SPEC §7.1), leaving seq/ratchet
            # untouched so the session stays usable once the fault is fixed.
            witness_copy = None
            if self.witness is not None:
                try:
                    witness_copy = build_witness_copy(
                        self.witness,
                        self._own_keys,
                        self._own_address,
                        self.session_id,
                        seq,
                        payload_wire,
                    )
                except Exception as exc:
                    raise SessionError(
                        f"witnessed session cannot produce its witness copy: {exc}"
                    ) from exc
            plaintext = json.dumps(payload_wire).encode()
            # Double-ratchet send: the header DH public key travels in the clear
            # (authenticated by the envelope signature and bound into the AEAD
            # AAD) so the peer can detect a direction turn before decrypting.
            dh_public, message_key = self._ratchet.encrypt_step()
            ciphertext = encrypt(message_key, plaintext, aad=self._aad(seq) + dh_public)
            envelope = Envelope(
                type=EnvelopeType.SESSION_MESSAGE,
                sender=self._own_address,
                to=self.peer_card.address,
                session_id=self.session_id,
                seq=seq,
                body=Envelope.encode_body(dh_public + ciphertext),
            ).signed(self._own_keys)
            self._send_seq = seq
            self.transcript.record(envelope)
            self._send_buffer[seq] = envelope
            while len(self._send_buffer) > _MAX_SEND_BUFFER:
                self._send_buffer.popitem(last=False)
            self.stats.sent += 1
            # Consume a window slot; the next receipt re-syncs the absolute value.
            if self._peer_recv_window is not None:
                self._peer_recv_window -= 1
            await self._send_fn(envelope)
            if witness_copy is not None:
                # Emitted after (and only after) the message itself, under the
                # same lock so copies leave in seq order. A delivery failure
                # here surfaces loudly: the message is out but its audit copy
                # is not, and the sender must know rather than drift into a
                # silently unwitnessed conversation.
                await self._send_fn(witness_copy)
        self.arm_maintenance()
        return envelope

    def arm_maintenance(self) -> None:
        """Start the background maintenance loop (retransmit-on-timeout + TTL
        reaper) if not already running. Idempotent; a no-op without a running
        loop or when disabled (``retransmit_interval is None``)."""
        if (
            not self.retransmit_interval
            or self._rto_task is not None
            or self.state is not SessionState.ESTABLISHED
        ):
            return
        try:
            self._rto_task = asyncio.get_running_loop().create_task(self._rto_loop())
        except RuntimeError:
            pass  # no running loop (e.g. sync construction in a test)

    def cancel_maintenance(self) -> None:
        """Cancel the background maintenance task without firing on_closed — for
        callers that retire a session out-of-band (e.g. resume superseding it)
        and manage the node's session map themselves."""
        if self._rto_task is not None:
            self._rto_task.cancel()
            self._rto_task = None

    def set_retransmit_interval(self, seconds: float | None) -> None:
        """Change the retransmit/reaper interval and restart the loop cleanly.
        ``None`` disables it (and stops the running loop)."""
        self.retransmit_interval = seconds
        if self._rto_task is not None:
            self._rto_task.cancel()
            self._rto_task = None
        self.arm_maintenance()

    async def _rto_loop(self) -> None:
        try:
            while self.state is SessionState.ESTABLISHED:
                await asyncio.sleep(self.retransmit_interval)
                # Reap an abandoned session (peer vanished, no in/outbound to
                # drive lazy expiry): finalize on TTL so the task and the node's
                # session reference don't leak, and we stop firing into a dead
                # transport past expiry.
                if datetime.now(UTC) >= self.expires_at:
                    self._rto_task = None  # avoid cancelling the task we're in
                    self._finalize(SessionState.EXPIRED)
                    return
                # Orphan reap: a responder that never heard from (or spoke to) its
                # peer past the grace window had its initiator abandon the session.
                if (
                    not self.initiator
                    and self.stats.received == 0
                    and self.stats.sent == 0
                    and (datetime.now(UTC) - self.created_at).total_seconds()
                    >= _ORPHAN_GRACE_SECONDS
                ):
                    self._rto_task = None
                    self._finalize(SessionState.EXPIRED)
                    return
                if self._send_buffer and self.state is SessionState.ESTABLISHED:
                    await self._retransmit_unacked()
        except asyncio.CancelledError:
            raise

    async def _retransmit_unacked(self) -> None:
        """Replay every still-unacked frame (bounded by the send buffer). Called
        by the RTO timer; also directly invokable for deterministic testing."""
        for envelope in list(self._send_buffer.values()):
            self.stats.retransmitted += 1
            await self._send_fn(envelope)

    async def send_text(self, text: str, **metadata: Any) -> Envelope:
        return await self.send(Payload.text(text, **metadata))

    async def send_json(self, data: Any, **metadata: Any) -> Envelope:
        return await self.send(Payload.json_data(data, **metadata))

    async def send_body(self, model: Any, **metadata: Any) -> Envelope:
        """Send a typed body model (e.g. ``TaskBody``, ``ClaimBody``)."""
        return await self.send(Payload.body(model, **metadata))

    async def close(self, reason: str = "") -> None:
        if self.state is not SessionState.ESTABLISHED:
            return
        envelope = Envelope(
            type=EnvelopeType.SESSION_CLOSE,
            sender=self._own_address,
            to=self.peer_card.address,
            session_id=self.session_id,
            body=Envelope.encode_body(
                encrypt(self._close_send_key, json.dumps({"reason": reason}).encode(), aad=b"close")
            ),
        ).signed(self._own_keys)
        self.transcript.record(envelope)
        self._finalize(SessionState.CLOSED)
        await self._send_fn(envelope)

    # -- inbound (called by the node) --------------------------------------

    async def handle_incoming(self, envelope: Envelope) -> None:
        """Process a signature-verified envelope addressed to this session."""
        if envelope.type is EnvelopeType.SESSION_CLOSE:
            decrypt(self._close_recv_key, envelope.body_bytes, aad=b"close")  # authenticate
            self.transcript.record(envelope)
            self._finalize(SessionState.CLOSED)
            return
        if envelope.type is EnvelopeType.RECEIPT:
            await self._handle_receipt(envelope)
            return
        if envelope.type is not EnvelopeType.SESSION_MESSAGE:
            raise SessionError(f"unexpected envelope type for session: {envelope.type}")

        # Decode under the recv lock so concurrent delivery can't interleave the
        # ratchet/seq state. Collect ready messages in order, then dispatch them
        # after releasing the lock (dispatch may await user/group callbacks).
        overflow = False
        async with self._recv_lock:
            self._require_open()
            try:
                ready, missing, ack = self._accept_locked(envelope)
            except SequenceError:
                # The reorder buffer is exhausted (a gap that can't be filled
                # within the window). This is unrecoverable via ARQ — surface it
                # as a deterministic close→resume instead of letting the raise
                # escape into the transport dispatcher and silently wedge the
                # session. The gapped frames were never ACKed, so resume recovers
                # them; no acknowledged message is lost.
                overflow = True
        if overflow:
            self.stats.unrecoverable_closes += 1
            _log.error(
                "session %s: reorder window exhausted; closing so the gap is "
                "resolved by a resume",
                self.session_id,
            )
            await self.close(reason="reorder window exhausted; resume required")
            return
        if not await self._deliver_screened(ready):
            return  # session closed on a typed-body protocol error
        self.stats.received += len(ready)
        # Emit a receipt whenever we delivered frames (cumulative ACK, so the
        # peer can prune its send buffer and stop RTO retransmits — this is what
        # lets tail loss recover) or detected a gap (NACK). The ack is captured
        # under the lock so it reflects the exact processed position.
        if ready or missing:
            if missing:
                self.stats.nacks_sent += 1
            await self._send_receipt(ack=ack, missing=missing)
        elif envelope.seq <= ack:
            # A retransmit of an already-delivered frame: the peer's original
            # cumulative ACK was lost, else it wouldn't be replaying. Re-ACK so
            # the lost-ACK case self-heals instead of retransmitting forever.
            await self._send_receipt(ack=ack, missing=[])

    def _accept_locked(self, envelope: Envelope) -> tuple[list[ReceivedMessage], list[int], int]:
        """Under _recv_lock: order the frame, decode all now-contiguous frames,
        and report (ready, still-missing seqs, cumulative-ack)."""
        expected = self._recv_seq + 1
        if envelope.seq < expected:
            # Already delivered (a benign retransmit under an at-least-once
            # transport or ARQ). Idempotent no-op, not an error.
            _log.debug("session %s ignoring already-seen seq %d", self.session_id, envelope.seq)
            return [], [], self._recv_seq
        if envelope.seq > expected:
            if len(self._reorder) >= _MAX_REORDER_WINDOW:
                raise SequenceError(
                    f"reorder window full ({_MAX_REORDER_WINDOW}); seq {envelope.seq} dropped"
                )
            if envelope.seq not in self._reorder:
                self._reorder[envelope.seq] = envelope
                self.stats.reorder_buffered += 1
            return [], self._missing_locked(), self._recv_seq
        ready: list[ReceivedMessage] = []
        current: Envelope | None = envelope
        while current is not None:
            if not self._has_capacity(len(ready)):
                # Backpressure backstop: the consumer hasn't drained the inbox.
                # Hold this in-order frame undecoded (and therefore unacked) so
                # it is recovered by retransmit or drained later — never decoded
                # then dropped, which is unrecoverable once the ratchet advances.
                # Held at its own seq, so it is not reported as a gap/NACK.
                self._reorder[current.seq] = current
                self.stats.backpressure_holds += 1
                break
            ready.append(self._decode_next(current))
            current = self._reorder.pop(self._recv_seq + 1, None)
        return ready, self._missing_locked(), self._recv_seq

    def _missing_locked(self) -> list[int]:
        """Seqs in the current gap (below the highest buffered frame, not yet
        received). Empty when there is no gap."""
        if not self._reorder:
            return []
        hi = max(self._reorder)
        return [s for s in range(self._recv_seq + 1, hi) if s not in self._reorder][
            :_MAX_MISSING_PER_RECEIPT
        ]

    async def _send_receipt(self, ack: int, missing: list[int]) -> None:
        # Each receipt carries a strictly increasing rseq so the peer can drop
        # replayed receipts (they carry no message seq and aren't ratcheted).
        # `window` advertises remaining inbox capacity (null = unbounded) so the
        # peer's flow control can stall before overrunning a slow consumer.
        self._receipt_send_seq += 1
        window = self._recv_window()
        self._last_recv_window_sent = window
        envelope = Envelope(
            type=EnvelopeType.RECEIPT,
            sender=self._own_address,
            to=self.peer_card.address,
            session_id=self.session_id,
            body=Envelope.encode_body(
                json.dumps(
                    {
                        "rseq": self._receipt_send_seq,
                        "ack": ack,
                        "missing": missing,
                        "window": window,
                    }
                ).encode()
            ),
        ).signed(self._own_keys)
        await self._send_fn(envelope)

    async def _handle_receipt(self, envelope: Envelope) -> None:
        """Peer's cumulative ack + gap NACK: prune acked frames, retransmit gaps.

        The envelope is signature-verified and sender-pinned by the node, so the
        values are authentic. A monotonic rseq drops replays (a captured receipt
        cannot be replayed to force repeated retransmit amplification).
        """
        info = json.loads(envelope.body_bytes)
        rseq = int(info.get("rseq", 0))
        if rseq <= self._receipt_recv_seq:
            _log.debug("session %s dropping replayed/stale receipt rseq %d", self.session_id, rseq)
            self.stats.receipts_dropped += 1
            return
        self._receipt_recv_seq = rseq
        # Flow control: adopt the peer's advertised remaining capacity (absolute)
        # and wake a stalled sender if the window reopened.
        window = info.get("window", None)
        self._peer_recv_window = None if window is None else int(window)
        if self._peer_recv_window is None or self._peer_recv_window > 0:
            self._window_event.set()
        ack = int(info.get("ack", 0))
        missing = [int(s) for s in info.get("missing", [])][:_MAX_MISSING_PER_RECEIPT]
        never_sent = [s for s in missing if s > self._send_seq]
        if never_sent:
            _log.warning(
                "session %s: peer NACKed seq %s we never sent (peer bug or probe)",
                self.session_id,
                never_sent,
            )

        # Prune + snapshot with NO await between reads and the snapshot, so this
        # section is atomic under asyncio and can't race a concurrent send()
        # mutating the buffer. (We must NOT take self._lock here: under a
        # synchronous transport, send() holds it across delivery, which can
        # re-enter this handler with the peer's NACK — that would deadlock.)
        for seq in list(self._send_buffer):
            if seq <= ack:
                self._send_buffer.pop(seq, None)
        lowest = min(self._send_buffer) if self._send_buffer else None
        to_send = [self._send_buffer[s] for s in missing if s in self._send_buffer]
        # A NACK for a seq we sent but already evicted is unrecoverable via ARQ —
        # surface it deterministically instead of leaving the peer to silently
        # wedge on a gap that can never fill.
        unrecoverable = [
            s
            for s in missing
            if s not in self._send_buffer
            and s <= self._send_seq
            and (lowest is None or s < lowest)
        ]
        for envelope_to_resend in to_send:
            self.stats.retransmitted += 1
            await self._send_fn(envelope_to_resend)
        if unrecoverable:
            _log.error(
                "session %s: peer needs seq %s but they are evicted from the send "
                "buffer; closing so the gap is resolved by a resume",
                self.session_id,
                unrecoverable,
            )
            self.stats.unrecoverable_closes += 1
            await self.close(reason="unrecoverable gap; resume required")

    def _decode_next(self, envelope: Envelope) -> ReceivedMessage:
        """Decrypt the next in-order frame and advance the ratchet/seq/transcript."""
        body = envelope.body_bytes
        if len(body) < 32:
            raise SessionError("session message too short for ratchet header")
        header_dh, ciphertext = body[:32], body[32:]
        # Prepare (no state mutation) so a decrypt/validate failure leaves the
        # ratchet untouched — the honest retransmit of the same seq still decodes.
        message_key, apply = self._ratchet.decrypt_prepare(header_dh)
        plaintext = decrypt(
            message_key, ciphertext, aad=self._aad(envelope.seq) + header_dh
        )
        payload = Payload.model_validate(json.loads(plaintext))
        apply()  # commit the ratchet advance (and any DH step) only on success
        self._recv_seq = envelope.seq
        self.transcript.record(envelope)
        return ReceivedMessage(
            payload=payload,
            sender=envelope.sender,
            session_id=self.session_id,
            seq=envelope.seq,
            received_at=datetime.now(UTC),
        )

    async def _dispatch_message(self, message: ReceivedMessage) -> None:
        if self.on_payload is not None and await self.on_payload(self, message):
            return
        # The decode-gate (_accept_locked / _drain_held) only decodes a frame
        # when there is inbox capacity, so this never overflows max_inflight and
        # no unread message is dropped.
        self._inbox.put_nowait(message)

    # -- typed bodies (SPEC §16) -------------------------------------------

    def _screen_outbound(self, payload: Payload) -> None:
        """Validate a typed outbound body against the registry and apply the
        task/payment lifecycles (including our own spend caps). Unregistered
        typed names pass through opaque — the peer negotiated them, and its
        own registry validates on receive."""
        body_type = (
            self.body_registry.get(payload.content_type)
            if is_typed_name(payload.content_type)
            else None
        )
        if body_type is None:
            return
        self._apply_typed(body_type.validate(payload.content), actor="local")

    def _screen_inbound(self, payload: Payload) -> str | None:
        """Screen a decoded inbound payload. Returns a rejection reason for a
        typed-body protocol error (unknown critical type, schema violation,
        illegal task/payment transition, spend-cap violation), else None.
        Unknown non-critical typed bodies are delivered opaque."""
        if not is_typed_name(payload.content_type):
            return None
        body_type = self.body_registry.get(payload.content_type)
        if body_type is None:
            if payload.metadata.get("critical") is True:
                return f"unknown critical body type {payload.content_type!r}"
            return None
        try:
            self._apply_typed(body_type.validate(payload.content), actor="peer")
        except BodyError as exc:
            return str(exc)
        return None

    def _apply_typed(self, parsed: BaseModel, actor: str) -> None:
        """Apply a validated typed body to this session's lifecycle state."""
        if isinstance(parsed, TaskBody):
            self.tasks.apply(parsed, actor=actor)
        elif isinstance(parsed, PaymentBody):
            self._apply_payment(parsed, actor)

    def _apply_payment(self, body: PaymentBody, actor: str) -> None:
        """Payment lifecycle + spend-scope enforcement (SPEC §16.5).

        An outbound authorization is verified against OUR delegation chain
        (raises before encrypt); an inbound one against the peer's
        handshake-verified chain (protocol error). Both checks feed the
        respective per-session spend ledger so ``total<=`` caps hold across
        authorizations. A rejection leaves tracker and ledger untouched.
        """
        chain = self._own_chain if actor == "local" else self._peer_chain
        ledger = self.spend if actor == "local" else self.peer_spend

        def spend_check(quote: Quote) -> None:
            try:
                SpendAuthority.verify(
                    chain, quote.asset, quote.amount, ledger.spent(quote.asset)
                )
            except SpendScopeError as exc:
                raise SpendRejectedError(str(exc)) from exc

        authorizing = body.kind is PaymentKind.AUTHORIZATION
        self.payments.apply(
            body,
            actor=actor,
            spend_check=spend_check if authorizing and chain is not None else None,
        )
        if authorizing:
            quote = self.payments.quote_of(body.payment_id)
            if quote is not None:  # always tracked post-apply; guard for typing
                ledger.record(quote.asset, quote.amount)

    async def _deliver_screened(self, ready: list[ReceivedMessage]) -> bool:
        """Dispatch decoded frames, screening typed bodies. A rejection is a
        protocol error: the session closes deterministically (the frames were
        already acked at the frame layer; the close reason carries the cause).
        Returns False when the session was closed."""
        for message in ready:
            reject = self._screen_inbound(message.payload)
            if reject is not None:
                _log.error(
                    "session %s: inbound body rejected: %s", self.session_id, reject
                )
                await self.close(reason=f"body rejected: {reject}")
                return False
            await self._dispatch_message(message)
        return True

    async def _drain_held(self) -> None:
        """After the consumer frees inbox capacity, decode any in-order frames
        held under backpressure and re-advertise the reopened window so a stalled
        sender resumes even without a fresh inbound frame. No-op when unbounded."""
        if self.max_inflight is None:
            return
        ready: list[ReceivedMessage] = []
        async with self._recv_lock:
            while self._has_capacity(len(ready)):
                nxt = self._reorder.pop(self._recv_seq + 1, None)
                if nxt is None:
                    break
                ready.append(self._decode_next(nxt))
            ack = self._recv_seq
            missing = self._missing_locked()
            reopened = self._last_recv_window_sent == 0 and (self._recv_window() or 0) > 0
        if not await self._deliver_screened(ready):
            return  # session closed on a typed-body protocol error
        if ready:
            self.stats.received += len(ready)
        if ready or reopened:
            await self._send_receipt(ack=ack, missing=missing)

    async def receive(self, timeout: float | None = None) -> ReceivedMessage:
        if timeout is None:
            message = await self._inbox.get()
        else:
            try:
                message = await asyncio.wait_for(self._inbox.get(), timeout)
            except TimeoutError:
                raise TimeoutError(
                    f"no message received on session {self.session_id} within {timeout}s"
                ) from None
        await self._drain_held()
        return message

    def receive_nowait(self) -> ReceivedMessage | None:
        try:
            message = self._inbox.get_nowait()
        except asyncio.QueueEmpty:
            return None
        # Best-effort drain of any backpressure-held frames; the sync caller
        # can't await, so schedule it when a loop is running (otherwise the next
        # receive()/inbound frame/RTO retransmit drains it).
        if self.max_inflight is not None and self._reorder:
            try:
                task = asyncio.get_running_loop().create_task(self._drain_held())
            except RuntimeError:
                pass  # no running loop; next receive()/inbound frame/RTO drains
            else:
                # Keep a strong reference until done, else the loop may GC the
                # task mid-run (asyncio holds only a weak reference).
                self._drain_tasks.add(task)
                task.add_done_callback(self._drain_tasks.discard)
        return message

    # -- identity & authority -------------------------------------------------

    def has_scope(self, scope: str) -> bool:
        """Whether the peer's verified delegation chain grants a scope."""
        return scope in self.peer_scopes

    def require_scope(self, scope: str, *, owner: str | None = None) -> None:
        """Raise SessionError unless the peer verifiably holds a scope.

        Call before acting on a message that commits to something — the check
        is against the delegation chain verified at handshake, not any claim
        inside the message. Scopes are only meaningful relative to a trusted
        owner: pass ``owner`` to also assert the peer's verified owner
        (``peer_owner``) is who you expect, closing the gap where a peer
        self-signs a chain granting itself the scope.
        """
        if owner is not None and self.peer_owner != owner:
            raise SessionError(
                f"peer owner {self.peer_owner} is not the expected {owner}"
            )
        if scope not in self.peer_scopes:
            raise SessionError(
                f"peer {self.peer_card.address} does not hold required scope {scope!r} "
                f"(verified scopes: {sorted(self.peer_scopes)})"
            )

    def transcript_matches(self, expected_head: bytes) -> bool:
        """Verify this session's transcript head against the peer's, proving
        both hold the identical, untampered conversation record."""
        return self.transcript.matches(expected_head)

    # -- internals ----------------------------------------------------------

    def _aad(self, seq: int) -> bytes:
        return f"{self.session_id}:{seq}".encode()

    def _has_capacity(self, pending: int) -> bool:
        """Whether the inbox can take `pending` more decoded frames right now."""
        return self.max_inflight is None or (self._inbox.qsize() + pending) < self.max_inflight

    def _recv_window(self) -> int | None:
        """Remaining inbox capacity to advertise to the peer (None = unbounded)."""
        if self.max_inflight is None:
            return None
        return max(0, self.max_inflight - self._inbox.qsize())

    def _require_open(self) -> None:
        if self.state is not SessionState.ESTABLISHED:
            raise SessionStateError(f"session is {self.state}")
        if datetime.now(UTC) >= self.expires_at:
            self._finalize(SessionState.EXPIRED)
            raise SessionStateError("session has expired")

    def _finalize(self, state: SessionState) -> None:
        self.state = state
        # Release any sender stalled on flow control so it wakes and errors out
        # via _require_open instead of blocking forever on a dead session.
        self._window_event.set()
        for task in list(self._drain_tasks):
            task.cancel()
        self._drain_tasks.clear()
        if self._rto_task is not None:
            self._rto_task.cancel()
            self._rto_task = None
        if self.mode is SessionMode.EPHEMERAL:
            # Drop all key material; the transcript head survives as evidence.
            self._ratchet.burn()
            self._close_send_key = b"\x00" * 32
            self._close_recv_key = b"\x00" * 32
        if self.on_closed is not None:
            self.on_closed(self)
