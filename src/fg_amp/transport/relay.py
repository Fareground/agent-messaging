"""Relay: hosted store-and-forward mailboxes + card directory.

Where do sessions live? At the endpoints — an AMP session exists only inside
the two (or N) nodes that hold its keys. A relay hosts none of that. It offers
exactly three things, all zero-knowledge of content:

- **mailboxes**: it holds signed envelopes (whose bodies are E2E ciphertext)
  for recipients that are offline or unreachable, until they pull them;
- **a card directory**: agents publish their signed AgentCards for discovery;
- **authenticated pulls**: draining a mailbox requires a fresh signature from
  the mailbox address's key, so nobody else can read or drop your envelopes.

Anyone can run a relay (it is a small FastAPI app — ``create_relay_app()``);
Fareground hosts one, and self-hosting changes nothing about security because
the relay is untrusted by construction: it sees routing metadata only.

Requires the ``http`` extra: pip install 'fg-amp[http]'.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from ..envelope.canonical import canonical_json
from ..envelope.envelope import Envelope
from ..errors import TransportError

# Module-level so FastAPI can resolve the `request: Request` annotation under
# `from __future__ import annotations` (get_type_hints reads module globals).
try:
    from starlette.requests import Request
except ImportError:  # pragma: no cover
    Request = None
from ..identity.address import signing_key_from_address
from ..identity.card import AgentCard
from ..identity.delegation import KeyRevocation, Revocation
from ..identity.keys import PublicKeys
from ..signing import (
    CONTEXT_RELAY_ACK,
    CONTEXT_RELAY_PULL,
    decode_signature,
    signing_input,
)
from .base import InboundHandler, Transport
from .wake import WakeNotifier

logger = logging.getLogger(__name__)

# Names the relay a signed pull/ack is addressed to. Relays and their clients
# MUST agree on this string; deployments that host more than one relay SHOULD
# set a distinct value per relay (its public URL is a good choice) so a signed
# request captured at one cannot be replayed at another.
DEFAULT_RELAY_AUDIENCE = "amp-relay"

if TYPE_CHECKING:
    from ..node.node import AmpNode

SEND_PATH = "/amp/v0/relay/send"
PULL_PATH = "/amp/v0/relay/pull"
ACK_PATH = "/amp/v0/relay/ack"
CARDS_PATH = "/amp/v0/relay/cards"
REVOCATIONS_PATH = "/amp/v0/relay/revocations"
KEY_REVOCATIONS_PATH = "/amp/v0/relay/key-revocations"

_MAX_MAILBOX_SIZE = 4096
_MAX_PER_SENDER = 512  # one sender can occupy at most this share of a mailbox
_PULL_MAX_AGE_SECONDS = 120.0
# A pulled message is leased, not deleted: it moves to an in-flight holding area
# and is only removed when the puller acks it. If the puller crashes or never
# acks within the lease, the message is reclaimed and redelivered on a later
# pull. This makes relay delivery at-least-once instead of at-most-once. The
# session layer's seq + reorder buffer + idempotent inbound absorb duplicate
# redeliveries, so the relay does not need ordered redelivery — only durability.
_LEASE_SECONDS = 30.0
# A message that parses but whose handler deterministically fails (a late frame
# for a closed session, a witness copy with no handler) is never acked, so it
# would be redelivered forever — a poison message that pins a mailbox against
# its quota. After this many delivery attempts it is dead-lettered (dropped)
# instead of redelivered. Generous enough that transient handler failures and
# lease-timeout reclaims recover; bounded so a poison message can't loop.
_MAX_DELIVERY_ATTEMPTS = 12
_MAX_ENVELOPE_BYTES = 1 << 20  # 1 MiB cap on a single relayed envelope
# Directory/revocation stores are bounded so a flood of free-to-mint identities
# can't grow the relay's shared state without limit (LRU eviction on overflow).
_MAX_CARDS = 100_000
_MAX_REVOCATIONS = 200_000

# Per-source request-rate cap on mutating endpoints. This bounds the CPU/bandwidth
# a single authenticated source can impose (each request costs a verify); it is a
# first-line defense, not a Sybil defense — identities are free to mint, so the
# durable fix is proof-of-work / pay-to-knock (roadmapped). Keyed by the
# signature-verified source, so it can't be spoofed by an on-path party.
_RATE_MAX_REQUESTS = 240
_RATE_WINDOW_SECONDS = 60.0
_RATE_MAX_TRACKED = 65_536


class _RateLimiter:
    """In-memory sliding-window limiter, bounded by LRU eviction so the tracking
    map can't itself be turned into a memory-exhaustion vector."""

    def __init__(
        self,
        max_requests: int | None = None,
        window: float | None = None,
        max_tracked: int | None = None,
    ):
        # Resolve from module globals at call time (not def time) so deployments
        # and tests can override the constants before constructing the app.
        self._max = _RATE_MAX_REQUESTS if max_requests is None else max_requests
        self._window = _RATE_WINDOW_SECONDS if window is None else window
        self._max_tracked = _RATE_MAX_TRACKED if max_tracked is None else max_tracked
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        hits = self._hits.get(key)
        if hits is None:
            hits = self._hits[key] = deque()
        self._hits.move_to_end(key)
        while hits and now - hits[0] > self._window:
            hits.popleft()
        while len(self._hits) > self._max_tracked:
            evicted, _ = self._hits.popitem(last=False)
            if evicted == key:  # pragma: no cover - defensive; key is MRU
                self._hits[key] = hits
                break
        if len(hits) >= self._max:
            return False
        hits.append(now)
        return True


def _pull_payload(address: str, timestamp: str, audience: str) -> bytes:
    # `audience` names the relay this request is for, so a signed pull captured
    # at one relay cannot be replayed at another to drain the same mailbox.
    return signing_input(
        CONTEXT_RELAY_PULL,
        {"action": "pull", "address": address, "audience": audience, "ts": timestamp},
    )


def _ack_payload(address: str, timestamp: str, ids: list[str], audience: str) -> bytes:
    # ids are bound into the signature so only the mailbox owner can remove
    # specific leased messages — a third party can neither ack (delete) a
    # victim's in-flight mail nor tamper with which ids are acked.
    return signing_input(
        CONTEXT_RELAY_ACK,
        {
            "action": "ack",
            "address": address,
            "audience": audience,
            "ids": list(ids),
            "ts": timestamp,
        },
    )


class PullRequest(BaseModel):
    """Authenticated mailbox drain request."""

    address: str
    ts: str  # RFC3339
    sig: str  # base64 ed25519 over the canonical pull payload
    wait_seconds: float = 0.0  # long-poll up to this many seconds


class AckRequest(BaseModel):
    """Authenticated confirmation that leased messages were received."""

    address: str
    ts: str  # RFC3339
    sig: str  # base64 ed25519 over the canonical ack payload (binds ids)
    ids: list[str]  # envelope ids being acknowledged


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class RelayState:
    """In-memory relay storage. ``SqliteRelayState`` is the persistent variant."""

    def __init__(self):
        self.mailboxes: dict[str, deque[dict]] = {}
        # LRU-ordered so an overflow evicts the least-recently-registered entry.
        self.cards: OrderedDict[str, dict] = OrderedDict()
        # address -> monotonic seq of its last (re-)registration; drives the
        # ?since= delta listing that federation peers sync from.
        self._card_seqs: dict[str, int] = {}
        self._card_seq = 0
        # digest/address -> {"seq": int, "data": json}; seq drives delta sync.
        self.revocations: OrderedDict[str, dict] = OrderedDict()
        self.key_revocations: OrderedDict[str, dict] = OrderedDict()
        self._rev_seq = 0  # monotonic cursor for delegation-revocation delta sync
        self._key_rev_seq = 0  # monotonic cursor for key-revocation delta sync
        self.waiters: dict[str, list[asyncio.Event]] = {}
        self._seen_pulls: dict[str, float] = {}  # sig -> expiry monotonic
        # address -> {msg_id: {"wire": dict, "expires": float}}: delivered but
        # not-yet-acked messages, reclaimed to the mailbox when their lease lapses.
        self.inflight: dict[str, dict[str, dict]] = {}
        # msg_id -> delivery attempts so far; a message reclaimed past the cap
        # is dead-lettered instead of redelivered forever. Cleared on ack.
        self._attempts: dict[str, int] = {}

    def enqueue(self, envelope: Envelope) -> None:
        box = self.mailboxes.setdefault(envelope.to, deque())
        if len(box) >= _MAX_MAILBOX_SIZE:
            raise TransportError(f"mailbox full for {envelope.to}")
        # Per-sender quota: one signer cannot fill a victim's whole mailbox and
        # starve every other sender (a signature is free to mint).
        from_sender = sum(1 for w in box if w.get("from") == envelope.sender)
        if from_sender >= _MAX_PER_SENDER:
            raise TransportError(f"per-sender quota reached for {envelope.sender}")
        box.append(envelope.to_wire())

    async def run(self, fn, *args):
        """Execute a storage operation. In-memory ops are event-loop-safe and run
        inline; the SQLite backend overrides this to offload blocking disk I/O to
        a worker thread so a slow fsync never stalls the event loop."""
        return fn(*args)

    def check_pull_replay(self, sig: str, now: float) -> bool:
        """Register a pull signature as used. Returns False if already seen
        (a replay). Prunes expired entries opportunistically."""
        for seen_sig in [s for s, exp in self._seen_pulls.items() if exp <= now]:
            del self._seen_pulls[seen_sig]
        if sig in self._seen_pulls:
            return False
        self._seen_pulls[sig] = now + _PULL_MAX_AGE_SECONDS
        return True

    def _reclaim_expired(self, address: str, now: float) -> None:
        """Return lapsed-lease messages to the mailbox for redelivery."""
        inflight = self.inflight.get(address)
        if not inflight:
            return
        expired = [mid for mid, entry in inflight.items() if entry["expires"] <= now]
        if not expired:
            return
        box = self.mailboxes.setdefault(address, deque())
        for mid in expired:
            wire = inflight.pop(mid)["wire"]
            attempts = self._attempts.get(mid, 0) + 1
            if attempts >= _MAX_DELIVERY_ATTEMPTS:
                # Poison message: dead-letter it rather than redeliver forever.
                self._attempts.pop(mid, None)
                logger.warning(
                    "relay dead-lettering %s for %s after %d delivery attempts",
                    mid, address, attempts,
                )
                continue
            self._attempts[mid] = attempts
            box.append(wire)
        if not box:
            self.mailboxes.pop(address, None)
        if not inflight:
            self.inflight.pop(address, None)

    def drain(
        self, address: str, now: float | None = None, lease_seconds: float = _LEASE_SECONDS
    ) -> list[dict]:
        """Lease all pending messages: return them and move them to in-flight.
        They are removed only on ``ack``; an unacked lease is reclaimed and
        redelivered. Expired leases are reclaimed first, so a crashed puller's
        messages reappear here."""
        now = time.monotonic() if now is None else now
        self._reclaim_expired(address, now)
        box = self.mailboxes.pop(address, deque())
        if not box:
            return []
        leased = list(box)
        inflight = self.inflight.setdefault(address, {})
        for wire in leased:
            inflight[wire["id"]] = {"wire": wire, "expires": now + lease_seconds}
        return leased

    def ack(self, address: str, ids: list[str]) -> int:
        """Confirm delivery of leased messages, removing them permanently.
        Returns the count actually removed (unknown/already-reclaimed ids are
        ignored, so acks are idempotent)."""
        inflight = self.inflight.get(address)
        if not inflight:
            return 0
        removed = 0
        for mid in ids:
            if inflight.pop(mid, None) is not None:
                removed += 1
                self._attempts.pop(mid, None)  # delivered — forget its attempts
        if not inflight:
            self.inflight.pop(address, None)
        return removed

    def put_card(self, card: AgentCard) -> None:
        self.cards[card.address] = card.model_dump(mode="json")
        self.cards.move_to_end(card.address)  # LRU: most-recent at the end
        self._card_seq += 1
        self._card_seqs[card.address] = self._card_seq
        while len(self.cards) > _MAX_CARDS:
            evicted, _ = self.cards.popitem(last=False)  # least-recently-registered
            self._card_seqs.pop(evicted, None)

    def get_card(self, address: str) -> dict | None:
        return self.cards.get(address)

    def list_cards(self, since: int = 0) -> tuple[list[dict], int]:
        """Cards (re-)registered after ``since``, plus the new cursor — the
        delta endpoint federation peers sync the directory from."""
        rows = sorted(
            (
                (seq, self.cards[address])
                for address, seq in self._card_seqs.items()
                if seq > since and address in self.cards
            ),
            key=lambda pair: pair[0],
        )
        return [data for _, data in rows], max(self._card_seq, since)

    def add_revocation(self, revocation: Revocation) -> None:
        key = revocation.delegation_digest
        # Fail-closed: a revocation is a security fact — never evict an existing
        # one to make room (that would let a cheap self-signed-spam flood
        # silently drop a real revocation, so a fresh client syncing from 0 would
        # never learn a key was compromised). On overflow reject the NEW write
        # loudly instead. Robust anti-flood needs proof-of-work / stake at
        # registration (roadmap: relay PoW / x402 pay-to-knock).
        if key not in self.revocations and len(self.revocations) >= _MAX_REVOCATIONS:
            raise TransportError("revocation store full")
        self._rev_seq += 1
        self.revocations[key] = {"seq": self._rev_seq, "data": revocation.model_dump(mode="json")}
        self.revocations.move_to_end(key)

    def list_revocations(self, since: int = 0) -> tuple[list[dict], int]:
        """Delegation revocations newer than `since`, plus the new cursor. A
        client passes its last cursor so each sync transfers only the delta,
        not the whole (unbounded) table."""
        rows = [v for v in self.revocations.values() if v["seq"] > since]
        cursor = max((v["seq"] for v in self.revocations.values()), default=since)
        return [v["data"] for v in rows], cursor

    def add_key_revocation(self, revocation: KeyRevocation) -> None:
        key = revocation.address
        # Fail-closed, same rationale as add_revocation — a key revocation is the
        # most critical, permanent security fact and must never be spam-evicted.
        if key not in self.key_revocations and len(self.key_revocations) >= _MAX_REVOCATIONS:
            raise TransportError("key-revocation store full")
        self._key_rev_seq += 1
        self.key_revocations[key] = {
            "seq": self._key_rev_seq,
            "data": revocation.model_dump(mode="json"),
        }
        self.key_revocations.move_to_end(key)

    def list_key_revocations(self, since: int = 0) -> tuple[list[dict], int]:
        rows = [v for v in self.key_revocations.values() if v["seq"] > since]
        cursor = max((v["seq"] for v in self.key_revocations.values()), default=since)
        return [v["data"] for v in rows], cursor

    def register_waiter(self, address: str) -> asyncio.Event:
        """Create a fresh per-request long-poll event for one puller."""
        event = asyncio.Event()
        self.waiters.setdefault(address, []).append(event)
        return event

    def drop_waiter(self, address: str, event: asyncio.Event) -> None:
        waiters = self.waiters.get(address)
        if waiters and event in waiters:
            waiters.remove(event)
            if not waiters:
                self.waiters.pop(address, None)

    def has_waiter(self, address: str) -> bool:
        """True when someone is currently long-polling for this address.

        This is the online/offline signal the wake mechanism keys off: nobody
        waiting means the mail would otherwise sit unnoticed.
        """
        return bool(self.waiters.get(address))

    def _notify(self, address: str) -> None:
        # Wake every current puller for this address; each holds its own event,
        # so one puller's lifecycle never stomps another's.
        for event in self.waiters.get(address, []):
            event.set()


class SqliteRelayState(RelayState):
    """Relay storage backed by SQLite: mailboxes, cards, and revocations
    survive relay restarts. Long-poll waiters remain in-memory (they are
    connection state, not data)."""

    def __init__(self, path: str):
        super().__init__()
        import json as _json
        import sqlite3
        import threading

        self._json = _json
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS mailbox ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  address TEXT NOT NULL,"
            "  sender TEXT NOT NULL DEFAULT '',"
            "  envelope TEXT NOT NULL,"
            "  attempts INTEGER NOT NULL DEFAULT 0)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS mailbox_addr ON mailbox(address)")
        mbox_cols = {row[1] for row in self._db.execute("PRAGMA table_info(mailbox)")}
        if "attempts" not in mbox_cols:
            self._db.execute(
                "ALTER TABLE mailbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
            )
        # In-flight (leased, delivered-but-unacked) messages. Persisted so a relay
        # restart does not lose delivered-unacked mail. ``expires`` is wall-clock
        # (time.time) rather than monotonic so it is meaningful across restarts.
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS inflight ("
            "  msg_id TEXT PRIMARY KEY,"
            "  address TEXT NOT NULL,"
            "  sender TEXT NOT NULL DEFAULT '',"
            "  envelope TEXT NOT NULL,"
            "  expires REAL NOT NULL,"
            "  attempts INTEGER NOT NULL DEFAULT 0)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS inflight_addr ON inflight(address)")
        # Migrate an inflight table created before delivery-attempt capping.
        cols = {row[1] for row in self._db.execute("PRAGMA table_info(inflight)")}
        if "attempts" not in cols:
            self._db.execute(
                "ALTER TABLE inflight ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
            )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS cards (address TEXT PRIMARY KEY, card TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS revocations ("
            "  digest TEXT PRIMARY KEY, revocation TEXT NOT NULL)"
        )
        # Key revocations are the strongest, permanent revocation type — they MUST
        # survive a relay restart on the persistent backend (the in-memory base
        # class would silently lose them).
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS key_revocations ("
            "  address TEXT PRIMARY KEY, revocation TEXT NOT NULL)"
        )
        self._db.commit()

    async def run(self, fn, *args):
        # Offload blocking sqlite I/O (including fsync on commit) to a worker
        # thread so the event loop stays responsive. self._lock serializes the
        # single shared connection across whichever pool threads run these.
        import asyncio as _asyncio

        return await _asyncio.to_thread(fn, *args)

    def enqueue(self, envelope: Envelope) -> None:
        with self._lock:
            count = self._db.execute(
                "SELECT COUNT(*) FROM mailbox WHERE address = ?", (envelope.to,)
            ).fetchone()[0]
            if count >= _MAX_MAILBOX_SIZE:
                raise TransportError(f"mailbox full for {envelope.to}")
            from_sender = self._db.execute(
                "SELECT COUNT(*) FROM mailbox WHERE address = ? AND sender = ?",
                (envelope.to, envelope.sender),
            ).fetchone()[0]
            if from_sender >= _MAX_PER_SENDER:
                raise TransportError(f"per-sender quota reached for {envelope.sender}")
            self._db.execute(
                "INSERT INTO mailbox (address, sender, envelope) VALUES (?, ?, ?)",
                (envelope.to, envelope.sender, self._json.dumps(envelope.to_wire())),
            )
            self._db.commit()

    def drain(
        self, address: str, now: float | None = None, lease_seconds: float = _LEASE_SECONDS
    ) -> list[dict]:
        import time as _time

        now = _time.time() if now is None else now
        with self._lock:
            # Reclaim expired leases back to the mailbox for redelivery, one
            # more delivery attempt each — but dead-letter (drop) any that have
            # reached the attempt cap rather than redelivering a poison message.
            expired = self._db.execute(
                "SELECT sender, envelope, attempts FROM inflight"
                " WHERE address = ? AND expires <= ?",
                (address, now),
            ).fetchall()
            for sender, envelope, attempts in expired:
                if attempts + 1 >= _MAX_DELIVERY_ATTEMPTS:
                    logger.warning(
                        "relay dead-lettering a message for %s after %d attempts",
                        address, attempts + 1,
                    )
                    continue
                self._db.execute(
                    "INSERT INTO mailbox (address, sender, envelope, attempts)"
                    " VALUES (?, ?, ?, ?)",
                    (address, sender, envelope, attempts + 1),
                )
            if expired:
                self._db.execute(
                    "DELETE FROM inflight WHERE address = ? AND expires <= ?", (address, now)
                )
            # Lease all pending: move mailbox rows into in-flight, return them,
            # carrying each message's accumulated attempt count forward.
            rows = self._db.execute(
                "SELECT sender, envelope, attempts FROM mailbox"
                " WHERE address = ? ORDER BY id",
                (address,),
            ).fetchall()
            leased = [self._json.loads(envelope) for _, envelope, _ in rows]
            for (sender, envelope, attempts), wire in zip(rows, leased, strict=True):
                self._db.execute(
                    "INSERT OR REPLACE INTO inflight "
                    "(msg_id, address, sender, envelope, expires, attempts)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (wire["id"], address, sender, envelope, now + lease_seconds, attempts),
                )
            if rows:
                self._db.execute("DELETE FROM mailbox WHERE address = ?", (address,))
            self._db.commit()
        return leased

    def ack(self, address: str, ids: list[str]) -> int:
        if not ids:
            return 0
        with self._lock:
            placeholders = ",".join("?" for _ in ids)
            cur = self._db.execute(
                f"DELETE FROM inflight WHERE address = ? AND msg_id IN ({placeholders})",
                (address, *ids),
            )
            self._db.commit()
            return cur.rowcount

    def put_card(self, card: AgentCard) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO cards (address, card) VALUES (?, ?)",
                (card.address, self._json.dumps(card.model_dump(mode="json"))),
            )
            # Bound the directory: keep only the most-recent _MAX_CARDS rows.
            self._db.execute(
                "DELETE FROM cards WHERE rowid NOT IN "
                "(SELECT rowid FROM cards ORDER BY rowid DESC LIMIT ?)",
                (_MAX_CARDS,),
            )
            self._db.commit()

    def get_card(self, address: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT card FROM cards WHERE address = ?", (address,)
            ).fetchone()
        return self._json.loads(row[0]) if row else None

    def list_cards(self, since: int = 0) -> tuple[list[dict], int]:
        """Delta listing via rowid — INSERT OR REPLACE re-registers a card at a
        fresh rowid, so re-registrations reappear after the peer's cursor."""
        with self._lock:
            rows = self._db.execute(
                "SELECT rowid, card FROM cards WHERE rowid > ? ORDER BY rowid", (since,)
            ).fetchall()
            cursor = self._db.execute(
                "SELECT COALESCE(MAX(rowid), ?) FROM cards", (since,)
            ).fetchone()[0]
        return [self._json.loads(row[1]) for row in rows], cursor

    def add_revocation(self, revocation: Revocation) -> None:
        with self._lock:
            # Fail-closed: never evict an existing revocation (see RelayState).
            exists = self._db.execute(
                "SELECT 1 FROM revocations WHERE digest = ?", (revocation.delegation_digest,)
            ).fetchone()
            if not exists:
                count = self._db.execute("SELECT COUNT(*) FROM revocations").fetchone()[0]
                if count >= _MAX_REVOCATIONS:
                    raise TransportError("revocation store full")
            self._db.execute(
                "INSERT OR REPLACE INTO revocations (digest, revocation) VALUES (?, ?)",
                (
                    revocation.delegation_digest,
                    self._json.dumps(revocation.model_dump(mode="json")),
                ),
            )
            self._db.commit()

    def list_revocations(self, since: int = 0) -> tuple[list[dict], int]:
        """Delta sync via SQLite rowid as the monotonic cursor."""
        with self._lock:
            rows = self._db.execute(
                "SELECT rowid, revocation FROM revocations WHERE rowid > ? ORDER BY rowid",
                (since,),
            ).fetchall()
            cursor = self._db.execute(
                "SELECT COALESCE(MAX(rowid), ?) FROM revocations", (since,)
            ).fetchone()[0]
        return [self._json.loads(row[1]) for row in rows], cursor

    def add_key_revocation(self, revocation: KeyRevocation) -> None:
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM key_revocations WHERE address = ?", (revocation.address,)
            ).fetchone()
            if not exists:
                count = self._db.execute("SELECT COUNT(*) FROM key_revocations").fetchone()[0]
                if count >= _MAX_REVOCATIONS:
                    raise TransportError("key-revocation store full")
            self._db.execute(
                "INSERT OR REPLACE INTO key_revocations (address, revocation) VALUES (?, ?)",
                (revocation.address, self._json.dumps(revocation.model_dump(mode="json"))),
            )
            self._db.commit()

    def list_key_revocations(self, since: int = 0) -> tuple[list[dict], int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT rowid, revocation FROM key_revocations WHERE rowid > ? ORDER BY rowid",
                (since,),
            ).fetchall()
            cursor = self._db.execute(
                "SELECT COALESCE(MAX(rowid), ?) FROM key_revocations", (since,)
            ).fetchone()[0]
        return [self._json.loads(row[1]) for row in rows], cursor


def create_relay_app(
    state: RelayState | None = None,
    audience: str | None = None,
    waker: WakeNotifier | None = None,
    peers: tuple[str, ...] = (),
    sync_interval: float = 30.0,
):
    """Build the relay FastAPI app. Mountable into any ASGI deployment.

    ``audience`` is this relay's own name, bound into every signed pull and ack
    so a request captured here cannot be replayed at a different relay. Clients
    must be configured with the same string.

    Leaving it unset falls back to a well-known constant, which means every
    stock relay shares an audience and the binding protects nothing — so that
    path logs a warning rather than passing silently. Set it to something
    unique per relay (its public URL is the obvious choice).

    ``waker`` enables wake notifications: when mail arrives for an address with
    nobody long-polling, the relay pings the ``wake`` endpoint from that
    participant's registered card. Pass None to disable (the default) — an
    agent that is always connected does not need it.

    ``peers`` enables federation-lite (SPEC §13.3): each URL is another relay
    whose card directory and revocation lists are pulled every
    ``sync_interval`` seconds (verify-before-admit). Mailboxes never federate.
    """
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, HTTPException

    from .http import read_capped_json

    if audience is None:
        audience = DEFAULT_RELAY_AUDIENCE
        logger.warning(
            "AMP relay started without an audience: using the shared default "
            "%r. Every relay using this value accepts the others' signed "
            "pulls, so a captured pull can drain the same mailbox elsewhere. "
            "Pass audience=<this relay's public URL>.",
            DEFAULT_RELAY_AUDIENCE,
        )
    relay = state or RelayState()

    @asynccontextmanager
    async def _lifespan(_app):
        # Federation-lite: background pullers of each peer's directory deltas.
        from .federation import RelaySyncer

        tasks = [
            asyncio.create_task(RelaySyncer(relay, peer).run(sync_interval))
            for peer in peers
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title="AMP Relay", version="0.1", lifespan=_lifespan)
    app.state.relay = relay
    rate = _RateLimiter()

    def _rate_check(key: str) -> None:
        if not rate.allow(key):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    @app.post(SEND_PATH)
    async def send(request: Request):
        # Byte-cap the raw body before buffering/parsing (memory/CPU exhaustion),
        # then reject non-canonical content (e.g. floats) after decode.
        envelope = await read_capped_json(request, _MAX_ENVELOPE_BYTES)
        try:
            canonical_json(envelope)
        except ValueError as exc:  # non-canonical content (e.g. floats)
            raise HTTPException(status_code=422, detail=f"non-canonical envelope: {exc}") from exc
        try:
            parsed = Envelope.from_wire(envelope)
            parsed.verify_signature()
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"invalid envelope: {exc}") from exc
        _rate_check(f"send:{parsed.sender}")  # signature-verified sender
        try:
            await relay.run(relay.enqueue, parsed)
        except TransportError as exc:
            raise HTTPException(status_code=507, detail=str(exc)) from exc
        relay._notify(parsed.to)  # wake pullers on the event loop (thread-safe)
        if waker is not None and not relay.has_waiter(parsed.to):
            # Nobody is listening: ping the recipient's advertised wake endpoint
            # so an asleep agent learns there is mail. Content-free and
            # best-effort — the poll loop remains the source of truth.
            waker.schedule(parsed.to, await relay.run(relay.get_card, parsed.to))
        return {"accepted": True, "id": parsed.id}

    @app.post(PULL_PATH)
    async def pull(request: PullRequest):
        _verify_pull(request.address, request.ts, request.sig)
        _rate_check(f"pull:{request.address}")  # signature-verified address
        envelopes = await relay.run(relay.drain, request.address)
        if not envelopes and request.wait_seconds > 0:
            event = relay.register_waiter(request.address)
            try:
                await asyncio.wait_for(event.wait(), min(request.wait_seconds, 30.0))
            except TimeoutError:
                pass
            finally:
                relay.drop_waiter(request.address, event)
            envelopes = await relay.run(relay.drain, request.address)
        return {"envelopes": envelopes}

    @app.post(ACK_PATH)
    async def ack(request: AckRequest):
        _verify_signed_request(
            request.address, request.ts, request.sig,
            _ack_payload(request.address, request.ts, request.ids, audience),
        )
        _rate_check(f"ack:{request.address}")
        removed = await relay.run(relay.ack, request.address, request.ids)
        return {"acked": removed}

    @app.put(CARDS_PATH)
    async def put_card(card: dict):
        try:
            parsed = AgentCard.model_validate(card)
            parsed.verify()
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"invalid card: {exc}") from exc
        _rate_check(f"card:{parsed.address}")  # self-signed, verified above
        await relay.run(relay.put_card, parsed)
        return {"registered": parsed.address}

    @app.get(CARDS_PATH + "/{address}")
    async def get_card(address: str):
        card = await relay.run(relay.get_card, address)
        if card is None:
            raise HTTPException(status_code=404, detail="unknown agent")
        return card

    @app.get(CARDS_PATH)
    async def list_cards(since: int = 0):
        """Delta listing of the card directory (federation sync; SPEC §13.3)."""
        rows, cursor = await relay.run(relay.list_cards, since)
        return {"cards": rows, "cursor": cursor}

    @app.post(REVOCATIONS_PATH)
    async def post_revocation(revocation: dict):
        try:
            parsed = Revocation.model_validate(revocation)
            parsed.verify()
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"invalid revocation: {exc}") from exc
        # Keyed on the signature-verified issuer, like every other endpoint —
        # never on the object being acted upon. Keying on the digest let one
        # issuer post unlimited revocations by varying it, and made the bucket
        # belong to the victim: re-posting one digest could lock the legitimate
        # issuer out of publishing its own revocation.
        _rate_check(f"rev:{parsed.issuer}")
        await relay.run(relay.add_revocation, parsed)
        return {"revoked": parsed.delegation_digest}

    @app.get(REVOCATIONS_PATH)
    async def get_revocations(since: int = 0):
        rows, cursor = await relay.run(relay.list_revocations, since)
        return {"revocations": rows, "cursor": cursor}

    @app.post(KEY_REVOCATIONS_PATH)
    async def post_key_revocation(revocation: dict):
        try:
            parsed = KeyRevocation.model_validate(revocation)
            parsed.verify()
        except Exception as exc:
            raise HTTPException(
                status_code=422, detail=f"invalid key-revocation: {exc}"
            ) from exc
        _rate_check(f"keyrev:{parsed.issuer}")
        await relay.run(relay.add_key_revocation, parsed)
        return {"revoked_key": parsed.address}

    @app.get(KEY_REVOCATIONS_PATH)
    async def get_key_revocations(since: int = 0):
        rows, cursor = await relay.run(relay.list_key_revocations, since)
        return {"key_revocations": rows, "cursor": cursor}

    def _verify_signed_request(address: str, ts: str, sig: str, payload: bytes) -> None:
        """Freshness + signature check shared by pull and ack."""
        try:
            issued = datetime.fromisoformat(ts)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="invalid timestamp") from exc
        # A naive (tz-less) timestamp parses fine but would raise TypeError on the
        # subtraction below; reject it as malformed rather than 500.
        if issued.tzinfo is None:
            raise HTTPException(status_code=422, detail="timestamp must be timezone-aware")
        age = abs((datetime.now(UTC) - issued).total_seconds())
        if age > _PULL_MAX_AGE_SECONDS:
            raise HTTPException(status_code=401, detail="request expired")
        try:
            keys = PublicKeys(signing=signing_key_from_address(address), agreement=b"\x00" * 32)
            # decode_signature, not bare b64decode: the single-use pull guard
            # below keys on this string, so accepting several spellings of one
            # signature would let a captured pull be replayed under each.
            keys.verify(decode_signature(sig), payload)
        except Exception as exc:
            raise HTTPException(status_code=401, detail="signature invalid") from exc

    def _verify_pull(address: str, ts: str, sig: str) -> None:
        _verify_signed_request(address, ts, sig, _pull_payload(address, ts, audience))
        # Single-use within the freshness window: a captured pull cannot be
        # replayed to re-drain a victim's mailbox. (Ack is idempotent, so it does
        # not need this guard.)
        if not relay.check_pull_replay(sig, time.monotonic()):
            raise HTTPException(status_code=401, detail="pull request already used")

    # Real-time WS transport (SPEC §13.4): same auth model, socket-scoped.
    from .relay_ws import register_ws_endpoint

    register_ws_endpoint(app, relay, audience, rate.allow, waker)

    return app


# --------------------------------------------------------------------------
# Client transport
# --------------------------------------------------------------------------


def relay_endpoints(card: AgentCard) -> list[str]:
    """A card's relay URLs in failover order (SPEC §13.3).

    Convention: the primary rides ``endpoints["relay"]``; additional relays
    ride ``relay.1``, ``relay.2``, … and are tried in numeric order. The card
    is signed, so the list — and its order — is the participant's own
    authenticated statement of where it can be reached.
    """
    ordered: list[tuple[int, str]] = []
    for name, url in card.endpoints.items():
        if name == "relay":
            ordered.append((0, url))
        elif name.startswith("relay."):
            suffix = name.removeprefix("relay.")
            if suffix.isdigit():
                ordered.append((int(suffix), url))
    return [url for _, url in sorted(ordered)]


class RelayTransport(Transport):
    """Transport that speaks to one or more relay servers over HTTP.

    ``base_url`` may be a single URL or an ordered sequence — additional URLs
    are failover targets tried in order when the one before them is
    unreachable or failing (5xx). First definitive answer wins; the seq-based
    session dedup absorbs any duplicate delivery a retry causes.

    ``audience`` mirrors that shape: one string applies to every relay, or a
    sequence pairs each relay with its own audience (audiences are unique per
    relay by design, so multi-relay deployments should pass the sequence).

    ``http_call`` is injectable for tests; the default uses aiohttp.
    """

    def __init__(
        self,
        base_url: str | Sequence[str],
        http_call: Any = None,
        audience: str | Sequence[str] = DEFAULT_RELAY_AUDIENCE,
    ):
        bases = [base_url] if isinstance(base_url, str) else list(base_url)
        if not bases:
            raise ValueError("RelayTransport needs at least one relay URL")
        audiences = [audience] * len(bases) if isinstance(audience, str) else list(audience)
        if len(audiences) != len(bases):
            raise ValueError(
                f"got {len(audiences)} audiences for {len(bases)} relays; "
                "pass one audience per relay (or a single shared string)"
            )
        self._targets: list[tuple[str, str]] = [
            (base.rstrip("/"), aud) for base, aud in zip(bases, audiences, strict=True)
        ]
        self._base, self._audience = self._targets[0]
        self._handlers: dict[str, InboundHandler] = {}
        self._http_call = http_call or self._aiohttp_call
        self._session = None  # aiohttp session, lazily created
        self._poll_tasks: dict[str, asyncio.Task] = {}
        # Delta-sync cursors: only revocations newer than these are re-fetched,
        # so a growing revocation table doesn't re-download in full each sync.
        self._rev_cursor = 0
        self._key_rev_cursor = 0

    @classmethod
    def for_card(
        cls,
        card: AgentCard,
        http_call: Any = None,
        audience: str | Sequence[str] = DEFAULT_RELAY_AUDIENCE,
    ) -> RelayTransport:
        """A transport targeting the relays a peer's signed card advertises.

        A participant reachable on relay A must be messaged via relay A —
        mailboxes never federate (SPEC §13.3) — so the peer's card, not our
        own configuration, is what names the send targets.
        """
        urls = relay_endpoints(card)
        if not urls:
            raise TransportError(f"card for {card.address} advertises no relay endpoint")
        return cls(urls, http_call=http_call, audience=audience)

    async def _call_failover(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        body_fn: Callable[[str, str], dict] | None = None,
    ) -> tuple[int, dict]:
        """Try each relay in order; first definitive answer wins.

        A transport error or 5xx moves on to the next relay; any status < 500
        (success or a real 4xx verdict) is returned as-is. ``body_fn`` builds a
        per-relay body for signed requests, whose signatures are audience-bound
        and therefore cannot be reused across relays.
        """
        last_exc: Exception | None = None
        last_result: tuple[int, dict] | None = None
        for base, aud in self._targets:
            body = body_fn(base, aud) if body_fn is not None else (json_body or {})
            try:
                status, data = await self._http_call(method, base + path, body)
            except Exception as exc:  # noqa: BLE001 — unreachable relay: try the next
                last_exc = exc
                continue
            if status >= 500:
                last_result = (status, data)
                continue
            return status, data
        if last_result is not None:
            return last_result
        raise TransportError(f"no relay reachable for {method} {path}: {last_exc}")

    async def _aiohttp_call(self, method: str, url: str, json_body: dict) -> tuple[int, dict]:
        try:
            import aiohttp
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "RelayTransport requires: pip install 'fg-amp[http]'"
            ) from exc
        if self._session is None:
            self._session = aiohttp.ClientSession()
        async with self._session.request(
            method, url, json=json_body, timeout=aiohttp.ClientTimeout(total=60)
        ) as response:
            data = await response.json() if response.content_type == "application/json" else {}
            return response.status, data

    async def connect(self, node: AmpNode, poll_interval: float = 1.0) -> None:
        """Register the node's card, bind it, and start pulling its mailbox.

        The card is registered on EVERY configured relay (each is a place the
        card claims we are reachable), tolerating individual failures as long
        as at least one registration lands.
        """
        card_wire = node.card.model_dump(mode="json")
        registered = 0
        last_error: str = "no relays configured"
        for base, _ in self._targets:
            try:
                status, data = await self._http_call("PUT", base + CARDS_PATH, card_wire)
            except Exception as exc:  # noqa: BLE001 — a down relay must not block the rest
                last_error = str(exc)
                continue
            if status >= 400:
                last_error = f"HTTP {status} {data}"
                continue
            registered += 1
        if registered == 0:
            raise TransportError(f"card registration failed on every relay: {last_error}")
        node.attach(self)
        self._poll_tasks[node.address] = asyncio.create_task(
            self._poll_loop(node, poll_interval)
        )

    async def disconnect(self, node: AmpNode) -> None:
        task = self._poll_tasks.pop(node.address, None)
        if task is not None:
            task.cancel()
        node.detach()
        if self._session is not None and not self._poll_tasks:
            await self._session.close()
            self._session = None

    async def publish_revocation(self, revocation: Revocation) -> None:
        """Announce an early delegation recall to everyone using this relay."""
        status, data = await self._call_failover(
            "POST", REVOCATIONS_PATH, revocation.model_dump(mode="json")
        )
        if status >= 400:
            raise TransportError(f"revocation publish failed: HTTP {status} {data}")

    async def sync_revocations(self, node: AmpNode) -> int:
        """Load new delegation revocations (since the last sync) into the node."""
        status, data = await self._call_failover(
            "GET", f"{REVOCATIONS_PATH}?since={self._rev_cursor}"
        )
        if status >= 400:
            raise TransportError(f"revocation fetch failed: HTTP {status}")
        count = 0
        for wire in data.get("revocations", []):
            try:
                node.revocations.add(Revocation.model_validate(wire))
                count += 1
            except Exception:  # noqa: BLE001 — a bad entry must not poison the sync
                continue
        self._rev_cursor = int(data.get("cursor", self._rev_cursor))
        return count

    async def publish_key_revocation(self, revocation: KeyRevocation) -> None:
        """Announce a compromised agent's identity-key revocation to the relay."""
        status, data = await self._call_failover(
            "POST", KEY_REVOCATIONS_PATH, revocation.model_dump(mode="json")
        )
        if status >= 400:
            raise TransportError(f"key-revocation publish failed: HTTP {status} {data}")

    async def sync_key_revocations(self, node: AmpNode) -> int:
        """Load new key revocations (since the last sync) into the node."""
        status, data = await self._call_failover(
            "GET", f"{KEY_REVOCATIONS_PATH}?since={self._key_rev_cursor}"
        )
        if status >= 400:
            raise TransportError(f"key-revocation fetch failed: HTTP {status}")
        count = 0
        for wire in data.get("key_revocations", []):
            try:
                node.revocations.revoke_key(KeyRevocation.model_validate(wire))
                count += 1
            except Exception:  # noqa: BLE001 — a bad entry must not poison the sync
                continue
        self._key_rev_cursor = int(data.get("cursor", self._key_rev_cursor))
        return count

    async def resolve_card(self, address: str) -> AgentCard:
        status, data = await self._call_failover("GET", f"{CARDS_PATH}/{address}")
        if status >= 400:
            raise TransportError(f"card lookup failed for {address}: HTTP {status}")
        card = AgentCard.model_validate(data)
        card.verify()
        return card

    async def deliver(self, envelope: Envelope) -> None:
        local = self._handlers.get(envelope.to)
        if local is not None:
            await local(envelope)
            return
        # Ordered failover across the configured relays (SPEC §13.3): first
        # relay that definitively accepts (or definitively rejects) wins. A
        # retry after an ambiguous failure can duplicate delivery; the session
        # layer's per-seq dedup absorbs that, and no stronger exactly-once
        # guarantee is claimed.
        status, data = await self._call_failover("POST", SEND_PATH, envelope.to_wire())
        if status >= 400:
            raise TransportError(f"relay send failed: HTTP {status} {data}")

    def bind(self, address: str, handler: InboundHandler) -> None:
        self._handlers[address] = handler

    def unbind(self, address: str) -> None:
        self._handlers.pop(address, None)

    async def _ack(self, node: AmpNode, ids: list[str]) -> None:
        """Acknowledge received messages so the relay removes them. Best-effort:
        a failed ack simply means those messages are redelivered later, which the
        session layer deduplicates — so an ack failure never loses or corrupts."""
        def signed_ack(base: str, audience: str) -> dict:
            # Signatures are audience-bound, so each relay gets its own.
            ts = datetime.now(UTC).isoformat()
            sig = base64.b64encode(
                node.identity.keys.sign(_ack_payload(node.address, ts, ids, audience))
            ).decode()
            return {"address": node.address, "ts": ts, "sig": sig, "ids": ids}

        try:
            await self._call_failover("POST", ACK_PATH, body_fn=signed_ack)
        except Exception:  # noqa: BLE001 — redelivery is the safety net
            pass

    async def _poll_loop(self, node: AmpNode, poll_interval: float) -> None:
        def signed_pull(base: str, audience: str) -> dict:
            # Per-relay body: pull signatures are audience-bound by design.
            ts = datetime.now(UTC).isoformat()
            sig = base64.b64encode(
                node.identity.keys.sign(_pull_payload(node.address, ts, audience))
            ).decode()
            return {"address": node.address, "ts": ts, "sig": sig, "wait_seconds": 25.0}

        while True:
            try:
                status, data = await self._call_failover(
                    "POST", PULL_PATH, body_fn=signed_pull
                )
                if status >= 400:
                    await asyncio.sleep(poll_interval)
                    continue
                handler = self._handlers.get(node.address)
                if handler is None:
                    return
                acked: list[str] = []
                for wire in data.get("envelopes", []):
                    mid = wire.get("id")
                    try:
                        parsed = Envelope.from_wire(wire)
                    except Exception:  # noqa: BLE001 — malformed: ack to drop (redelivery won't help)
                        if mid:
                            acked.append(mid)
                        continue
                    try:
                        await handler(parsed)
                    except Exception:  # noqa: BLE001 — leave unacked so the relay redelivers
                        continue
                    if mid:
                        acked.append(mid)
                # Confirm the messages we durably handled so the relay drops them;
                # anything we didn't ack is reclaimed and redelivered (at-least-once).
                if acked:
                    await self._ack(node, acked)
                await asyncio.sleep(0)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — transient network errors: back off and retry
                await asyncio.sleep(poll_interval)


def main() -> None:  # pragma: no cover - thin CLI wrapper
    """Run a standalone relay: ``amp-relay [--host 0.0.0.0] [--port 8404]``."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Run an AMP relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8404)
    parser.add_argument(
        "--db", default=None, help="SQLite path for persistent storage (default: in-memory)"
    )
    parser.add_argument(
        "--audience", default=None, help="this relay's unique audience (its public URL)"
    )
    parser.add_argument(
        "--peer",
        action="append",
        default=[],
        metavar="URL",
        help="federate with another relay: pull its cards/revocations deltas "
        "periodically (repeatable; mailboxes never federate)",
    )
    parser.add_argument(
        "--sync-interval",
        type=float,
        default=30.0,
        help="seconds between federation sync rounds (default: 30)",
    )
    args = parser.parse_args()
    state = SqliteRelayState(args.db) if args.db else RelayState()
    app = create_relay_app(
        state,
        audience=args.audience,
        peers=tuple(args.peer),
        sync_interval=args.sync_interval,
    )
    uvicorn.run(app, host=args.host, port=args.port)
