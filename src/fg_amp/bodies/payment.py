"""``amp.payment/1`` — the x402 payment profile and its per-session state.

AMP carries, x402 settles. A payment is a four-step exchange: the payee sends
a ``quote`` (amount, asset, destination, and the x402 payment-requirements
object verbatim), the payer answers with an ``authorization`` (the x402
payment payload verbatim), and the payee closes with ``settled`` or
``failed``. The x402 structures ride opaque under the ``x402`` field — this
profile never re-models or validates x402's own schema.

Spend authority comes from delegation chains (``fg_agent_id.spend``, SPEC
§10 of the identity standard): before a payer's ``authorization`` leaves the
session, its own chain must cap-verify the quoted (asset, amount) against a
per-session :class:`SpendLedger` of what it has already authorized. The payee
holds the payer's chain from the handshake and MAY run the same verification
on receive. ``PaymentTracker`` enforces lifecycle legality per session, in
the same style as ``TaskTracker``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, ClassVar

from fg_agent_id.spend import parse_amount
from pydantic import BaseModel, Field, field_validator, model_validator

from ..errors import PaymentLifecycleError


class PaymentKind(StrEnum):
    QUOTE = "quote"
    AUTHORIZATION = "authorization"
    SETTLED = "settled"
    FAILED = "failed"


class PaymentState(StrEnum):
    QUOTED = "quoted"
    AUTHORIZED = "authorized"


class PaymentBody(BaseModel):
    """One event in a payment's lifecycle, keyed by a sender-unique
    ``payment_id`` (the quote's id; every later kind references it)."""

    TYPE: ClassVar[str] = "amp.payment/1"

    payment_id: str
    kind: PaymentKind
    amount: str = ""  # decimal string (never a float); REQUIRED on quote
    asset: str = ""  # opaque lowercase asset token; REQUIRED on quote
    pay_to: str = ""  # settlement destination; REQUIRED on quote
    valid_until: str | None = None  # RFC 3339 quote expiry
    x402: dict[str, Any] = Field(default_factory=dict)  # opaque x402 passthrough
    chain_ref: str = ""  # authorization: reference to the payer's presented chain
    tx_ref: str = ""  # settled/failed: settlement transaction reference
    reason: str = ""  # failed: why

    model_config = {"extra": "allow", "frozen": True}

    @field_validator("payment_id")
    @classmethod
    def _payment_id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("payment_id must be non-empty")
        return v

    @model_validator(mode="after")
    def _quote_is_complete(self) -> PaymentBody:
        if self.kind is PaymentKind.QUOTE:
            if not self.asset.strip():
                raise ValueError("a payment quote must carry an asset")
            if not self.pay_to.strip():
                raise ValueError("a payment quote must carry a pay_to destination")
            try:
                parse_amount(self.amount)
            except Exception as exc:
                raise ValueError(f"quote amount must be a decimal string: {exc}") from exc
        return self


class Quote:
    """The tracked terms of a live quote — what an authorization commits to."""

    __slots__ = ("amount", "asset", "pay_to", "valid_until", "quoter")

    def __init__(
        self,
        amount: Decimal,
        asset: str,
        pay_to: str,
        valid_until: datetime | None,
        quoter: str,
    ) -> None:
        self.amount = amount
        self.asset = asset
        self.pay_to = pay_to
        self.valid_until = valid_until
        self.quoter = quoter  # "local" | "peer" — the payee side


class _Payment:
    __slots__ = ("state", "quote")

    def __init__(self, quote: Quote) -> None:
        self.state = PaymentState.QUOTED
        self.quote = quote


def _parse_valid_until(text: str | None) -> datetime | None:
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PaymentLifecycleError(f"invalid valid_until timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


class PaymentTracker:
    """Per-session payment lifecycle legality (SPEC §16.5).

    ``apply`` is called for every ``amp.payment/1`` body crossing the session
    — ``actor="local"`` for outbound (before encrypt), ``actor="peer"`` for
    inbound (after decrypt). An illegal transition raises
    :class:`PaymentLifecycleError` and MUST NOT mutate tracker state. For an
    ``authorization``, an optional ``spend_check`` callback runs against the
    referenced quote after all legality checks and before any mutation, so a
    spend-cap rejection also leaves the tracker untouched.
    """

    def __init__(self) -> None:
        self._payments: dict[str, _Payment] = {}

    def state_of(self, payment_id: str) -> PaymentState | None:
        payment = self._payments.get(payment_id)
        return payment.state if payment else None

    def quote_of(self, payment_id: str) -> Quote | None:
        payment = self._payments.get(payment_id)
        return payment.quote if payment else None

    def apply(
        self,
        body: PaymentBody,
        *,
        actor: str,
        spend_check: Callable[[Quote], None] | None = None,
        now: datetime | None = None,
    ) -> None:
        kind, pid = body.kind, body.payment_id
        payment = self._payments.get(pid)
        if kind is PaymentKind.QUOTE:
            if payment is not None:
                raise PaymentLifecycleError(f"payment {pid!r} already exists")
            quote = Quote(
                amount=parse_amount(body.amount),
                asset=body.asset,
                pay_to=body.pay_to,
                valid_until=_parse_valid_until(body.valid_until),
                quoter=actor,
            )
            self._payments[pid] = _Payment(quote)
            return
        if payment is None:
            raise PaymentLifecycleError(f"{kind} for unknown payment {pid!r}")
        quote = payment.quote
        if kind is PaymentKind.AUTHORIZATION:
            if actor == quote.quoter:
                raise PaymentLifecycleError(
                    f"the quoting side cannot authorize its own quote {pid!r}"
                )
            if payment.state is not PaymentState.QUOTED:
                raise PaymentLifecycleError(
                    f"authorization on payment {pid!r} in state {payment.state}"
                )
            if quote.valid_until is not None:
                if (now or datetime.now(UTC)) >= quote.valid_until:
                    raise PaymentLifecycleError(f"quote {pid!r} has expired")
            if spend_check is not None:
                spend_check(quote)  # may raise; tracker state is still untouched
            payment.state = PaymentState.AUTHORIZED
            return
        if kind in (PaymentKind.SETTLED, PaymentKind.FAILED):
            if actor != quote.quoter:
                raise PaymentLifecycleError(
                    f"only the quoting side may report {kind} for payment {pid!r}"
                )
            if payment.state is not PaymentState.AUTHORIZED:
                raise PaymentLifecycleError(
                    f"{kind} on payment {pid!r} requires an authorized payment "
                    f"(state: {payment.state})"
                )
            del self._payments[pid]
            return
        raise PaymentLifecycleError(f"unhandled payment kind {kind!r}")  # pragma: no cover


class SpendLedger:
    """Cumulative authorized amounts per asset — one session's own books.

    In-memory and per-session, on the same footing as the trackers: it feeds
    ``spent_so_far`` into chain verification so a ``total<=`` cap holds across
    multiple authorizations, and records only after a send/receive is legal.
    """

    def __init__(self) -> None:
        self._spent: dict[str, Decimal] = {}

    def spent(self, asset: str) -> Decimal:
        return self._spent.get(asset, Decimal(0))

    def record(self, asset: str, amount: Decimal) -> None:
        self._spent[asset] = self.spent(asset) + amount
