"""amp.payment/1: lifecycle legality, spend-scope enforcement at both ends,
and the full quote→authorize→settle flow over real sessions."""

import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from fg_amp import (
    AgentIdentity,
    AmpNode,
    Delegation,
    DelegationChain,
    InMemoryTransport,
    PaymentBody,
    PaymentKind,
    PaymentLifecycleError,
    PaymentState,
    PaymentTracker,
    Session,
    SessionState,
    SpendRejectedError,
)

ASSET = "usdc"


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def quote(pid: str, amount: str = "10", valid_for: float | None = 3600.0) -> PaymentBody:
    return PaymentBody(
        payment_id=pid,
        kind=PaymentKind.QUOTE,
        amount=amount,
        asset=ASSET,
        pay_to="0x" + "ff" * 20,
        valid_until=(
            rfc3339(datetime.now(UTC) + timedelta(seconds=valid_for)) if valid_for else None
        ),
        x402={"scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "10000000"},
    )


def authorization(pid: str) -> PaymentBody:
    return PaymentBody(
        payment_id=pid,
        kind=PaymentKind.AUTHORIZATION,
        x402={"signature": "0x" + "aa" * 65},
        chain_ref="handshake",
    )


def payer_identity(scopes: set[str]) -> AgentIdentity:
    """A payer whose delegation chain grants the given (spend) scopes."""
    principal = AgentIdentity.generate("principal")
    payer = AgentIdentity.generate("payer")
    chain = DelegationChain(
        links=(
            Delegation.grant(principal.keys, principal.address, payer.address, scopes, 3600),
        )
    )
    return payer.with_delegation(chain)


async def make_pair(payer: AgentIdentity) -> tuple[Session, Session]:
    """(payer session, payee session) over an in-memory transport."""
    inbound: list[Session] = []

    async def on_session(session: Session):
        inbound.append(session)

    payee_node = AmpNode(identity=AgentIdentity.generate("payee"), on_session=on_session)
    payer_node = AmpNode(identity=payer)
    transport = InMemoryTransport()
    payer_node.attach(transport)
    payee_node.attach(transport)
    session = await payer_node.initiate(payee_node.card, purpose="payment", ttl_seconds=60)
    assert len(inbound) == 1
    return session, inbound[0]


# -- body schema ------------------------------------------------------------


def test_quote_requires_amount_asset_and_pay_to():
    with pytest.raises(ValidationError, match="asset"):
        PaymentBody(payment_id="p1", kind=PaymentKind.QUOTE, amount="5", pay_to="dest")
    with pytest.raises(ValidationError, match="pay_to"):
        PaymentBody(payment_id="p1", kind=PaymentKind.QUOTE, amount="5", asset=ASSET)
    with pytest.raises(ValidationError, match="decimal"):
        PaymentBody(
            payment_id="p1", kind=PaymentKind.QUOTE, amount="1e6", asset=ASSET, pay_to="dest"
        )


def test_x402_content_is_opaque_passthrough():
    body = quote("p1")
    round_tripped = PaymentBody.model_validate(body.model_dump(mode="json"))
    assert round_tripped.x402 == body.x402  # carried verbatim, never re-modeled


# -- lifecycle legality (PaymentTracker) ------------------------------------


def test_full_lifecycle_is_legal():
    tracker = PaymentTracker()
    tracker.apply(quote("p1"), actor="local")  # payee quotes
    assert tracker.state_of("p1") is PaymentState.QUOTED
    tracker.apply(authorization("p1"), actor="peer")  # payer authorizes
    assert tracker.state_of("p1") is PaymentState.AUTHORIZED
    tracker.apply(
        PaymentBody(payment_id="p1", kind=PaymentKind.SETTLED, tx_ref="0xdead"), actor="local"
    )
    assert tracker.state_of("p1") is None  # terminal


def test_duplicate_quote_is_illegal():
    tracker = PaymentTracker()
    tracker.apply(quote("p1"), actor="local")
    with pytest.raises(PaymentLifecycleError, match="already exists"):
        tracker.apply(quote("p1"), actor="local")


def test_authorization_needs_a_known_quote():
    with pytest.raises(PaymentLifecycleError, match="unknown payment"):
        PaymentTracker().apply(authorization("ghost"), actor="peer")


def test_quoter_cannot_authorize_its_own_quote():
    tracker = PaymentTracker()
    tracker.apply(quote("p1"), actor="local")
    with pytest.raises(PaymentLifecycleError, match="cannot authorize"):
        tracker.apply(authorization("p1"), actor="local")


def test_expired_quote_cannot_be_authorized():
    tracker = PaymentTracker()
    tracker.apply(quote("p1", valid_for=3600), actor="local")
    later = datetime.now(UTC) + timedelta(hours=2)
    with pytest.raises(PaymentLifecycleError, match="expired"):
        tracker.apply(authorization("p1"), actor="peer", now=later)
    assert tracker.state_of("p1") is PaymentState.QUOTED  # untouched


def test_settlement_requires_an_authorized_payment_and_the_quoter():
    tracker = PaymentTracker()
    tracker.apply(quote("p1"), actor="local")
    with pytest.raises(PaymentLifecycleError, match="requires an authorized"):
        tracker.apply(PaymentBody(payment_id="p1", kind=PaymentKind.SETTLED), actor="local")
    tracker.apply(authorization("p1"), actor="peer")
    with pytest.raises(PaymentLifecycleError, match="only the quoting side"):
        tracker.apply(PaymentBody(payment_id="p1", kind=PaymentKind.FAILED), actor="peer")


def test_failed_spend_check_leaves_tracker_untouched():
    tracker = PaymentTracker()
    tracker.apply(quote("p1"), actor="local")

    def reject(_quote):
        raise SpendRejectedError("over cap")

    with pytest.raises(SpendRejectedError):
        tracker.apply(authorization("p1"), actor="peer", spend_check=reject)
    assert tracker.state_of("p1") is PaymentState.QUOTED


# -- spend-scope enforcement over real sessions -----------------------------


async def test_e2e_payment_flow():
    payer, payee = await make_pair(payer_identity({f"pay:{ASSET}:tx<=25:total<=40"}))

    await payee.send_body(quote("p1", amount="12.50"))
    assert (await payer.receive(timeout=1)).payload.content["amount"] == "12.50"

    await payer.send_body(authorization("p1"))
    got = await payee.receive(timeout=1)
    assert got.payload.content["x402"] == {"signature": "0x" + "aa" * 65}
    assert payee.payments.state_of("p1") is PaymentState.AUTHORIZED
    # both ledgers track the authorized amount
    assert payer.spend.spent(ASSET) == Decimal("12.50")
    assert payee.peer_spend.spent(ASSET) == Decimal("12.50")

    await payee.send_body(PaymentBody(payment_id="p1", kind=PaymentKind.SETTLED, tx_ref="0xok"))
    assert (await payer.receive(timeout=1)).payload.content["tx_ref"] == "0xok"
    assert payer.payments.state_of("p1") is None
    assert payer.state is SessionState.ESTABLISHED


async def test_sender_rejects_authorization_over_tx_cap():
    payer, payee = await make_pair(payer_identity({f"pay:{ASSET}:tx<=25"}))
    await payee.send_body(quote("p1", amount="26"))
    await payer.receive(timeout=1)
    sent_before = payer.stats.sent
    with pytest.raises(SpendRejectedError, match="per-transaction cap"):
        await payer.send_body(authorization("p1"))
    assert payer.stats.sent == sent_before  # never reached the wire
    assert payer.payments.state_of("p1") is PaymentState.QUOTED
    assert payer.spend.spent(ASSET) == Decimal(0)
    assert payer.state is SessionState.ESTABLISHED


async def test_sender_rejects_total_cap_across_authorizations():
    payer, payee = await make_pair(payer_identity({f"pay:{ASSET}:tx<=25:total<=40"}))
    for pid in ("p1", "p2"):
        await payee.send_body(quote(pid, amount="25"))
        await payer.receive(timeout=1)

    await payer.send_body(authorization("p1"))  # 25 of 40: fine
    await payee.receive(timeout=1)
    with pytest.raises(SpendRejectedError, match="total cap"):
        await payer.send_body(authorization("p2"))  # 25 + 25 > 40
    assert payer.spend.spent(ASSET) == Decimal("25")
    assert payer.state is SessionState.ESTABLISHED


async def test_sender_without_spend_authority_cannot_pay():
    payer, payee = await make_pair(payer_identity({"converse"}))
    await payee.send_body(quote("p1", amount="1"))
    await payer.receive(timeout=1)
    with pytest.raises(SpendRejectedError, match="no spend authority"):
        await payer.send_body(authorization("p1"))


async def test_receiver_rejects_authorization_beyond_payer_chain():
    payer, payee = await make_pair(payer_identity({f"pay:{ASSET}:tx<=25"}))
    await payee.send_body(quote("p1", amount="26"))
    await payer.receive(timeout=1)
    # A dishonest payer skips its own outbound check; the payee still holds the
    # payer's handshake-verified chain and rejects as a protocol error.
    payer._own_chain = None
    await payer.send_body(authorization("p1"))
    await asyncio.sleep(0)
    assert payee.state is SessionState.CLOSED
    assert payee.receive_nowait() is None  # never delivered
    assert payee.peer_spend.spent(ASSET) == Decimal(0)
