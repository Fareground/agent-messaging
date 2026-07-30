"""Contact policy: code-enforced rules for who may open a session, and how.

The policy engine runs on every handshake.initiate *after* signature and card
verification. It is deliberately not an LLM decision — refusing unwanted
contact must not be promptable.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable
from enum import StrEnum

from pydantic import BaseModel

from ..bodies import BUILTIN_BODY_TYPES
from ..errors import DelegationError
from ..identity.card import ParticipantKind
from ..session.group import GROUP_PAYLOAD_TYPES
from ..session.handshake import HandshakeInitiate
from ..session.states import SessionMode

# Cap on distinct peers tracked for rate limiting, bounding memory under an
# address-churn flood. Large enough that legitimate peer counts never evict.
_MAX_TRACKED_PEERS = 65_536

DEFAULT_ACCEPTED_PAYLOAD_TYPES = (
    "text/plain",
    "application/json",
    *BUILTIN_BODY_TYPES,
    *GROUP_PAYLOAD_TYPES,
)

_log = logging.getLogger("fg_amp.policy")


class PolicyMode(StrEnum):
    OPEN = "open"                  # anyone with a valid card may initiate
    CREDENTIALED = "credentialed"  # must present a delegation chain with required scopes
    ALLOWLIST = "allowlist"        # only listed addresses / operators
    CLOSED = "closed"              # no inbound initiations


class Decision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    DEFER = "defer"  # route to human approval callback


class PolicyResult(BaseModel):
    decision: Decision
    reason: str = ""
    accepted_payload_types: tuple[str, ...] = ()

    model_config = {"frozen": True}


ApprovalFn = Callable[[HandshakeInitiate], Awaitable[bool]]


class ContactPolicy(BaseModel):
    mode: PolicyMode = PolicyMode.OPEN
    require_scopes: frozenset[str] = frozenset()
    # Owners (delegation-chain roots) whose authority this endpoint trusts.
    # Scopes are only meaningful relative to a trusted root: a peer can always
    # self-sign a chain granting itself any scope, so require_scopes is an
    # access gate ONLY when trusted_issuers pins who may have granted them.
    trusted_issuers: frozenset[str] = frozenset()
    allow_addresses: frozenset[str] = frozenset()
    allow_operators: frozenset[str] = frozenset()
    allow_kinds: frozenset[ParticipantKind] = frozenset(ParticipantKind)  # who may knock
    accepted_payload_types: tuple[str, ...] = DEFAULT_ACCEPTED_PAYLOAD_TYPES
    accept_modes: frozenset[SessionMode] = frozenset(
        {SessionMode.EPHEMERAL, SessionMode.PERSISTENT}
    )
    max_sessions: int = 256
    rate_limit_per_peer: int = 10       # initiations per window per peer
    rate_limit_window_seconds: float = 60.0
    max_ttl_seconds: float = 86400.0
    human_approval: bool = False

    model_config = {"frozen": True}

    @classmethod
    def open(cls) -> ContactPolicy:
        return cls(mode=PolicyMode.OPEN)

    @classmethod
    def credentialed(
        cls, scopes: set[str], trusted_issuers: set[str] | None = None
    ) -> ContactPolicy:
        """Require a delegation chain granting ``scopes``.

        Pass ``trusted_issuers`` (the owner addresses you trust) to make this a
        real access gate — without it, any peer can self-sign a satisfying
        chain and the scopes are advisory only. A warning is logged in that
        case so the weaker configuration is never silent.
        """
        return cls(
            mode=PolicyMode.CREDENTIALED,
            require_scopes=frozenset(scopes),
            trusted_issuers=frozenset(trusted_issuers or set()),
        )

    @classmethod
    def allowlist(
        cls, addresses: set[str] | None = None, operators: set[str] | None = None
    ) -> ContactPolicy:
        return cls(
            mode=PolicyMode.ALLOWLIST,
            allow_addresses=frozenset(addresses or set()),
            allow_operators=frozenset(operators or set()),
        )


class PolicyEngine:
    """Evaluates initiations against a ContactPolicy, with rate limiting.

    ``revoked_digests`` supplies the node's known revocations at check time,
    so recalled delegations fail even before their natural expiry.
    """

    def __init__(
        self,
        policy: ContactPolicy,
        approval_fn: ApprovalFn | None = None,
        revoked_digests: Callable[[], frozenset[str]] | None = None,
        revoked_keys: Callable[[], frozenset[str]] | None = None,
    ):
        self.policy = policy
        self.approval_fn = approval_fn
        self.revoked_digests = revoked_digests or frozenset
        self.revoked_keys = revoked_keys or frozenset
        # Per-peer initiation timestamps for rate limiting. Bounded: an attacker
        # minting unlimited distinct addresses (each knocking once) would
        # otherwise grow this map without limit. LRU-evict cold peers past a cap;
        # an evicted peer simply gets a fresh (empty) window on its next knock,
        # which is harmless — the window only ever *restricts* a peer.
        self._initiations: OrderedDict[str, deque[float]] = OrderedDict()

    async def evaluate(self, initiate: HandshakeInitiate, active_sessions: int) -> PolicyResult:
        policy = self.policy
        peer = initiate.card.address

        if policy.mode is PolicyMode.CLOSED:
            return _reject("this agent does not accept inbound initiations")
        if active_sessions >= policy.max_sessions:
            return _reject("session capacity reached")
        if initiate.card.kind not in policy.allow_kinds:
            return _reject(f"participant kind {initiate.card.kind} not accepted")
        if initiate.mode not in policy.accept_modes:
            return _reject(f"session mode {initiate.mode} not accepted")
        if initiate.ttl_seconds > policy.max_ttl_seconds:
            return _reject(f"requested ttl exceeds maximum {policy.max_ttl_seconds}s")
        if not self._within_rate(peer):
            return _reject("rate limit exceeded")

        # Verify the delegation chain ONCE, up front, and drive every
        # authorization decision from the cryptographically verified owner and
        # scopes — never from self-signed card fields. ``card.operator`` is set
        # by the agent's own key and is not trustworthy for access control.
        try:
            scopes = initiate.delegation_chain.verify(
                peer, revoked=self.revoked_digests(), revoked_keys=self.revoked_keys()
            )
        except DelegationError as exc:
            return _reject(f"invalid delegation chain: {exc}")
        verified_owner = initiate.delegation_chain.root_issuer
        # A card that claims an operator it can't prove via the chain is refused
        # outright, so a displayed operator always matches the verified owner.
        if initiate.card.operator is not None and initiate.card.operator != verified_owner:
            return _reject("card operator does not match the verified delegation chain")

        if policy.mode is PolicyMode.ALLOWLIST:
            if peer not in policy.allow_addresses and (
                verified_owner is None or verified_owner not in policy.allow_operators
            ):
                return _reject("initiator is not on the allowlist")

        # Trusted-issuer pinning: the verified owner must be one we trust.
        # This is what turns require_scopes into a real gate.
        if policy.trusted_issuers and verified_owner not in policy.trusted_issuers:
            return _reject("initiator's owner is not a trusted issuer")

        if policy.mode is PolicyMode.CREDENTIALED or policy.require_scopes:
            if policy.require_scopes and not policy.trusted_issuers:
                _log.warning(
                    "ContactPolicy requires scopes %s but sets no trusted_issuers: "
                    "any peer can self-sign a satisfying chain. Scopes are advisory "
                    "until trusted_issuers is set.",
                    sorted(policy.require_scopes),
                )
            missing = policy.require_scopes - scopes
            if missing:
                return _reject(f"missing required scopes: {sorted(missing)}")

        accepted_types = tuple(
            t for t in initiate.payload_types if t in policy.accepted_payload_types
        )
        if not accepted_types:
            return _reject("no mutually accepted payload types")

        if policy.human_approval:
            if self.approval_fn is None:
                return _reject("human approval required but no approver configured")
            approved = await self.approval_fn(initiate)
            if not approved:
                return _reject("initiation declined by human reviewer")

        return PolicyResult(
            decision=Decision.ACCEPT,
            accepted_payload_types=accepted_types,
        )

    def _within_rate(self, peer: str) -> bool:
        now = time.monotonic()
        window = self.policy.rate_limit_window_seconds
        history = self._initiations.get(peer)
        if history is None:
            history = self._initiations[peer] = deque()
        self._initiations.move_to_end(peer)
        while history and now - history[0] > window:
            history.popleft()
        # Drop cold peers so the map can't grow unboundedly under an address-churn
        # flood. Evict from the LRU end, never the peer we're currently serving.
        while len(self._initiations) > _MAX_TRACKED_PEERS:
            evicted, _ = self._initiations.popitem(last=False)
            if evicted == peer:  # pragma: no cover - defensive; peer is MRU
                self._initiations[peer] = history
                break
        if len(history) >= self.policy.rate_limit_per_peer:
            return False
        history.append(now)
        return True


def _reject(reason: str) -> PolicyResult:
    return PolicyResult(decision=Decision.REJECT, reason=reason)
