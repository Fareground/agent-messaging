"""Group sessions: multi-agent conversations over a full mesh of pairwise sessions.

Design: no new cryptography. A group is a set of members, each pair connected
by an ordinary AMP session — so every group message inherits pairwise E2E
encryption, signatures, sequencing, and policy enforcement. A group message
is fanned out once per member; at agent scale (units to tens of members) the
N-fold encryption cost is irrelevant and the security argument stays exactly
as strong as the pairwise one. A Signal-style sender-key optimization is a
planned, compatible upgrade for large groups (see blueprint roadmap).

Membership protocol (carried as payloads inside pairwise sessions):
- ``amp/group-invite``: founder -> member; contains group id, purpose, roster.
- Mesh completion: each invited member initiates sessions to fellow members
  with a lexicographically greater address (so each pair connects exactly once),
  using purpose ``amp-group:<group_id>``.
- ``amp/group``: a group message wrapping an inner payload.
- ``amp/group-leave``: sender leaves; receivers drop it from their roster.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ..identity.card import AgentCard
from .session import Payload, Session

GROUP_PAYLOAD = "amp/group"
GROUP_INVITE_PAYLOAD = "amp/group-invite"
GROUP_LEAVE_PAYLOAD = "amp/group-leave"
GROUP_ROSTER_PAYLOAD = "amp/group-roster"  # founder reissues a new-epoch roster
GROUP_ROSTER_ACK_PAYLOAD = "amp/group-roster-ack"  # member echoes (epoch, digest)
GROUP_PAYLOAD_TYPES = (
    GROUP_PAYLOAD,
    GROUP_INVITE_PAYLOAD,
    GROUP_LEAVE_PAYLOAD,
    GROUP_ROSTER_PAYLOAD,
    GROUP_ROSTER_ACK_PAYLOAD,
)
GROUP_PURPOSE_PREFIX = "amp-group:"


class GroupInfo(BaseModel):
    """A group roster at a specific epoch, signed by the founder.

    The signature pins the founder to exactly this membership at this epoch, so
    a member can verify the roster is authentic and detect equivocation by
    comparing ``roster_digest`` with peers over their pairwise sessions. Epoch
    increments on every membership change.
    """

    group_id: str
    purpose: str = ""
    founder: str
    epoch: int = 0
    members: tuple[AgentCard, ...]  # full roster including founder
    signature: str = ""  # base64 ed25519 by the founder over the canonical roster

    model_config = {"frozen": True}

    def _payload(self) -> dict:
        return {
            "group_id": self.group_id,
            "purpose": self.purpose,
            "founder": self.founder,
            "epoch": self.epoch,
            "members": sorted(c.address for c in self.members),
        }

    @property
    def roster_digest(self) -> str:
        """Stable digest of (group, epoch, membership) — compare with peers to
        detect a founder handing different members different rosters."""
        from ..signing import CONTEXT_GROUP_ROSTER, signing_input

        return hashlib.sha256(signing_input(CONTEXT_GROUP_ROSTER, self._payload())).hexdigest()

    def signed_by(self, founder_keys) -> GroupInfo:
        from ..signing import CONTEXT_GROUP_ROSTER, sign_payload

        signature = sign_payload(founder_keys, CONTEXT_GROUP_ROSTER, self._payload())
        return self.model_copy(update={"signature": signature})

    def verify(self) -> None:
        """The roster must be signed by the founder's own key."""
        from ..signing import CONTEXT_GROUP_ROSTER, verify_by_address

        verify_by_address(
            self.founder, CONTEXT_GROUP_ROSTER, self._payload(), self.signature
        )


class GroupMessage(BaseModel):
    """A group payload plus its verified (pairwise-session) provenance."""

    group_id: str
    payload: Payload
    sender: str
    received_at: datetime

    model_config = {"frozen": True}


class GroupEvent(BaseModel):
    """Membership/roster change visible to the application."""

    group_id: str
    kind: str  # "joined" | "left" | "removed" | "epoch" | "equivocation"
    member: str
    epoch: int = 0
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = {"frozen": True}


class GroupSession:
    """One agent's view of a group: roster + pairwise sessions to each member."""

    def __init__(self, info: GroupInfo, own_address: str):
        self.info = info
        self.own_address = own_address
        self.members: dict[str, AgentCard] = {
            card.address: card for card in info.members if card.address != own_address
        }
        self.sessions: dict[str, Session] = {}  # member address -> pairwise session
        self.closed = False
        self._inbox: asyncio.Queue[GroupMessage | GroupEvent] = asyncio.Queue()
        # Set by the GroupManager so founder-only ops (add/remove) can drive the
        # node's transport. None for a view that isn't manager-attached.
        self._manager: Any = None

    @property
    def is_founder(self) -> bool:
        return self.own_address == self.info.founder

    @property
    def group_id(self) -> str:
        return self.info.group_id

    @property
    def roster(self) -> list[str]:
        return sorted([self.own_address, *self.members])

    @property
    def roster_digest(self) -> str:
        """Founder-signed (group, epoch, membership) digest. Compare with what a
        peer reports to detect a founder handing members divergent rosters."""
        return self.info.roster_digest

    @property
    def epoch(self) -> int:
        return self.info.epoch

    def attach(self, member_address: str, session: Session) -> None:
        self.sessions[member_address] = session

    async def send(self, payload: Payload) -> None:
        """Fan a payload out to every connected member over its pairwise session."""
        if self.closed:
            raise RuntimeError("group session is closed")
        wrapper = Payload(
            content_type=GROUP_PAYLOAD,
            content={"group_id": self.group_id, "payload": payload.model_dump(mode="json")},
        )
        results = await asyncio.gather(
            *(session.send(wrapper) for session in self.sessions.values()),
            return_exceptions=True,
        )
        failures = [r for r in results if isinstance(r, Exception)]
        if failures:
            raise failures[0]

    async def send_text(self, text: str, **metadata: Any) -> None:
        await self.send(Payload.text(text, **metadata))

    async def send_json(self, data: Any, **metadata: Any) -> None:
        await self.send(Payload.json_data(data, **metadata))

    async def receive(self, timeout: float | None = None) -> GroupMessage | GroupEvent:
        if timeout is None:
            return await self._inbox.get()
        return await asyncio.wait_for(self._inbox.get(), timeout)

    async def leave(self) -> None:
        """Announce departure and stop participating. Pairwise sessions survive."""
        if self.closed:
            return
        self.closed = True
        farewell = Payload(
            content_type=GROUP_LEAVE_PAYLOAD, content={"group_id": self.group_id}
        )
        await asyncio.gather(
            *(session.send(farewell) for session in self.sessions.values()),
            return_exceptions=True,
        )

    # -- founder-only membership operations -----------------------------------

    async def add_member(self, card: AgentCard) -> None:
        """Founder adds a member: bump the epoch, reissue a signed roster to all,
        and bootstrap the newcomer into the mesh."""
        self._require_founder_manager()
        await self._manager.add_member(self, card)

    async def remove_member(self, address: str) -> None:
        """Founder removes a member: bump the epoch, reissue a signed roster to
        the remaining members, and close pairwise sessions to the removed member
        so it receives no further group traffic (forward secrecy across the
        change — a pairwise mesh has no shared group key to rotate; exclusion is
        achieved by tearing down the removed member's sessions)."""
        self._require_founder_manager()
        await self._manager.remove_member(self, address)

    def _require_founder_manager(self) -> None:
        if not self.is_founder:
            raise PermissionError("only the group founder can change membership")
        if self._manager is None:
            raise RuntimeError("group is not attached to a node manager")

    # -- called by the node's group manager -----------------------------------

    async def _deliver(self, item: GroupMessage | GroupEvent) -> None:
        await self._inbox.put(item)

    def _remove_member(self, address: str) -> None:
        self.members.pop(address, None)
        self.sessions.pop(address, None)

    def apply_roster(
        self, new_info: GroupInfo
    ) -> tuple[set[str], set[str], list[Session]]:
        """Adopt a newer founder-signed roster. Returns (added, removed,
        removed_sessions) relative to the current view. The removed members'
        pairwise Session objects are detached and returned so the caller can
        close them — closing (not just forgetting) is what actually excludes a
        removed member from the mesh."""
        old = set(self.members) | {self.own_address}
        new = {c.address for c in new_info.members}
        added = new - old
        removed = old - new - {self.own_address}
        self.info = new_info
        self.members = {
            card.address: card for card in new_info.members if card.address != self.own_address
        }
        removed_sessions: list[Session] = []
        for address in removed:
            session = self.sessions.pop(address, None)
            if session is not None:
                removed_sessions.append(session)
        return added, removed, removed_sessions
