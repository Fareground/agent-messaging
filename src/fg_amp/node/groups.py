"""Group manager: runs the group membership protocol on behalf of a node.

Owns group state, intercepts ``amp/group*`` payloads from pairwise sessions,
and completes the mesh when invites arrive. Handles the arrival races
(mesh sessions or group messages landing before the invite) by buffering
until the invite shows up.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..identity.card import AgentCard
from ..session.group import (
    GROUP_INVITE_PAYLOAD,
    GROUP_LEAVE_PAYLOAD,
    GROUP_PAYLOAD,
    GROUP_PURPOSE_PREFIX,
    GROUP_ROSTER_ACK_PAYLOAD,
    GROUP_ROSTER_PAYLOAD,
    GroupEvent,
    GroupInfo,
    GroupMessage,
    GroupSession,
)
from ..session.session import Payload, ReceivedMessage, Session
from ..session.states import SessionMode

if TYPE_CHECKING:
    from .node import AmpNode

_log = logging.getLogger("fg_amp.groups")

GroupCallback = Callable[[GroupSession], Awaitable[None]]

_MAX_PENDING_PER_GROUP = 256  # cap buffered pre-invite sessions/messages per group id
_MAX_PENDING_GROUP_IDS = 1024  # cap distinct un-invited group ids buffered at once


class GroupManager:
    def __init__(self, node: AmpNode, on_group: GroupCallback | None = None):
        self._node = node
        self.on_group = on_group
        self.groups: dict[str, GroupSession] = {}
        # OrderedDict so the oldest orphan group-id is evicted first — a peer
        # can open group-purpose sessions with arbitrary random ids, so the
        # number of distinct buffered ids is bounded, not just each buffer.
        self._pending_sessions: OrderedDict[str, list[Session]] = OrderedDict()
        self._pending_messages: OrderedDict[
            str, list[tuple[Session, ReceivedMessage]]
        ] = OrderedDict()
        # Fire-and-forget cleanup closes, tracked so the tasks aren't GC'd mid-flight.
        self._close_tasks: set[asyncio.Task] = set()

    async def _safe_close(self, session: Session, reason: str) -> None:
        try:
            await session.close(reason=reason)
        except Exception:  # noqa: BLE001 — cleanup is best-effort
            _log.debug("group cleanup: close failed")

    def _schedule_close(self, session: Session, reason: str) -> None:
        """Close an orphaned session without blocking the caller. Prevents a
        claimed-but-unattached group session from lingering in node.sessions
        until its TTL (which an attacker could exploit to pin capacity)."""
        try:
            task = asyncio.create_task(self._safe_close(session, reason))
        except RuntimeError:  # pragma: no cover - no running loop
            return
        self._close_tasks.add(task)
        task.add_done_callback(self._close_tasks.discard)

    def _evict_pending_sessions(self) -> None:
        # Evicting a buffered group-id drops its Session objects; close them so
        # an orphan-group-id flood can't leak sessions on the node.
        while len(self._pending_sessions) > _MAX_PENDING_GROUP_IDS:
            _gid, sessions = self._pending_sessions.popitem(last=False)
            for session in sessions:
                self._schedule_close(session, "group buffer evicted")

    def _evict_pending_messages(self) -> None:
        # Buffered messages hold references to sessions that are also tracked via
        # _pending_sessions / attachment, so eviction drops only the messages.
        while len(self._pending_messages) > _MAX_PENDING_GROUP_IDS:
            self._pending_messages.popitem(last=False)

    # -- founding a group -------------------------------------------------------

    async def create(
        self,
        member_cards: list[AgentCard],
        purpose: str = "",
        mode: SessionMode = SessionMode.EPHEMERAL,
        ttl_seconds: float = 3600.0,
    ) -> GroupSession:
        group_id = str(uuid.uuid4())
        info = GroupInfo(
            group_id=group_id,
            purpose=purpose,
            founder=self._node.address,
            epoch=0,
            members=(self._node.card, *member_cards),
        ).signed_by(self._node.identity.keys)  # founder signs the roster
        group = GroupSession(info, self._node.address)
        group._manager = self
        self.groups[group_id] = group
        invite = Payload(
            content_type=GROUP_INVITE_PAYLOAD, content=info.model_dump(mode="json")
        )
        # Atomic: if any member can't be reached or invited (policy rejection,
        # timeout, revoked peer), tear down the sessions already opened and drop
        # the half-built group, so a failed create() never leaves live pairwise
        # sessions dangling or a partial group registered on the node.
        try:
            for card in member_cards:
                session = await self._node.initiate(
                    card,
                    purpose=GROUP_PURPOSE_PREFIX + group_id,
                    mode=mode,
                    ttl_seconds=ttl_seconds,
                )
                group.attach(card.address, session)
                await session.send(invite)
        except Exception:
            self.groups.pop(group_id, None)
            for opened in group.sessions.values():
                try:
                    await opened.close(reason="group creation failed")
                except Exception:  # noqa: BLE001 — rollback is best-effort
                    _log.debug("group %s rollback: close failed", group_id)
            raise
        return group

    # -- inbound hooks (called by the node) --------------------------------------

    async def claim_inbound_session(self, session: Session) -> bool:
        """Route a new inbound group-mesh session — but only if the peer is on
        the founder-signed roster. A session is attached to a group's fan-out
        set (which receives every group message) solely when the peer is a
        verified roster member; otherwise it is not group traffic to us."""
        if not session.purpose.startswith(GROUP_PURPOSE_PREFIX):
            return False
        group_id = session.purpose[len(GROUP_PURPOSE_PREFIX):]
        group = self.groups.get(group_id)
        if group is None:
            pending = self._pending_sessions.setdefault(group_id, [])
            if len(pending) < _MAX_PENDING_PER_GROUP:
                pending.append(session)
            else:
                # Buffer full: close rather than silently drop-and-leak.
                self._schedule_close(session, "group pending buffer full")
            self._evict_pending_sessions()
            return True
        if session.peer_card.address in group.members:
            group.attach(session.peer_card.address, session)
            return True
        # A group-purpose session from a non-roster peer: claim it (keep it out of
        # the normal on_session path) and close it, so it doesn't linger in
        # node.sessions until TTL.
        await self._safe_close(session, "not a group member")
        return True

    async def dispatch(self, session: Session, message: ReceivedMessage) -> bool:
        """Session payload interceptor. Returns True when consumed."""
        content_type = message.payload.content_type
        if content_type == GROUP_INVITE_PAYLOAD:
            await self._handle_invite(session, message)
            return True
        if content_type == GROUP_PAYLOAD:
            await self._handle_message(session, message)
            return True
        if content_type == GROUP_LEAVE_PAYLOAD:
            self._handle_leave(message)
            return True
        if content_type == GROUP_ROSTER_PAYLOAD:
            await self._handle_roster(session, message)
            return True
        if content_type == GROUP_ROSTER_ACK_PAYLOAD:
            self._handle_roster_ack(message)
            return True
        return False

    # -- protocol steps -----------------------------------------------------------

    async def _handle_invite(self, session: Session, message: ReceivedMessage) -> None:
        info = GroupInfo.model_validate(message.payload.content)
        if message.sender != info.founder:
            return  # only the founder may issue this roster
        try:
            info.verify()  # the roster must be signed by the founder's key
        except Exception:  # noqa: BLE001 — an unsigned/forged roster is dropped
            return
        # The invite must arrive over a session the founder opened AS this
        # group (its purpose names the group id). This stops any peer from
        # turning an ordinary conversation into a coerced mesh of outbound
        # initiations to attacker-chosen endpoints.
        if session.purpose != GROUP_PURPOSE_PREFIX + info.group_id:
            return
        if self._node.address not in {c.address for c in info.members}:
            return  # we're not actually on the roster
        if info.group_id in self.groups:
            return
        group = GroupSession(info, self._node.address)
        group._manager = self
        self.groups[info.group_id] = group
        group.attach(message.sender, session)

        # Complete the mesh: connect to fellow members deterministically
        # (only toward greater addresses, so each pair connects exactly once).
        # Concurrent + fail-isolated: one unreachable member neither blocks the
        # others behind its handshake timeout nor aborts the mesh mid-build.
        ttl = max(1.0, (session.expires_at - datetime.now(UTC)).total_seconds())
        targets = [
            card
            for card in info.members
            if card.address not in (self._node.address, info.founder)
            and card.address > self._node.address
        ]
        await self._complete_mesh(group, targets, info.group_id, ttl)

        # Drain anything that raced ahead of the invite — re-checking the
        # roster now that we know it. A buffered session from a non-member is
        # *closed* (not merely dropped from the buffer): leaving it open would
        # pin it in node.sessions until TTL — the exact leak M2 guards against.
        for pending in self._pending_sessions.pop(info.group_id, []):
            if pending.peer_card.address in group.members:
                group.attach(pending.peer_card.address, pending)
            else:
                await self._safe_close(pending, "not a group member")
        for pending_session, pending_message in self._pending_messages.pop(info.group_id, []):
            await self._handle_message(pending_session, pending_message)

        # Echo our roster digest so equivocation (founder handing divergent
        # rosters at the same epoch) is detected automatically among members.
        await self._broadcast_roster_ack(group)

        if self.on_group is not None:
            await self.on_group(group)

    async def _complete_mesh(
        self,
        group: GroupSession,
        targets: list[AgentCard],
        group_id: str,
        ttl_seconds: float | None = None,
    ) -> None:
        """Open pairwise mesh sessions to `targets` concurrently, isolating
        failures: an unreachable member is logged and skipped rather than
        blocking or aborting the rest of the mesh. Partial connectivity is
        acceptable for a mesh — reachable members still talk."""
        if not targets:
            return

        async def link(card: AgentCard) -> None:
            kwargs: dict = {"purpose": GROUP_PURPOSE_PREFIX + group_id}
            if ttl_seconds is not None:
                kwargs["ttl_seconds"] = ttl_seconds
            try:
                mesh_session = await self._node.initiate(card, **kwargs)
            except Exception:  # noqa: BLE001 — one bad link must not fail the mesh
                _log.warning(
                    "group %s: could not connect mesh link to %s", group_id, card.address
                )
                return
            group.attach(card.address, mesh_session)

        await asyncio.gather(*(link(card) for card in targets))

    async def _handle_message(self, session: Session, message: ReceivedMessage) -> None:
        content = message.payload.content or {}
        group_id = content.get("group_id", "")
        group = self.groups.get(group_id)
        if group is None:
            pending = self._pending_messages.setdefault(group_id, [])
            if len(pending) < _MAX_PENDING_PER_GROUP:
                pending.append((session, message))
            self._evict_pending_messages()
            return
        if message.sender not in group.members:
            return  # not on the roster — drop
        await group._deliver(
            GroupMessage(
                group_id=group_id,
                payload=Payload.model_validate(content.get("payload", {})),
                sender=message.sender,
                received_at=message.received_at,
            )
        )

    def _handle_leave(self, message: ReceivedMessage) -> None:
        content = message.payload.content or {}
        group = self.groups.get(content.get("group_id", ""))
        if group is None or message.sender not in group.members:
            return
        group._remove_member(message.sender)
        group._inbox.put_nowait(
            GroupEvent(group_id=group.group_id, kind="left", member=message.sender)
        )

    # -- founder-only membership changes ------------------------------------------

    async def add_member(self, group: GroupSession, card: AgentCard) -> None:
        """Founder: reissue the roster at epoch+1 with `card` added, bootstrap the
        newcomer with an invite, and push the new roster to existing members."""
        new_info = GroupInfo(
            group_id=group.group_id,
            purpose=group.info.purpose,
            founder=self._node.address,
            epoch=group.epoch + 1,
            members=(*group.info.members, card),
        ).signed_by(self._node.identity.keys)
        # Open a session to the newcomer and invite it (it bootstraps the mesh to
        # existing members via the invite path).
        session = await self._node.initiate(
            card, purpose=GROUP_PURPOSE_PREFIX + group.group_id
        )
        group.apply_roster(new_info)
        group.attach(card.address, session)
        await session.send(
            Payload(content_type=GROUP_INVITE_PAYLOAD, content=new_info.model_dump(mode="json"))
        )
        await self._broadcast_roster(group, exclude={card.address})
        group._inbox.put_nowait(
            GroupEvent(
                group_id=group.group_id, kind="joined", member=card.address, epoch=new_info.epoch
            )
        )

    async def remove_member(self, group: GroupSession, address: str) -> None:
        """Founder: reissue the roster at epoch+1 without `address`, push it to the
        remaining members (who close their pairwise session to the removed peer),
        and close the founder's own session to the removed peer."""
        if address not in group.members:
            return
        remaining = tuple(c for c in group.info.members if c.address != address)
        new_info = GroupInfo(
            group_id=group.group_id,
            purpose=group.info.purpose,
            founder=self._node.address,
            epoch=group.epoch + 1,
            members=remaining,
        ).signed_by(self._node.identity.keys)
        _added, _removed, removed_sessions = group.apply_roster(new_info)
        await self._broadcast_roster(group, exclude={address})
        for removed_session in removed_sessions:  # close = exclude (forward secrecy)
            await removed_session.close(reason="removed from group")
        group._inbox.put_nowait(
            GroupEvent(
                group_id=group.group_id, kind="removed", member=address, epoch=new_info.epoch
            )
        )

    async def _broadcast_roster(self, group: GroupSession, exclude: set[str]) -> None:
        payload = Payload(
            content_type=GROUP_ROSTER_PAYLOAD, content=group.info.model_dump(mode="json")
        )
        await asyncio.gather(
            *(
                s.send(payload)
                for addr, s in group.sessions.items()
                if addr not in exclude
            ),
            return_exceptions=True,
        )

    async def _broadcast_roster_ack(self, group: GroupSession) -> None:
        """Echo (epoch, digest) to peers so a founder equivocating (different
        rosters to different members at the same epoch) is detected automatically."""
        payload = Payload(
            content_type=GROUP_ROSTER_ACK_PAYLOAD,
            content={
                "group_id": group.group_id,
                "epoch": group.epoch,
                "roster_digest": group.roster_digest,
            },
        )
        await asyncio.gather(
            *(s.send(payload) for s in group.sessions.values()),
            return_exceptions=True,
        )

    async def _handle_roster(self, session: Session, message: ReceivedMessage) -> None:
        """A member adopts a newer founder-signed roster: verify, apply, then wire
        up sessions to any added members and drop any removed ones."""
        info = GroupInfo.model_validate(message.payload.content)
        group = self.groups.get(info.group_id)
        if group is None:
            return
        if message.sender != info.founder or info.founder != group.info.founder:
            return  # only the group's founder may reissue the roster
        try:
            info.verify()
        except Exception:  # noqa: BLE001 — unsigned/forged roster dropped
            _log.debug("group %s: dropping unsigned roster update", info.group_id)
            return
        if info.epoch <= group.epoch:
            return  # stale or replayed roster
        if self._node.address not in {c.address for c in info.members}:
            # We've been removed: drop the group and close our sessions.
            for s in list(group.sessions.values()):
                await s.close(reason="removed from group")
            self.groups.pop(info.group_id, None)
            group._inbox.put_nowait(
                GroupEvent(
                    group_id=info.group_id,
                    kind="removed",
                    member=self._node.address,
                    epoch=info.epoch,
                )
            )
            return
        added, removed, removed_sessions = group.apply_roster(info)
        # Close the pairwise session to every removed member: a kicked member
        # must not retain a live E2E channel to the remaining members.
        for removed_session in removed_sessions:
            await removed_session.close(reason="removed from group")
        for address in removed:
            group._inbox.put_nowait(
                GroupEvent(group_id=info.group_id, kind="removed", member=address, epoch=info.epoch)
            )
        # Connect to added members with a greater address (deterministic pairing);
        # added members with a lesser address will initiate toward us. Concurrent
        # + fail-isolated (see _complete_mesh).
        targets = [
            card
            for card in info.members
            if card.address in added and card.address > self._node.address
        ]
        await self._complete_mesh(group, targets, info.group_id)
        for address in added:
            group._inbox.put_nowait(
                GroupEvent(group_id=info.group_id, kind="joined", member=address, epoch=info.epoch)
            )
        await self._broadcast_roster_ack(group)

    def _handle_roster_ack(self, message: ReceivedMessage) -> None:
        content = message.payload.content or {}
        group = self.groups.get(content.get("group_id", ""))
        if group is None or message.sender not in group.members:
            return
        if int(content.get("epoch", -1)) != group.epoch:
            return  # only compare at the same epoch
        if content.get("roster_digest") != group.roster_digest:
            _log.warning(
                "group %s: roster equivocation — %s reports a different roster at epoch %d",
                group.group_id,
                message.sender,
                group.epoch,
            )
            group._inbox.put_nowait(
                GroupEvent(
                    group_id=group.group_id,
                    kind="equivocation",
                    member=message.sender,
                    epoch=group.epoch,
                )
            )
