"""Multi-agent group sessions over the pairwise mesh."""

import asyncio

import pytest

from fg_amp import (
    AgentIdentity,
    AmpNode,
    ContactPolicy,
    GroupEvent,
    GroupMessage,
    InMemoryTransport,
)
from fg_amp.errors import PolicyRejection
from fg_amp.policy.policy import PolicyMode


def make_mesh(*names: str):
    groups: dict[str, list] = {name: [] for name in names}
    nodes = {}
    transport = InMemoryTransport()
    for name in names:
        async def on_group(group, _name=name):
            groups[_name].append(group)

        node = AmpNode(identity=AgentIdentity.generate(name), on_group=on_group)
        node.attach(transport)
        nodes[name] = node
    return nodes, groups


async def collect_until(group, count, timeout=2.0):
    messages = []
    while len(messages) < count:
        item = await group.receive(timeout=timeout)
        if isinstance(item, GroupMessage):
            messages.append(item)
    return messages


async def test_three_agent_group_chat():
    nodes, groups = make_mesh("alice", "bob", "carol")
    alice, bob, carol = nodes["alice"], nodes["bob"], nodes["carol"]

    group = await alice.create_group([bob.card, carol.card], purpose="standup")
    await asyncio.sleep(0.05)  # let invites and mesh sessions settle

    bob_group = groups["bob"][0]
    carol_group = groups["carol"][0]
    assert sorted(group.roster) == sorted([alice.address, bob.address, carol.address])
    assert bob_group.roster == group.roster == carol_group.roster
    # the mesh is complete: every member has a session to both others
    assert len(group.sessions) == 2
    assert len(bob_group.sessions) == 2
    assert len(carol_group.sessions) == 2

    await group.send_text("morning everyone")
    for member_group in (bob_group, carol_group):
        [message] = await collect_until(member_group, 1)
        assert message.payload.content == "morning everyone"
        assert message.sender == alice.address
        assert message.group_id == group.group_id

    # non-founder broadcasts reach everyone too
    await bob_group.send_json({"status": "shipping"})
    for member_group in (group, carol_group):
        [message] = await collect_until(member_group, 1)
        assert message.payload.content == {"status": "shipping"}
        assert message.sender == bob.address


async def test_member_leave_updates_rosters():
    nodes, groups = make_mesh("alice", "bob", "carol")
    alice, bob, carol = nodes["alice"], nodes["bob"], nodes["carol"]
    group = await alice.create_group([bob.card, carol.card])
    await asyncio.sleep(0.05)
    bob_group, carol_group = groups["bob"][0], groups["carol"][0]

    await carol_group.leave()
    for member_group in (group, bob_group):
        event = await member_group.receive(timeout=2)
        assert isinstance(event, GroupEvent)
        assert event.kind == "left" and event.member == carol.address
        assert carol.address not in member_group.members

    # remaining members keep talking
    await group.send_text("just us now")
    [message] = await collect_until(bob_group, 1)
    assert message.payload.content == "just us now"


async def test_roster_is_signed_and_members_agree_on_digest():
    """Every member's founder-signed roster digest matches — a shared,
    verifiable view of who's in the room."""
    nodes, groups = make_mesh("alice", "bob", "carol")
    alice, bob, carol = nodes["alice"], nodes["bob"], nodes["carol"]
    group = await alice.create_group([bob.card, carol.card], purpose="standup")
    await asyncio.sleep(0.05)

    group.info.verify()  # founder signature is valid
    bob_group, carol_group = groups["bob"][0], groups["carol"][0]
    assert group.roster_digest == bob_group.roster_digest == carol_group.roster_digest
    assert group.epoch == 0


async def test_unsigned_or_forged_roster_invite_dropped():
    """An invite whose roster isn't validly signed by the founder is ignored."""
    from fg_amp import Payload
    from fg_amp.session.group import GROUP_INVITE_PAYLOAD, GROUP_PURPOSE_PREFIX, GroupInfo

    nodes, groups = make_mesh("alice", "bob")
    alice, bob = nodes["alice"], nodes["bob"]

    # alice crafts a roster but does NOT sign it (or signs with the wrong key)
    gid = "forged-group"
    unsigned = GroupInfo(
        group_id=gid, founder=alice.address, epoch=0,
        members=(alice.card, bob.card),
    )  # no .signed_by()
    session = await alice.initiate(bob.card, purpose=GROUP_PURPOSE_PREFIX + gid)
    await session.send(Payload(content_type=GROUP_INVITE_PAYLOAD,
                               content=unsigned.model_dump(mode="json")))
    await asyncio.sleep(0.05)
    assert gid not in bob.groups.groups  # invite dropped, no group formed


async def test_non_member_group_messages_dropped():
    nodes, groups = make_mesh("alice", "bob")
    mallory = AmpNode(identity=AgentIdentity.generate("mallory"))
    alice, bob = nodes["alice"], nodes["bob"]
    transport = alice._transport
    mallory.attach(transport)

    group = await alice.create_group([bob.card])
    await asyncio.sleep(0.05)
    bob_group = groups["bob"][0]

    # mallory opens a legitimate pairwise session and tries to speak in the group
    session = await mallory.initiate(bob.card)
    from fg_amp import Payload
    from fg_amp.session.group import GROUP_PAYLOAD

    await session.send(
        Payload(
            content_type=GROUP_PAYLOAD,
            content={"group_id": group.group_id, "payload": {"content": "injected"}},
        )
    )
    await asyncio.sleep(0.05)
    assert bob_group._inbox.empty()  # dropped: mallory is not on the roster


async def test_group_create_rolls_back_on_partial_failure():
    """If a member refuses the invite mid-fan-out, create() tears down the
    sessions already opened and drops the half-built group — no dangling
    sessions, no partial group registered (audit blocker #4)."""
    transport = InMemoryTransport()
    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    # carol refuses all inbound initiations, so the fan-out fails on her.
    carol = AmpNode(
        identity=AgentIdentity.generate("carol"),
        policy=ContactPolicy(mode=PolicyMode.CLOSED),
    )
    for n in (alice, bob, carol):
        n.attach(transport)

    with pytest.raises(PolicyRejection):
        await alice.create_group([bob.card, carol.card], purpose="doomed")

    # No group left registered, and the session opened to bob was closed.
    assert alice.groups.groups == {}
    live = [s for s in alice.sessions.values() if s.state.name == "ESTABLISHED"]
    assert live == []


async def test_founder_add_member_bumps_epoch_and_completes_mesh():
    """Founder adds a member: epoch bumps, the newcomer joins the mesh, existing
    members learn of the join, and everyone can talk."""
    nodes, groups = make_mesh("alice", "bob", "carol")
    alice, bob, carol = nodes["alice"], nodes["bob"], nodes["carol"]
    group = await alice.create_group([bob.card], purpose="standup")
    await asyncio.sleep(0.05)
    assert group.epoch == 0

    await group.add_member(carol.card)
    await asyncio.sleep(0.1)
    assert group.epoch == 1
    carol_group = groups["carol"][0]
    assert set(group.roster) == {alice.address, bob.address, carol.address}
    assert carol_group.epoch == 1

    # bob saw a "joined" event for carol
    bob_group = groups["bob"][0]
    seen = []
    while not bob_group._inbox.empty():
        seen.append(bob_group._inbox.get_nowait())
    assert any(isinstance(e, GroupEvent) and e.kind == "joined" and e.member == carol.address
               for e in seen)

    # full three-way chat now works
    await group.send_text("welcome carol")
    [m] = await collect_until(carol_group, 1)
    assert m.payload.content == "welcome carol"


async def test_founder_remove_member_excludes_and_rekeys():
    """Founder removes a member: epoch bumps, remaining members close their
    pairwise session to the removed peer (exclusion), and the removed peer stops
    receiving group traffic."""
    from fg_amp import Payload, SessionState

    nodes, groups = make_mesh("alice", "bob", "carol")
    alice, bob, carol = nodes["alice"], nodes["bob"], nodes["carol"]
    group = await alice.create_group([bob.card, carol.card])
    await asyncio.sleep(0.05)
    bob_group, carol_group = groups["bob"][0], groups["carol"][0]

    # capture the ACTUAL pairwise sessions between bob and carol before removal
    bob_to_carol = bob_group.sessions[carol.address]
    carol_to_bob = carol_group.sessions[bob.address]
    assert bob_to_carol.state is SessionState.ESTABLISHED

    await group.remove_member(carol.address)
    await asyncio.sleep(0.1)
    assert group.epoch == 1
    assert carol.address not in group.members
    assert carol.address not in bob_group.members  # bob dropped carol

    # The real exclusion: bob's (non-founder) pairwise session to carol is CLOSED,
    # not merely popped from the roster dict — a kicked member must not keep a
    # live E2E channel to remaining members.
    assert bob_to_carol.state is not SessionState.ESTABLISHED
    assert carol.address not in bob.sessions  # dropped from the node too
    # carol's side received the close as well
    assert carol_to_bob.state is not SessionState.ESTABLISHED

    # carol can no longer deliver anything to bob over the (now closed) session.
    from fg_amp.session.group import GROUP_PAYLOAD

    before = bob_group._inbox.qsize()
    try:
        await carol_to_bob.send(
            Payload(
                content_type=GROUP_PAYLOAD,
                content={"group_id": group.group_id, "payload": {"content": "ghost"}},
            )
        )
    except Exception:
        pass  # sending over a closed session may raise — that's fine, it's excluded
    await asyncio.sleep(0.05)
    assert bob_group._inbox.qsize() == before  # nothing from the kicked member


async def test_roster_equivocation_is_detected():
    """A member reporting a different roster digest at the same epoch surfaces an
    equivocation event."""
    nodes, groups = make_mesh("alice", "bob")
    alice, bob = nodes["alice"], nodes["bob"]
    group = await alice.create_group([bob.card])
    await asyncio.sleep(0.05)

    # Simulate a peer ack carrying a divergent digest at the current epoch.
    from datetime import UTC, datetime

    from fg_amp.session.group import GROUP_ROSTER_ACK_PAYLOAD
    from fg_amp.session.session import Payload, ReceivedMessage

    fake = ReceivedMessage(
        payload=Payload(
            content_type=GROUP_ROSTER_ACK_PAYLOAD,
            content={"group_id": group.group_id, "epoch": group.epoch,
                     "roster_digest": "deadbeef-divergent"},
        ),
        sender=bob.address,
        session_id="x",
        seq=1,
        received_at=datetime.now(UTC),
    )
    alice.groups._handle_roster_ack(fake)
    events = []
    while not group._inbox.empty():
        events.append(group._inbox.get_nowait())
    assert any(isinstance(e, GroupEvent) and e.kind == "equivocation" for e in events)


async def test_non_roster_group_session_is_closed_not_leaked():
    """A stranger opening a group-purpose session to a group we host must not
    linger in node.sessions until TTL — the manager closes it (M2)."""
    from fg_amp.session.group import GROUP_PURPOSE_PREFIX

    nodes, groups = make_mesh("alice", "bob")
    mallory = AmpNode(identity=AgentIdentity.generate("mallory"))
    alice, bob = nodes["alice"], nodes["bob"]
    mallory.attach(alice._transport)

    group = await alice.create_group([bob.card])
    await asyncio.sleep(0.05)

    # mallory (not on the roster) opens a session tagged as this group.
    await mallory.initiate(bob.card, purpose=GROUP_PURPOSE_PREFIX + group.group_id)
    await asyncio.sleep(0.05)

    # The session is neither attached to bob's group nor left open on bob.
    bob_group = groups["bob"][0]
    assert mallory.address not in bob_group.sessions
    assert not any(
        s.peer_card.address == mallory.address for s in bob.sessions.values()
    )


async def test_non_roster_session_buffered_before_invite_is_closed():
    """The pending-buffer path of M2: a non-member session that races AHEAD of
    the invite (buffered while the group is still unknown) must be CLOSED when
    the invite is drained, not merely dropped from the buffer — otherwise it
    lingers in node.sessions."""
    from fg_amp.session.group import GROUP_PURPOSE_PREFIX, GroupInfo

    nodes, groups = make_mesh("alice", "bob")
    alice, bob = nodes["alice"], nodes["bob"]
    mallory = AmpNode(identity=AgentIdentity.generate("mallory"))
    mallory.attach(alice._transport)

    real_handle_invite = bob.groups._handle_invite
    staged = {}

    async def gated_invite(session, message):
        # Before bob registers the group, sneak in a non-member session tagged
        # with this group's id — it buffers into _pending_sessions.
        if not staged:
            staged["gid"] = GroupInfo.model_validate(message.payload.content).group_id
            await mallory.initiate(
                bob.card, purpose=GROUP_PURPOSE_PREFIX + staged["gid"]
            )
            await asyncio.sleep(0.02)
            assert staged["gid"] in bob.groups._pending_sessions  # buffered
        await real_handle_invite(session, message)

    bob.groups._handle_invite = gated_invite

    group = await alice.create_group([bob.card])  # mallory is NOT a member
    await asyncio.sleep(0.1)

    assert group.group_id not in bob.groups._pending_sessions
    assert not any(
        s.peer_card.address == mallory.address for s in bob.sessions.values()
    ), "buffered non-member session must be closed, not left lingering"


async def test_complete_mesh_isolates_unreachable_member():
    """_complete_mesh connects reachable peers even when another target is
    unreachable, and never raises out of the invite/roster path (M3)."""
    nodes, groups = make_mesh("alice", "bob")
    alice, bob = nodes["alice"], nodes["bob"]
    group = await alice.create_group([bob.card])
    await asyncio.sleep(0.05)

    # An "unreachable" peer that rejects fast (closed policy) rather than hanging
    # the test on a handshake timeout — either way it surfaces as an exception
    # that _complete_mesh must isolate.
    refuser = AmpNode(
        identity=AgentIdentity.generate("refuser"),
        policy=ContactPolicy(mode=PolicyMode.CLOSED),
    )
    refuser.attach(alice._transport)
    # A genuinely reachable extra peer on the same transport.
    reachable = AmpNode(identity=AgentIdentity.generate("dave"), policy=ContactPolicy.open())
    reachable.attach(alice._transport)

    # Mixed targets: one failing, one reachable. Must not raise; must attach the
    # reachable one and skip the failing one.
    await alice.groups._complete_mesh(group, [refuser.card, reachable.card], group.group_id)
    assert refuser.address not in group.sessions
    assert reachable.address in group.sessions
