"""AMP-layer domain separation and relay audience binding."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from fg_amp import AgentIdentity, Envelope, EnvelopeType
from fg_amp.errors import SignatureError
from fg_amp.session.group import GroupInfo
from fg_amp.signing import (
    CONTEXT_ENVELOPE,
    CONTEXT_GROUP_ROSTER,
    CONTEXT_RELAY_ACK,
    CONTEXT_RELAY_PULL,
    DOMAIN,
    domain_tag,
    sign_payload,
    signing_input,
    verify_payload,
)
from fg_amp.transport.relay import (
    DEFAULT_RELAY_AUDIENCE,
    _ack_payload,
    _pull_payload,
)


def test_amp_domain_is_distinct_from_identity_domain():
    """AMP artifacts and identity artifacts must never share a signing input."""
    from fg_agent_id.signing import DOMAIN as ID_DOMAIN
    from fg_agent_id.signing import signing_input as id_signing_input

    assert DOMAIN != ID_DOMAIN
    payload = {"same": "payload"}
    assert signing_input(CONTEXT_ENVELOPE, payload) != id_signing_input(
        "agent-card", payload
    )


def test_signing_input_is_length_prefixed():
    tag = domain_tag(CONTEXT_ENVELOPE)
    data = signing_input(CONTEXT_ENVELOPE, {"a": 1})
    assert data[:2] == len(tag).to_bytes(2, "big")
    assert data[2:2 + len(tag)] == tag


def test_signature_does_not_transfer_across_amp_contexts():
    identity = AgentIdentity.generate("alice")
    payload = {"group_id": "g1"}
    signature = sign_payload(identity.keys, CONTEXT_GROUP_ROSTER, payload)

    verify_payload(identity.keys.public, CONTEXT_GROUP_ROSTER, payload, signature)
    with pytest.raises(SignatureError):
        verify_payload(identity.keys.public, CONTEXT_ENVELOPE, payload, signature)


def test_envelope_signature_is_domain_bound():
    """An envelope signature must not verify as a bare canonical-JSON signature
    (the pre-hardening format)."""
    from fg_agent_id.canonical import canonical_json

    alice = AgentIdentity.generate("alice")
    env = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=alice.address,
        to=alice.address,
        session_id="s",
        body=Envelope.encode_body(b"{}"),
    ).signed(alice.keys)

    env.verify_signature()

    # The same signature over the undomained payload must fail.
    with pytest.raises(SignatureError):
        alice.keys.public.verify(
            base64.b64decode(env.sig), canonical_json(env._payload())
        )


def test_legacy_undomained_envelope_signature_is_rejected():
    alice = AgentIdentity.generate("alice")
    env = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=alice.address,
        to=alice.address,
        session_id="s",
        body=Envelope.encode_body(b"{}"),
    )
    from fg_agent_id.canonical import canonical_json

    legacy_sig = base64.b64encode(alice.keys.sign(canonical_json(env._payload()))).decode()
    with pytest.raises(SignatureError):
        env.model_copy(update={"sig": legacy_sig}).verify_signature()


def test_group_roster_signature_and_digest_are_domain_bound():
    alice = AgentIdentity.generate("alice")
    card = alice.card()
    roster = GroupInfo(
        group_id="g1", purpose="standup", founder=card.address, epoch=1, members=(card,)
    ).signed_by(alice.keys)

    roster.verify()

    import hashlib

    expected = hashlib.sha256(
        signing_input(CONTEXT_GROUP_ROSTER, roster._payload())
    ).hexdigest()
    assert roster.roster_digest == expected


def test_tampered_roster_fails_verification():
    alice = AgentIdentity.generate("alice")
    card = alice.card()
    roster = GroupInfo(
        group_id="g1", purpose="standup", founder=card.address, epoch=1, members=(card,)
    ).signed_by(alice.keys)

    with pytest.raises(SignatureError):
        roster.model_copy(update={"epoch": 2}).verify()


class TestRelayAudienceBinding:
    def test_pull_payload_binds_audience(self):
        a = _pull_payload("amp:key:x", "2026-01-01T00:00:00+00:00", "relay-a")
        b = _pull_payload("amp:key:x", "2026-01-01T00:00:00+00:00", "relay-b")
        assert a != b

    def test_ack_payload_binds_audience(self):
        a = _ack_payload("amp:key:x", "2026-01-01T00:00:00+00:00", ["1"], "relay-a")
        b = _ack_payload("amp:key:x", "2026-01-01T00:00:00+00:00", ["1"], "relay-b")
        assert a != b

    def test_pull_and_ack_use_distinct_contexts(self):
        """A signed pull must never be usable as a signed ack, or vice versa."""
        ts = "2026-01-01T00:00:00+00:00"
        pull = _pull_payload("amp:key:x", ts, DEFAULT_RELAY_AUDIENCE)
        ack = _ack_payload("amp:key:x", ts, [], DEFAULT_RELAY_AUDIENCE)

        assert domain_tag(CONTEXT_RELAY_PULL) in pull
        assert domain_tag(CONTEXT_RELAY_ACK) in ack
        assert domain_tag(CONTEXT_RELAY_ACK) not in pull
        assert domain_tag(CONTEXT_RELAY_PULL) not in ack

    async def test_pull_signed_for_another_relay_is_rejected(self):
        """A pull captured at one relay must not drain the same mailbox at
        another relay configured with a different audience."""
        from fg_amp.transport.relay import PULL_PATH, create_relay_app

        pytest.importorskip("fastapi")
        owner = AgentIdentity.generate("owner")
        ts = datetime.now(UTC).isoformat()

        # Signed for "relay-a" ...
        sig = base64.b64encode(
            owner.keys.sign(_pull_payload(owner.address, ts, "relay-a"))
        ).decode()

        # ... presented to a relay that calls itself "relay-b".
        app = create_relay_app(audience="relay-b")
        status, _ = await _call(app, PULL_PATH, {
            "address": owner.address, "ts": ts, "sig": sig, "wait_seconds": 0.0
        })
        assert status == 401

    async def test_pull_signed_for_the_right_relay_is_accepted(self):
        from fg_amp.transport.relay import PULL_PATH, create_relay_app

        pytest.importorskip("fastapi")
        owner = AgentIdentity.generate("owner")
        ts = datetime.now(UTC).isoformat()
        sig = base64.b64encode(
            owner.keys.sign(_pull_payload(owner.address, ts, "relay-b"))
        ).decode()

        app = create_relay_app(audience="relay-b")
        status, _ = await _call(app, PULL_PATH, {
            "address": owner.address, "ts": ts, "sig": sig, "wait_seconds": 0.0
        })
        assert status == 200


async def _call(app, path: str, body: dict):
    """Minimal ASGI JSON POST against the relay app."""
    import json

    payload = json.dumps(body).encode()
    messages = []
    received = {"done": False}

    async def receive():
        if received["done"]:
            return {"type": "http.disconnect"}
        received["done"] = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 80),
    }
    await app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    import json as _json

    return status, (_json.loads(raw) if raw else None)


class TestSignatureCanonicalization:
    """One signature must have exactly one wire form.

    A 64-byte Ed25519 signature has 16 valid base64 spellings (the final
    character's low bits are ignored on decode). That is a security problem
    wherever a signature doubles as an identifier — the relay keys its
    single-use pull guard on the signature string, so a re-spelled signature
    looked new while still verifying.
    """

    @staticmethod
    def respell(signature: str) -> str | None:
        raw = base64.b64decode(signature)
        for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
            candidate = signature[:-3] + ch + "=="
            if candidate == signature:
                continue
            try:
                if base64.b64decode(candidate, validate=True) == raw:
                    return candidate
            except Exception:
                pass
        return None

    def test_alternate_spellings_exist(self):
        identity = AgentIdentity.generate("alice")
        sig = sign_payload(identity.keys, CONTEXT_ENVELOPE, {"a": 1})
        assert self.respell(sig) is not None

    def test_non_canonical_signature_is_refused(self):
        identity = AgentIdentity.generate("alice")
        payload = {"a": 1}
        sig = sign_payload(identity.keys, CONTEXT_ENVELOPE, payload)
        alt = self.respell(sig)

        verify_payload(identity.keys.public, CONTEXT_ENVELOPE, payload, sig)
        with pytest.raises(SignatureError, match="canonically base64"):
            verify_payload(identity.keys.public, CONTEXT_ENVELOPE, payload, alt)

    def test_envelope_with_respelled_signature_is_refused(self):
        alice = AgentIdentity.generate("alice")
        env = Envelope(
            type=EnvelopeType.HANDSHAKE_REJECT,
            sender=alice.address,
            to=alice.address,
            session_id="s",
            body=Envelope.encode_body(b"{}"),
        ).signed(alice.keys)
        env.verify_signature()

        alt = self.respell(env.sig)
        with pytest.raises(SignatureError):
            env.model_copy(update={"sig": alt}).verify_signature()

    async def test_respelled_pull_cannot_replay(self):
        """The single-use pull guard keys on the signature, so a re-spelled
        signature must not read as a different request."""
        pytest.importorskip("fastapi")
        from fg_amp.transport.relay import PULL_PATH, create_relay_app

        owner = AgentIdentity.generate("victim")
        app = create_relay_app(audience="relay-x")
        ts = datetime.now(UTC).isoformat()
        raw = owner.keys.sign(_pull_payload(owner.address, ts, "relay-x"))
        sig = base64.b64encode(raw).decode()
        body = {"address": owner.address, "ts": ts, "sig": sig,
                "wait_seconds": 0.0}

        status, _ = await _call(app, PULL_PATH, body)
        assert status == 200

        alt = self.respell(sig)
        assert alt is not None
        status, _ = await _call(app, PULL_PATH, {**body, "sig": alt})
        assert status == 401, "re-spelled signature replayed the pull"


class TestRateLimitKeys:
    """Every limiter must be keyed on the party it protects. Keying on the
    object being acted upon lets an attacker vary it freely, and hands the
    bucket to the victim."""

    async def test_revocations_are_limited_per_issuer(self):
        pytest.importorskip("fastapi")
        from fg_amp import OwnerIdentity
        from fg_amp.transport import relay as relay_mod
        from fg_amp.transport.relay import REVOCATIONS_PATH, create_relay_app

        original = relay_mod._RATE_MAX_REQUESTS
        relay_mod._RATE_MAX_REQUESTS = 5
        try:
            app = create_relay_app(audience="relay-x")
            owner = OwnerIdentity.generate("spammer")
            accepted = 0
            for i in range(20):
                # A different digest every time — previously this defeated the
                # limiter entirely, because the key varied with the payload.
                subject = OwnerIdentity.generate(f"victim{i}")
                grant = owner.grant(subject.address, {"read"}, ttl_seconds=3600)
                revocation = owner.revoke(grant)
                status, _ = await _call(app, REVOCATIONS_PATH,
                                        revocation.model_dump(mode="json"))
                if status < 400:
                    accepted += 1
            assert accepted <= 5, f"{accepted} accepted despite a cap of 5"
        finally:
            relay_mod._RATE_MAX_REQUESTS = original


class TestResumeReplayKey:
    def test_replay_key_is_the_decoded_bytes(self):
        """One 32-byte key has several base64 spellings; keying the replay
        guard on the text would let the same resume slip through per spelling."""
        import inspect

        from fg_amp.node import node as node_mod

        source = inspect.getsource(node_mod.AmpNode._handle_resume_request) \
            if hasattr(node_mod.AmpNode, "_handle_resume_request") else ""
        if not source:
            # Find whichever method holds the guard.
            source = inspect.getsource(node_mod)
        assert "_seen_resume_keys[replay_key]" in source
        assert "b64decode(request.ephemeral_key, validate=True)" in source
