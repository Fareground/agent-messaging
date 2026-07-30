"""Domain-separated signing input for AMP's own signed artifacts.

Same construction as ``fg_agent_id.signing`` but under AMP's own
namespace, so an AMP artifact and an identity artifact can never be confused
for one another even if their payloads canonicalize identically:

    uint16be(len(tag)) || tag || canonical_json(payload)
    tag = UTF-8("fg-amp/v1/" || context)

AMP signs several kinds of thing, each with its own context. Identity artifacts
(cards, delegations, revocations) are signed by ``fg-agent-id`` under
*its* namespace — never re-sign those here.
"""

from __future__ import annotations

import base64
from typing import Any

from fg_agent_id.canonical import canonical_json

from .errors import SignatureError
from .identity.keys import KeyPair, PublicKeys

DOMAIN = "fg-amp/v1"

CONTEXT_ENVELOPE = "envelope"
CONTEXT_GROUP_ROSTER = "group-roster"
CONTEXT_RELAY_PULL = "relay-pull"
CONTEXT_RELAY_ACK = "relay-ack"
CONTEXT_RELAY_WS = "relay-ws"

_MAX_TAG_BYTES = 0xFFFF
_NO_AGREEMENT = b"\x00" * 32


def domain_tag(context: str) -> bytes:
    if not context:
        raise ValueError("signing context must be a non-empty string")
    tag = f"{DOMAIN}/{context}".encode()
    if len(tag) > _MAX_TAG_BYTES:
        raise ValueError("signing context tag is too long")
    return tag


def signing_input(context: str, payload: Any) -> bytes:
    """The exact bytes to sign or verify for ``payload`` under ``context``."""
    tag = domain_tag(context)
    return len(tag).to_bytes(2, "big") + tag + canonical_json(payload)


def sign_payload(keys: KeyPair, context: str, payload: Any) -> str:
    """Sign ``payload`` under ``context``; returns a base64 signature."""
    return base64.b64encode(keys.sign(signing_input(context, payload))).decode()


def decode_signature(signature: str) -> bytes:
    """Decode a base64 signature, rejecting any non-canonical spelling.

    ``b64decode(validate=True)`` still accepts trailing padding bits that are
    non-zero, so one 64-byte signature has 16 valid base64 spellings. That is a
    security problem wherever a signature doubles as an identifier — the relay
    keys its single-use pull guard on the signature string, so a re-spelled
    signature looked new while still verifying, and a captured pull could
    re-drain a mailbox. Requiring the canonical spelling gives one signature
    exactly one wire form.
    """
    try:
        raw = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise SignatureError("signature is not valid base64") from exc
    if base64.b64encode(raw).decode() != signature:
        raise SignatureError("signature is not canonically base64-encoded")
    return raw


def verify_payload(
    public: PublicKeys, context: str, payload: Any, signature: str
) -> None:
    public.verify(decode_signature(signature), signing_input(context, payload))


def verify_by_address(address: str, context: str, payload: Any, signature: str) -> None:
    """Verify against the signing key an AMP address self-certifies."""
    from .identity.address import signing_key_from_address

    public = PublicKeys(signing=signing_key_from_address(address), agreement=_NO_AGREEMENT)
    verify_payload(public, context, payload, signature)
