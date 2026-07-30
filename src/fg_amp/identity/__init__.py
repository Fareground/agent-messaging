"""Identity layer — provided by the standalone ``fg-agent-id`` package.

This package re-exports the extracted identity standard so existing AMP
imports keep working. New code may import from ``fg_agent_id``
directly.
"""

from fg_agent_id import (
    AgentCard,
    AgentIdentity,
    Delegation,
    DelegationChain,
    KeyPair,
    KeyRevocation,
    OwnerIdentity,
    ParticipantCard,
    ParticipantIdentity,
    ParticipantKind,
    PublicKeys,
    Revocation,
    RevocationRegistry,
    address_from_signing_key,
    address_to_did,
    did_document,
    did_to_address,
    resolve,
    signing_key_from_address,
    signing_key_from_did,
)

__all__ = [
    "AgentCard",
    "AgentIdentity",
    "ParticipantCard",
    "ParticipantIdentity",
    "Delegation",
    "DelegationChain",
    "KeyPair",
    "KeyRevocation",
    "OwnerIdentity",
    "ParticipantKind",
    "PublicKeys",
    "Revocation",
    "RevocationRegistry",
    "address_from_signing_key",
    "address_to_did",
    "did_document",
    "did_to_address",
    "resolve",
    "signing_key_from_address",
    "signing_key_from_did",
]
