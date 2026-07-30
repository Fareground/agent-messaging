"""Capability negotiation tokens for AMP handshakes.

A capability is an opaque, versioned token a peer advertises support for. The
handshake negotiates the *intersection* of both sides' offers; the established
session then knows exactly which optional features are in force
(``session.capabilities``). New capabilities can be introduced without a wire
break — an unknown token is simply absent from the intersection, so an old peer
and a new peer transparently fall back to the features they share.

This is the forward-compatibility counterpart to unknown-field-preserving
signatures: additive *fields* survive because signed models use ``extra=allow``;
additive *features* survive because they are negotiated, not assumed.
"""

from __future__ import annotations

# Known capability tokens. Peers MAY advertise tokens not listed here; the
# negotiation is pure set-intersection, so forward compatibility is automatic.
CAP_RATCHET_DH_V1 = "amp.ratchet.dh-v1"  # DH double ratchet (baseline, always on)
CAP_PQ_ML_KEM_768 = "amp.kem.ml-kem-768-x25519"  # hybrid post-quantum handshake
CAP_WITNESSED_V1 = "amp.posture.witnessed-v1"  # witnessed session posture (SPEC §7.1)

# What this reference implementation advertises by default. PQ is added by the
# node when a KEM backend is available (see crypto/pq.py).
DEFAULT_CAPABILITIES: tuple[str, ...] = (CAP_RATCHET_DH_V1,)


def default_capabilities() -> tuple[str, ...]:
    """The reference node's advertised set: baseline plus PQ when a KEM backend
    is installed. Computed at call time so availability is detected dynamically."""
    from .crypto.pq import PQ_AVAILABLE

    caps = list(DEFAULT_CAPABILITIES)
    if PQ_AVAILABLE:
        caps.append(CAP_PQ_ML_KEM_768)
    return tuple(caps)


def negotiate(local: tuple[str, ...], remote: tuple[str, ...]) -> tuple[str, ...]:
    """The agreed capability set: the sorted intersection of both offers.

    Deterministic (sorted) so both peers derive the identical set and can bind
    it into transcripts/keys without ordering ambiguity.
    """
    return tuple(sorted(set(local) & set(remote)))
