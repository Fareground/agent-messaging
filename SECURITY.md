# Security Policy

AMP is a security protocol; we take vulnerabilities seriously.

## Reporting

Email **security@fareground.ai** with details. Do not open a public issue for a
suspected vulnerability. We aim to acknowledge within 3 business days and to
ship a fix or mitigation for confirmed high-severity issues promptly.

Please include: affected version, a description, and a proof-of-concept if
possible.

## Scope

In scope: the protocol design and the `fg_amp` reference
implementation — identity/delegation, envelope signing/encryption, the session
handshake/ratchet/resume, group membership, contact policy, and the relay.

Out of scope (by design):
- Content-level trust and agent alignment (prompt injection across an agent
  boundary is contained, not eliminated — see the threat model).
- Endpoint/host compromise (a stolen agent private key impersonates that agent
  until its delegation is revoked).
- Relays are untrusted by construction; a malicious relay can delay or refuse
  delivery (detectable via signatures and sequence gaps) but cannot read,
  forge, or undetectably reorder traffic.

## Cryptography

AMP uses only standard primitives from `cryptography` (pyca): Ed25519
signatures, X25519 key agreement, HKDF-SHA256, ChaCha20-Poly1305, and a
Signal-style symmetric key ratchet. We do not ship custom cryptography. If you
believe a construction is misused, that is in scope.

## Hardening status

The v0.3 release incorporates an independent three-lens audit (cryptography,
concurrency, API). See `CHANGELOG.md` for the specific findings addressed.
Known residual limitations (large-group MLS, per-message DH ratchet, relay
proof-of-work/payment gating) are tracked in the blueprint roadmap.
