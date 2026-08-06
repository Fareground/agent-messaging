# Changelog

All notable changes to `fg-amp`. Format loosely follows Keep a
Changelog; the wire protocol version (`amp`) is tracked separately from the
package version and remains `0.1` until the v1.0 freeze.

## [Unreleased]

### Added

- **Witnessed session posture (SPEC §7.1) — `amp.posture.witnessed-v1`.** A
  negotiated middle ground between sealed E2E and auditability: both parties
  name the SAME witness (address + X25519 key) inside the signed, sealed
  handshake — the initiate's witness block feeds the transcript salt, so the
  agreement is bound into the session key; a divergent or missing block is a
  handshake reject. Every send then also seals the plaintext to the witness as
  a signed `witness.copy` envelope (new envelope type) bound to
  `(session_id, seq, sender)` both by the envelope signature and by a sealed
  inner duplicate — splicing a copy onto another frame is detectable. A sender
  that cannot produce the copy refuses to send (seq/ratchet untouched).
  `WitnessSpec` (node config `witness=`), `WitnessReceiver` (decrypts copies
  into `(session_id, seq, sender, payload)`), `node.on_witness_copy` routing,
  new `WitnessError`. Posture survives resume via `SessionRecord.witness`.
  Sealed default is byte-for-byte unchanged (absent witness is omitted from
  the wire, preserving handshake digests). The spec states honestly what is
  cryptographically bound vs detectable-not-preventable.
- **Federation-lite (SPEC §13.3).** Cards may list multiple relays
  (`endpoints["relay"]`, `relay.1`, `relay.2`, … — ordered failover);
  `RelayTransport` now accepts a list of relay URLs (+ per-relay audiences,
  since pull/ack signatures are audience-bound), tries them in order for
  send/pull/cards/revocations (first definitive answer wins; 4xx never fails
  over), registers the card on every relay, and `RelayTransport.for_card` /
  `relay_endpoints` build the failover set from a peer's signed card. New
  `RelaySyncer` pulls a peer relay's `cards` / `revocations` /
  `key-revocations` deltas over the existing `?since=` cursors (cards gained
  a `GET ?since=` delta listing on both state backends) with
  verify-before-admit — hostile records are rejected and counted, and never
  stall the cursor. `amp-relay --peer URL --sync-interval N` runs syncers in
  the app lifespan. Mailboxes deliberately do not federate.
- **WebSocket relay transport (SPEC §13.4).** The relay app gains
  `/amp/v0/relay/ws`: socket-session auth adapting the pull credential (new
  signing context `relay-ws`; audience-bound, freshness-windowed, single-use,
  periodic re-auth with a grace window), real-time push delivery with the
  same lease/ack at-least-once semantics, and sends over the socket verified
  exactly like HTTP sends. Client-side `WsRelayTransport` is a drop-in
  `RelayTransport` that serves the mailbox over the socket and falls back to
  authenticated HTTP pulls whenever the socket is down. No new dependency:
  the WS client is aiohttp, already part of the `http` extra.

- **x402 payment profile (SPEC §16.5) — `amp.payment/1`.** Payment carriage
  over a session: `quote` → `authorization` → `settled`/`failed`, with x402
  payment-requirements and payment-payload objects riding verbatim (and
  unvalidated) under `x402` — AMP carries, x402 settles. A per-session
  `PaymentTracker` enforces lifecycle legality (authorization must reference a
  known unexpired quote; settlement must reference an authorization) in the
  same style as `TaskTracker`. Spend-scope enforcement via `fg_agent_id.spend`:
  a payer's outbound `authorization` is cap-verified against its own delegation
  chain before encrypt (per-tx and cumulative caps, tracked in a per-session
  `SpendLedger`), and the receiver verifies the payer's handshake-presented
  chain the same way — a violation raises `SpendRejectedError` before send and
  is a protocol error on receive. New `PaymentLifecycleError`.
- **MCP-over-AMP profile (SPEC §16.6) — `amp.mcp/1`.** Carriage for MCP
  JSON-RPC messages: each body wraps one message verbatim plus an opaque
  `mcp_session` correlator; only the outer frame is validated (`payload` must
  be a JSON object with `jsonrpc == "2.0"`). Capability advertisement rides
  the existing `payload_types` negotiation. A thin `McpBridge` helper exposes
  a local async MCP handler over a session and calls the remote one with
  request/response correlation by JSON-RPC id, timeouts, and
  unmatched-response drop-and-count.
- Sessions now carry the node's own delegation chain and the peer's
  handshake-verified chain (`own_chain`/`peer_chain`) so profile-level
  authority checks (spend scopes) run against verified credentials.

- **Typed bodies (SPEC §16) — AMP's MIME layer.** A payload-type registry
  (`fg_amp.bodies`) of versioned, schema-validated body types named
  `<name>/<version>`; `text/plain` / `application/json` remain the untyped
  fallback tier. Built-ins: `amp.task/1` (work lifecycle with a per-session
  `TaskTracker` state machine enforcing transition legality), `amp.receipt/1`
  (application-level acknowledgements, distinct from §10 transport receipts),
  `amp.ref/1` (external artifact pointers), `amp.claim/1` (knowledge-claim
  carriage). Sessions validate recognized typed bodies before encrypt and
  after decrypt; an unknown typed body with `metadata.critical: true` is
  rejected as a protocol error, while unknown non-critical ones deliver
  opaque. Built-ins are advertised in the default `payload_types` offer so
  they negotiate at handshake like any other payload type. New
  `Payload.body()` / `Session.send_body()` helpers, `BodyError` hierarchy,
  and `vectors.typed_bodies` golden examples.

### Changed

- **Renamed to `fg-amp`** (was `fareground-amp`); import path is now `fg_amp`.
  Aligns with the other Fareground `fg-*` packages. The sibling identity package
  is now `fg-agent-id` (import `fg_agent_id`).
- **Domain-separation tag is now `fg-amp/v1`** (was `fareground-amp/v1`). This is
  a **wire-breaking change**: the tag is part of the signing input, so artifacts
  signed under the old tag will not verify. Golden vectors in
  `spec/vectors.json` were regenerated. Nothing had been published, so no
  released artifacts are affected.

## [0.11.0] — 2026-07-14

### Trust-core hardening (fourth scored audit remediation)

- **Zero-DH rejection unified.** `derive_session_key` and the seal/open paths now
  reject a low-order/degenerate X25519 shared secret, matching the DH ratchet and
  SPEC §8 (previously only the ratchet enforced it).
- **Reject-handler sender binding.** `handshake.reject` / `resume.reject` are now
  dropped unless the envelope sender matches the pending peer, closing a cheap
  on-path handshake-abort DoS.
- **Owner-key revocation in the accept path.** Handshake-accept chain verification
  now passes `revoked_keys`, so a compromised owner (root) tears down every chain
  it signed — not just individually revoked digests.
- **Freshness-window replay caches**, orphan-responder reaping, accept-consumes-
  pending, bounded policy rate map, and inbox error-text redaction.

### Relay hardening

- **At-least-once delivery** via leased pull + explicit ack (a client crash mid-
  pull no longer drops messages).
- **Blocking SQLite moved off the event loop**; per-source **rate limiting** on
  unauthenticated endpoints; naive-timestamp pull now returns 422, not 500.
- **Group manager**: session-leak fixes and atomic mesh invites.

### Interop — multi-frame ratchet conformance vectors

- **`vectors.ratchet`**: golden vectors for the deterministic double-ratchet
  internals — a multi-frame symmetric chain, the root step, the direction seed,
  and the close key — closing the gap where the ratchet had a single
  implementation. The JS reference now reproduces them byte-for-byte (32 JS
  conformance checks), and a Python test reproduces them from the real ratchet
  KDFs. SPEC §8 pins the exact KDF inputs.

### Identity — `did:amp` interoperability

- **New `did:amp` DID method** (`identity/did.py`): registry-free, self-certifying
  mapping between `amp:key:` addresses and W3C DIDs, with full DID Document
  resolution (Ed25519 verification method, X25519 key agreement, transport
  services) in `did:key`-style `publicKeyMultibase`. `AgentCard.did` /
  `AgentCard.to_did_document()` helpers. Opens interop with the decentralized-
  identity ecosystem (resolvers, DID Documents, DIDComm). SPEC §2.1.

## [0.10.0] — 2026-07-14

### Standard-grade round: extensibility, PQ, groups, interop

- **Wire extensibility.** Signed models (`Envelope`, `AgentCard`, handshake
  payloads) now preserve unknown fields (`extra="allow"`) and sign over the full
  canonical form, so additive wire-format fields no longer break signatures across
  versions. New **capability negotiation** in the handshake (sorted set-
  intersection, recorded on `session.capabilities`) lets features be added without
  a wire break; capabilities ride inside the signed, sealed handshake so they
  can't be stripped (downgrade-resistant).
- **Post-quantum hybrid handshake.** When both peers advertise it, an ML-KEM-768
  shared secret is mixed with X25519 into the session key (HKDF IKM
  concatenation), for both the initial handshake and resume — harvest-now-
  decrypt-later defense. Transparent classical fallback when unavailable.
- **Real group epoch / rekey / kick.** Founder-signed roster reissue at epoch+1 on
  add/remove; deterministic mesh completion for new members; pairwise-session
  teardown for removed members (exclusion / forward secrecy across membership
  change); automatic `roster_digest` equivocation detection via roster-acks.
- **Relay hardening.** Bounded card directory and revocation stores (LRU
  eviction) and **delta revocation sync** via a monotonic `?since=<cursor>`,
  closing the unbounded-growth / full-refetch DoS on shared trust infrastructure.
- **Forward-secret initiate.** Cards advertise a rotatable, signed
  `agreement_prekey`; the first knock is sealed to it and `rotate_prekey()` makes
  past knocks unrecoverable once the previous key is dropped.
- **Interop: spec + conformance vectors + second implementation.** `spec/SPEC.md`
  (byte-level wire spec), `spec/vectors.json` (11 golden vector groups), and a
  dependency-free JavaScript reference in `reference/js/` that reproduces every
  vector byte-for-byte (run in CI via `tests/test_conformance.py`). Coverage spans
  the primitives (canonical JSON, base58, Ed25519, X25519, HKDF, AEAD, transcript
  chain) **and composed constructions**: seal/open, AgentCard and group-roster
  signing + digest, session-message AAD, and a **real ML-KEM-768 decapsulation
  interop** vector (Python-produced ciphertext decapsulated by Node to the identical
  shared secret). Not yet pinned: a full multi-frame ratchet exchange and one-time
  prekeys.

### Post-audit remediation (three independent adversarial re-audits)

- **Group kick now actually excludes.** Non-founder members were popping a removed
  peer from the roster dict but never closing the pairwise `Session`, leaving a
  kicked member a live E2E channel. `apply_roster` now returns the removed sessions
  and every member closes them (regression test asserts the session state, not a
  vacuous `or`).
- **`session.capabilities` no longer overstates PQ.** The PQ token is recorded only
  when a KEM secret was actually exchanged, so an app gating on it can't be told a
  purely-classical session is hybrid-secure.
- **Relay revocation store is fail-closed.** It no longer LRU-evicts revocations
  (which let a cheap self-signed-spam flood silently drop a real revocation); at
  capacity it rejects new writes loudly and never loses an existing security fact.
  The card directory remains a best-effort LRU cache; flood-resistant registration
  (proof-of-work / stake) is roadmapped.

## [0.9.0] — 2026-07-13

### Correctness — third scored audit, remediation round

- **No acknowledged message is dropped under backpressure.** `max_inflight`
  previously evicted the oldest *unread* frame on overflow — but that frame had
  already been ratcheted, transcript-recorded, and ACKed, so its loss was silent
  and unrecoverable (at-least-once quietly degraded to at-most-once). Replaced
  with real windowed flow control: the receiver advertises remaining inbox
  capacity in every receipt (`window`), the sender stalls when it reaches zero,
  and a decode-gate backstop holds an over-capacity in-order frame *undecoded and
  unacked* so it is recovered by retransmit or drained later. Draining the
  consumer reopens the window. New `SessionStats.backpressure_holds` /
  `send_stalls`. `max_inflight` is validated (1..reorder-window; rejects 0) so a
  held frame can never overflow the reorder buffer, a reorder-window overflow now
  deterministically closes the session for resume instead of silently wedging,
  and `receive_nowait()`'s drain task is kept referenced and cancelled on close.
- **Resume-accept replay is rejected.** Because a session id is stable across
  resumes, a captured `resume.accept` could be replayed into a later resume of
  the same session, resolving it into a dead session key (a targeted resume-jam
  defeating the fresh-key/PCS guarantee). Each `resume` now carries a fresh nonce
  echoed in the accept and mixed into the resumed session key; a stale accept
  fails the constant-time nonce check and is dropped.
- **HTTP inbox and relay cap the raw body at 1 MiB BEFORE buffering or parsing**
  (early Content-Length reject, then a streamed byte cap), so a directly-reachable
  agent or relay can't be exhausted by an oversized payload — the prior check ran
  only after the whole body had already been read and JSON-decoded.
- **`create_group()` is atomic.** A member refusing the invite mid-fan-out now
  tears down the pairwise sessions already opened and drops the half-built group,
  instead of leaving dangling sessions and a partial group registered.

## [0.8.0] — 2026-07-13

### Group membership integrity
- **Founder-signed, versioned group roster.** `GroupInfo` now carries an epoch
  and a founder signature over the canonical (group, epoch, membership). Each
  member verifies the signature on the invite (unsigned/forged rosters are
  dropped) and exposes `roster_digest` — comparing it with peers over their
  pairwise sessions detects a founder handing different members divergent
  rosters. This is the cheap membership-integrity win short of full MLS, which
  remains overkill for small agent groups.

### Operational
- **Durable revocation registry:** `RevocationRegistry.snapshot()` / `restore()`
  so a node doesn't forget revoked keys/delegations on restart (a security
  control that resets on reboot is a trap). Restore is additive — revocation is
  permanent.

## [0.7.0] — 2026-07-13

### Security — agent identity-key revocation
- `KeyRevocation` revokes a compromised agent's whole identity key, not just a
  delegation. Honored when self-signed (`agent.revoke_own_key()`) or
  owner-signed with a proof chain rooting at the owner
  (`owner.revoke_agent_key(agent)`). A key-revoked agent is refused ALL sessions
  regardless of the recipient's contact policy (closes the gap where delegation
  revocation left an `open`-policy agent still able to connect). Distributed via
  the relay (`publish_key_revocation` / `sync_key_revocations`).
- Ratchet: reject a low-order/zero X25519 shared secret (defense in depth).

### Testing
- Joint DH-turn × loss/reorder/duplicate property fuzzer (the seam the prior
  one-directional ARQ fuzzer and in-order ratchet fuzzer each missed), plus an
  explicit old-chain-frame-retransmitted-after-a-turn regression.
- Ratchet-layer regression tests: simultaneous-first-send no-divergence,
  same-direction burst shares one DH key, low-order-point rejection.

## [0.6.0] — 2026-07-13

### Cryptography — DH double ratchet (post-compromise security)
- Session messages now use a **double ratchet**: the existing per-message
  symmetric chain (forward secrecy) plus a Diffie-Hellman ratchet that mixes a
  fresh X25519 secret into the root on every direction turn, so a key
  compromise heals after the next reply. Each session message carries the
  sender's current ratchet public key in a signed, AAD-bound 32-byte header.
- **AMP variant preserves either-party-first sending** (vanilla Signal forces
  initiator-first): the responder→initiator direction is seeded so the
  responder can speak first, and `DHs` advances only inside a receive-triggered
  step, so simultaneous first sends never diverge the root. Verified by a
  bidirectional property fuzzer (50 random who-sends/how-many interleavings),
  simultaneous-first-send, responder-first, and 25-turn ping-pong tests.
- Wire change: SESSION_MESSAGE body is now `dh_public(32) || nonce || ciphertext`.
  Integrates cleanly with the reorder buffer + ARQ (in-order decode means no
  skipped-message-key store is needed).

## [0.5.0] — 2026-07-13

Reliability completeness + fourth audit round (scored 8.6). Adds true delivery
guarantees and observability.

### Reliability
- **Tail-loss recovery.** Property-based fuzzing (Hypothesis) of the reorder/ARQ
  state machine revealed that pure NACK-based ARQ can't recover a lost frame
  with nothing after it (no gap signal). Added retransmit-on-timeout: the sender
  periodically replays unacked frames; cumulative ACK-on-delivery lets the peer
  prune the send buffer and stop retransmission. Delivery is now exactly-once,
  in-order, and complete (or a deterministic close) under arbitrary
  drop/reorder/duplicate — asserted by a property test over 60 schedules.

### Observability
- `SessionStats` counters (sent/received/retransmitted/nacks_sent/
  reorder_buffered/receipts_dropped/inbox_evicted/unrecoverable_closes) and
  `AmpNode.metrics()` aggregate. NACKs for never-sent seqs are logged.

## [0.4.0] — 2026-07-13

Reliability + second audit round (scored 7.5 → 8.0, then this round). Wire
protocol stays `0.1` but the handshake wire representation changed (`ttl_ms`),
so this is a minor bump.

### Reliability
- **Receipt-driven retransmit (ARQ).** Receivers NACK gaps; senders retransmit
  from a bounded send buffer — a frame lost by the transport now recovers
  instead of stalling the session. Cumulative ack prunes the send buffer.
- **Bounded reorder buffer.** Out-of-order frames are held and delivered in
  sequence once the gap fills, rather than one reorder bricking the session.
- **Idempotent inbound.** A redelivered already-seen frame is a silent no-op
  (at-least-once transports and ARQ retransmits no longer raise).

### Security / correctness
- Inbound decode runs under a dedicated per-session recv lock (was unguarded
  while send held a lock — unsafe under concurrent HTTP-inbox dispatch).
- Handshake/resume freshness: stale `created_at` (±300s) rejected + bounded
  seen-envelope-id cache, so a captured establishing frame can't be replayed
  after the session is forgotten.
- Session-key KDF salt binds BOTH handshake ephemerals, not just the initiator's.
- Wire determinism: handshake TTL is integer milliseconds; `canonical_json`
  rejects floats in signed/salt payloads (cross-implementation agreement).

## [0.3.0] — 2026-07-13

Hardening release incorporating an independent three-lens audit (cryptography,
concurrency, API completeness). Package version jumps to 0.3.0; wire protocol
stays `0.1`.

### Security
- **Trusted-issuer pinning.** `ContactPolicy.credentialed(scopes, trusted_issuers=…)`
  anchors a delegation chain's root to owners you trust — closing the bypass
  where any peer could self-sign a chain granting itself scopes. Without
  `trusted_issuers`, scopes are advisory and a warning is logged.
- **Operator fields are verified, not trusted.** Allowlist-by-operator now uses
  the cryptographically verified chain root; a card whose `operator` disagrees
  with its chain is rejected.
- **Revocation and expiry survive resume.** Resume re-verifies the delegation
  chain fresh (against current revocations/expiry) instead of reinstating
  frozen scopes.
- **Group fan-out is bound to the signed roster.** A group-purpose session is
  joined to the fan-out set only if the peer is on the founder's roster;
  invites are honored only over their own group-purpose session (stops a
  coerced-mesh amplifier and an outbound-message confidentiality leak).
- **Relay:** single-use pull signatures (drain-and-drop replay closed),
  per-sender mailbox quotas, and a 1 MiB envelope size cap.
- **Per-message key ratchet** (added 0.2→0.3): forward secrecy within a
  session; a decrypt/validate failure no longer desyncs the chain.
- Replay guards: a replayed `handshake.initiate`/`session.resume` can neither
  clobber a live session nor build a duplicate.
- Canonical JSON now NFC-normalizes strings for cross-implementation
  signature agreement.
- `require_scope(scope, owner=…)` asserts the verified peer owner.

### Correctness
- Concurrent `send()` no longer reorders on the wire (delivery serialized with
  seq assignment) — previously bricked a session permanently.
- Bounded memory everywhere remotely drivable (resume-key set, group pre-invite
  buffers, closed sessions pruned, relay long-poll waiters per-request).
- Double/concurrent resume supersedes the prior session instead of orphaning it.

### API / DX
- `HttpTransport` and `create_inbox_router` are now exported and tested
  (including a real cross-app session); `HttpTransport` accepts an injectable
  poster for testing.
- `AmpNode.aclose()` for graceful shutdown; sessions self-prune on close.
- Protocol major-version check on inbound envelopes (`ProtocolVersionError`).
- Structured `logging` across node/session/policy/transport.
- Richer error taxonomy: `SessionStateError`, `SessionNotFoundError`,
  `ResumeError`, `ConfigurationError`, `ProtocolVersionError`; `AddressError`
  now exported.
- Participant-neutral aliases `ParticipantIdentity` / `ParticipantCard`.
- `SqliteRelayState` persistent relay backend; `amp-relay --db`.
- `Session.max_inflight` optional inbox backpressure.
- `py.typed` shipped in the wheel.

## [0.2.0] — 2026-07-13
- Owner identity as first-class; mutual delegation-chain verification.
- `session.resume` with fresh-key rotation; `SessionStore` (memory/file).
- Multi-agent group sessions over the pairwise mesh.
- Hosted relay: mailboxes, signed card directory, authenticated pulls.
- Participant kinds (agent/human/service); `ContactPolicy.allow_kinds`.

## [0.1.0] — 2026-07-13
- Initial: identity + delegation, signed/encrypted envelopes, pairwise
  ephemeral & persistent sessions, contact policy, in-memory + HTTP transports,
  transcript hash chain.
