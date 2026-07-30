# AMP — Agent Messaging Protocol

**Blueprint v0.3 — 2026-07-13**

AMP is the messaging layer in Fareground's family of open agent building blocks. Where an agent framework gives agents a brain, AMP gives them a **phone**: a verifiable address, an inbox, and the ability to *initiate* secure conversations with other agents — ephemeral or persistent, one-to-one or group — across trust boundaries.

It is a standalone protocol + reference implementation that anyone can adopt; nothing in it depends on Fareground infrastructure.

---

## 1. Why AMP exists

The 2026 protocol landscape solved three problems and left one open:

| Layer | Solved by | What it does |
|---|---|---|
| Agent → tool | **MCP** | Tool calling, resources, prompts |
| Agent → agent (request/response) | **A2A v1.0** (Linux Foundation) | Client calls a remote agent's task API |
| Agent payments | **x402** (Linux Foundation) | Stateless pay-per-request over HTTP |
| **Agent ↔ agent conversation** | **nobody** | Agent-initiated, encrypted, stateful sessions |

A2A is client-server RPC: a remote agent cannot spontaneously open a conversation, sessions are task objects rather than relationships, and encryption is transport TLS only. DIDComm has the right envelope design but lives in the SSI ecosystem with no agent semantics. Matrix/XMTP are mature encrypted messengers with the wrong identity models. AGNTCY/SLIM is the closest (pub/sub + MLS) but is heavy vendor infrastructure.

**AMP's thesis:** the missing primitive is the *session* — a mutually-consented, end-to-end-encrypted, resumable conversation between agents that either side can initiate, carrying whatever payloads the parties negotiate (natural language, structured messages, embedded A2A tasks, MCP interactions, x402 payments).

AMP does not compete with MCP or A2A. It is the layer *under* them for peer conversation — inside an AMP session you can carry A2A tasks and MCP tool calls.

---

## 2. Design principles

1. **Agents are peers.** Any agent can initiate contact with any other agent whose address it can resolve. No client/server asymmetry at the protocol level.
2. **Consent before conversation.** Initiation is a handshake against the recipient's published *contact policy*. Unsolicited contact is structurally rate-limitable, credential-gated, and refusable. This is what makes agent-initiated messaging safe rather than a spam/prompt-injection cannon.
3. **Identity is a delegation chain, not a key.** Every message is attributable to *agent instance → operator → principal (human/org)* with verifiable scope of authority. "Who is this, acting for whom, allowed to do what."
4. **End-to-end encryption is not optional.** Relays and transports never see plaintext. Session keys are per-session with forward secrecy; ephemeral sessions leave no recoverable trace.
5. **Sessions are the unit of trust.** Authority, capabilities, rate limits, and payload schemas are negotiated per session and enforced at the boundary. A compromised session never grants more than its negotiated scope.
6. **Transport-agnostic.** The protocol is defined over signed/encrypted envelopes. In-process, HTTP, WebSocket, or a message broker are interchangeable carriers. Store-and-forward relays let offline / scale-to-zero agents receive initiations.
7. **Boring cryptography.** Ed25519 signatures, X25519 key agreement, ChaCha20-Poly1305 AEAD, HKDF key derivation — all from `cryptography`'s audited primitives. No invented crypto. MLS (RFC 9420) is the intended path for large-group sessions (see roadmap).
8. **Open by design.** Wire format is versioned JSON envelopes; the spec is implementation-independent; the reference implementation is a small, dependency-light Python package.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Application layer                     │
│   NL chat · structured payloads · A2A tasks · MCP · x402   │
├────────────────────────────────────────────────────────────┤
│  Session layer          Session lifecycle, consent,        │
│                         capability negotiation, transcript │
├────────────────────────────────────────────────────────────┤
│  Envelope layer         Signed + E2E-encrypted envelopes   │
├────────────────────────────────────────────────────────────┤
│  Identity layer         Keys, delegation chain, AgentCard, │
│                         addresses, contact policy          │
├────────────────────────────────────────────────────────────┤
│  Transport layer        in-memory · HTTP · WebSocket ·     │
│                         store-and-forward relay            │
└────────────────────────────────────────────────────────────┘
```

The node (`AmpNode`) composes all layers: it holds one agent's identity, enforces its policy, manages its sessions, and binds to one or more transports.

### 3.1 Identity layer

**AMP is participant-agnostic: any principal can hold an endpoint — an AI agent, a human, or a plain service.** Every identity and card carries a `kind` (`agent` | `human` | `service`), signed into the card so it cannot be forged, and policies can gate on it ("humans only", "no anonymous services"). Agent↔agent, agent↔human, human↔human, and mixed groups all run over the identical protocol; a human joins by minting an endpoint from their owner key (`owner.create_endpoint()`), typically wrapped by a chat UI.

Two distinct identity concepts, deliberately kept separate:

- **Agent identity** (`AgentIdentity`) — the *instance* doing the talking. Each agent holds an Ed25519 signing keypair and an X25519 key-agreement keypair. The agent's canonical ID is derived from the signing public key: `amp:key:<base58(ed25519-pub)>` (a `did:key`-style self-certifying identifier — no registry required to verify). Agent keys are hot (used online, per message) and expected to rotate; losing one loses nothing durable.
- **Owner identity** (`OwnerIdentity`) — the *principal* (human or org) the agent acts for. Owners hold their own keypair and AMP address but never appear on the wire; their authority reaches the network only as signed **delegation chains** attached to their agents. Owner keys are cold (used only to mint/revoke delegations) and are the durable root of trust.
- **Delegation chain.** A `Delegation` is a signed credential: *issuer* (owner or operator key) grants *subject* (agent key) a set of scopes (`converse`, `negotiate`, `commit:<domain>`, `spend:<limit>` …) with expiry. Chains compose: owner → operator → agent; effective authority is the **intersection** of all links (a delegate can never exceed its delegator). Verification walks the chain; any expired/invalid link invalidates authority (but not message authenticity).
- **Mutual verification.** The handshake carries delegation chains in *both* directions, so every established session knows, with signature-verified certainty: the peer agent's key, its owner (`session.peer_owner` = chain root), and its effective scopes (`session.peer_scopes`). Applications gate actions with `session.require_scope("commit:purchase")` — a code check against the verified chain, never against claims inside message content.
- **AgentCard.** A signed, versioned JSON document: agent ID, display name, operator, public keys, supported payload types, transport endpoints, contact policy summary. Distributable via `.well-known/amp/agent-card.json`, a registry, or out-of-band. Signature covers a canonical JSON serialization (sorted keys, no whitespace).

### 3.2 Envelope layer

Every wire message is an `Envelope`:

```json
{
  "amp": "0.1",
  "id": "uuid",
  "type": "handshake.initiate | handshake.accept | handshake.reject |
           session.message | session.close | session.resume | receipt",
  "from": "amp:key:...",
  "to": "amp:key:...",
  "session_id": "uuid | null (handshake.initiate)",
  "seq": 4,
  "created_at": "RFC3339",
  "body": "<base64 ciphertext>  |  <plaintext JSON for handshake.initiate>",
  "sig": "<base64 ed25519 over canonical envelope sans sig>"
}
```

- **Signing:** every envelope is Ed25519-signed by the sender over canonical JSON. Receivers verify before any processing.
- **Encryption:** handshake.initiate bodies are sealed to the recipient's X25519 key (ephemeral-static ECDH → HKDF → ChaCha20-Poly1305), so even the first knock is confidential to the recipient. Post-handshake bodies use a **double ratchet**: a symmetric chain-key ratchet gives a fresh AEAD key per message (forward secrecy), and a Diffie-Hellman ratchet mixes a new X25519 shared secret into the root on every direction turn (post-compromise security — a leaked key heals after the next reply). Each session message carries the sender's current ratchet public key in a signed, AAD-bound header. AMP's variant seeds the responder→initiator direction so either party (or both simultaneously) can send first, and advances the DH key only inside a receive-triggered step so concurrent sends never diverge the root.
- **Ordering & integrity:** `seq` is per-sender-per-session, strictly increasing; each message carries the running transcript hash (see 3.3), so tampering or reordering is detectable by both sides.

### 3.3 Session layer

The core primitive. State machine:

```
            initiate                accept
  (none) ──────────────▶ PENDING ──────────▶ ESTABLISHED
                            │  reject/timeout      │ close/expire
                            ▼                      ▼
                         REJECTED               CLOSED
                                        resume ──▶ ESTABLISHED (persistent only)
```

- **Handshake.** Initiator sends `handshake.initiate` with: its AgentCard, delegation chain, proposed mode (`ephemeral`|`persistent`), proposed payload types, purpose string, and an ephemeral X25519 public key. The responder's policy engine evaluates it (see 3.4). On accept, responder returns its own ephemeral X25519 key + accepted capabilities; both sides derive the session key via ECDH(ephemeral, ephemeral) + HKDF with the handshake transcript as salt — forward secrecy from the first message.
- **Modes.**
  - *Ephemeral:* TTL-bound, keys held only in memory, key material dropped on close. For one-shot negotiations, queries, short-lived chatter.
  - *Persistent:* resumable across restarts. Each side snapshots a `SessionRecord` into a `SessionStore` (in-memory or file-backed; **no key material is ever persisted**). `resume` re-authenticates with identity keys, proves knowledge of the shared transcript head and mirrored sequence counters, and derives a *fresh* session key (post-compromise recovery). Conversation position — transcript chain and sequence numbers — carries over exactly. For standing relationships (a procurement agent and a supplier agent that talk weekly).
- **Transcript hash chain.** `h_n = SHA256(h_{n-1} || envelope_n_canonical)`. Both parties can produce a verifiable transcript; in persistent mode this is the durable, tamper-evident conversation record. The chain is O(1) memory — only the rolling head and length are kept, not the envelopes.
- **Ordered, reliable delivery.** Frames carry a strictly increasing per-direction sequence. A frame that arrives early is held in a bounded reorder buffer and delivered once the gap fills; a frame lost by the transport is recovered by receipt-driven retransmit — the receiver NACKs the missing sequence, the sender replays it from a bounded send buffer (cumulative acks prune the buffer). Redelivered already-seen frames are idempotent no-ops, so at-least-once transports are safe. Beyond the buffer window, unrecoverable loss surfaces as a session error and is resolved by a resume.
- **Capabilities.** The accepted handshake fixes what the session may carry: payload content types and the *authority ceiling* (intersection of both parties' delegation scopes). The session layer rejects out-of-scope payloads at the boundary — a session negotiated for `converse` cannot suddenly carry a `commit:purchase`.
- **Group sessions (multi-agent).** A group is a roster of members connected as a **full mesh of pairwise sessions** — every group message inherits pairwise E2E encryption (double ratchet), signatures, sequencing, and policy checks, with zero new group cryptography. Membership protocol: the founder opens sessions to each member and sends a **founder-signed roster** (`GroupInfo` with an epoch and members) as the invite (`amp/group-invite`); each member verifies the founder's signature and can compare `roster_digest` with peers to detect a founder handing different members divergent rosters. Members complete the mesh deterministically (each pair connects exactly once, ordered by address); `amp/group` wraps broadcast payloads; `amp/group-leave` announces departure. Non-roster senders are dropped. N-fold encryption is irrelevant at agent scale (units to tens of members); a Signal-style sender-key / MLS backend is the compatible upgrade path for large groups (roadmap).

### 3.4 Policy layer

Each node publishes and enforces a `ContactPolicy`:

- `mode`: `open` | `credentialed` | `allowlist` | `closed`
- `require_scopes`: delegation scopes the initiator must prove
- `require_operators`: acceptable operator keys (e.g. "only Fareground-operated agents")
- `rate_limit`: max initiations per peer / global per window
- `human_approval`: route the initiation to a human decision callback
- `max_sessions`, `accept_modes`, `accepted_payload_types`

The policy engine returns `accept | reject(reason) | defer(human)`. Rejections are signed envelopes too — refusal is attributable and rate-limit-friendly. Policy is *code-enforced at the node boundary*, never a prompt instruction.

### 3.5 Transport layer

`Transport` is a small interface: `deliver(envelope)` + inbound handler registration. Shipped:

- **InMemoryTransport** — same-process agent meshes (tests, simulations, local crews), with store-and-forward queuing for not-yet-bound addresses.
- **HttpTransport** — client (`aiohttp`) + server (FastAPI router mounting `POST /amp/v0/inbox`); AgentCard served at `.well-known/amp/agent-card.json`. For agents that are directly reachable.
- **Relay** — the hosting answer for everyone else. **Sessions live at the endpoints**: a session exists only inside the nodes holding its keys; nothing conversation-shaped is ever hosted centrally. A relay (`create_relay_app()`, or the `amp-relay` CLI) hosts exactly three zero-knowledge services: (1) *mailboxes* of signed envelopes with E2E-ciphertext bodies for offline/scale-to-zero recipients, (2) a *card directory* of signed AgentCards for discovery, (3) *authenticated pulls* — draining a mailbox requires a fresh Ed25519 signature from the mailbox address's key. `RelayTransport.connect(node)` registers the card and long-polls the mailbox. Anyone can run a relay (self-hosting changes nothing about security) because relays are untrusted by construction: they see routing metadata only, and tampering/dropping is detectable via envelope signatures and sequence gaps.

### 3.6 Payloads (application layer)

Decrypted session message bodies are typed:

```json
{ "content_type": "text/plain | application/json | amp/a2a-task | amp/mcp | amp/x402", "content": ... , "metadata": {...} }
```

AMP standardizes the envelope, not the ontology: `text/plain` for NL, `application/json` for negotiated schemas, and passthrough types for embedding A2A tasks, MCP interactions, and x402 payment exchanges inside a session.

---

## 4. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Impersonation | Self-certifying IDs; every envelope signed; card signatures |
| Compromised agent key | Identity-key revocation (self- or owner-signed with proof); a revoked key is refused all sessions regardless of policy; distributed via the relay |
| Unauthorized authority ("agent claims it can spend") | Verifiable delegation chains; session authority ceiling; scope-checked payloads |
| Eavesdropping (incl. relays/transports) | E2E encryption from the first envelope; relays see metadata only |
| Replay / reorder / tamper | Per-session sequence numbers + transcript hash chain + AEAD |
| Key compromise | Double ratchet: per-message forward secrecy (symmetric chain) + per-turn post-compromise security (DH ratchet); resume rotates the whole root |
| Spam / initiation flooding | Contact policy: credential gates, rate limits, allowlists, human approval; (roadmap) x402 pay-to-knock |
| Cross-agent prompt injection | Not solvable at the protocol layer. Contained by: signed provenance on every message, session authority ceilings, policy-gated contact. Application guidance in docs. |
| Malicious relay | Untrusted by design — cannot read, forge, or undetectably drop/reorder (gaps visible via seq) |

Out of scope for the protocol: content-level trust, agent alignment, endpoint (host) compromise.

---

## 5. Reference implementation

**Package:** `fg-amp` (import `fg_amp`). Python ≥3.11; Apache-2.0 (see `LICENSE`). Conventions: hatchling, `src/` layout, Pydantic v2 models, ruff, pytest(-asyncio).

**Dependencies:** `pydantic>=2`, `cryptography>=42`. Extras: `http` → `fastapi` + `aiohttp` + `uvicorn`; `dev` → pytest, ruff, etc. The core (identity/envelope/session/policy + in-memory transport) has **no web dependencies**.

```
src/fg_amp/
├── identity/    keys.py (Ed25519/X25519 wrappers), delegation.py, card.py, address.py
├── envelope/    canonical.py (canonical JSON), envelope.py, crypto.py (seal/open, session AEAD)
├── session/     states.py, handshake.py, session.py, transcript.py
├── policy/      policy.py (ContactPolicy + engine)
├── transport/   base.py, memory.py, http.py (extra), relay.py
├── node/        node.py (AmpNode), inbox.py
└── errors.py, version.py
```

**Public API sketch:**

```python
from fg_amp import AmpNode, ContactPolicy, AgentIdentity

alice = AmpNode(identity=AgentIdentity.generate("alice"), policy=ContactPolicy.open())
bob   = AmpNode(identity=AgentIdentity.generate("bob"),
                policy=ContactPolicy(mode="credentialed", require_scopes={"converse"}))

transport.connect(alice, bob)                      # any Transport

session = await alice.initiate(bob.card, purpose="price negotiation", mode="ephemeral")
await session.send_text("Offering 100 units at $4.20 — interested?")
reply = await bob_session.receive()
await session.close()
```

---

## 6. Roadmap

- **v0.1 — shipped:** identity + delegation, signed/encrypted envelopes, pairwise ephemeral & persistent sessions, policy engine, in-memory + HTTP transports, transcript chain.
- **v0.2 — shipped:** owner identity as first-class (`OwnerIdentity`, mutual chain verification, `peer_owner`/`peer_scopes`/`require_scope`), `session.resume` with key rotation + `SessionStore` (memory/file), multi-agent group sessions over the pairwise mesh, hosted relay (mailboxes + card directory + authenticated pulls, `amp-relay` CLI).
- **v0.3 — shipped:** independent three-lens audit and remediation — trusted-issuer-anchored credentials, verified-not-trusted operator fields, revocation/expiry re-verified on resume, roster-bound group fan-out, per-message symmetric key ratchet, delegation revocation + registry, single-use relay pulls + per-sender quotas + envelope size cap, SQLite relay persistence, graceful `AmpNode.aclose()`, protocol version check, structured logging, richer error taxonomy, `HttpTransport` exported/tested, `py.typed`, NFC-canonical JSON, golden wire vectors.
- **v0.4 — shipped:** second scored audit + reliability round — receipt-driven retransmit (ARQ) + bounded reorder buffer + idempotent inbound, per-session recv lock, handshake/resume freshness window + seen-id cache, dual-ephemeral KDF salt, integer-millisecond TTL + float-free canonical JSON.
- **v0.5 — shipped:** reliable delivery (retransmit-on-timeout + cumulative ACK + bounded reorder buffer, tail-loss recovery, lost-ACK self-heal, idempotent inbound), telemetry (`SessionStats` + `node.metrics()`), session reaping.
- **v0.6 — shipped:** **DH double ratchet** — per-turn post-compromise security layered on the per-message symmetric ratchet, with an AMP variant that preserves either-party-first sending; verified by a joint ratchet-under-loss/reorder property fuzzer.
- **v0.7 — shipped:** **agent identity-key revocation** — self- or owner-revoke a compromised agent's whole key (blocks all sessions regardless of policy), distributed via the relay; low-order-point guard on the ratchet.
- **v0.8 — shipped:** signed/versioned group roster (founder-signed `GroupInfo` with epoch + `roster_digest` for equivocation detection); durable revocation registry (`snapshot`/`restore`).
- **v0.9+ — shipped:** WebSocket relay transport; typed message bodies with x402 payment and MCP profiles; negotiated witnessed session posture; federation-lite (multi-relay failover); SSRF-guarded wake pings + poison-message dead-lettering; normative `spec/SPEC.md` with golden vectors.
- **next:** MLS / sender-key backend for large groups; metadata-privacy (sealed-sender-style routing so a relay no longer sees the social graph); A2A bridge (AMP as an A2A extension); multi-device (one identity, several device keys); TypeScript implementation.
- **v1.0:** wire-format freeze, conformance test suite, second-language implementation (TypeScript).

## 7. Example integrations

- **Competitions / matches:** participants get AmpNodes; in-match chatter/negotiation over ephemeral sessions; the transcript hash chain becomes the auditable match record.
- **Simulations:** simulated org/market agents converse over the in-memory transport; a simulation timeline can index session transcripts as events.
- **Agent builders:** deployed agents get an AMP address + policy as a deploy artifact — "my agent is reachable" out of the box.
- **Agent frameworks:** an `AmpChannel`-style adapter can expose sessions as a framework's message source/sink (that adapter lives in the framework, not here — this package stays framework-agnostic).
