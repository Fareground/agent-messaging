# AMP Wire Specification

**Version:** `amp/0.1` · **Status:** draft for the v1.0 freeze · **Companion:** `spec/vectors.json` (golden conformance vectors), `reference/js/` (independent implementation)

This document specifies the AMP wire format precisely enough for an independent
implementation to interoperate byte-for-byte with the Python reference. Every
`MUST`/`SHOULD`/`MAY` is [RFC 2119]. Where this document and the code disagree,
the golden vectors in `spec/vectors.json` are authoritative for the byte-level
constructions they cover.

## 1. Cryptographic primitives

| Purpose | Algorithm |
|---|---|
| Signatures | Ed25519 (deterministic) |
| Key agreement | X25519 |
| Post-quantum KEM (optional, negotiated) | ML-KEM-768 (FIPS 203) |
| AEAD | ChaCha20-Poly1305 (IETF, 96-bit nonce, 128-bit tag) |
| KDF | HKDF-SHA256 |
| Hash | SHA-256 |

All raw public keys are 32 bytes (Ed25519, X25519). ML-KEM-768: encapsulation
key 1184 B, ciphertext 1088 B, shared secret 32 B.

## 2. Identity and addresses

An address is self-certifying: `amp:key:<base58(ed25519_public_key)>`. The
address **is** the signing public key, so any signed artifact verifies from the
address alone with no registry.

Base58 uses the Bitcoin alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
big-endian, with leading `0x00` bytes encoded as leading `1`s. See
`vectors.base58` and `vectors.ed25519.address`.

### 2.1 `did:amp` method

The same key MAY be expressed as a W3C DID: `did:amp:<base58(ed25519_public_key)>`.
Like `did:key`, the method is registry-free and self-certifying — the DID **is**
the key, and its Ed25519 verification method resolves deterministically from the
identifier alone. `amp:key:<b58>` and `did:amp:<b58>` share the same `<b58>` and
map 1:1; a `did:amp` MAY carry a path/query/fragment, and the method-specific id
is the first segment. A signed `AgentCard` enriches resolution with the X25519
`keyAgreement` key and transport `service` endpoints. Public keys in the DID
Document are `publicKeyMultibase` (multibase base58btc `z` of a multicodec-
prefixed key: `0xed01` ed25519-pub, `0xec01` x25519-pub), so off-the-shelf DID
resolvers understand them.

## 3. Canonical JSON

Every signed or KDF-salt payload is serialized to **canonical JSON** before
hashing/signing:

1. Object keys sorted by Unicode code point, ascending.
2. No insignificant whitespace (`,` and `:` separators only).
3. UTF-8 output, strings NFC-normalized.
4. No `NaN`/`Infinity`.
5. **No floating-point numbers** — floats format differently across languages and
   would break cross-implementation agreement. Use integers (e.g. milliseconds)
   or strings. Booleans are permitted.

See `vectors.canonical_json`.

### 3.1 Domain-separated signing input

Signatures MUST NOT be computed over bare canonical JSON. Every AMP signature
is computed over:

```
signing_input(context, payload) =
    uint16be(len(tag)) || tag || canonical_json(payload)

tag = UTF-8("fg-amp/v1/" || context)
```

`context` is one of `envelope` (§4), `group-roster` (§12), `relay-pull` (§13),
`relay-ack` (§13), `relay-ws` (§13.4). Identity artifacts (agent cards, delegations, revocations,
key rotations) are signed under the **agent-id** domain
(`fg-agent-id/v1/…`) and MUST NOT be re-signed under AMP's.

A verifier MUST verify under the context of the artifact it expects, and MUST
NOT accept a signature that verifies only under a different context. New signed
artifact types MUST take a new context string.

Rationale: without domain separation, a signature harvested from one artifact
type can be presented as another whenever their payloads canonicalize
identically. See `vectors.agent_card.signing_input_hex` and
`vectors.group_roster.signing_input_hex`.

## 4. Envelope

Every wire message is one JSON object:

```json
{
  "amp": "0.1", "id": "<uuid>", "type": "<type>",
  "from": "amp:key:...", "to": "amp:key:...",
  "session_id": "<uuid|null>", "seq": 0, "created_at": "<RFC3339>",
  "body": "<base64>", "sig": "<base64 ed25519>"
}
```

Types: `handshake.initiate`, `handshake.accept`, `handshake.reject`,
`session.message`, `session.close`, `session.resume`, `resume.accept`,
`resume.reject`, `receipt`, `witness.copy` (§7.1).

**Signing.** `sig` = Ed25519 over `canonical_json(envelope without "sig", with
the internal field `sender` emitted as `from`)`. Receivers MUST verify before any
other processing.

**Forward compatibility (extensibility).** Implementations MUST preserve unknown
top-level fields and include them in the canonical signing payload. This is what
lets the format add fields without breaking signatures across versions: a newer
signer includes the new field; an older verifier preserves and re-canonicalizes
it, so the signature still checks. Implementations MUST NOT strip unknown fields
before verifying. The same rule applies to `AgentCard` and handshake payloads.

**Versioning.** `amp` carries `MAJOR.MINOR`. A receiver MUST reject a differing
MAJOR. Within a MAJOR, features are negotiated via capabilities (§7), not implied
by MINOR.

## 5. Seal / open (pre-session confidentiality)

`handshake.initiate` / `*.accept` / `session.resume` bodies are **sealed** to the
recipient: `seal = ephemeral_pub(32) || nonce(12) || ChaCha20Poly1305(K, plaintext, aad=ephemeral_pub)`
where `K = HKDF-SHA256(ikm=X25519(ephemeral_priv, recipient_pub), salt=ephemeral_pub, info="amp/0.1/seal")`.

The recipient key is the card's `agreement_prekey` when present (a rotatable
short-lived key giving forward secrecy for the first knock), else the static
`agreement_key`. Recipients try current+previous prekeys, then the static key.

## 6. Session key derivation

`session_key = HKDF-SHA256(ikm = X25519(own_eph, peer_eph) || pq_shared, salt =
transcript_salt, info = "amp/0.1/session")`, 32 bytes. `pq_shared` is empty when
PQ is not negotiated (so classical and hybrid derivations are byte-identical
absent PQ). `transcript_salt` binds both handshake ephemerals plus the full
initiate (see §7). See `vectors.session_key` (classical and hybrid).

## 7. Handshake

`handshake.initiate` body (sealed) fields: `session_id`, `card`,
`delegation_chain`, `mode` (`ephemeral|persistent`), `purpose`, `payload_types`,
`ttl_ms` (integer), `ephemeral_key` (base64 X25519 pub), `capabilities`
(string[]), `pq_kem_key` (base64 ML-KEM-768 encapsulation key or null).

`transcript_salt = SHA-256(canonical_json(initiate_body))`. The responder's
session salt = `SHA-256(transcript_salt || responder_ephemeral_pub)`, binding
both ephemerals (UKS resistance).

`handshake.accept` body (sealed) fields: `session_id`, `card`,
`delegation_chain`, `accepted_payload_types`, `ttl_ms`, `ephemeral_key`,
`capabilities` (the negotiated intersection), `pq_ciphertext` (base64 ML-KEM
ciphertext or null).

**Capability negotiation.** Each token is an opaque versioned string. The agreed
set is the sorted set-intersection of both offers. Unknown tokens are simply
absent from the intersection, so old/new peers fall back to shared features.
`amp.ratchet.dh-v1` is the baseline; `amp.kem.ml-kem-768-x25519` enables the PQ
hybrid. Because `capabilities` and `pq_kem_key` ride inside the signed, sealed
handshake, an on-path attacker cannot strip a capability (downgrade) without
breaking the envelope signature.

**PQ hybrid.** If `amp.kem.ml-kem-768-x25519` is negotiated and the initiate
carries `pq_kem_key`, the responder encapsulates to it, returns `pq_ciphertext`,
and both mix the 32-byte KEM secret into the session key (§6). The key is secure
if **either** X25519 or ML-KEM holds.

### 7.1 Witnessed session posture

The default posture is **sealed**: only the two parties can read session
traffic, and nothing in this section changes sealed behavior in any way. Some
deployments need an audit trail without giving the relay plaintext. The
negotiated capability `amp.posture.witnessed-v1` provides it: both parties
agree on a single **witness** — an agent address plus its X25519 public key —
and every sender additionally seals each plaintext body to that witness.

**Negotiation.** The capability follows §7: it activates only when it appears
in the negotiated intersection. When either side offers it, its initiate or
accept body carries a `witness` object: `{"address": "amp:key:...",
"agreement_key": "<base58 x25519 public>"}`. The field is OMITTED (not null)
when unused, preserving byte-compatibility of the initiate digest with
pre-witness peers. When the capability is negotiated:

- both frames MUST carry a `witness` block, and both MUST name the identical
  witness (same address AND same key). A missing or divergent block is a
  handshake reject — never a silent fallback to sealed.
- the witnessed agreement is part of the signed, sealed handshake transcript:
  the initiate's `witness` feeds the transcript salt (and therefore the
  session key itself), and the accept's rides the signed sealed accept, which
  the initiator MUST verify names its proposed witness. Neither side, nor any
  on-path party, can enable, disable, or swap the witness without breaking
  the handshake.

**Witness copies.** In a witnessed session, for every `session.message` a
sender sends, it MUST also emit a `witness.copy` envelope addressed to the
witness, after the message itself: `body` = seal (§5, to the witness's
`agreement_key`) of `{"session_id", "seq", "sender", "payload"}` where
`payload` is the message's full plaintext payload object and
`session_id`/`seq`/`sender` equal the carrying envelope's own fields. The
envelope is signed as usual and routed like any mail (via the relay to the
witness's mailbox); the relay and everyone except the witness see only
ciphertext. The witness MUST reject a copy whose sealed inner fields disagree
with its signed outer envelope — that binding is what stops anyone without
the sender's key from detaching a copy from its frame or splicing it into a
different session or seq.

A party that cannot produce the witness copy (e.g. a bad witness key) MUST
refuse to send the message at all: the copy is constructed before the message
is committed or delivered, so no witnessed message ever exists without its
copy having been producible.

**Persistence.** Witnessed posture survives resume (§11): the agreement was
bound into the original handshake, and dropping it across a close/resume
cycle would let a party silently exit the audit trail.

**What is enforced, honestly.** Cryptographically bound: (a) witnessed
status itself — it rides the signed, sealed handshake and the session key;
(b) a copy's binding to `(session_id, seq, sender)` and its confidentiality
to the witness. Best-effort / detectable-not-provable: the guarantee that a
copy exists for every message, and that a copy's plaintext equals what the
peer actually received. A malicious sender can withhold copies or seal
divergent content — no receiver can observe the witness's mailbox, and the
witness cannot decrypt the session itself. What the honest parties get is
**provable detection, not prevention**: per-sender `seq` is strictly
contiguous, so the witness can name exactly which seqs it is missing; the
receiver holds the signed handshake proving witnessed mode was agreed; and a
receiver-disclosed transcript exposes any divergence between copies and the
real conversation. Receivers MUST treat a witness-reported missing or
divergent copy as a protocol violation of the peer, with the signed
handshake as the evidence that the obligation existed. Implementations MUST
NOT claim stronger (e.g. relay-enforced) witnessing than this.

## 8. Double ratchet and session messages

`session.message` body = `dh_pub(32) || nonce(12) || ciphertext || tag(16)`,
base64-encoded. The 32-byte header is the sender's current ratchet X25519 public
key, in the clear but bound: `aad = utf8("<session_id>:<seq>") || dh_pub`.

- **Symmetric ratchet:** each message advances a chain key → fresh message key
  (per-message forward secrecy).
- **DH ratchet:** the DH public advances only on a *receive*-triggered step,
  never on send. This is what makes AMP's either-party-may-send-first variant
  safe (concurrent sends never diverge the root). A degenerate/all-zero X25519
  output MUST be rejected.
- `seq` is per-sender-per-session, strictly increasing from 1.

The ratchet KDFs are HKDF-SHA256 with an empty salt unless noted:

- **Chain step:** `message_key = HKDF(chain, info="amp/0.1/ratchet/message")`,
  `next_chain = HKDF(chain, info="amp/0.1/ratchet/advance")`.
- **Root step:** `HKDF(dh_out, salt=root, info="amp/0.1/ratchet/root", len=64)`;
  first 32 bytes = new root, last 32 = new chain.
- **Direction seed:** `HKDF(session_key, info="amp/0.1/ratchet/seed/" || label)`
  where `label ∈ {"r2i"}`.

See `vectors.ratchet` for a multi-frame chain, a root step, the r2i seed, and the
close key — a second implementation must reproduce these byte-for-byte.

`session.close` body = `ChaCha20Poly1305(close_key, {"reason":...}, aad="close")`
where `close_key = HKDF(session_key, salt=direction, info="amp/0.1/close")`,
independent of ratchet position.

## 9. Transcript hash chain

`h_0 = 0x00*32`; `h_n = SHA-256(h_{n-1} || canonical_json(envelope_n))`. Only the
rolling head + length are kept (O(1) memory). See `vectors.transcript_chain`.

## 10. Reliable delivery (ARQ) and flow control

`receipt` body (JSON): `{"rseq", "ack", "missing":[...], "window"}`. `rseq` is a
strictly increasing receipt counter (drops replays). `ack` is the cumulative
in-order sequence delivered. `missing` lists gap seqs (NACK). `window` is the
receiver's remaining inbox capacity (`null` = unbounded); a sender MUST stall new
sends when a peer's advertised window reaches 0 and resume when it reopens. A
frame beyond the reorder window that cannot be recovered escalates to
`close → resume`; no acknowledged frame is ever dropped.

## 11. Resume

`session.resume` body (sealed): `session_id`, `card`, `delegation_chain`,
`transcript_head`, `send_seq`, `recv_seq`, `ephemeral_key`, `nonce` (base64, 16
random bytes, fresh per attempt), `pq_kem_key`. `resume.accept` echoes `nonce`
and carries `pq_ciphertext`. The resumed key = §6 with salt =
`SHA-256(transcript_head || nonce)`. The initiator MUST reject an accept whose
`nonce` differs from its pending request (replay defense; session ids are stable
across resumes). Resume re-verifies the delegation chain against current
revocations (never restores stored scopes).

## 12. Groups

A group is a full mesh of pairwise sessions (no group-wide key). `GroupInfo`
(founder-signed): `group_id`, `purpose`, `founder`, `epoch`, `members`
(AgentCard[]), `signature` over `canonical_json({group_id, purpose, founder,
epoch, members: sorted(addresses)})`.

- `amp/group-invite`: founder → member, carries the `GroupInfo`.
- `amp/group`: a wrapped group message.
- `amp/group-leave`: voluntary departure.
- `amp/group-roster`: founder reissues the roster at `epoch+1` on add/remove.
  Members verify signature + `epoch` strictly increasing, connect to added
  members (deterministic pairing: initiate toward greater addresses), and **close
  pairwise sessions to removed members** — exclusion / forward secrecy across the
  change (a pairwise mesh has no shared key to rotate).
- `amp/group-roster-ack`: `{group_id, epoch, roster_digest}`. Members echo their
  digest; a peer reporting a different digest at the same epoch surfaces an
  equivocation event (detects a founder handing divergent rosters).

Non-roster senders are dropped.

## 13. Relay services

A relay is untrusted and zero-knowledge of content. Endpoints (`/amp/v0/relay`):
`send` (enqueue a signed, E2E-ciphertext envelope; 1 MiB raw-body cap enforced
before parsing; per-mailbox and per-sender quotas), `pull` (single-use signed,
freshness-windowed mailbox drain), `cards` (signed AgentCard directory, bounded
with LRU eviction), `revocations` / `key-revocations` (bounded; delta sync via a
monotonic `?since=<cursor>`). Relays see routing metadata only; tampering or
drops are detectable via envelope signatures and sequence gaps.

Signed `pull` and `ack` payloads MUST include an `audience` naming the relay
they are addressed to, and a relay MUST reject a request whose audience is not
its own. Without it, a signed pull captured at one relay drains the same
mailbox at any other relay the victim uses.

The audience MUST be unique per relay. A shared or default value gives every
relay using it the same identity, which makes the binding inert — the
implementation warns when started without an explicit audience.

### 13.1 Wake notifications

Delivery is pull-based, so a participant only receives mail while it is
connected. A participant MAY advertise a `wake` endpoint in its signed card
(§ agent-id spec §4). When a relay accepts an envelope for an address with no
active puller, it MAY POST a notification to that URL.

A wake notification MUST be content-free: no sender, no envelope id, no
message count, no timing detail beyond the fact of the request itself. It means
only "there is mail, connect and pull". A relay MUST NOT include anything it
learned from the envelope.

Note that the notification's occurrence and timing are themselves observable:
anyone on the relay-to-agent path, and the operator of whatever terminates the
wake URL, learns that mail arrived for that participant at that moment. The
content is protected; the fact of it is not.

Relays sending wake notifications:

- MUST refuse any target that is not publicly routable — loopback, private,
  link-local, multicast, reserved, and carrier-grade NAT space — unless
  explicitly configured otherwise. Wake URLs come from participant-published
  cards and are therefore attacker-controlled; an unguarded relay is an SSRF
  proxy into its own network.
- MUST NOT follow redirects. Validating only the first URL is defeated by a
  302 into internal space.
- MUST apply the address check to the address it actually connects to.
  Validating a hostname and then letting the HTTP client resolve it again is a
  race that an attacker controlling a low-TTL DNS record wins reliably.
- MUST rate-limit per wake **host**, not per recipient address. Addresses are
  free to mint, so per-address limiting lets one party aim many addresses at a
  single victim URL and bypass the limit entirely.
- SHOULD drop notifications rather than queue them once a concurrency limit is
  reached, and MUST bound any per-target state it retains.
- MUST treat delivery as best-effort with a short timeout and no retries. A
  wake is a latency optimization; the authenticated pull remains the only
  delivery mechanism, so a lost notification MUST NOT lose or reorder mail.

Because the URL is a bearer capability, it SHOULD be unguessable, and a
participant SHOULD rotate it (by republishing its card) if it leaks.

### 13.2 Deferred initiation

A handshake to an offline peer is delivered to its mailbox and answered
whenever the peer next connects — which may be far longer than any reasonable
blocking timeout. An implementation SHOULD therefore offer a non-blocking
initiation that returns a handle once the handshake is delivered, and MUST keep
the initiator's pending handshake state alive until it is either answered,
explicitly abandoned, or expires.

Pending handshakes MUST expire and SHOULD be bounded in number: they outlive
the call that created them, so a node contacting many sleeping peers would
otherwise accumulate handshake state without limit.

### 13.3 Federation-lite: multiple relays, synced directories

**Multiple relay endpoints.** A card MAY advertise more than one relay:
`endpoints["relay"]` is the primary and `endpoints["relay.1"]`,
`endpoints["relay.2"]`, … are ordered failover targets (numeric order; other
`relay.*` suffixes are ignored). The card is signed, so the list and its
order are the participant's authenticated statement of where it is
reachable. A sender tries relays in order and stops at the first that gives
a definitive answer — success, or a real rejection (4xx); only
unreachability and server failure (5xx) move it to the next. Retrying after
an ambiguous failure MAY duplicate delivery; the per-sender `seq` dedup (§8,
§10) absorbs this, and no exactly-once guarantee is claimed beyond it. A
recipient SHOULD register its card on every relay it advertises. Because a
puller also drains its relays in failover order, mail accepted at a
lower-priority relay during a partition is collected only when the puller
itself fails over (or polls that relay); cross-relay delivery latency under
split-brain is therefore bounded by the client's failover behavior, not by
the relays.

**Directory sync.** A relay MAY be configured with peer relays whose card
directory and revocation lists it periodically pulls through the same public
delta endpoints every client uses: `GET cards?since=<cursor>`,
`revocations?since=`, `key-revocations?since=` (each returns rows plus a new
monotonic cursor; a re-registered card reappears after the cursor). Every
record MUST be verified before it is admitted — the same signature
verification the local write endpoints apply — and a record that fails MUST
be skipped without stalling the sync (cursors still advance; hostile peers
can inject garbage, not wedge convergence). Federation is eventual,
best-effort convergence of *public, self-certifying* facts only.

**Mailboxes do not federate.** An envelope enqueued at relay A exists only
at relay A; a relay MUST NOT forward mailbox contents to another relay. A
participant reachable on relay A must be messaged via relay A — its card
says which relays those are. Relay-to-relay forwarding would create delivery
paths the recipient never consented to and break the lease/ack model.

### 13.4 WebSocket transport

A relay MAY expose `/amp/v0/relay/ws`: one WebSocket per participant over
which the relay pushes mailbox deliveries in real time and accepts sends,
replacing polling. The security model is the pull credential's, adapted from
single-use-per-request to a bounded socket session:

- **Auth.** The client's first frame is `{"type": "auth", "address", "ts",
  "sig"}` where `sig` signs (context `relay-ws`, §3.1) `{"action":
  "connect", "address", "audience", "ts"}`. The relay enforces the same
  audience binding and freshness window as pulls, and the credential is
  single-use — a captured auth frame cannot open a second socket. On success
  the relay answers `{"type": "ready"}` and the socket is authenticated as
  `address` for a bounded period (reference: 300 s).
- **Re-auth.** When the period lapses the relay sends `{"type":
  "auth_required"}`; the client MUST answer with a fresh auth frame for the
  SAME address (a socket never changes hands) within a short grace window or
  the relay closes the socket. This is the periodic-freshness choice: one
  signature per period, not per message.
- **Delivery.** The relay pushes `{"type": "deliver", "envelopes": [...]}`
  as mail arrives, using the same lease semantics as pull (§13): the client
  acks handled envelopes with `{"type": "ack", "ids": [...]}` and anything
  unacked is reclaimed and redelivered — at-least-once holds unchanged. Acks
  need no signature of their own: they ride the authenticated,
  non-expired socket (HTTP acks are signed only because HTTP is stateless).
- **Send.** `{"type": "send", "envelope": {...}}` submits an envelope,
  verified exactly as the HTTP `send` endpoint verifies it (signature,
  canonicality, size cap, quotas, rate limit keyed on the verified sender —
  the socket's identity grants senders nothing). The relay answers
  `{"type": "sent", "id", "accepted", "error"?}`.

The socket is an optimization, never the source of truth: a client MUST fall
back to authenticated HTTP pulls when the socket is unavailable, so a
dropped connection costs latency, not mail.

## 14. Delegation and policy

A `Delegation` is a signed credential (issuer → subject, scopes, expiry). Chains
compose as the **intersection** of scopes. A recipient's `ContactPolicy` gates
initiation (`open|credentialed|allowlist|closed`, required scopes/operators, rate
limits, human approval). Required scopes are only meaningful relative to
`trusted_issuers`; an implementation MUST NOT treat a peer-self-signed scope as
authoritative.

## 15. Operational assumptions

Freshness windows, TTLs, and delegation expiry depend on **wall-clock** time;
peers SHOULD keep clocks synchronized (e.g. NTP) within the freshness window
(reference default 300 s). This is a deliberate, documented assumption.

## 16. Typed bodies

A session message's plaintext is a payload object
`{"content_type", "content", "metadata"}`. Two tiers of `content_type` exist:

- **Untyped tier** — free-form types (`text/plain`, `application/json`, and
  any other name without an integer version segment). Their `content` is
  opaque to the protocol; implementations MUST NOT validate it.
- **Typed tier** — registry names of the form `<name>/<version>` where
  `<name>` matches `[a-z0-9][a-z0-9_.-]*` and `<version>` is a positive
  decimal integer (e.g. `amp.task/1`). A typed name binds `content` to a
  versioned schema. An incompatible schema change MUST take a new version
  (`amp.task/2`), which is a distinct name for negotiation.

**Advertisement and negotiation.** Typed names ride the existing
`payload_types` handshake fields (§7): a node advertises the types it will
send in `payload_types` and the responder intersects them with its accepted
set into `accepted_payload_types`. The built-ins below SHOULD be included in a
conforming node's default offer. A sender MUST NOT emit a `content_type`
outside the negotiated set.

**Validation.** A sender MUST validate a typed body it recognizes against its
schema before encryption. A receiver MUST validate a recognized typed body
after decryption and before delivery; a schema violation or illegal task
transition is a protocol error — the receiver MUST reject the body and MUST
NOT deliver it (the reference implementation closes the session with the
rejection reason, since the peer validated-before-send and a bad body
therefore signals a fault or an attack). Unknown fields in a typed body MUST
be preserved (same forward-compatibility rule as §4).

**Criticality.** A body whose `metadata.critical` is `true` declares that
processing it is essential to the conversation. A receiver that does not
recognize the body's typed `content_type` MUST reject a critical body as a
protocol error, and MUST deliver an unknown *non-critical* typed body opaque
(unvalidated) to the application, which MAY ignore it.

### 16.1 `amp.task/1` — work lifecycle

Fields: `task_id` (string, sender-unique, non-empty), `kind`
(`request|accept|reject|progress|complete|fail|cancel`), `title` (string,
REQUIRED non-empty for `request`), `body` (string), `inputs` (object),
`outputs` (object), `deadline` (RFC 3339 string or null), `refs` (array of
`amp.ref/1` objects).

Each session tracks task state per `task_id`. The **requester** is the side
that sent the `request`; the other side is the **worker**. Legal transitions:

| State | Kind | Actor | Next state |
|---|---|---|---|
| *(none)* | `request` | either | `requested` |
| `requested` | `accept` | worker | `accepted` |
| `requested` | `reject` | worker | *(terminal)* |
| `requested` | `cancel` | requester | *(terminal)* |
| `accepted` | `progress` | worker | `accepted` |
| `accepted` | `complete` | worker | *(terminal)* |
| `accepted` | `fail` | worker | *(terminal)* |
| `accepted` | `cancel` | requester | *(terminal)* |

Any other `(state, kind, actor)` combination — including a duplicate
`request` for a live `task_id`, or any kind for an unknown/terminal task —
is illegal: a sender MUST NOT emit it and a receiver MUST treat it as a
protocol error (§16 Validation).

### 16.2 `amp.receipt/1` — application receipts

Fields: `status` (`accepted|completed|rejected`), exactly one of `task_id`
(references an `amp.task/1` by its id) or `message_id` (references any body
by its envelope `id`), and optional `reason` (string).

These are **application**-level acknowledgements — "I acted on that body" —
and are unrelated to the transport `receipt` envelope (§10), which
acknowledges frame *delivery* only. An implementation MUST NOT treat an
`amp.receipt/1` as a delivery ack, nor a §10 receipt as an application
outcome.

### 16.3 `amp.ref/1` — external artifact pointer

Fields: `uri` (string, non-empty), `kind`
(`artifact|proposal|ticket|commit|claim`), `version` (string, target-defined
revision identifier), `content_hash` (string; SHOULD be
`sha256:<lowercase hex>` when present, empty = unverifiable). A receiver
SHOULD verify `content_hash` against fetched content before trusting it.

### 16.4 `amp.claim/1` — knowledge claim

Fields: `claim_id` (string, non-empty), `statement` (string, non-empty),
`confidence` (number in [0, 1]), `pedigree` (object: `source` — the
originating AMP address, `evidence` — array of `amp.ref/1` objects,
`observed_at` — RFC 3339 string or null), `supersedes` (claim id or null).

`amp.claim/1` is a carriage format: the protocol validates shape only.
Belief, promotion, supersession, and decay are governance concerns of the
knowledge layer and are out of scope for AMP.

### 16.5 `amp.payment/1` — x402 payment carriage

AMP carries, x402 settles. Fields: `payment_id` (string, sender-unique,
non-empty; assigned by the quote and referenced by every later kind), `kind`
(`quote|authorization|settled|failed`), `amount` (non-negative decimal
**string**, never a float; REQUIRED on `quote`), `asset` (opaque lowercase
asset token; REQUIRED on `quote`), `pay_to` (settlement destination string;
REQUIRED on `quote`), `valid_until` (RFC 3339 quote expiry or null), `x402`
(object, opaque passthrough), `chain_ref` (string; on `authorization`, a
reference to the payer's delegation chain as presented at handshake), `tx_ref`
(string; settlement transaction reference on `settled`/`failed`), `reason`
(string; on `failed`).

The `x402` field carries the x402 structures **verbatim**: the payee's
payment-requirements object on `quote`, the payer's payment payload on
`authorization`, and any settlement detail on `settled`/`failed`.
Implementations MUST NOT validate or re-model the contents of `x402` — its
schema belongs to x402, and settlement (constructing, submitting, and
confirming the on-chain or off-chain transfer) is out of scope for AMP.

**Lifecycle.** The **payee** is the side that sent the `quote`; the other
side is the **payer**. Each session tracks payment state per `payment_id`:

| State | Kind | Actor | Next state |
|---|---|---|---|
| *(none)* | `quote` | either | `quoted` |
| `quoted` | `authorization` | payer | `authorized` |
| `authorized` | `settled` | payee | *(terminal)* |
| `authorized` | `failed` | payee | *(terminal)* |

An `authorization` MUST reference a known `payment_id` in state `quoted`
whose `valid_until` (when present) has not passed; `settled`/`failed` MUST
reference a known `payment_id` in state `authorized`. Any other
`(state, kind, actor)` combination is illegal: a sender MUST NOT emit it and
a receiver MUST treat it as a protocol error (§16 Validation).

**Spend-scope enforcement.** Monetary authority comes from spend scopes in
delegation chains (`pay:<asset>[:tx<=..][:total<=..]`, identity standard
§10). Before sending an `authorization`, the payer MUST verify that its own
delegation chain grants spend authority over the quoted `(asset, amount)`,
counting amounts it has already authorized in this session against any
`total<=` cap (a per-session spend ledger). A payment that fails this check
MUST NOT reach the wire. The payee holds the payer's chain from the
handshake and MAY (SHOULD, when it will act on the payment) run the same
verification against its own ledger of the payer's authorizations; a
violation is a protocol error (§16 Validation). A rejected authorization —
on either side — MUST NOT mutate payment or ledger state.

### 16.6 `amp.mcp/1` — MCP carriage

Carriage, not an MCP implementation. Fields: `payload` (object; one MCP
JSON-RPC message, verbatim), `mcp_session` (string; an opaque correlator
distinguishing concurrent MCP sessions within one AMP session — `""` is a
valid single-session value).

Validation covers only the outer frame: `payload` MUST be a JSON object with
`jsonrpc` equal to `"2.0"`. Everything inside — methods, ids, capability
negotiation, tool schemas, errors — belongs to MCP; implementations MUST NOT
validate it, and inner JSON-RPC faults (e.g. an unmatched response id) are
NOT AMP protocol errors.

**Capability advertisement** needs no new machinery: `amp.mcp/1` is a
payload type, so a node advertises MCP carriage by including it in its
`payload_types` offer, and the handshake intersection (§7, §16) tells both
sides whether the peer speaks it. What tools/resources the peer actually
serves is discovered inside the tunnel with MCP's own `initialize` /
`tools/list` exchange.

Request/response correlation is by JSON-RPC `id`, scoped per `mcp_session`
and per direction. Both sides MAY issue requests concurrently (MCP is
symmetric over an established transport); a message carrying `method` is a
request or notification, one carrying `result`/`error` a response.

See `vectors.typed_bodies` for a canonical example of each built-in.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
