<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/wordmark-dark.svg" />
    <img src="assets/wordmark.svg" alt="Fareground" width="320" />
  </picture>
</p>

# agent-messaging

<p align="center">
  <em>Give your agent a phone: a verifiable address, an inbox, and end-to-end-encrypted conversations with any peer.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-3b82f6?style=flat-square" />
  <img alt="Status" src="https://img.shields.io/badge/spec-draft%20amp%2F0.1-f472b6?style=flat-square" />
</p>

---

## Overview

**AMP (Agent Messaging Protocol)** gives any participant — agent, human, or
service — the ability to *initiate* a consented, end-to-end-encrypted, stateful
conversation with any other participant across trust boundaries.

MCP gives agents tools. A2A gives agents a task API. Neither lets an agent
spontaneously contact a stranger agent and hold a private, stateful conversation:
A2A is client-server RPC (remote agents can't initiate; TLS-only), DIDComm has
the right envelope but no agent semantics, and Matrix/XMTP carry the wrong
identity models. AMP fills exactly that gap — and composes with the rest: inside
an AMP session you can carry natural language, structured JSON, A2A tasks, MCP
interactions, or x402 payments.

### Security model at a glance

- **Self-certifying addresses.** An address `amp:key:<base58>` *is* the
  participant's Ed25519 public key — anything it signs is verifiable with no
  registry or CA.
- **Agent keys vs owner keys.** Agents hold hot, rotatable keys; owners
  (humans/orgs) hold cold keys that never touch the wire and authorize agents via
  signed **delegation chains**. Every session knows the peer agent, its verified
  owner (`peer_owner`), and its verified scopes (`peer_scopes` / `require_scope()`).
- **Consent before conversation.** Every initiation is evaluated against the
  recipient's code-enforced `ContactPolicy` (open / credentialed / allowlist /
  closed, rate limits, human approval).
- **Encrypted from the first knock.** Handshakes are sealed to the recipient's
  X25519 key; sessions run a per-message double ratchet (forward secrecy +
  post-compromise security, PQ-hybrid root) over ChaCha20-Poly1305.
- **Untrusted relays.** Relays host only encrypted mailboxes and a signed-card
  directory; they are untrusted by construction, and anyone can run one.
- **Domain-separated signatures.** Every signature names the artifact type it
  covers, so a signature can never be replayed as a different kind of artifact.

> A valid sender signature proves *who* sent a message — never that its content
> is safe to act on. Applications MUST treat message content as untrusted,
> prompt-injectable input regardless of a verified sender.

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the full protocol design and
threat model, and [docs/ANALYSIS.md](docs/ANALYSIS.md) for the cryptographic
analysis.

## Install

```bash
pip install git+https://github.com/Fareground/agent-messaging.git            # core (no web dependencies)
pip install 'fg-amp[http] @ git+https://github.com/Fareground/agent-messaging.git'  # + HTTP transport (FastAPI/aiohttp)
```

> **Package naming:** the installable distribution is `fg-amp` and the import
> package is `fg_amp`. These are stable public identifiers that other projects
> depend on, so they are intentionally left unchanged by the `agent-messaging`
> rename — see [Distribution name](#distribution-name).

## Usage

### Two participants, one encrypted session

```python
import asyncio
from fg_amp import AgentIdentity, AmpNode, ContactPolicy, InMemoryTransport

async def main():
    inbound = []

    async def on_session(session):          # bob's callback for accepted sessions
        inbound.append(session)

    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    bob = AmpNode(
        identity=AgentIdentity.generate("bob"),
        policy=ContactPolicy.open(),
        on_session=on_session,
    )

    transport = InMemoryTransport()
    alice.attach(transport)
    bob.attach(transport)

    session = await alice.initiate(bob.card, purpose="price negotiation")
    await session.send_text("Offering 100 units at $4.20 — interested?")

    message = await inbound[0].receive(timeout=1)
    print(message.sender, "→", message.payload.content)

    await session.close()

asyncio.run(main())
```

### Owners, scopes, and groups

```python
from fg_amp import AmpNode, OwnerIdentity

acme = OwnerIdentity.generate("acme-corp")                     # cold root of trust
buyer = AmpNode(identity=acme.create_agent("buyer", {"converse", "negotiate"}))

# a peer can now verify who stands behind the agent, in code:
#   session.peer_owner == acme.address
#   session.require_scope("negotiate")

group = await buyer.create_group([seller.card, broker.card], purpose="deal room")
await group.send_text("proposal: 500 units at $3.90")          # E2E to every member
```

A group is a full mesh of pairwise sessions — broadcast messaging with the exact
same end-to-end guarantees, plus membership invite/leave events.

### Relays: offline delivery and discovery

Run a relay anywhere; it only ever sees ciphertext.

```bash
pip install 'fg-amp[http]' && amp-relay --port 8404
```

```python
from fg_amp import RelayTransport

relay = RelayTransport("https://relay.example")
await relay.connect(node)                        # registers card, polls mailbox
card = await relay.resolve_card("amp:key:…")     # discovery
```

### Reaching an agent that is asleep

Publish a `wake` endpoint in the card, run the relay with a waker, and knock
without blocking. When mail arrives with nobody long-polling, the relay sends a
content-free ping ("connect and pull" — no sender, no message id, no counts).

```python
from fg_amp import WakeNotifier, WakePolicy, create_relay_app

# Relay side: WakePolicy refuses private/loopback/metadata targets — wake URLs
# come from agent-published cards, so an unguarded relay is an SSRF proxy.
app = create_relay_app(waker=WakeNotifier(policy=WakePolicy()))

# Caller side: don't block on a peer that may take hours to wake up.
pending = await node.initiate(peer_card, wait=False)
session = await pending.wait(timeout=None)       # resolves whenever they answer
```

The listener at the wake URL is runtime-specific (it might connect a node, resume
a poll loop, or spawn an agent process), so `WakeReceiver` is a small reference
that serves the endpoint and runs a callback on ping:

```python
from fg_amp import WakeReceiver, RelayTransport, AmpNode

async def on_wake():                     # a ping means "there may be mail"
    node = AmpNode(identity=me, on_session=handle)
    transport = RelayTransport(relay_url)
    await transport.connect(node)        # pull drains everything waiting

receiver = WakeReceiver(on_wake, path="/wake")
await receiver.start(host="0.0.0.0", port=8080)   # front with TLS in production
```

The poll loop stays the source of truth, so a dropped ping costs latency, never
correctness. End to end — mail for a sleeping agent → relay ping → receiver →
connect → the agent has its mail — is covered by `tests/test_wake.py`.

More runnable examples live in [`examples/`](examples): `negotiation.py`,
`group_chat.py`, and `networked_relay.py`.

## Protocol / Concepts

- **Any participant.** Endpoints carry a signed `kind` (`agent` / `human` /
  `service`); the protocol treats them identically and policies can gate by kind.
- **Sessions as the trust unit.** Ephemeral (keys dropped on close) or persistent
  and resumable — `SessionStore` records hold **no key material**; resume
  re-authenticates and rotates the key. Payload types are negotiated and enforced
  at the boundary, with a tamper-evident transcript hash chain both sides compare.
- **Typed bodies.** Messages carry a negotiated content type: plain text, JSON,
  or registry-backed bodies for A2A tasks, MCP interactions, and x402 payments.
- **Federation-lite.** Multi-relay failover; in-memory, HTTP, relay, and
  WebSocket transports.
- **Wire version `amp/0.1`.** The wire format is a contract; changes that affect
  bytes-on-the-wire bump the protocol version and update the golden vectors in
  `tests/test_wire_vectors.py`.

**Known limits, stated plainly:** identities are free to mint, so Sybil
resistance is rate-limiting only; envelope routing metadata (`from` / `to` /
`session_id`) is cleartext, so a relay sees the social graph; groups are a full
mesh with no cross-member message ordering; the envelope cap is 1 MiB with no
chunking (large payloads go out-of-band via `amp.ref/1`); and one identity means
one key, so multi-device requires sharing a key. The roadmap (MLS for large
groups, sealed-sender routing, A2A bridge, multi-device, TypeScript
implementation) is in the [blueprint](docs/BLUEPRINT.md).

## Project Structure

```
src/fg_amp/
├── identity/     # re-exports fg-agent-id: agent/owner keys, delegation, cards
├── envelope/     # signed wire envelope + canonical JSON
├── signing.py    # domain-separated signing input
├── crypto/       # PQ-hybrid KEM helpers
├── session/      # pairwise + group sessions, double ratchet, resume, witness
├── policy/       # code-enforced ContactPolicy
├── bodies/       # typed message bodies (task, mcp, payment, receipt, ref, claim)
├── node/         # AmpNode — attach transports, initiate, groups
└── transport/    # in-memory / HTTP / relay / WebSocket + hosted relay + wake
docs/             # BLUEPRINT (design + threat model), ANALYSIS (crypto)
examples/         # runnable end-to-end scripts
spec/             # protocol spec
tests/            # full suite incl. golden wire vectors
```

### Distribution name

The rename to **agent-messaging** is a repository/branding change. The published
distribution (`fg-amp`), the import package (`fg_amp`), the `amp-relay` console
script, and the wire identifier (`amp/0.1`) are **unchanged** — other projects
import and depend on them. Renaming those is a separate, breaking decision left
to the maintainers.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, tests, lint/format, and
commit conventions. Security issues: see [SECURITY.md](SECURITY.md) — please do
not open a public issue for a vulnerability.

---

<p align="center"><sub>Built by <a href="https://github.com/Fareground">Fareground</a>.</sub></p>

<p align="center"><sub>Licensed under <a href="LICENSE">Apache-2.0</a>.</sub></p>
