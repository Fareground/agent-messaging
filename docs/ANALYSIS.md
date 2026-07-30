# AMP Security Analysis

A structured argument for AMP's security properties, with explicit attention to
the parts that are *non-standard* and therefore need justification rather than
appeal to a known result. This is an engineering analysis, not a machine-checked
proof; §8 states what a full formal treatment would add.

## 1. Threat model

- **Network / relay adversary (Dolev–Yao):** reads, drops, reorders, replays,
  and injects any wire message; runs relays. Cannot break the primitives (§ AMP
  SPEC 1) or forge Ed25519 signatures.
- **Harvest-now-decrypt-later:** records ciphertext today, obtains a quantum
  computer later.
- **Key-compromise:** may obtain a party's long-term or session keys at some
  point in time; we consider security *before* and *after* that point.
- **Out of scope:** endpoint/host compromise while live, content-level trust,
  agent alignment, traffic analysis of message timing/size.

## 2. Mutual authentication and identity binding

Addresses are self-certifying (`address = ed25519 public key`), so a signature
verifies from the address alone. The handshake carries delegation chains in both
directions; each side verifies the other's chain to a trusted issuer (§ SPEC 14),
so an established session authenticates: the peer key, its owner (chain root), and
its effective scopes. Authorization checks (`require_scope`) are evaluated against
this verified chain, never against message content.

**UKS (unknown-key-share) resistance.** The session-key salt commits to *both*
ephemeral public keys and the full canonical initiate:
`salt = SHA-256(SHA-256(canonical(initiate)) || responder_eph_pub)`. An attacker
cannot rebind a captured handshake to a different identity's session, because any
change to the initiate (including the initiator card/address) changes the salt and
thus the derived key, causing the first AEAD to fail.

## 3. Confidentiality and forward secrecy

- **Session traffic:** each message key comes from a symmetric chain-key ratchet
  (per-message forward secrecy) keyed by an ephemeral-ephemeral X25519 secret that
  never touches identity keys. Compromise of identity keys does not expose past
  session content.
- **The first knock:** the sealed `initiate` is, by necessity, a 0-RTT message —
  the responder has not yet contributed an ephemeral. AMP narrows the classic
  0-RTT gap with a **rotatable signed prekey**: initiators seal to the card's
  `agreement_prekey`, and rotating + dropping the old prekey private renders past
  knocks unrecoverable. This yields forward secrecy for the knock bounded by the
  rotation cadence (the Signal "signed prekey" guarantee), strictly better than
  sealing to a never-rotated static key. A one-time-prekey extension would close
  the residual window fully and is compatible future work.

## 4. Post-compromise security (PCS)

- **Within a session:** the DH ratchet mixes a fresh X25519 secret into the root
  on each direction turn. After an adversary who leaked the current keys misses one
  reply, it can no longer derive subsequent message keys — the session *heals*.
- **Across restarts:** `resume` derives an entirely fresh session key
  (ephemeral-ephemeral + fresh nonce), so a compromise before a resume does not
  carry forward.

**The either-party-first variant (the part needing justification).** Standard
double-ratchet presentations assume a strict initiator/responder send order. AMP
allows either party (or both concurrently) to send first. The safety argument:
the DH public key advances **only on a receive-triggered step, never on send**
(SPEC §8). Therefore two concurrent sends by both parties do not each advance the
root; they are both encrypted under the current sending chain, and each side's DH
step happens deterministically when it *receives* the peer's header. This removes
the race where simultaneous sends diverge the root. The reference implementation
uses a peek/commit decrypt (state mutates only after AEAD+validation succeeds), so
a failed/forged frame cannot desynchronize the ratchet, and an honest retransmit
of the same sequence still decrypts. This variant is what a formal model (§8)
should verify mechanically; the property claimed is *agreement*: both parties
derive identical message keys for identical (seq, direction) regardless of send
interleaving.

## 5. Post-quantum posture

When negotiated, an ML-KEM-768 shared secret is concatenated with the X25519
secret as HKDF IKM (SPEC §6). This is a hybrid: the session key is
pseudorandom to an adversary who breaks *at most one* of {X25519, ML-KEM}. It
defends harvest-now-decrypt-later against a future quantum adversary while
retaining classical security against ML-KEM analytic risk. The DH ratchet
remains classical in v0.x (a PQ ratchet à la Signal SPQR is future work); the
*initial* root — the highest-value harvest target — is hybrid.

## 6. Replay, reorder, downgrade

- **Establishing frames** (`initiate`, `resume`) are guarded by a freshness
  window + seen-id cache; `resume.accept` is bound to a fresh per-attempt nonce
  mixed into the key, defeating replay of a captured accept into a later resume.
- **Session frames** are replay/reorder-protected by the per-session sequence,
  the ratchet (a replayed frame yields no new key), and the transcript chain.
- **Downgrade** of capabilities (e.g. stripping PQ) is prevented because
  `capabilities`/`pq_kem_key` are inside the signed, sealed handshake; altering
  them breaks the envelope signature. A genuine downgrade only occurs when a peer
  truly lacks a capability, which is not an attack.

## 7. Groups

The pairwise-mesh design inherits every pairwise property per edge. Membership
integrity: rosters are founder-signed and epoch-versioned; equivocation (divergent
rosters at one epoch) is detected by automatic digest cross-checks between members.
Exclusion/forward-secrecy across removal is achieved by tearing down pairwise
sessions to the removed member (there is no shared group key to rotate). Limits:
this is O(N²) and suited to units–tens of members; an MLS/sender-key backend is the
compatible path for large groups. A malicious founder can still partition a group
by never delivering a roster update — detection (equivocation events), not
prevention, is what the protocol offers, and applications SHOULD surface it.

## 8. Non-repudiation / deniability (explicit trade-off)

Every envelope — including ordinary session messages — is Ed25519-signed by the
sender's identity key, and the transcript chain makes that a durable,
independently reproducible record. AMP therefore provides **strong attribution and
no cryptographic deniability**, a deliberate choice for auditable agent commerce
(the opposite of Signal's deniability goal). Integrators handling sensitive content
should treat every message as a signed, non-repudiable artifact.

## 9. What a full formal treatment would add

The above is a hand argument. Standard-grade assurance would add: a Tamarin or
ProVerif model of the handshake (secrecy + mutual authentication + UKS), and a
model of the either-party-first ratchet establishing key-agreement and PCS as
mechanized lemmas rather than prose. The conformance vectors (`spec/vectors.json`)
and the independent JS implementation (`reference/js/`) already pin the *wire*
behavior across implementations; the formal model would pin the *protocol* logic.
This is the main remaining gap between "carefully engineered" and "proven," and is
tracked as the top pre-1.0 assurance item.
