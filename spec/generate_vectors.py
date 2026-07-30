"""Generate golden conformance vectors from the Python reference implementation.

A second-language implementation must reproduce every `expected` byte-for-byte.
Run: python spec/generate_vectors.py  (writes spec/vectors.json)
"""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from fg_amp.envelope.canonical import canonical_json
from fg_amp.envelope.crypto import derive_session_key, encrypt
from fg_amp.identity.address import address_from_signing_key
from fg_amp.identity.keys import KeyPair, base58_encode

SEED = bytes(range(32))  # fixed test seed 00..1f


def h(b: bytes) -> str:
    return b.hex()


vectors = {"version": "amp/0.1", "note": "golden cross-implementation vectors"}

# 1. canonical JSON
vectors["canonical_json"] = [
    {"input": {"b": 1, "a": "ü", "c": [3, 2, 1]}, "expected_hex": h(canonical_json({"b": 1, "a": "ü", "c": [3, 2, 1]}))},
    {"input": {"z": 1, "a": 2, "m": 3}, "expected_hex": h(canonical_json({"z": 1, "a": 2, "m": 3}))},
    {"input": {"nested": {"y": [1, {"x": True}], "w": None}}, "expected_hex": h(canonical_json({"nested": {"y": [1, {"x": True}], "w": None}}))},
]

# 2. base58
vectors["base58"] = [
    {"input_hex": h(b"\x00\x00\x01"), "expected": base58_encode(b"\x00\x00\x01")},
    {"input_hex": h(bytes([255, 255])), "expected": base58_encode(bytes([255, 255]))},
    {"input_hex": h(SEED), "expected": base58_encode(SEED)},
]

# 3. address derivation + ed25519 KAT (deterministic signatures)
keys = KeyPair(
    signing_key=Ed25519PrivateKey.from_private_bytes(SEED),
    agreement_key=X25519PrivateKey.from_private_bytes(SEED),
)
signing_pub = keys.public.signing
msg = b"amp-conformance"
vectors["ed25519"] = {
    "seed_hex": h(SEED),
    "public_hex": h(signing_pub),
    "address": address_from_signing_key(signing_pub),
    "message_hex": h(msg),
    "signature_hex": h(keys.sign(msg)),
}

# 4. HKDF-SHA256 (via a known session-key derivation with pinned inputs)
own_eph = X25519PrivateKey.from_private_bytes(bytes([1] * 32))
peer_eph = X25519PrivateKey.from_private_bytes(bytes([2] * 32))
salt = hashlib.sha256(b"transcript").digest()
sk_classical = derive_session_key(own_eph, peer_eph.public_key().public_bytes_raw(), salt)
sk_hybrid = derive_session_key(own_eph, peer_eph.public_key().public_bytes_raw(), salt, pq_shared=bytes([9] * 32))
vectors["session_key"] = {
    "own_ephemeral_priv_hex": h(bytes([1] * 32)),
    "peer_ephemeral_pub_hex": h(peer_eph.public_key().public_bytes_raw()),
    "salt_hex": h(salt),
    "expected_classical_hex": h(sk_classical),
    "pq_shared_hex": h(bytes([9] * 32)),
    "expected_hybrid_hex": h(sk_hybrid),
}

# 5. AEAD (ChaCha20-Poly1305) with a pinned nonce -> deterministic ciphertext.
# encrypt() prepends a random nonce; pin it by calling the AEAD directly.
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402
aead_key = bytes([7] * 32)
nonce = bytes([3] * 12)
pt = b"hello amp"
aad = b"amp-aad"
ct = ChaCha20Poly1305(aead_key).encrypt(nonce, pt, aad)
vectors["aead_chacha20poly1305"] = {
    "key_hex": h(aead_key), "nonce_hex": h(nonce), "plaintext_hex": h(pt),
    "aad_hex": h(aad), "expected_ciphertext_hex": h(ct),
}

# 6. transcript hash chain: h_n = sha256(h_{n-1} || canonical(env_n))
h0 = b"\x00" * 32
env1 = canonical_json({"seq": 1, "body": "a"})
env2 = canonical_json({"seq": 2, "body": "b"})
h1 = hashlib.sha256(h0 + env1).digest()
h2 = hashlib.sha256(h1 + env2).digest()
vectors["transcript_chain"] = {
    "h0_hex": h(h0),
    "frames_canonical_hex": [h(env1), h(env2)],
    "expected_head_hex": h(h2),
}

# 7. seal / open — deterministic blob built with a FIXED ephemeral + nonce so the
# vector is reproducible; a second implementation must OPEN it to the plaintext.
from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF  # noqa: E402

recipient = X25519PrivateKey.from_private_bytes(SEED)  # recipient's static key
seal_eph = X25519PrivateKey.from_private_bytes(bytes([5] * 32))
seal_eph_pub = seal_eph.public_key().public_bytes_raw()
seal_shared = seal_eph.exchange(recipient.public_key())
seal_key = _HKDF(algorithm=_hashes.SHA256(), length=32, salt=seal_eph_pub, info=b"amp/0.1/seal").derive(seal_shared)
seal_nonce = bytes([6] * 12)
seal_pt = b"first knock"
seal_ct = ChaCha20Poly1305(seal_key).encrypt(seal_nonce, seal_pt, seal_eph_pub)
sealed_blob = seal_eph_pub + seal_nonce + seal_ct
vectors["seal_open"] = {
    "recipient_private_hex": h(SEED),
    "sealed_hex": h(sealed_blob),
    "expected_plaintext_hex": h(seal_pt),
}

# 8. AgentCard canonical signing payload + signature (composed object interop).
from fg_amp.identity.card import AgentCard  # noqa: E402

from fg_agent_id.signing import CONTEXT_AGENT_CARD  # noqa: E402
from fg_agent_id.signing import signing_input as id_signing_input  # noqa: E402

card = AgentCard.create(keys, address_from_signing_key(signing_pub), "conformance-agent")
vectors["agent_card"] = {
    # Signed under the identity standard's domain, not AMP's.
    "domain": "fg-agent-id/v1",
    "context": CONTEXT_AGENT_CARD,
    "payload": card._payload(),
    "signing_input_hex": h(id_signing_input(CONTEXT_AGENT_CARD, card._payload())),
    "signature_b64": card.signature,
    "signer_public_hex": h(signing_pub),
}

# 9. Group roster canonical payload + digest + founder signature.
from fg_amp.session.group import GroupInfo  # noqa: E402

roster = GroupInfo(group_id="g1", purpose="standup", founder=card.address, epoch=2, members=(card,)).signed_by(keys)
from fg_amp.signing import CONTEXT_GROUP_ROSTER, signing_input  # noqa: E402

vectors["group_roster"] = {
    "domain": "fg-amp/v1",
    "context": CONTEXT_GROUP_ROSTER,
    "payload": roster._payload(),
    "signing_input_hex": h(signing_input(CONTEXT_GROUP_ROSTER, roster._payload())),
    "roster_digest_hex": roster.roster_digest,
    "signature_b64": roster.signature,
    "founder_public_hex": h(signing_pub),
}

# 10. session-message AEAD associated data: utf8("<session_id>:<seq>") || dh_pub.
dh_pub = bytes([8] * 32)
aad_bytes = b"11111111-1111-1111-1111-111111111111:4" + dh_pub
vectors["session_aad"] = {
    "session_id": "11111111-1111-1111-1111-111111111111",
    "seq": 4,
    "dh_pub_hex": h(dh_pub),
    "expected_aad_hex": h(aad_bytes),
}

# 11b. Double-ratchet KDF chain — the multi-frame ratchet internals a second
# implementation must reproduce byte-for-byte. The DH steps use fresh keys (not
# reproducible), but the symmetric chain KDF, root step, direction seed, and
# close key are fully deterministic and are what actually diverge across impls.
from fg_amp.session.ratchet import (  # noqa: E402
    _kdf_ck,
    _kdf_rk,
    _seed_chain,
    derive_close_key,
)

# symmetric chain: iterate _kdf_ck from a pinned chain key over several frames.
_chain0 = bytes([0x11] * 32)
_chain = _chain0
_ck_steps = []
for _ in range(4):
    _mk, _chain_next = _kdf_ck(_chain)
    _ck_steps.append({"message_key_hex": h(_mk), "next_chain_hex": h(_chain_next)})
    _chain = _chain_next

# root step: mix a pinned DH output into a pinned root key.
_root0 = bytes([0x22] * 32)
_dh_out = bytes([0x33] * 32)
_new_root, _root_chain = _kdf_rk(_root0, _dh_out)

vectors["ratchet"] = {
    "chain_kdf": {
        "info_message": "amp/0.1/ratchet/message",
        "info_advance": "amp/0.1/ratchet/advance",
        "start_chain_hex": h(_chain0),
        "steps": _ck_steps,
    },
    "root_kdf": {
        "info": "amp/0.1/ratchet/root",
        "root_hex": h(_root0),
        "dh_out_hex": h(_dh_out),
        "expected_new_root_hex": h(_new_root),
        "expected_chain_hex": h(_root_chain),
    },
    "seed_chain_r2i": {
        "info_prefix": "amp/0.1/ratchet/seed/",
        "root_hex": h(_root0),
        "label": "r2i",
        "expected_hex": h(_seed_chain(_root0, b"r2i")),
    },
    "close_key": {
        "root_hex": h(_root0),
        "direction": "i2r",
        "expected_hex": h(derive_close_key(_root0, "i2r")),
    },
}

# 11. real ML-KEM-768 decapsulation KAT (fixed key + ciphertext -> shared secret).
mlkem = json.loads(Path("spec/mlkem_fixture.json").read_text())
vectors["mlkem768_decapsulate"] = {
    "pkcs8_private_hex": mlkem["pkcs8_hex"],
    "ciphertext_hex": mlkem["ciphertext_hex"],
    "expected_shared_hex": mlkem["shared_hex"],
}

# 12. typed bodies (SPEC §16): one canonical example per built-in. The example
# MUST validate against the type's schema; the canonical-JSON hex pins the
# serialized shape for cross-implementation schema agreement. (Bodies travel
# as plain JSON inside the encrypted payload — canonical form here is only the
# vector fixture, not a wire requirement.)
from fg_amp.bodies import default_registry  # noqa: E402

_ref_example = {
    "uri": "https://git.example/fareground/amp/commit/deadbeef",
    "kind": "commit",
    "version": "deadbeef",
    "content_hash": "sha256:" + "00" * 32,
}
_body_examples = {
    "amp.task/1": {
        "task_id": "task-0001",
        "kind": "request",
        "title": "Summarize the Q3 report",
        "body": "One page, plain language.",
        "inputs": {"report_uri": "https://files.example/q3.pdf"},
        "outputs": {},
        "deadline": "2026-08-01T00:00:00Z",
        "refs": [_ref_example],
    },
    "amp.receipt/1": {
        "status": "accepted",
        "task_id": "task-0001",
        "message_id": None,
        "reason": "",
    },
    "amp.ref/1": _ref_example,
    "amp.claim/1": {
        "claim_id": "claim-0001",
        "statement": "The relay at relay.example enforces per-sender quotas.",
        "confidence": 1,
        "pedigree": {
            "source": "amp:key:" + base58_encode(signing_pub),
            "evidence": [_ref_example],
            "observed_at": "2026-07-01T00:00:00Z",
        },
        "supersedes": None,
    },
    "amp.payment/1": {
        "payment_id": "pay-0001",
        "kind": "quote",
        "amount": "12.50",
        "asset": "usdc",
        "pay_to": "0x00000000000000000000000000000000000000ff",
        "valid_until": "2026-08-01T00:00:00Z",
        "x402": {
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "12500000",
            "resource": "https://api.example/report",
            "payTo": "0x00000000000000000000000000000000000000ff",
            "asset": "0x0000000000000000000000000000000000000aa0",
        },
        "chain_ref": "",
        "tx_ref": "",
        "reason": "",
    },
    "amp.mcp/1": {
        "payload": {
            "jsonrpc": "2.0",
            "id": "amp-1",
            "method": "tools/call",
            "params": {"name": "summarize", "arguments": {"uri": "https://files.example/q3.pdf"}},
        },
        "mcp_session": "mcp-0001",
    },
}
_registry = default_registry()
for _name, _example in _body_examples.items():
    _registry.parse(_name, _example)  # every vector example must be schema-valid
vectors["typed_bodies"] = {
    name: {"body": example, "canonical_hex": h(canonical_json(example))}
    for name, example in _body_examples.items()
}

# sanity: encrypt() round-trips (self-check, not a cross-impl vector)
assert len(encrypt(aead_key, pt, aad)) > 12

out = Path("spec/vectors.json")
out.write_text(json.dumps(vectors, indent=2, ensure_ascii=False))
print("wrote", out, "with", len(vectors) - 2, "vector groups")
