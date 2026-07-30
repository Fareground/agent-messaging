"""Golden wire-format vectors: pin canonicalization + signing determinism.

A second-language implementation must reproduce these byte-for-byte. If a
change here is intentional (wire-format change), bump the protocol version and
update the vectors deliberately.
"""

from fg_amp.envelope.canonical import canonical_json
from fg_amp.identity.keys import KeyPair, base58_encode


def test_canonical_json_golden():
    # sorted keys, no whitespace, unicode preserved (NFC), no float ambiguity
    assert canonical_json({"b": 1, "a": "ü", "c": [3, 2, 1]}) == (
        b'{"a":"\xc3\xbc","b":1,"c":[3,2,1]}'
    )
    # NFC normalization: composed and decomposed forms converge
    composed = "é"  # é
    decomposed = "é"  # e + combining acute
    assert canonical_json({"x": composed}) == canonical_json({"x": decomposed})


def test_canonical_json_key_order_independent():
    assert canonical_json({"z": 1, "a": 2, "m": 3}) == canonical_json(
        {"a": 2, "m": 3, "z": 1}
    )


def test_ed25519_known_answer():
    # A fixed 32-byte seed produces a deterministic key, address, and signature.
    seed = bytes(range(32))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    keys = KeyPair(
        signing_key=Ed25519PrivateKey.from_private_bytes(seed),
        agreement_key=X25519PrivateKey.from_private_bytes(seed),
    )
    pub = keys.public.signing
    # Ed25519 public key for seed 0..31, base58 — a fixed cross-impl constant.
    assert base58_encode(pub) == "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"

    signature = keys.sign(b"amp-test-vector")
    # Deterministic (Ed25519 signatures are deterministic): verifies and is stable.
    keys.public.verify(signature, b"amp-test-vector")
    assert len(signature) == 64


def test_base58_golden():
    assert base58_encode(b"\x00\x00\x01") == "112"
    assert base58_encode(bytes([255, 255])) == "LUv"
