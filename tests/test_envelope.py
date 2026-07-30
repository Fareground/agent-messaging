"""Envelope layer: canonical JSON, crypto primitives, signed envelopes."""

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from fg_amp.envelope import (
    Envelope,
    EnvelopeType,
    canonical_json,
    decrypt,
    derive_session_key,
    encrypt,
    open_sealed,
    seal,
)
from fg_amp.errors import DecryptionError, SignatureError
from fg_amp.identity import AgentIdentity


def test_canonical_json_deterministic():
    assert canonical_json({"b": 1, "a": [2, {"z": None, "y": "ü"}]}) == \
        canonical_json({"a": [2, {"y": "ü", "z": None}], "b": 1})


def test_aead_roundtrip_and_tamper():
    key = b"k" * 32
    box = encrypt(key, b"secret", aad=b"context")
    assert decrypt(key, box, aad=b"context") == b"secret"
    with pytest.raises(DecryptionError):
        decrypt(key, box, aad=b"other-context")
    with pytest.raises(DecryptionError):
        decrypt(key, box[:-1] + bytes([box[-1] ^ 1]), aad=b"context")


def test_seal_open_roundtrip():
    recipient = X25519PrivateKey.generate()
    sealed = seal(recipient.public_key(), b"first knock")
    assert open_sealed(recipient, sealed) == b"first knock"
    wrong = X25519PrivateKey.generate()
    with pytest.raises(DecryptionError):
        open_sealed(wrong, sealed)


def test_session_key_agreement_symmetric():
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    salt = b"handshake-transcript-digest-32bb"
    key_a = derive_session_key(a, b.public_key().public_bytes_raw(), salt)
    key_b = derive_session_key(b, a.public_key().public_bytes_raw(), salt)
    assert key_a == key_b
    assert derive_session_key(a, b.public_key().public_bytes_raw(), b"other-salt" * 3) != key_a


def test_envelope_sign_verify_and_tamper():
    identity = AgentIdentity.generate("alice")
    envelope = Envelope(
        type=EnvelopeType.SESSION_MESSAGE,
        sender=identity.address,
        to="amp:key:1111111111111111111111111111111111111111111",
        session_id="s1",
        seq=1,
        body=Envelope.encode_body(b"ciphertext"),
    ).signed(identity.keys)
    envelope.verify_signature()
    tampered = envelope.model_copy(update={"seq": 2})
    with pytest.raises(SignatureError):
        tampered.verify_signature()


def test_envelope_wire_roundtrip():
    identity = AgentIdentity.generate("alice")
    envelope = Envelope(
        type=EnvelopeType.HANDSHAKE_REJECT,
        sender=identity.address,
        to=identity.address,
        session_id="s1",
        body=Envelope.encode_body(b"{}"),
    ).signed(identity.keys)
    wire = envelope.to_wire()
    assert "from" in wire and "sender" not in wire
    restored = Envelope.from_wire(wire)
    restored.verify_signature()
    assert restored == envelope
