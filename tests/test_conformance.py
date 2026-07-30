"""Cross-implementation conformance: the golden vectors are reproducible from
Python, and the dependency-free JS reference implementation reproduces them
byte-for-byte (interop proof)."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors.json"


def test_vectors_exist_and_are_wellformed():
    data = json.loads(VECTORS.read_text())
    for group in ("canonical_json", "base58", "ed25519", "session_key",
                  "aead_chacha20poly1305", "transcript_chain", "ratchet"):
        assert group in data, f"missing vector group {group}"


def test_typed_body_vectors_validate_and_pin_canonical_form():
    """Every SPEC §16 built-in has a golden example that (a) validates against
    its registered schema and (b) canonicalizes to the pinned bytes."""
    from fg_amp.bodies import BUILTIN_BODY_TYPES, default_registry
    from fg_amp.envelope.canonical import canonical_json

    vectors = json.loads(VECTORS.read_text())["typed_bodies"]
    assert set(vectors) == set(BUILTIN_BODY_TYPES)
    registry = default_registry()
    for name, vector in vectors.items():
        registry.parse(name, vector["body"])  # schema-valid
        assert canonical_json(vector["body"]).hex() == vector["canonical_hex"]


def test_ratchet_vectors_match_implementation():
    """The multi-frame ratchet vectors are reproduced by the real ratchet KDFs —
    so a second implementation matching the vectors matches AMP's ratchet."""
    from fg_amp.session.ratchet import (
        _kdf_ck,
        _kdf_rk,
        _seed_chain,
        derive_close_key,
    )

    rt = json.loads(VECTORS.read_text())["ratchet"]
    chain = bytes.fromhex(rt["chain_kdf"]["start_chain_hex"])
    for step in rt["chain_kdf"]["steps"]:
        message_key, chain = _kdf_ck(chain)
        assert message_key.hex() == step["message_key_hex"]
        assert chain.hex() == step["next_chain_hex"]

    new_root, root_chain = _kdf_rk(
        bytes.fromhex(rt["root_kdf"]["root_hex"]), bytes.fromhex(rt["root_kdf"]["dh_out_hex"])
    )
    assert new_root.hex() == rt["root_kdf"]["expected_new_root_hex"]
    assert root_chain.hex() == rt["root_kdf"]["expected_chain_hex"]

    assert (
        _seed_chain(bytes.fromhex(rt["seed_chain_r2i"]["root_hex"]), b"r2i").hex()
        == rt["seed_chain_r2i"]["expected_hex"]
    )
    assert (
        derive_close_key(bytes.fromhex(rt["close_key"]["root_hex"]), "i2r").hex()
        == rt["close_key"]["expected_hex"]
    )


def test_vectors_are_reproducible_from_python():
    """Regenerating must yield identical bytes — guards against silent wire drift."""
    before = VECTORS.read_text()
    subprocess.run(
        [sys.executable, "spec/generate_vectors.py"], cwd=ROOT, check=True, capture_output=True
    )
    assert VECTORS.read_text() == before, "vectors changed — wire format drifted!"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_reference_implementation_matches_vectors():
    """The independent JS implementation reproduces every vector byte-for-byte."""
    result = subprocess.run(
        ["node", "reference/js/conformance.mjs"], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, f"JS conformance failed:\n{result.stdout}\n{result.stderr}"
    assert "0 failed" in result.stdout
