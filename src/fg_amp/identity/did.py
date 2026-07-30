"""Re-export of :mod:`fg_agent_id.did` (extracted identity standard)."""

from fg_agent_id.did import (  # noqa: F401
    DID_PREFIX,
    _decode_multibase_b58,
    _multibase_b58,
    address_to_did,
    did_document,
    did_to_address,
    resolve,
    signing_key_from_did,
)
