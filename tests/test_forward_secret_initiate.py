"""Forward-secret initiate: the first knock is sealed to a rotatable prekey, so
a later static-key compromise doesn't expose past initiate payloads."""

import pytest

from fg_amp import AgentIdentity, AmpNode, InMemoryTransport


def connect(*nodes):
    t = InMemoryTransport()
    for n in nodes:
        n.attach(t)
    return t


async def test_card_advertises_prekey_and_initiate_uses_it():
    alice = AmpNode(identity=AgentIdentity.generate("alice"))
    inbound = []

    async def on_session(s):
        inbound.append(s)

    bob = AmpNode(identity=AgentIdentity.generate("bob"), on_session=on_session)
    connect(alice, bob)

    # bob's card advertises a prekey distinct from its static agreement key
    assert bob.card.agreement_prekey is not None
    assert bob.card.agreement_prekey != bob.card.agreement_key
    bob.card.verify()  # prekey is covered by the card signature

    # a handshake sealed to the prekey still opens and establishes
    session = await alice.initiate(bob.card, ttl_seconds=60)
    await session.send_text("sealed to prekey")
    assert (await inbound[0].receive(timeout=1)).payload.content == "sealed to prekey"


async def test_prekey_rotation_reissues_signed_card_and_still_opens():
    bob = AmpNode(identity=AgentIdentity.generate("bob"))
    first = bob.card.agreement_prekey
    new_card = bob.rotate_prekey()
    new_card.verify()
    assert new_card.agreement_prekey != first  # rotated
    # previous prekey retained for a grace window: a knock to the OLD prekey
    # still opens (the ring keeps one previous key)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    from fg_amp.envelope.crypto import seal
    from fg_amp.identity.keys import base58_decode

    old_pub = X25519PublicKey.from_public_bytes(base58_decode(first))
    sealed = seal(old_pub, b"to old prekey")
    assert bob._open_sealed(sealed) == b"to old prekey"

    # after a SECOND rotation the original prekey is dropped -> unrecoverable (FS)
    bob.rotate_prekey()
    from fg_amp.errors import DecryptionError

    with pytest.raises(DecryptionError):
        bob._open_sealed(sealed)
