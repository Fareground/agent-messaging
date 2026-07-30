// AMP wire-critical primitives — a dependency-free second implementation.
//
// Uses only Node's built-in `crypto` (Ed25519, X25519, HKDF-SHA256,
// ChaCha20-Poly1305), so it runs with zero npm install. Its whole purpose is to
// prove the AMP wire format is implementation-independent: it reproduces the
// Python reference's golden vectors byte-for-byte (see conformance.mjs).

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  hkdfSync,
  diffieHellman,
  createCipheriv,
  createDecipheriv,
  decapsulate as kemDecapsulate,
} from "node:crypto";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// --- base58 (Bitcoin alphabet), matching the Python implementation ----------
export function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) {
    const rem = num % 58n;
    num = num / 58n;
    out = B58[Number(rem)] + out;
  }
  let pad = 0;
  for (const b of bytes) {
    if (b === 0) pad++;
    else break;
  }
  return "1".repeat(pad) + out;
}

// --- canonical JSON: sorted keys, no whitespace, NFC, UTF-8, no floats ------
function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("floats not allowed in canonical JSON");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k.normalize("NFC")) + ":" + canonicalize(value[k])).join(",") + "}";
  }
  throw new Error("unsupported type in canonical JSON");
}

export function canonicalJson(value) {
  return Buffer.from(canonicalize(value), "utf-8");
}

// --- domain-separated signing input -----------------------------------------
// signing_input = uint16be(len(tag)) || tag || canonicalJson(payload)
// The tag names the artifact type, so a signature can never be replayed as a
// different kind of artifact. Identity artifacts (cards, delegations) use the
// agent-id domain; AMP's own artifacts (envelopes, rosters) use AMP's.
export const DOMAIN_AGENT_ID = "fg-agent-id/v1";
export const DOMAIN_AMP = "fg-amp/v1";

export function signingInput(domain, context, payload) {
  const tag = Buffer.from(`${domain}/${context}`, "utf-8");
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(tag.length, 0);
  return Buffer.concat([prefix, tag, canonicalJson(payload)]);
}

// --- addresses --------------------------------------------------------------
export const ADDRESS_PREFIX = "amp:key:";
export function addressFromSigningKey(pub32) {
  if (pub32.length !== 32) throw new Error("signing public key must be 32 bytes");
  return ADDRESS_PREFIX + base58Encode(pub32);
}

// --- Ed25519 (raw 32-byte keys -> Node KeyObjects) --------------------------
const ED_PUB_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // SPKI header
const ED_PRIV_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex"); // PKCS8 header

export function ed25519PublicFromRaw(raw32) {
  return createPublicKey({ key: Buffer.concat([ED_PUB_PREFIX, raw32]), format: "der", type: "spki" });
}
export function ed25519PrivateFromSeed(seed32) {
  return createPrivateKey({ key: Buffer.concat([ED_PRIV_PREFIX, seed32]), format: "der", type: "pkcs8" });
}
export function ed25519Sign(seed32, message) {
  return edSign(null, message, ed25519PrivateFromSeed(seed32));
}
export function ed25519Verify(rawPub32, message, signature) {
  return edVerify(null, message, ed25519PublicFromRaw(rawPub32), signature);
}

// --- X25519 -----------------------------------------------------------------
const X_PUB_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const X_PRIV_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
export function x25519PublicFromRaw(raw32) {
  return createPublicKey({ key: Buffer.concat([X_PUB_PREFIX, raw32]), format: "der", type: "spki" });
}
export function x25519PrivateFromRaw(raw32) {
  return createPrivateKey({ key: Buffer.concat([X_PRIV_PREFIX, raw32]), format: "der", type: "pkcs8" });
}
export function x25519Shared(ownPrivRaw32, peerPubRaw32) {
  return diffieHellman({
    privateKey: x25519PrivateFromRaw(ownPrivRaw32),
    publicKey: x25519PublicFromRaw(peerPubRaw32),
  });
}

// --- HKDF-SHA256 ------------------------------------------------------------
export function hkdf(ikm, salt, info, length = 32) {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

// --- session key: HKDF(x25519_shared || pq_shared, salt=transcript, info) ---
const SESSION_INFO = Buffer.from("amp/0.1/session", "utf-8");
export function deriveSessionKey(ownEphPrivRaw, peerEphPubRaw, transcript, pqShared = Buffer.alloc(0)) {
  const shared = x25519Shared(ownEphPrivRaw, peerEphPubRaw);
  return hkdf(Buffer.concat([shared, pqShared]), transcript, SESSION_INFO, 32);
}

// --- AEAD: ChaCha20-Poly1305, output = ciphertext || tag(16) ----------------
export function aeadEncrypt(key, nonce, plaintext, aad) {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  if (aad && aad.length) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

export function aeadDecrypt(key, nonce, ciphertextWithTag, aad) {
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  if (aad && aad.length) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// --- seal / open: ephemeral_pub(32) || nonce(12) || ct||tag -----------------
const SEAL_INFO = Buffer.from("amp/0.1/seal", "utf-8");
export function openSealed(recipientPrivRaw32, sealed) {
  const ephPub = sealed.subarray(0, 32);
  const rest = sealed.subarray(32);
  const shared = x25519Shared(recipientPrivRaw32, ephPub);
  const key = hkdf(shared, ephPub, SEAL_INFO, 32);
  const nonce = rest.subarray(0, 12);
  return aeadDecrypt(key, nonce, rest.subarray(12), ephPub);
}

// --- double-ratchet KDFs (deterministic parts; DH steps use fresh keys) -----
const RATCHET_MESSAGE_INFO = Buffer.from("amp/0.1/ratchet/message", "utf-8");
const RATCHET_ADVANCE_INFO = Buffer.from("amp/0.1/ratchet/advance", "utf-8");
const RATCHET_ROOT_INFO = Buffer.from("amp/0.1/ratchet/root", "utf-8");
const RATCHET_SEED_INFO = Buffer.from("amp/0.1/ratchet/seed/", "utf-8");
const RATCHET_CLOSE_INFO = Buffer.from("amp/0.1/close/", "utf-8");

// Advance a symmetric chain key: returns { messageKey, nextChain }.
export function ratchetKdfCk(chain) {
  return {
    messageKey: hkdf(chain, Buffer.alloc(0), RATCHET_MESSAGE_INFO, 32),
    nextChain: hkdf(chain, Buffer.alloc(0), RATCHET_ADVANCE_INFO, 32),
  };
}

// Root step: mix a DH secret into the root (salt=root). Returns { newRoot, chain }.
export function ratchetKdfRk(root, dhOut) {
  const material = hkdf(dhOut, root, RATCHET_ROOT_INFO, 64);
  return { newRoot: material.subarray(0, 32), chain: material.subarray(32, 64) };
}

// Direction seed chain and close key (info carries the label as a suffix).
export function ratchetSeedChain(root, label) {
  return hkdf(root, Buffer.alloc(0), Buffer.concat([RATCHET_SEED_INFO, Buffer.from(label, "utf-8")]), 32);
}
export function ratchetCloseKey(root, direction) {
  return hkdf(root, Buffer.alloc(0), Buffer.concat([RATCHET_CLOSE_INFO, Buffer.from(direction, "utf-8")]), 32);
}

// --- ML-KEM-768 decapsulation (Node built-in; PKCS8 import) -----------------
export function mlkemDecapsulate(pkcs8Der, ciphertext) {
  const sk = createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
  return Buffer.from(kemDecapsulate(sk, ciphertext));
}

// --- transcript hash chain: h_n = sha256(h_{n-1} || canonical(frame_n)) -----
export function transcriptExtend(head, frameCanonicalBytes) {
  return createHash("sha256").update(head).update(frameCanonicalBytes).digest();
}
