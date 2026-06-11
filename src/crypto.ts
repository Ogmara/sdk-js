/**
 * E2E crypto core (P1, protocol §8). Shared symmetric content encryption + key
 * wrapping, mirrored **byte-for-byte** by sdk-rust `crypto.rs` (the same RFC
 * known-answer tests and the same Ogmara wrap vector are asserted in both SDKs —
 * any drift breaks one suite).
 *
 * Primitives are audited libraries wrapped behind Ogmara-native names so the rest
 * of the SDK never couples to a specific package API:
 * - **AEAD:** XChaCha20-Poly1305, 24-byte nonce (`@noble/ciphers`)
 * - **KDF:**  HKDF-SHA256 (`@noble/hashes`)
 * - **DH:**   X25519 (vendored `./x25519`, constant-time-ish; see that file)
 *
 * `@noble/ciphers` is a DIRECT dependency of every consumer (web/desktop/mobile),
 * mirroring how `@noble/hashes` is handled — a transitive-only `@noble` dep is not
 * reliably present in a `file:`-linked consumer's node_modules (the reason
 * `./x25519` is vendored). The `.js` subpath is required by its `exports` map.
 *
 * Every function is deterministic given its inputs; randomness is injected by the
 * caller ({@link wrapKey} is the one convenience that draws fresh randomness) so
 * the cross-impl vectors reproduce exactly.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import {
  getPublicKey as x25519GetPublicKey,
  getSharedSecret as x25519GetShared,
  randomPrivateKey as x25519Random,
} from './x25519';

/** XChaCha20-Poly1305 nonce length (bytes). 24 bytes makes random nonces safe at message scale. */
export const AEAD_NONCE_LEN = 24;
/** Symmetric key length (bytes) — content keys, channel keys, wrapped keys. */
export const KEY_LEN = 32;
/** Poly1305 tag length (bytes); appended to the ciphertext by {@link aeadEncrypt}. */
export const AEAD_TAG_LEN = 16;

/** HKDF `info` label for the ECIES key-wrap KDF (domain separation). */
const KEYWRAP_INFO = new TextEncoder().encode('ogmara-keywrap-v1');

/**
 * Encrypt `plaintext` under `key` with XChaCha20-Poly1305. Returns `ct || tag`
 * (trailing 16 bytes are the Poly1305 tag). `aad` is authenticated but not
 * encrypted — pass the envelope binding (content: `channel_id || epoch || msg_id`;
 * key wrap: the ephemeral pubkey) so a ciphertext can't be spliced onto a
 * different envelope. The caller owns nonce uniqueness per `key`.
 */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error(`AEAD key must be ${KEY_LEN} bytes, got ${key.length}`);
  if (nonce.length !== AEAD_NONCE_LEN)
    throw new Error(`AEAD nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`);
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/**
 * Decrypt `ciphertext` (`ct || tag`) produced by {@link aeadEncrypt}. Throws on
 * ANY authentication failure (wrong key, tampered bytes, or wrong `aad`) — the
 * underlying library throws a generic error, indistinguishable across causes.
 */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error(`AEAD key must be ${KEY_LEN} bytes, got ${key.length}`);
  if (nonce.length !== AEAD_NONCE_LEN)
    throw new Error(`AEAD nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`);
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

/** HKDF-SHA256 (RFC 5869): derive `len` bytes from `ikm` with `salt` + `info`. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  len: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, len);
}

/**
 * X25519 Diffie-Hellman. Delegates to the vendored {@link x25519GetShared}, which
 * rejects an all-zero (low-order point) shared secret. A throw means a
 * hostile/invalid peer key — callers MUST treat it as fatal, never fall back.
 */
export function x25519Dh(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  return x25519GetShared(privateKey, peerPublic);
}

/** The X25519 public key (32 bytes) for a 32-byte secret. */
export function x25519Public(privateKey: Uint8Array): Uint8Array {
  return x25519GetPublicKey(privateKey);
}

/** A symmetric key wrapped to a recipient's device encryption public key (ECIES, §8.2). */
export interface WrappedKey {
  /** Ephemeral X25519 public key (32 bytes). */
  ephPub: Uint8Array;
  /** AEAD nonce (24 bytes). */
  nonce: Uint8Array;
  /** Wrapped key bytes: `KEY_LEN + AEAD_TAG_LEN` = 48 bytes. */
  wrapped: Uint8Array;
}

/** A cryptographically-random 24-byte AEAD nonce. Throws if no CSPRNG is available
 * (never silently emits a zero nonce — that would be catastrophic for AEAD; audit N1). */
function randomNonce(): Uint8Array {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available for AEAD nonce');
  }
  return crypto.getRandomValues(new Uint8Array(AEAD_NONCE_LEN));
}

/**
 * Wrap a 32-byte symmetric key `k` for `recipientPub` (a device enc pubkey) using
 * a **caller-supplied** ephemeral secret + nonce. Deterministic — used by the
 * cross-impl test vector; production code calls {@link wrapKey}.
 *
 * Construction (must stay identical to sdk-rust `wrap_key_with`):
 * `shared = X25519(ephPriv, recipientPub)`,
 * `wk = HKDF-SHA256(ikm=shared, salt=context, info="ogmara-keywrap-v1", 32)`,
 * `wrapped = AEAD(wk, nonce, k, aad=ephPub)`.
 */
export function wrapKeyWith(
  k: Uint8Array,
  recipientPub: Uint8Array,
  context: Uint8Array,
  ephPriv: Uint8Array,
  nonce: Uint8Array,
): WrappedKey {
  if (k.length !== KEY_LEN) throw new Error(`key to wrap must be ${KEY_LEN} bytes`);
  const ephPub = x25519Public(ephPriv);
  const shared = x25519Dh(ephPriv, recipientPub);
  const wk = hkdfSha256(shared, context, KEYWRAP_INFO, KEY_LEN);
  // Bind the wrap to its ephemeral pubkey so a wrapped blob can't be replayed
  // under a substituted ephPub.
  const wrapped = aeadEncrypt(wk, nonce, k, ephPub);
  wk.fill(0);
  shared.fill(0);
  return { ephPub, nonce, wrapped };
}

/**
 * Wrap `k` for `recipientPub` with a fresh ephemeral keypair and random nonce
 * (production path). `context` domain-separates the KDF (e.g. channel/conversation id).
 */
export function wrapKey(k: Uint8Array, recipientPub: Uint8Array, context: Uint8Array): WrappedKey {
  const ephPriv = x25519Random();
  const nonce = randomNonce();
  try {
    return wrapKeyWith(k, recipientPub, context, ephPriv, nonce);
  } finally {
    ephPriv.fill(0);
  }
}

/**
 * Unwrap a {@link WrappedKey} using the recipient's device enc secret. `context`
 * must match the one used at wrap time. Throws on any authentication failure.
 */
export function unwrapKey(w: WrappedKey, recipientPriv: Uint8Array, context: Uint8Array): Uint8Array {
  const shared = x25519Dh(recipientPriv, w.ephPub);
  const wk = hkdfSha256(shared, context, KEYWRAP_INFO, KEY_LEN);
  let pt: Uint8Array;
  try {
    pt = aeadDecrypt(wk, w.nonce, w.wrapped, w.ephPub);
  } finally {
    wk.fill(0);
    shared.fill(0);
  }
  if (pt.length !== KEY_LEN) throw new Error('unwrapped key has wrong length');
  return pt;
}
