/**
 * X25519 (RFC 7748) — vendored, dependency-free.
 *
 * Replaces `@noble/curves` to avoid its fragile package `exports` subpath (which
 * broke the production build: its types don't resolve under older TypeScript, and
 * as a transitive dep of this `file:`-linked package it wasn't present in consumer
 * node_modules). This is the standard Montgomery-ladder scalar multiplication over
 * Curve25519 (GF(2^255-19)); verified against the RFC 7748 test vectors in
 * `encryption.test.ts`. Used for device encryption keypairs (protocol §2.4) and,
 * later, X25519 Diffie-Hellman (P1).
 *
 * Note: BigInt-based, not constant-time. Adequate for keypair generation and the
 * key-wrap DH in this SDK; not intended to defend against local timing attackers.
 */

const P = (1n << 255n) - 19n;
const A24 = 121665n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

/** Modular inverse via Fermat: a^(p-2) mod p. */
function invert(a: bigint): bigint {
  let result = 1n;
  let base = mod(a);
  let exp = P - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base);
    base = mod(base * base);
    exp >>= 1n;
  }
  return result;
}

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function decodeScalar(k: Uint8Array): bigint {
  const e = Uint8Array.from(k.subarray(0, 32));
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  return decodeLittleEndian(e);
}

function decodeU(u: Uint8Array): bigint {
  const e = Uint8Array.from(u.subarray(0, 32));
  e[31] &= 127; // mask the unused high bit
  return mod(decodeLittleEndian(e));
}

function encodeU(n: bigint): Uint8Array {
  let v = mod(n);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** X25519 scalar multiplication: returns the u-coordinate of scalar·point. */
export function scalarMult(scalar: Uint8Array, uCoord: Uint8Array): Uint8Array {
  const x1 = decodeU(uCoord);
  const k = decodeScalar(scalar);

  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    if (swap === 1n) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;

    const a = mod(x2 + z2);
    const aa = mod(a * a);
    const b = mod(x2 - z2);
    const bb = mod(b * b);
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = mod(d * a);
    const cb = mod(c * b);
    x3 = mod(mod(da + cb) ** 2n);
    z3 = mod(x1 * mod(mod(da - cb) ** 2n));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + mod(A24 * e)));
  }

  if (swap === 1n) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }

  return encodeU(mod(x2 * invert(z2)));
}

/** The Curve25519 base point u-coordinate (9). */
const BASE_POINT = (() => {
  const u = new Uint8Array(32);
  u[0] = 9;
  return u;
})();

/** Derive the X25519 public key (32 bytes) for a 32-byte secret. */
export function getPublicKey(privateKey: Uint8Array): Uint8Array {
  return scalarMult(privateKey, BASE_POINT);
}

/** Generate a random 32-byte X25519 secret key. */
export function randomPrivateKey(): Uint8Array {
  const k = new Uint8Array(32);
  crypto.getRandomValues(k);
  return k;
}

/** X25519 Diffie-Hellman shared secret (32 bytes) — for P1 key agreement. */
export function getSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  return scalarMult(privateKey, peerPublicKey);
}
