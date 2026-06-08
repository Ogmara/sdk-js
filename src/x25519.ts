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
 * Timing: the Montgomery ladder uses a BRANCHLESS constant-time conditional
 * swap (no secret-dependent control flow). The underlying field arithmetic is
 * BigInt-based, so individual limb operations are not guaranteed constant-time
 * — a local timing attacker with high-resolution measurement could in theory
 * still learn information. This is an accepted residual for a client-side
 * wallet (no co-resident attacker in the threat model); a fully constant-time
 * path would require a fixed-width / WASM field implementation. See audit
 * 2026-06-07 C2.
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
    // Branchless constant-time conditional swap. `mask` is -1n (all ones, via
    // two's-complement sign-extension) when swap==1, else 0n. `mask & v`
    // selects v or 0 with no secret-dependent branch; XOR then swaps in place.
    // This removes the original `if (swap === 1n)` leak (audit 2026-06-07 C2).
    const mask = -swap;
    const dx = mask & (x2 ^ x3);
    x2 ^= dx;
    x3 ^= dx;
    const dz = mask & (z2 ^ z3);
    z2 ^= dz;
    z3 ^= dz;
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

  const finalMask = -swap;
  const dxf = finalMask & (x2 ^ x3);
  x2 ^= dxf;
  x3 ^= dxf;
  const dzf = finalMask & (z2 ^ z3);
  z2 ^= dzf;
  z3 ^= dzf;

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

/**
 * X25519 Diffie-Hellman shared secret (32 bytes) — for P1 key agreement.
 *
 * Validates the peer key length and rejects an all-zero output (RFC 7748
 * §6.1): a low-order `peerPublicKey` drives the shared secret to zero, which
 * is attacker-predictable and would silently break the confidentiality of any
 * key wrapped with it. Callers MUST treat a throw as a hostile/invalid peer
 * key, never fall back to an unauthenticated path. (audit 2026-06-07 C2)
 */
export function getSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new Error(`X25519 private key must be 32 bytes, got ${privateKey.length}`);
  }
  if (peerPublicKey.length !== 32) {
    throw new Error(`X25519 peer public key must be 32 bytes, got ${peerPublicKey.length}`);
  }
  const shared = scalarMult(privateKey, peerPublicKey);
  // Constant-time-ish all-zero check (low-order point → zero shared secret).
  let acc = 0;
  for (let i = 0; i < shared.length; i++) acc |= shared[i];
  if (acc === 0) {
    throw new Error('X25519 produced an all-zero shared secret (low-order peer key rejected)');
  }
  return shared;
}
