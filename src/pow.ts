/**
 * Proof-of-Work solver for anti-spam challenges.
 *
 * When a wallet is unknown to the node, the node returns a 429 response
 * with a PoW challenge. The client must find a nonce such that
 * SHA-256(prefix + nonce) has the required number of leading zero bits.
 *
 * Typical difficulty: 20 bits ≈ ~1M hashes ≈ 2-3 seconds on modern hardware.
 * This is a one-time cost per wallet — once solved, the wallet is "known"
 * and future messages are accepted without PoW.
 */

import { sha256 } from '@noble/hashes/sha256';

/** A PoW challenge issued by the node. */
export interface PowChallenge {
  challenge_id: string;
  prefix: string;
  difficulty: number;
  expires_at: number;
}

/** A PoW solution to submit back to the node. */
export interface PowSolution {
  challenge_id: string;
  address: string;
  nonce: number;
}

/** Result of a PoW solve attempt. */
export interface PowResult {
  /** The nonce that satisfies the difficulty requirement. */
  nonce: number;
  /** Total hashes computed to find the solution. */
  hashes: number;
  /** Time taken in milliseconds. */
  elapsed_ms: number;
}

/**
 * Check if a hash has at least `n` leading zero bits.
 */
function hasLeadingZeros(hash: Uint8Array, n: number): boolean {
  const fullBytes = Math.floor(n / 8);
  const remainingBits = n % 8;

  for (let i = 0; i < fullBytes; i++) {
    if (hash[i] !== 0) return false;
  }

  if (remainingBits > 0) {
    const mask = 0xff << (8 - remainingBits);
    if ((hash[fullBytes] & mask) !== 0) return false;
  }

  return true;
}

/**
 * Solve a PoW challenge by finding a nonce that produces the required
 * number of leading zero bits in SHA-256(prefix + nonce).
 *
 * Uses the same encoding as the Rust node: nonce as 8 little-endian bytes.
 *
 * @param challenge - The challenge from the node
 * @param onProgress - Optional callback with (hashes_so_far) for UI updates
 * @returns The nonce, hash count, and elapsed time
 */
export function solveChallenge(
  challenge: PowChallenge,
  onProgress?: (hashes: number) => void,
): PowResult {
  const prefixBytes = new TextEncoder().encode(challenge.prefix);
  const difficulty = challenge.difficulty;

  // Pre-allocate buffer: prefix + 8 bytes for nonce (little-endian u64)
  const buf = new Uint8Array(prefixBytes.length + 8);
  buf.set(prefixBytes, 0);
  const nonceOffset = prefixBytes.length;

  const start = Date.now();
  let nonce = 0;
  const progressInterval = 100_000; // report every 100k hashes

  while (true) {
    // Write nonce as little-endian u64 (same as Rust's to_le_bytes)
    writeU64LE(buf, nonceOffset, nonce);

    const hash = sha256(buf);

    if (hasLeadingZeros(hash, difficulty)) {
      return {
        nonce,
        hashes: nonce + 1,
        elapsed_ms: Date.now() - start,
      };
    }

    nonce++;

    if (onProgress && nonce % progressInterval === 0) {
      onProgress(nonce);
    }

    // Safety: prevent infinite loop on impossible difficulty
    if (nonce > 0xffffffff) {
      throw new Error(`PoW solve exceeded max iterations (difficulty ${difficulty} may be too high)`);
    }
  }
}

/**
 * Async wrapper for solveChallenge that yields to the event loop periodically
 * to keep the UI responsive. In browser contexts this prevents the tab from
 * freezing during the ~2-3 second solve.
 */
export async function solveChallengeAsync(
  challenge: PowChallenge,
  onProgress?: (hashes: number) => void,
): Promise<PowResult> {
  const prefixBytes = new TextEncoder().encode(challenge.prefix);
  const difficulty = challenge.difficulty;

  const buf = new Uint8Array(prefixBytes.length + 8);
  buf.set(prefixBytes, 0);
  const nonceOffset = prefixBytes.length;

  const start = Date.now();
  let nonce = 0;
  const batchSize = 50_000; // yield every 50k hashes

  while (true) {
    const batchEnd = nonce + batchSize;

    while (nonce < batchEnd) {
      writeU64LE(buf, nonceOffset, nonce);
      const hash = sha256(buf);

      if (hasLeadingZeros(hash, difficulty)) {
        return {
          nonce,
          hashes: nonce + 1,
          elapsed_ms: Date.now() - start,
        };
      }

      nonce++;
    }

    if (onProgress) onProgress(nonce);

    // Yield to event loop so UI stays responsive
    await new Promise((r) => setTimeout(r, 0));

    if (nonce > 0xffffffff) {
      throw new Error(`PoW solve exceeded max iterations (difficulty ${difficulty} may be too high)`);
    }
  }
}

/** Write a number as little-endian u64 (8 bytes) into a buffer at the given offset. */
function writeU64LE(buf: Uint8Array, offset: number, value: number): void {
  // JavaScript numbers are safe up to 2^53, which is more than enough for PoW nonces.
  // Write as two 32-bit LE values.
  const lo = value & 0xffffffff;
  const hi = Math.floor(value / 0x100000000) & 0xffffffff;
  buf[offset] = lo & 0xff;
  buf[offset + 1] = (lo >> 8) & 0xff;
  buf[offset + 2] = (lo >> 16) & 0xff;
  buf[offset + 3] = (lo >> 24) & 0xff;
  buf[offset + 4] = hi & 0xff;
  buf[offset + 5] = (hi >> 8) & 0xff;
  buf[offset + 6] = (hi >> 16) & 0xff;
  buf[offset + 7] = (hi >> 24) & 0xff;
}
