import { keccak_256 } from '@noble/hashes/sha3';

/**
 * `channel_id` derivation for PRIVATE channels (protocol spec 01 §channels,
 * `docs/specs/05-clients.md` §private-channel-creation):
 *
 *   channel_id = Keccak-256(creator_wallet_address + slug + id_derivation_ts)
 *                % (2^53 - 1)
 *
 * `creator_wallet_address` MUST be the wallet address (`klv1...`), never a
 * delegated device key — the l2-node (0.139.0+) independently recomputes
 * this hash using the envelope's RESOLVED wallet identity, so a hash
 * computed over a device address will never verify.
 *
 * Security note (l2-node 0.139.0 CHANGELOG): verifying this derivation
 * makes channel creatorship self-certifying on a node's first-ever
 * encounter with a `channel_id` — closing a creator-forgery gap. The
 * modulus is `Number.MAX_SAFE_INTEGER` (a JS-safe-integer constraint, not
 * full 64-bit truncation), so this is a ~53-bit binding, not full 256-bit
 * Keccak strength — it raises the cost of forging a SPECIFIC target
 * `channel_id` to roughly 2^53 hash evaluations, not to infeasibility.
 *
 * Centralized here (not duplicated per-client) specifically to avoid the
 * wallet-vs-device-address mixup: a caller that passed a device address by
 * mistake would silently produce a `channel_id` the node will reject.
 */
export interface PrivateChannelIdDerivation {
  /** The derived `channel_id`, already re-rolled past the node's namespace floor. */
  channelId: number;
  /**
   * The timestamp actually used (may have been incremented past the
   * caller-supplied `ts` by the floor-retry loop below) — this EXACT value
   * must be sent on the wire as `ChannelCreatePayload.id_derivation_ts`,
   * never approximated from the envelope's own `timestamp` field.
   */
  idDerivationTs: number;
}

/**
 * The l2-node's `PRIVATE_CHANNEL_ID_FLOOR` (`validation.rs`) — namespace
 * separation between the SC's sequential Public/ReadPublic id space and
 * client-derived Private ids. A derived id at or below this is re-rolled
 * (not a security concern — the floor exists so this node-side check can
 * assume "large id = client-derived", not because a low hash is weak).
 */
const PRIVATE_CHANNEL_ID_FLOOR = 2 ** 32;

/** `Number.MAX_SAFE_INTEGER` as a modulus — matches the node's exact arithmetic. */
const JS_SAFE_INTEGER_MODULUS = Number.MAX_SAFE_INTEGER;

/**
 * Derive a private channel_id for `(creatorWalletAddress, slug, ts)`,
 * re-rolling `ts` upward while the result lands at or below
 * `PRIVATE_CHANNEL_ID_FLOOR` (~1-in-2^21 chance per attempt — the loop
 * terminates almost immediately in practice).
 *
 * `ts` defaults to `Date.now()`, captured HERE — before the caller signs
 * anything — and is deliberately distinct from the envelope's own
 * `timestamp` field (set later, inside `buildEnvelope`, after a
 * potentially slow signer round-trip for extension/hardware wallets).
 */
export function derivePrivateChannelId(
  creatorWalletAddress: string,
  slug: string,
  ts: number = Date.now(),
): PrivateChannelIdDerivation {
  let idDerivationTs = ts;
  for (;;) {
    const hash = keccak_256(new TextEncoder().encode(creatorWalletAddress + slug + idDerivationTs));
    const view = new DataView(hash.buffer, hash.byteOffset, hash.byteLength);
    const raw = view.getBigUint64(0);
    const channelId = Number(raw % BigInt(JS_SAFE_INTEGER_MODULUS));
    if (channelId > PRIVATE_CHANNEL_ID_FLOOR) {
      return { channelId, idDerivationTs };
    }
    idDerivationTs += 1;
  }
}
