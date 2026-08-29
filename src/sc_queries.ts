/**
 * General-purpose on-chain read helpers against the Ogmara KApp, distinct
 * from `sc_discovery.ts` (which is scoped to node bootstrap enumeration).
 *
 * These are on-chain SOURCE-OF-TRUTH reads, not the primary data path for
 * most consumers — an app talking to an Ogmara L2 node normally gets
 * channel/user data from the node's own REST API (faster, no Klever RPC
 * round-trip, and reflects gossip-propagated state the node already
 * tracks locally). Use these when you need a chain-verified answer
 * directly (verification/reconciliation tooling, or an SDK consumer that
 * has no L2 node to talk to).
 *
 * Reuses `sc_discovery.ts`'s `vmQuery` implementation and encoding helpers
 * so request/response handling stays byte-identical across both modules —
 * mirrors `l2-node/src/chain/sc_views.rs`'s equivalent client functions.
 */

import {
  SC_NETWORKS,
  ScRequireError,
  bytesToHex,
  bytesToUtf8,
  decodeU64Be,
  u64MinimalHex,
  vmQuery,
  type ScNetwork,
} from './sc_discovery';
import { addressToPubkey } from './encryption';

export interface ScQueryOptions {
  /** Per-RPC timeout (ms). Default 8000. */
  timeoutMs?: number;
}

/** A channel's on-chain type + creation timestamp, or `null` if the channel
 *  does not exist on-chain. */
export interface ScChannelInfo {
  /** 0 = Public, 1 = ReadPublic. */
  channelType: number;
  /** Unix seconds. */
  createdAt: number;
}

function net(network: ScNetwork) {
  const n = SC_NETWORKS[network];
  if (!n) throw new Error('unknown network: ' + network);
  return n;
}

/**
 * `u64MinimalHex` (from `sc_discovery.ts`) assumes a non-negative safe
 * integer — every existing internal call site guarantees that, but these
 * are public SDK entry points taking a raw `number` with no such guarantee.
 * Validate here so a caller mistake (negative, fractional, NaN, Infinity)
 * throws a clear client-side error instead of producing malformed hex
 * (e.g. `u64MinimalHex(-1)` → `"-1"`) that would only surface as an opaque
 * RPC/decode failure.
 */
function assertU64Arg(v: number, name: string): void {
  if (!Number.isInteger(v) || v < 0) {
    throw new Error(`${name} must be a non-negative integer, got ${v}`);
  }
}

/**
 * Registration timestamp (unix seconds) for a registered user, or `0` if
 * not registered. Mirrors the SC's `getUserRegisteredAt` view.
 */
export async function getUserRegisteredAt(
  network: ScNetwork,
  klvAddress: string,
  opts: ScQueryOptions = {},
): Promise<number> {
  const { rpc, sc } = net(network);
  const timeoutMs = opts.timeoutMs ?? 8000;
  // `addressToPubkey` itself verifies the bech32 checksum and the decoded
  // length, so a malformed/mistyped address surfaces as a clear client-side
  // error here rather than an ambiguous "not registered" require! failure
  // from the chain.
  const addressHex = bytesToHex(addressToPubkey(klvAddress));
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getUserRegisteredAt', [addressHex], timeoutMs);
  } catch (e) {
    if (e instanceof ScRequireError) return 0;
    throw e;
  }
  return items.length > 0 ? decodeU64Be(items[0]) : 0;
}

/**
 * A channel's on-chain type + creation timestamp, or `null` if the
 * channel does not exist. Mirrors the SC's `getChannelInfo` view
 * (`MultiValue2<u8, u64>` — flattens to exactly two return items).
 */
export async function getChannelInfo(
  network: ScNetwork,
  channelId: number,
  opts: ScQueryOptions = {},
): Promise<ScChannelInfo | null> {
  const { rpc, sc } = net(network);
  assertU64Arg(channelId, 'channelId');
  const timeoutMs = opts.timeoutMs ?? 8000;
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getChannelInfo', [u64MinimalHex(channelId)], timeoutMs);
  } catch (e) {
    if (e instanceof ScRequireError) return null;
    throw e;
  }
  if (items.length !== 2) {
    throw new Error(`getChannelInfo returned unexpected item count: ${items.length} (expected 2)`);
  }
  const typeBytes = items[0];
  if (typeBytes.length > 1) {
    throw new Error('getChannelInfo channel_type has unexpected length');
  }
  const channelType = typeBytes.length === 1 ? typeBytes[0] : 0;
  const createdAt = decodeU64Be(items[1]);
  return { channelType, createdAt };
}

/**
 * Raw read of a contested anchor height's MATERIALIZED resolution, or
 * `null` if it has not (yet) been finalized on-chain — either via
 * escalated-quorum agreement or a completed `resolveTiebreak` call.
 * Mirrors the SC's `getEscalatedCanonical` view (0.7.0).
 *
 * Distinct from a `getCanonicalAnchor` call (not exposed here — this SDK
 * is not a node and has no reason to read general anchor state): for an
 * escalated height, `getCanonicalAnchor` starts returning the §2.9
 * tiebreak's PROVISIONAL preview the instant escalation triggers — well
 * before the 24h grace window closes — and that preview can still be
 * overridden by real escalated-quorum agreement on a different root
 * during the window. This function never computes or returns that
 * preview; `null` means "still provisional or not escalated," never
 * "resolved to nothing."
 */
export async function getEscalatedCanonical(
  network: ScNetwork,
  blockHeight: number,
  opts: ScQueryOptions = {},
): Promise<string | null> {
  const { rpc, sc } = net(network);
  assertU64Arg(blockHeight, 'blockHeight');
  const timeoutMs = opts.timeoutMs ?? 8000;
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getEscalatedCanonical', [u64MinimalHex(blockHeight)], timeoutMs);
  } catch (e) {
    if (e instanceof ScRequireError) return null;
    throw e;
  }
  if (items.length === 0 || items[0].length === 0) return null;
  const root = bytesToUtf8(items[0]);
  if (!/^[0-9a-f]{64}$/i.test(root)) {
    throw new Error(`getEscalatedCanonical returned a malformed root: expected 64 hex chars, got ${JSON.stringify(root.slice(0, 16))}${root.length > 16 ? '…' : ''} (length ${root.length})`);
  }
  return root;
}
