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
  decodeBigUintBe,
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
 * The current USER registration fee, in raw KLV units (1 KLV = 10^6).
 * Mirrors the SC's `getRegistrationFee` view (smart-contract 0.10.0+).
 *
 * `0n` means registration is free, which is the state of a deployed
 * contract until its owner switches the fee on — so it is an expected
 * reading, not an error. A contract older than 0.10.0 has no such view;
 * that surfaces as a `require` failure and also returns `0n`, which is the
 * correct answer for it too.
 *
 * **Read this before building a `register` transaction.** The fee is
 * node-governance controlled and changes with no client release.
 *
 * Returns `bigint`, not `number` — see `decodeBigUintBe`.
 */
export async function getRegistrationFee(
  network: ScNetwork,
  opts: ScQueryOptions = {},
): Promise<bigint> {
  const { rpc, sc } = net(network);
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getRegistrationFee', [], opts.timeoutMs ?? 8000);
  } catch (e) {
    if (e instanceof ScRequireError) return 0n;
    throw e;
  }
  return items.length > 0 ? decodeBigUintBe(items[0]) : 0n;
}

/**
 * Share of each user registration fee routed to the node the user
 * registered through, in basis points (10_000 = 100%). `0` means the whole
 * fee goes to the protocol treasury. Capped on-chain at 8000 (80%).
 * Mirrors the SC's `getNodeFeeShareBps` view (smart-contract 0.10.0+).
 *
 * A `number` rather than a `bigint`: this is a `u32` bounded well below
 * 2^53, so there is no precision concern and callers want plain arithmetic.
 */
export async function getNodeFeeShareBps(
  network: ScNetwork,
  opts: ScQueryOptions = {},
): Promise<number> {
  const { rpc, sc } = net(network);
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getNodeFeeShareBps', [], opts.timeoutMs ?? 8000);
  } catch (e) {
    if (e instanceof ScRequireError) return 0;
    throw e;
  }
  return items.length > 0 ? decodeU64Be(items[0]) : 0;
}

/**
 * Unclaimed KLV (raw units) that `klvAddress` has accrued from users who
 * registered through its node, claimable with the SC's `claimNodeEarnings`
 * endpoint. `0n` for an address that is not a node or has nothing owed.
 * Mirrors the SC's `getNodeEarnings` view (smart-contract 0.10.0+).
 */
export async function getNodeEarnings(
  network: ScNetwork,
  klvAddress: string,
  opts: ScQueryOptions = {},
): Promise<bigint> {
  const { rpc, sc } = net(network);
  // Verifies the bech32 checksum client-side, so a mistyped address fails
  // clearly here instead of returning an ambiguous zero balance.
  const addressHex = bytesToHex(addressToPubkey(klvAddress));
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getNodeEarnings', [addressHex], opts.timeoutMs ?? 8000);
  } catch (e) {
    if (e instanceof ScRequireError) return 0n;
    throw e;
  }
  return items.length > 0 ? decodeBigUintBe(items[0]) : 0n;
}

/**
 * Total unclaimed node earnings across every operator — the contract's
 * outstanding liability to node operators, in raw KLV units. Mirrors the
 * SC's `getTotalUnclaimedNodeEarnings` view (smart-contract 0.10.0+).
 */
export async function getTotalUnclaimedNodeEarnings(
  network: ScNetwork,
  opts: ScQueryOptions = {},
): Promise<bigint> {
  const { rpc, sc } = net(network);
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getTotalUnclaimedNodeEarnings', [], opts.timeoutMs ?? 8000);
  } catch (e) {
    if (e instanceof ScRequireError) return 0n;
    throw e;
  }
  return items.length > 0 ? decodeBigUintBe(items[0]) : 0n;
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
 * A contested anchor height's FINAL answer, or `null` while its contest is
 * still open. Mirrors the SC's `getEscalatedCanonical` view: the stored
 * `resolveTiebreak` winner, or — since SC 0.12.0 — the winner once the
 * contest's 24 h window has closed (no further submissions are accepted).
 * `null` also for a closed DISPUTED height (tied vote counts, no root) and
 * for a height that never escalated.
 *
 * Distinct from a raw `getCanonicalAnchor` call (use
 * {@link getFinalCanonicalAnchor}, which applies the full verifier rules):
 * for an escalated height `getCanonicalAnchor` returns a PROVISIONAL answer
 * while the contest is open, which can still change when it closes.
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

async function isDivergenceEscalated(
  rpc: string,
  sc: string,
  blockHeight: number,
  timeoutMs: number,
): Promise<boolean> {
  // The view never `require!`s; a require failure means a misconfigured
  // RPC or contract, so it propagates (fail closed) instead of reading
  // as "not escalated".
  const items = await vmQuery(rpc, sc, 'isDivergenceEscalated', [u64MinimalHex(blockHeight)], timeoutMs);
  const b = items[0];
  return b !== undefined && b.length > 0 && b[b.length - 1] === 1;
}

/** Verifiers trust anchored roots only at multiples of this many blocks
 *  (24 h): the only boundaries every honest anchoring interval submits
 *  (spec 03; spec 12 §2.9a, SC 0.12.0 / l2-node 0.154.0). */
export const TRUST_BOUNDARY_BLOCKS = 21_600;

/** Blocks a non-escalated root must be behind the chain tip before it is
 *  trusted (~3 h): until honest nodes contest a front-run root, it is the
 *  canonical answer. */
export const ANCHOR_SETTLE_BLOCKS = 2_700;

/** Tenured agreeing votes (`getEligibleAgreementCount`) a root needs. */
export const TRUSTED_TENURED_VOTES = 3;

/** A root must also hold at least this share of ALL tenured votes at the
 *  height (`getTenuredVotesAt`): `num / den` = 2/3, compared in integers
 *  (`tenured * den >= total * num`), as l2-node does. Tenured colluders who
 *  front-run a height while an honest node is offline face the honest votes
 *  as dissent and stay untrusted instead of forging a root. */
export const TRUSTED_TENURED_SHARE = { num: 2, den: 3 } as const;

/**
 * Every tenured vote cast at `blockHeight`, whatever its root — the SC's
 * `getTenuredVotesAt` view (SC 0.12.0). Throws on an older contract.
 */
export async function getTenuredVotesAt(
  network: ScNetwork,
  blockHeight: number,
  opts: ScQueryOptions = {},
): Promise<number> {
  const { rpc, sc } = net(network);
  assertU64Arg(blockHeight, 'blockHeight');
  const timeoutMs = opts.timeoutMs ?? 8000;
  const items = await vmQuery(rpc, sc, 'getTenuredVotesAt', [u64MinimalHex(blockHeight)], timeoutMs);
  if (items.length === 0) return 0;
  // Parse strictly: `decodeU64Be` maps an oversized value to 0, which here
  // would mean "no dissent" and let the share check pass. Count anything
  // over 8 bytes as maximal dissent, as l2-node does.
  if (items[0].length > 8) return Number.MAX_SAFE_INTEGER;
  return decodeU64Be(items[0]);
}

/** The Klever node's current block nonce (`GET /node/overview`). */
async function getChainTip(rpc: string, timeoutMs: number): Promise<number> {
  const url = rpc.replace(/\/+$/, '') + '/node/overview';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) throw new Error('node/overview HTTP ' + resp.status);
  const json: any = await resp.json();
  const nonce = json && json.data && json.data.overview && json.data.overview.nonce;
  if (!Number.isSafeInteger(nonce) || nonce <= 0) {
    throw new Error('node/overview has no nonce');
  }
  return nonce;
}

/**
 * Tenured agreeing votes for (`blockHeight`, `root`) — the SC's
 * `getEligibleAgreementCount` view (SC 0.12.0): votes from anchorers with
 * 7 days of tenure at the contest start. Throws on an older contract.
 */
export async function getEligibleAgreementCount(
  network: ScNetwork,
  blockHeight: number,
  root: string,
  opts: ScQueryOptions = {},
): Promise<number> {
  const { rpc, sc } = net(network);
  assertU64Arg(blockHeight, 'blockHeight');
  if (!/^[0-9a-f]{64}$/i.test(root)) throw new Error('root must be 64 hex chars');
  const timeoutMs = opts.timeoutMs ?? 8000;
  // The SC stores the root as the bytes of its 64-char hex string.
  const rootArg = bytesToHex(new TextEncoder().encode(root.toLowerCase()));
  const items = await vmQuery(rpc, sc, 'getEligibleAgreementCount', [u64MinimalHex(blockHeight), rootArg], timeoutMs);
  if (items.length === 0) return 0;
  // The SC returns a u32; anything larger is malformed and counts as no
  // tenured votes (fail closed), as in l2-node.
  const n = decodeU64Be(items[0]);
  return n > 0xffff_ffff ? 0 : n;
}

/**
 * The trusted canonical state root anchored at `blockHeight` (64 hex
 * chars), or `null` if there is none — the trust anchor for
 * `verifyStateProof` (l2-node 0.147.0+ state proofs). Same rules as the
 * l2-node verifier (spec 03; SC 0.12.0):
 *
 * - only a DAILY boundary (multiple of {@link TRUST_BOUNDARY_BLOCKS}) at or
 *   below the Klever node's chain tip — at other boundaries the honest
 *   fleet may not anchor at all, so a forged root there goes uncontested;
 * - an escalated height: only its final contest result
 *   ({@link getEscalatedCanonical}) — never the provisional answer, and
 *   nothing for a disputed height;
 * - a non-escalated root only once it is {@link ANCHOR_SETTLE_BLOCKS}
 *   behind the tip (a front-run root is canonical until honest nodes
 *   contest it); escalation is re-checked after reading the root;
 * - in every case at least {@link TRUSTED_TENURED_VOTES} tenured votes for
 *   the root — roots by fresh nodes or planted before SC 0.12.0 have none —
 *   that are at least two thirds of all tenured votes at the height
 *   ({@link getTenuredVotesAt}).
 *
 * Trusted is not yet immutable: a settled, never-contested root can still
 * be contested (three tenured votes on another root) until it is
 * 21 600 blocks behind the tip, and a contest can then replace it — do not
 * cache a verdict as permanent before that, or re-check it. Once that old
 * (or once its contest has closed) the answer will not change. "Will not
 * change" is not "honest": the scheme assumes honest tenured anchorers
 * outnumber any colluding group (spec 12 §2.9a). A malformed canonical root
 * on-chain yields `null` (a malformed contest result makes
 * {@link getEscalatedCanonical} throw). Errors, including an older contract
 * without the views, propagate (fail closed).
 */
export async function getFinalCanonicalAnchor(
  network: ScNetwork,
  blockHeight: number,
  opts: ScQueryOptions = {},
): Promise<string | null> {
  const { rpc, sc } = net(network);
  assertU64Arg(blockHeight, 'blockHeight');
  const timeoutMs = opts.timeoutMs ?? 8000;
  if (blockHeight === 0 || blockHeight % TRUST_BOUNDARY_BLOCKS !== 0) return null;
  const tip = await getChainTip(rpc, timeoutMs);
  if (blockHeight > tip) return null;
  const root = await settledOrFinalRoot(network, rpc, sc, blockHeight, tip, opts, timeoutMs);
  if (root === null) return null;
  const tenured = await getEligibleAgreementCount(network, blockHeight, root, opts);
  if (tenured < TRUSTED_TENURED_VOTES) return null;
  const total = await getTenuredVotesAt(network, blockHeight, opts);
  // Integer form of tenured / total >= num / den, as l2-node computes it.
  const { num, den } = TRUSTED_TENURED_SHARE;
  return tenured * den >= total * num ? root : null;
}

async function settledOrFinalRoot(
  network: ScNetwork,
  rpc: string,
  sc: string,
  blockHeight: number,
  tip: number,
  opts: ScQueryOptions,
  timeoutMs: number,
): Promise<string | null> {
  if (await isDivergenceEscalated(rpc, sc, blockHeight, timeoutMs)) {
    return lower(await getEscalatedCanonical(network, blockHeight, opts));
  }
  let items: Uint8Array[];
  try {
    items = await vmQuery(rpc, sc, 'getCanonicalAnchor', [u64MinimalHex(blockHeight)], timeoutMs);
  } catch (e) {
    if (e instanceof ScRequireError) return null;
    throw e;
  }
  if (items.length === 0 || items[0].length === 0) return null;
  const root = bytesToUtf8(items[0]);
  // A malformed root can only be junk written by colluders (honest nodes
  // submit 64 lowercase hex chars): it is not trustworthy, so no root.
  if (!/^[0-9a-f]{64}$/i.test(root)) return null;
  if (tip < blockHeight + ANCHOR_SETTLE_BLOCKS) return null;
  if (await isDivergenceEscalated(rpc, sc, blockHeight, timeoutMs)) {
    return lower(await getEscalatedCanonical(network, blockHeight, opts));
  }
  return root.toLowerCase();
}

function lower(root: string | null): string | null {
  return root === null ? null : root.toLowerCase();
}
