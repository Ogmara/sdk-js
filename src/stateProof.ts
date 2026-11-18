/**
 * Verification of state inclusion proofs from `GET /api/v1/state/proof`
 * (l2-node 0.148.0+, anchored state root v4; spec 03 §3.6, spec 02 §7).
 *
 * A proof shows that an on-chain user registration, channel or device
 * delegation is part of the state root anchored on-chain at
 * `block_height`. The node is not trusted: {@link verifyStateProof} checks
 * that the proof is about the record you ASKED for (key rebuilt from your
 * query, identity fields inside the value), recomputes the leaf from the
 * value, rebuilds the subtree root from the sibling path, frames it with
 * the other subtree `(count, root)` pairs into the state root and compares
 * that with the root you supply — normally the canonical root from
 * {@link getFinalCanonicalAnchor} (or use {@link verifyStateProofOnChain},
 * which does both).
 *
 * What a valid proof means: the record had this value in the state anchored
 * at `block_height`. It says nothing about later changes — bind a recent
 * height with `minBlockHeight`, and for delegations also check the proven
 * record's `revoked_at` / `expires_at`. Only chain records are anchored
 * (v4): a users record exists exactly for on-chain registered wallets.
 * Profiles, channel metadata, memberships and messages are not anchored —
 * they are authenticated by their authors' signatures.
 *
 * Mirrors `l2-node/src/crypto/merkle.rs` (`hash_leaf`, `hash_pair`,
 * `root_from_path`, `frame_state_root`) and the key layout of
 * `l2-node/src/storage/anchored_state.rs`.
 */

import { sha256 } from '@noble/hashes/sha2';
import { getFinalCanonicalAnchor, type ScQueryOptions } from './sc_queries';
import type { ScNetwork } from './sc_discovery';

/** The anchored subtrees, in state-root framing order. */
export const STATE_SUBTREES = ['users', 'channels', 'delegations'] as const;
export type StateSubtree = (typeof STATE_SUBTREES)[number];

/** `ogmara-state-root-v4` — the node's `STATE_ROOT_DOMAIN`. */
const STATE_ROOT_DOMAIN = new TextEncoder().encode('ogmara-state-root-v4');

/** One subtree's `(count, root)` as served in a proof. */
export interface StateProofSubtree {
  name: StateSubtree;
  count: number;
  /** 64 hex chars. */
  root: string;
}

/** Wire shape of `GET /api/v1/state/proof`. */
export interface StateProof {
  block_height: number;
  /** 64 hex chars — the root this node anchored at `block_height`. */
  state_root: string;
  /** Node hint that this height's root matched the canonical root on-chain.
   *  Not trusted — verification always checks the chain. */
  canonical_confirmed?: boolean;
  subtree: StateSubtree;
  /** Hex key of the record in the node's anchored chain mirror. */
  key: string;
  /** Base64 canonical record value (the bytes the leaf hashes), as sealed
   *  at `block_height`. */
  value: string;
  leaf: string;
  leaf_index: number;
  leaf_count: number;
  siblings: string[];
  subtrees: StateProofSubtree[];
}

/** Query for {@link OgmaraClient.getStateProof}. */
export type StateProofQuery =
  | { subtree: 'users'; address: string; height?: number }
  | { subtree: 'channels'; channelId: number; height?: number }
  | { subtree: 'delegations'; address: string; deviceKey: string; height?: number };

/** What a proof must match, for {@link verifyStateProof}. */
export interface StateProofExpectation {
  /** The trusted state root (64 hex chars), normally from
   *  {@link getFinalCanonicalAnchor} for `proof.block_height`. */
  stateRoot: string;
  /** The query the proof was requested for; the proof must be about exactly
   *  this record (and this height, when `query.height` is set). */
  query: StateProofQuery;
  /** Reject proofs anchored below this height (stale state). */
  minBlockHeight?: number;
}

/** Result of {@link verifyStateProof}. */
export type StateProofVerdict =
  | {
      ok: true;
      blockHeight: number;
      subtree: StateSubtree;
      key: Uint8Array;
      /** The proven record bytes. */
      value: Uint8Array;
      /** The proven record, parsed: users `{address, public_key}`, channels
       *  `{channel_id, creator, slug}`, delegations `{created_at, device_key,
       *  expires_at, permissions, revoked_at, user}`. */
      record: unknown;
    }
  | { ok: false; reason: string };

function fromHex(hex: unknown, bytes?: number): Uint8Array | null {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  if (bytes !== undefined && hex.length !== bytes * 2) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromBase64(b64: unknown): Uint8Array | null {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return null;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/** The node's anchored-mirror key for the queried record
 *  (`l2-node storage::anchored_state`): `u` + address, `c` + u64 BE channel
 *  id, `d` + address + 0x00 + device key. */
export function stateRecordKey(query: StateProofQuery): Uint8Array {
  if ('channelId' in query && (!Number.isSafeInteger(query.channelId) || query.channelId < 0)) {
    throw new Error('channelId must be a non-negative safe integer');
  }
  switch (query.subtree) {
    case 'users':
      return concat(utf8('u'), utf8(query.address));
    case 'channels':
      return concat(utf8('c'), u64be(query.channelId));
    case 'delegations':
      return concat(utf8('d'), utf8(query.address), new Uint8Array([0x00]), utf8(query.deviceKey));
  }
}

/** The leaf hashes the value only, so the record must name itself: its
 *  identity fields must match the query. */
function valueMatchesQuery(query: StateProofQuery, record: unknown): boolean {
  if (!record || typeof record !== 'object') return false;
  const r = record as Record<string, unknown>;
  switch (query.subtree) {
    case 'users':
      return r.address === query.address;
    case 'channels':
      return r.channel_id === query.channelId;
    case 'delegations':
      return r.user === query.address && r.device_key === query.deviceKey;
  }
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** `SHA-256(0x00 || data)` — node `hash_leaf`. */
export function hashStateLeaf(data: Uint8Array): Uint8Array {
  return sha256(concat(new Uint8Array([0x00]), data));
}

/** Leaf of a record: `hashStateLeaf(value)` — each canonical value names
 *  its own identity (address, channel id, user + device key). */
export function stateRecordLeaf(value: Uint8Array): Uint8Array {
  return hashStateLeaf(value);
}

function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

/** Rebuild a subtree root from a leaf, its index, the subtree's leaf count
 *  and the sibling path (directions come from the index; an odd last node is
 *  paired with itself and has no sibling entry). `null` if malformed. */
export function stateRootFromPath(
  leaf: Uint8Array,
  index: number,
  leafCount: number,
  siblings: readonly Uint8Array[],
): Uint8Array | null {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(leafCount) || index < 0 || index >= leafCount) {
    return null;
  }
  let hash = leaf;
  let idx = index;
  let n = leafCount;
  let s = 0;
  while (n > 1) {
    if (idx % 2 === 1) {
      if (s >= siblings.length) return null;
      hash = hashPair(siblings[s++], hash);
    } else if (idx + 1 < n) {
      if (s >= siblings.length) return null;
      hash = hashPair(hash, siblings[s++]);
    } else {
      hash = hashPair(hash, hash);
    }
    idx = Math.floor(idx / 2);
    n = Math.ceil(n / 2);
  }
  return s === siblings.length ? hash : null;
}

/** Frame the subtree `(count, root)` pairs into the anchored state root. */
export function frameStateRoot(subtrees: ReadonlyArray<{ count: number; root: Uint8Array }>): Uint8Array {
  return sha256(concat(STATE_ROOT_DOMAIN, ...subtrees.flatMap((s) => [u64be(s.count), s.root])));
}

/**
 * Verify that `proof` proves the record `expected.query` asks for, in the
 * state whose root is `expected.stateRoot`. The root must come from a
 * source you trust (the chain), never from the proof or the node.
 */
export function verifyStateProof(proof: StateProof, expected: StateProofExpectation): StateProofVerdict {
  const fail = (reason: string): StateProofVerdict => ({ ok: false, reason });
  if (!proof || typeof proof !== 'object') return fail('malformed proof');
  if (!expected || typeof expected !== 'object' || !expected.query) return fail('missing expectation');
  const index = STATE_SUBTREES.indexOf(proof.subtree);
  if (index < 0) return fail('unknown subtree');
  if (!Number.isSafeInteger(proof.block_height) || proof.block_height < 0) return fail('bad block_height');
  const expectedRoot = fromHex(expected.stateRoot, 32);
  if (!expectedRoot) return fail('bad expected root');
  const stateRoot = fromHex(proof.state_root, 32);
  const key = fromHex(proof.key);
  const value = fromBase64(proof.value);
  const leaf = fromHex(proof.leaf, 32);
  if (!stateRoot || !key || !value || !leaf) return fail('malformed proof field');
  if (!Array.isArray(proof.siblings) || proof.siblings.length > 64) return fail('bad siblings');
  const siblings = proof.siblings.map((h) => fromHex(h, 32));
  if (siblings.some((s) => !s)) return fail('bad sibling hash');
  if (!Array.isArray(proof.subtrees) || proof.subtrees.length !== STATE_SUBTREES.length) {
    return fail('bad subtrees');
  }
  const framed: { count: number; root: Uint8Array }[] = [];
  for (let i = 0; i < STATE_SUBTREES.length; i++) {
    const st = proof.subtrees[i];
    const root = fromHex(st?.root, 32);
    if (st?.name !== STATE_SUBTREES[i] || !root || !Number.isSafeInteger(st.count) || st.count < 0) {
      return fail('bad subtrees');
    }
    framed.push({ count: st.count, root });
  }

  // The proof must be about the record that was asked for, at the height
  // that was asked for.
  const query = expected.query;
  if (proof.subtree !== query.subtree) return fail('proof is for a different subtree');
  let expectedKey: Uint8Array;
  try {
    expectedKey = stateRecordKey(query);
  } catch {
    return fail('bad query');
  }
  if (!equal(expectedKey, key)) return fail('proof is for a different record');
  if (query.height !== undefined && proof.block_height !== query.height) return fail('proof is for a different height');
  if (expected.minBlockHeight !== undefined && proof.block_height < expected.minBlockHeight) {
    return fail('proof is older than minBlockHeight');
  }
  let record: unknown;
  try {
    record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value));
  } catch {
    return fail('record value is not JSON');
  }
  if (!valueMatchesQuery(query, record)) return fail('record does not belong to the queried key');

  if (!equal(stateRecordLeaf(value), leaf)) return fail('value does not match leaf');
  if (framed[index].count !== proof.leaf_count) return fail('leaf_count does not match subtree count');
  const subRoot = stateRootFromPath(leaf, proof.leaf_index, proof.leaf_count, siblings as Uint8Array[]);
  if (!subRoot) return fail('malformed inclusion path');
  if (!equal(subRoot, framed[index].root)) return fail('path does not lead to the subtree root');
  if (!equal(frameStateRoot(framed), stateRoot)) return fail('subtrees do not frame to state_root');
  if (!equal(expectedRoot, stateRoot)) return fail('state_root is not the expected root');
  return { ok: true, blockHeight: proof.block_height, subtree: proof.subtree, key, value, record };
}

/**
 * Fetch the canonical root for `proof.block_height` from the Klever SC and
 * verify that `proof` proves the record `query` asks for against it. Fails
 * with reason `not_canonical` when the height has no canonical root yet
 * (not canonicalized, or escalated and still provisional) — retry later or
 * request an older height. See {@link getFinalCanonicalAnchor} for what
 * "final" can and cannot guarantee.
 *
 * @throws on RPC/network failure or an error from the escalation view
 *   (fails closed) — distinct from the `not_canonical` verdict.
 */
export async function verifyStateProofOnChain(
  proof: StateProof,
  query: StateProofQuery,
  network: ScNetwork,
  opts: ScQueryOptions & { minBlockHeight?: number } = {},
): Promise<StateProofVerdict> {
  if (!proof || !Number.isSafeInteger(proof.block_height) || proof.block_height < 0) {
    return { ok: false, reason: 'bad block_height' };
  }
  const root = await getFinalCanonicalAnchor(network, proof.block_height, opts);
  if (root === null) return { ok: false, reason: 'not_canonical' };
  return verifyStateProof(proof, { stateRoot: root, query, minBlockHeight: opts.minBlockHeight });
}
