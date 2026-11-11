/**
 * Shared channel KEYRING (sdk-js 0.68.0): the in-memory store of channel
 * epoch keys and its key-vault mapping, shared by web, desktop and mobile
 * instead of three separate implementations.
 *
 * Keys are addressed by slot `${scopeHex}:${epoch}`. A slot holds a PRIMARY
 * key (decrypt first, send / cover under) and ALTERNATES: other keys seen for
 * the same epoch (a superseded winner, a key restored from the vault, our own
 * not-yet-final key that lost). All rules are pinned by
 * `channelKeyring.test.ts` and the seeded property test.
 *
 * THREE DIFFERENT CHECKS — never confuse them:
 *  - PAIR-CONSISTENT (`verified`): the key's pair `(keyTs, commitment)`
 *    re-hashes to the key (`computeKeyCommitment`, done by the keyring). Says
 *    nothing about WHO made the key: a hostile node can compute a consistent
 *    pair for any key of its own, with any `keyTs`.
 *  - AUTHOR-VERIFIED (`source: 'establish' | 'wrap'`): we made the key, or its
 *    wrap's author and membership were verified (`verifyChannelKeyWrap`). The
 *    caller attests this by the source it passes. `fetch`, `legacy` and
 *    `vault` keys are NOT author-verified; `markVerified` cannot make them so
 *    (it returns `'needs_author_proof'`) — re-`put` the same bytes with
 *    `source: 'wrap'` once the wrap verified.
 *  - FINAL (`final`): the node reported this pair as the epoch's final winner.
 *
 * TRUSTED = author-verified AND pair-consistent AND not provisional. Only a
 * trusted key counts as evidence (`latestVerified`) or is sent under.
 *
 * PRIMARY ORDER (rank): trusted+final 4 > trusted 3 > provisional (our own
 * not-final first key) 2 > own provenance / vault 1 > node-served 0. A key
 * strictly better than the primary PROMOTES itself; the old primary stays as
 * an alternate. Among equal ranks the FIRST SEEN key stays primary.
 *
 * NEVER LOSE A KEY
 *  - A put or import never overwrites a held key and never changes held bytes
 *    in place; keys are COPIED in and out (caller buffers are never kept or
 *    zeroed).
 *  - Only UNPROTECTED keys may be refused, evicted or left out of a backup:
 *    NODE-SERVED keys no author source ever vouched for (`nodeServed`; backed
 *    up under their own `#ns<n>` names and still node-served after a restore)
 *    — the node can serve them again. Being backed up never protects them.
 *    A commitment-less node-served key is not held at an occupied epoch.
 *  - No cap ever evicts an own, author-verified, provisional or restored key.
 *    Other members' wraps (not `ownSlot`) beyond the member caps are REFUSED,
 *    never evicting anything ({@link MAX_MEMBER_EPOCHS_PER_SCOPE}, per-epoch
 *    and per-session limits); only `pruneUnverified` (user-confirmed) removes
 *    keys that are not node-served.
 *  - Downgrades ("this pair lost") are NOT in the keyring: clients keep that
 *    state themselves; the keyring never lowers a key.
 *  - `exportForVault()` is the UNION of every held exportable PROTECTED key,
 *    every vault entry this keyring could not interpret, and — within the
 *    byte budget ({@link VAULT_CHAN_SOFT_LIMIT_BYTES}) — the unprotected
 *    ones, under COLLISION-FREE names in CANONICAL order (see VAULT FORMAT).
 *    If the protected keys alone exceed the budget it throws
 *    `vault_too_large`; it never silently shrinks. A provisional key is held
 *    back until finalised (or until a vault copy of it exists).
 *
 * VAULT FORMAT (unchanged, cross-client): the `chan` map. Per slot, in this
 * order: `${scope}:${epoch}` (primary), `${slot}#pri` (a COPY of the primary
 * value), `${slot}#alt<n>` ascending, `${slot}#ovf<n>` ascending; every
 * uninterpretable entry after all slots. New alternates are numbered from
 * `#alt5` ({@link FIRST_WRITTEN_ALT_INDEX}) up to {@link MAX_ALT_INDEX}, then
 * `#ovf<n>`. Older clients keep 4 alternates and rewrite `S:E` and
 * `#alt1..#alt4` on their own export: one with room renumbers ours (values
 * kept); one whose own slot is FULL keeps ours verbatim — under names it never
 * rewrites (`#alt5+`, `#pri`), so the only name it overwrites (`S:E`) is
 * backed by the `#pri` copy. Read: `#alt1..#alt999`, `#ovf<n>`, `#pri`, and
 * `${slot}~<n>` (older mobile); `#alt1..#alt4` and `~<n>` are re-homed to
 * `#alt5+` on export, every other name stays stable once assigned.
 *
 * CALLER RESPONSIBILITIES: `source: 'wrap'` only after `verifyChannelKeyWrap`
 * verified the wrap's author and membership; `final` only for the pair the
 * node reports as the epoch's final winner; `ownSlot: true` for EVERY wrap
 * from our own slot that our own wallet authored (else it counts as another
 * member's: refused once the member cap is full, prunable as `memberWraps`) —
 * after a restart re-verify the latest own epoch first; `maxEpoch` (node
 * highest + 256) on puts of keys that are not ours and on `importFromVault`. RESIDUAL (by design): a malicious
 * MEMBER can author a verified wrap, and a hostile node can call its pair
 * final — that key then outranks our own non-final key; among two final keys
 * the first seen stays (no tie-break can be trusted when `final` can be
 * claimed for both).
 *
 * The keyring never logs and never puts key material into an error message.
 */
import { computeKeyCommitment, keyCommitmentsEqual } from './channelKeyCommit';
import { renameProtoKey } from './keyVault';
import { keccak_256 } from '@noble/hashes/sha3';

/** Where a key came from. */
export type ChannelKeySource =
  /** `establishEpochKey`: our own key, or a winner it adopted from an author-verified wrap. AUTHOR-VERIFIED. */
  | 'establish'
  /** Our own slot's wrap, author-verified (`verifyChannelKeyWrap`). AUTHOR-VERIFIED. */
  | 'wrap'
  /** Served by a node from our slot, NOT author-verified. */
  | 'fetch'
  /** Restored from this wallet's key vault (provenance not recorded: NOT author-verified). */
  | 'vault'
  /** A commitment-less (pre-arbitration) key served by a node. */
  | 'legacy';

/** An arbitration pair `(keyTs, keyCommitment)` of a key (protocol §8.1). */
export interface ChannelKeyPair {
  keyTs: number;
  /** 32-byte key commitment. */
  commitment: Uint8Array;
}

/** Options of {@link ChannelKeyring.put}. */
export interface ChannelKeyPutOptions {
  source: ChannelKeySource;
  /** The key's pair, when known. Never with `source: 'legacy'`. */
  pair?: ChannelKeyPair;
  /**
   * PAIR-CONSISTENT: the keyring re-hashes `pair` to this key (else
   * `'invalid'`). Not author verification — that is the `source`.
   */
  verified?: boolean;
  /** The node reports this pair FINAL. Requires `verified`. */
  final?: boolean;
  /**
   * `true`: our own not-yet-final key (early use; `source: 'establish'` only):
   * held, never exported until finalised. A held provisional key is
   * finalised ONLY by an author source (`establish` / `wrap`) with
   * `provisional: false` or `verified` + `final`; a `fetch` / `vault` copy
   * never finalises it, even claiming `final`.
   */
  provisional?: boolean;
  /**
   * With `source: 'wrap'`: the wrap's verified AUTHOR is our own wallet (a key WE
   * established, e.g. re-verified from our own slot after a restart). Such keys are ours:
   * never subject to the member caps. Leave unset for keys other members authored.
   */
  ownSlot?: boolean;
  /**
   * Ceiling for keys that are not ours: clients MUST pass the node's highest epoch + 256.
   * A node-served key or another member's wrap (final or not) above it is `'refused'`;
   * own keys (`establish`, provisional, `ownSlot`) and client-put `vault` keys never are.
   */
  maxEpoch?: number;
  /** Account-switch generation captured BEFORE the caller's network round trip. */
  generation?: number;
}

/** Options of {@link ChannelKeyring.importFromVault}. */
export interface ChannelKeyImportOptions {
  /**
   * The node's highest epoch + 256 at restore time. Restored keys of unknown provenance
   * ABOVE it cannot be ours (no node accepts such an epoch from us); they are classed
   * `memberWraps` for `pruneUnverified`, so a restored member flood can be removed
   * without touching history below the ceiling. They are still imported (never dropped).
   */
  maxEpoch?: number;
}

/** Options of {@link ChannelKeyring.markVerified}. */
export interface ChannelKeyMarkOptions {
  /** The node reports the pair FINAL. */
  final?: boolean;
  generation?: number;
}

/** Result of {@link ChannelKeyring.put}. */
export type ChannelKeyPutResult =
  /** Held (new slot, or the same bytes merged) without becoming a new primary. */
  | 'stored'
  /** Became the slot's primary over a lower-ranked key, which stays as an alternate. */
  | 'promoted'
  /** A different key stays primary; this key was kept as an alternate. Log / heal (gated). */
  | 'conflict'
  /** NOT held: an unprotected node-served key (alternate cap, untrusted-epoch cap, or a commitment-less duplicate). Never a protected key. */
  | 'refused'
  /** Dropped: the account generation changed. */
  | 'stale'
  /** Dropped: malformed input, or a `verified` pair that does not hash to the key. */
  | 'invalid';

/** Result of {@link ChannelKeyring.markVerified}. */
export type ChannelKeyMarkResult =
  | 'verified'
  | 'promoted'
  /** The key is held but not author-verified (`fetch` / `legacy` / `vault`): nothing changed. */
  | 'needs_author_proof'
  | 'not_held'
  | 'pair_mismatch'
  | 'stale'
  | 'invalid';

/** A held key, as a COPY (mutating it never changes the keyring). */
export interface ChannelKeyInfo {
  key: Uint8Array;
  source: ChannelKeySource;
  /** PAIR-CONSISTENT (see the module comment). */
  verified: boolean;
  /** `source` is `establish` or `wrap`. */
  authorVerified: boolean;
  /** Author-verified AND pair-consistent AND not provisional: evidence / send grade. */
  trusted: boolean;
  /** The node reported the pair final. */
  final: boolean;
  pair?: ChannelKeyPair;
  provisional: boolean;
  /** Goes into the vault export. */
  exportable: boolean;
  /** Restored from, or already written to, the vault (never evicted — unless `nodeServed`). */
  persisted: boolean;
  /**
   * NODE-SERVED provenance and never vouched for by an author source (backed up as
   * `#ns<n>`): may be evicted or left out of a backup at any time; the node can serve
   * it again. Re-`put` it with `source: 'wrap'` after `verifyChannelKeyWrap` to protect it.
   */
  nodeServed: boolean;
  /** Ours: established by us, put with `ownSlot`, or provisional. Never member-capped. */
  own: boolean;
  /** Restored from (or merged by) a vault import: provenance unknown. */
  restored: boolean;
  /** The slot's primary. */
  primary: boolean;
}

/** Options of {@link ChannelKeyring.pruneUnverified}. */
export interface ChannelKeyPruneOptions {
  /** Epochs per scope (its highest) left untouched (default 16). */
  keepLatestPerScope?: number;
  /** Only report what would be removed. */
  dryRun?: boolean;
  /**
   * LAST RESORT: also remove keys restored under the PRIMARY vault name (most likely
   * the user's own history after a restart). Default false.
   */
  includeRestoredPrimaries?: boolean;
  /**
   * Classes to remove (default `['nodeServed']`, the zero-risk path):
   *  - `nodeServed`: keys a node served that no author vouched for (`#ns`);
   *  - `restoredAlternates`: restored from `#alt` / `~` names — MAY be the user's own key
   *    that another key outranked (see `byClass.ownAlternatesAtRisk`);
   *  - `memberWraps`: other members' non-final wraps of this session;
   *  - `restoredPrimaries`: restored primary-name keys (or client-put `vault` keys once
   *    backed up) — most likely the user's own history: last resort (same as
   *    `includeRestoredPrimaries`).
   */
  classes?: ChannelKeyPruneClassName[];
  /** Only these scopes (e.g. the one channel a hostile member flooded). Default: all. */
  scopes?: string[];
  generation?: number;
}

/** A class of keys `pruneUnverified` can remove. */
export type ChannelKeyPruneClassName = 'nodeServed' | 'restoredAlternates' | 'memberWraps' | 'restoredPrimaries';

/** Count and estimated vault bytes of one class of pruned keys. */
export interface ChannelKeyPruneClass {
  count: number;
  bytes: number;
}

/** Result of {@link ChannelKeyring.pruneUnverified}. */
export interface ChannelKeyPruneResult {
  removedCount: number;
  /** Estimated vault bytes those keys took. */
  removedBytes: number;
  /** Per class: node-served (`#ns`, fetched), restored alternates (`#alt`, `~`), restored primary-name keys, member wraps. */
  byClass: {
    nodeServed: ChannelKeyPruneClass; restoredAlternates: ChannelKeyPruneClass; restoredPrimaries: ChannelKeyPruneClass;
    memberWraps: ChannelKeyPruneClass;
    /** Of the removed restored alternates: these MAY be the user's own outranked keys — warn before confirming. */
    ownAlternatesAtRisk: ChannelKeyPruneClass;
  };
}

/** Opaque handle from {@link ChannelKeyring.prepareExport}, redeemed by {@link ChannelKeyring.commitExport}. */
export interface ChannelKeyExportToken {
  readonly __channelKeyExportToken: true;
}

/** Result of {@link ChannelKeyring.prepareExport}. */
export interface ChannelKeyPreparedExport {
  /** The vault `chan` record (same as `exportForVault` returns). */
  chan: Record<string, Uint8Array>;
  /** Pass to `commitExport` ONLY after the sealed vault was published successfully. */
  commitToken: ChannelKeyExportToken;
}

/** Options of {@link ChannelKeyring.bestForSendLegacy}. */
export interface ChannelKeyLegacyQuery {
  /** Ignore epochs above this (node highest + 256). */
  maxEpoch?: number;
  /** REQUIRED: true only for an epoch the node reports as legacy (commitment-less). */
  isLegacyEpoch: (epoch: number) => boolean;
}

/** A held key with its epoch. */
export interface ChannelKeyHeld extends ChannelKeyInfo {
  epoch: number;
}

/** Construction options (all caps have safe defaults). */
export interface ChannelKeyringOptions {
  /** Current account-switch generation; when given, puts / marks / import / export must pass a matching `generation`. */
  generation?: () => number;
  /** Alternates per epoch before UNPROTECTED ones are evicted (default {@link MAX_ALTS_PER_EPOCH}). */
  maxAltsPerEpoch?: number;
  /** Untrusted epochs ABOVE the highest trusted epoch, per scope, before new node-served epochs there are refused (default {@link MAX_UNTRUSTED_EPOCHS_PER_SCOPE}). */
  maxUntrustedEpochsPerScope?: number;
  /** Absolute epochs per scope beyond which a new node-served epoch is refused (default {@link MAX_EPOCHS_PER_SCOPE}). */
  maxEpochsPerScope?: number;
  /** New node-served epochs at or below the trusted epoch, per scope per session (default {@link MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE}). */
  maxSessionHistoryEpochsPerScope?: number;
  /** Byte budget of the exported `chan` map (default {@link VAULT_CHAN_SOFT_LIMIT_BYTES}). */
  maxVaultBytes?: number;
  /** Maybe-member epochs above the highest final epoch per scope before other members' new wraps are refused (default {@link MAX_MEMBER_EPOCHS_PER_SCOPE}). */
  maxMemberEpochsPerScope?: number;
  /** Uninterpretable vault entries kept verbatim (default {@link MAX_OPAQUE_VAULT_ENTRIES}). */
  maxOpaqueEntries?: number;
}

/** Error codes of {@link ChannelKeyringError}. */
export type ChannelKeyringErrorCode =
  /** The vault held more uninterpretable entries than the cap: a backup would shrink it, so it is refused. */
  | 'opaque_overflow'
  /** Import / export for an outdated account generation. */
  | 'stale'
  /** The keys that must be backed up exceed the vault byte budget: the backup is refused, never shrunk. */
  | 'vault_too_large';

/** Thrown by {@link ChannelKeyring.exportForVault} / {@link ChannelKeyring.importFromVault}. Never carries key material. */
export class ChannelKeyringError extends Error {
  readonly code: ChannelKeyringErrorCode;
  constructor(code: ChannelKeyringErrorCode, message: string) {
    super(message);
    this.name = 'ChannelKeyringError';
    this.code = code;
  }
}

/** Alternates per epoch kept before unprotected ones are evicted (cross-client `#alt1..#alt4`). */
export const MAX_ALTS_PER_EPOCH = 4;
/**
 * UNTRUSTED epochs per scope — epochs holding no own / author-verified /
 * provisional key — counted only ABOVE the scope's highest trusted epoch
 * (`latestVerified`), before a NEW node-served epoch there is refused (the
 * oldest all-unprotected one is evicted first). History at or below the
 * trusted epoch does not count, so re-verifying the latest own-slot wrap after
 * a restart frees all restored history; restored epochs above it count, so a
 * hostile node cannot grow the backup across sessions. Equal to the node's
 * own per-scope key row cap.
 */
export const MAX_UNTRUSTED_EPOCHS_PER_SCOPE = 512;
/** Absolute memory bound: a new node-served epoch is refused once a scope holds this many epochs (protected keys are never evicted for it). */
export const MAX_EPOCHS_PER_SCOPE = 4096;
/**
 * New node-served epochs AT OR BELOW the scope's highest trusted epoch taken
 * per scope per SESSION (oldest unprotected shed beyond it, else refused).
 * Restored history is exempt; a reader's legacy history still accumulates,
 * but at most this much per session, never in one burst.
 */
export const MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE = 64;
/**
 * Byte budget of the exported `chan` map (estimated msgpack size, see
 * {@link estimateVaultChanBytes}): 1.5 MiB of the node's 2 MiB sealed-vault
 * limit (l2-node MAX_KEY_VAULT_SIZE = 2,097,152 B), leaving room for `conv`
 * and the AEAD framing. Over half of it the `#pri` copies are dropped; over
 * it, unprotected node-served keys are left out; if protected keys alone
 * exceed it the export throws `vault_too_large`.
 */
export const VAULT_CHAN_SOFT_LIMIT_BYTES = 1_572_864;
/** `#pri` copies written per scope (its highest epochs) and in total — old mobile keeps at most 1024 unknown entries. */
export const PRI_COPIES_PER_SCOPE = 16;
/**
 * Share of the byte budget node-served (`#ns`) keys may fill in an export: they are
 * included only while the WHOLE record stays within this share, so however much a
 * hostile node serves, at least 3/4 of the budget stays for the user's own keys.
 */
export const NODE_SERVED_VAULT_SHARE = 0.25;
/**
 * Epochs per scope ABOVE the highest FINAL epoch that may be another member's (no own /
 * final / provisional key, not only node keys; restored keys of unknown provenance count
 * after a restart): beyond it another member's NEW wrap epoch is refused. Refuse-only —
 * nothing is ever evicted for it. Our own keys (`establish`, provisional, `ownSlot` wraps)
 * are never capped. Residual: a hostile member can make further member wraps be refused.
 */
export const MAX_MEMBER_EPOCHS_PER_SCOPE = 512;
export const MAX_PRI_COPIES = 512;

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;
/** Estimated msgpack bytes of one `chan` entry: str header + name + bin8 header + 32. */
function entryBytes(name: string): number {
  const n = utf8Len(name);
  return (n < 32 ? 1 : n < 256 ? 2 : n < 65536 ? 3 : 5) + n + 2 + 32;
}
/** Estimated msgpack size of a vault `chan` map (what `exportForVault` budgets against). */
export function estimateVaultChanBytes(chan: Record<string, Uint8Array>): number {
  let t = 5;
  for (const name of Object.keys(chan)) t += entryBytes(name);
  return t;
}
/**
 * First alias index WRITTEN for a new alternate. Older clients keep at most 4
 * alternates and rewrite `#alt1..#alt4` on their own export; an older client
 * whose own slot is full keeps our aliases verbatim, so they must never be
 * one of those four names.
 */
export const FIRST_WRITTEN_ALT_INDEX = 5;
/** Uninterpretable vault entries kept verbatim (re-exported unchanged); a memory bound. */
export const MAX_OPAQUE_VAULT_ENTRIES = 8192;
/** Highest `#alt<n>` index WRITTEN (read: 1..999); beyond it `#ovf<n>`. */
export const MAX_ALT_INDEX = 64;

const KEY_LEN = 32;
const SCOPE_RE = /^[0-9A-Za-z]{1,128}$/;
const SCOPE_HEX32_RE = /^[0-9a-fA-F]{64}$/;
/**
 * A vault `chan` entry name: `<scope>:<epoch>` with an optional alias
 * `#alt<n>`, `~<n>` (older mobile) or `#ovf<n>`. Epoch without leading zeros
 * so a parsed name is re-generated byte-identically; anything else is opaque.
 */
const VAULT_NAME_RE = /^([0-9A-Za-z]{1,128}):(0|[1-9]\d{0,15})(?:#alt([1-9]\d{0,2})|~([1-9]\d{0,2})|#ovf([1-9]\d{0,5})|(#pri)|#ns([1-9]\d{0,5}))?$/;

const SOURCE_RANK: Record<ChannelKeySource, number> = { legacy: 0, fetch: 1, vault: 2, wrap: 3, establish: 4 };
const SOURCES = new Set<ChannelKeySource>(['establish', 'wrap', 'fetch', 'vault', 'legacy']);

interface Entry {
  key: Uint8Array;
  source: ChannelKeySource;
  /** Pair-consistent. */
  pairOk: boolean;
  pair?: ChannelKeyPair;
  final: boolean;
  provisional: boolean;
  /** Restored from or written to the vault. */
  persisted: boolean;
  /** The vault name this key was last read / written under (kept stable across exports). */
  vaultName?: string;
  /** Came only from an alias name: never claims the primary vault name. */
  aliasOrigin: boolean;
  /** Was served by a node (`fetch` / `legacy`) in this session: never an `allowUnverified` send key. */
  served: boolean;
  /**
   * NODE-SERVED provenance, never author-verified: served by a node, or restored from a
   * `#ns<n>` vault name. Never protected — not even once backed up — so node junk can
   * always be shed; cleared when an author source (`establish` / `wrap`) puts the key.
   */
  ns: boolean;
  /** Ours (`establish`, `ownSlot` wrap, provisional) — sticky. */
  own: boolean;
  /** Ever restored from / merged by a vault import (or put as `vault`) — sticky. */
  wasVault: boolean;
  /** Restored ABOVE the import ceiling (`importFromVault` `maxEpoch`): cannot be ours. */
  aboveCeiling: boolean;
  seq: number;
}

interface Slot {
  entries: Entry[];
  seq: number;
  /** Created in THIS session by a node-served put (counts against the session history budget). */
  nodeNew: boolean;
  /** Created in THIS session by another member's wrap (counts against the session budget below the final epoch). */
  memberNew: boolean;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
};

const isKey = (v: unknown): v is Uint8Array => v instanceof Uint8Array && v.length === KEY_LEN;
const isEpoch = (e: unknown): e is number => typeof e === 'number' && Number.isSafeInteger(e) && e >= 0;
const isAuthor = (s: ChannelKeySource): boolean => s === 'establish' || s === 'wrap';
const isNodeServed = (s: ChannelKeySource): boolean => s === 'fetch' || s === 'legacy';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function validPair(p: unknown): p is ChannelKeyPair {
  const q = p as ChannelKeyPair | undefined;
  return !!q && isEpoch(q.keyTs) && isKey(q.commitment);
}

const copyPair = (p: ChannelKeyPair): ChannelKeyPair => ({ keyTs: p.keyTs, commitment: p.commitment.slice() });

/** Does `pair` re-hash to `key` at (scope, epoch)? False for a non-hex scope. */
function pairMatches(scopeHex: string, epoch: number, key: Uint8Array, pair: ChannelKeyPair): boolean {
  if (!SCOPE_HEX32_RE.test(scopeHex)) return false;
  return keyCommitmentsEqual(computeKeyCommitment(hexToBytes(scopeHex), epoch, pair.keyTs, key), pair.commitment);
}

const trusted = (e: Entry): boolean => isAuthor(e.source) && e.pairOk && !e.provisional;

/** Primary rank (module comment). */
function rank(e: Entry): number {
  if (trusted(e)) return e.final ? 4 : 3;
  if (e.provisional) return 2;
  return isNodeServed(e.source) || e.ns ? 0 : 1;
}

/**
 * May this key be refused / evicted / left out of a backup? Only a NODE-SERVED key that
 * no author source ever vouched for (`ns`) — backed up or not: the node can serve it again.
 */
function unprotected(e: Entry): boolean {
  return e.ns && !e.provisional;
}

const exportable = (e: Entry): boolean => !e.provisional || e.persisted;

/** An untrusted epoch for the per-scope cap: no own / author-verified / provisional key in it. */
const untrustedSlot = (s: Slot): boolean => s.entries.every((e) => !isAuthor(e.source) && !e.provisional);

/** Record a pair-consistent pair: the first one stays unless a FINAL one replaces a non-final one. */
function notePair(e: Entry, pair: ChannelKeyPair, final: boolean): void {
  if (!e.pairOk || !e.pair || (final && !e.final)) e.pair = copyPair(pair);
  e.pairOk = true;
  if (final) e.final = true;
}

const EXPORT_TOKENS = new WeakMap<object, { ring: object; clears: number; items: Array<{ e: Entry; name: string }> }>();

/** Session id of a pruned key: slot + keccak of the key (no key material kept). */
function prunedId(scope: string, epoch: number, key: Uint8Array): string {
  const h = keccak_256(key);
  let x = '';
  for (let i = 0; i < 16; i++) x += h[i]!.toString(16).padStart(2, '0');
  return `${scope}:${epoch}|${x}`;
}

/**
 * Should a node-served key envelope be accepted for `requestedEpoch`? Only
 * when the envelope's own epoch is a non-negative safe integer EQUAL to the
 * epoch the client asked for: a hostile node otherwise labels a key with an
 * arbitrary epoch (e.g. 100000) and we would store it there. Clients MUST call
 * this before `put(..., { source: 'fetch' | 'legacy' })`.
 */
export function acceptFetchedEnvelope(requestedEpoch: number, envelopeEpoch: unknown): boolean {
  return isEpoch(requestedEpoch) && isEpoch(envelopeEpoch) && envelopeEpoch === requestedEpoch;
}

/** Options of the epoch queries. */
export interface ChannelKeyQuery {
  /** Ignore epochs above this (e.g. node highest + 256). */
  maxEpoch?: number;
  /** Only keys the node reported FINAL. */
  finalOnly?: boolean;
}

/** The shared channel keyring (see the module comment for the rules). */
export class ChannelKeyring {
  private readonly scopes = new Map<string, Map<number, Slot>>();
  /** Vault entries this keyring cannot interpret: name → bytes, re-exported verbatim. */
  private readonly opaque = new Map<string, Uint8Array>();
  /** Opaque entries that did not fit the cap: while > 0, a backup would shrink the vault. */
  private opaqueDropped = 0;
  private seq = 0;
  /** Bumped by `clear()`: export tokens of an earlier state are refused. */
  private clears = 0;
  /** Keys removed by `pruneUnverified` this session, `${scope}:${epoch}|keccak(key)`: never re-imported. */
  private readonly pruned = new Set<string>();
  private readonly gen?: () => number;
  private readonly maxAlts: number;
  private readonly maxUntrusted: number;
  private readonly maxEpochs: number;
  private readonly maxSessionHistory: number;
  private readonly maxVaultBytes: number;
  private readonly maxMember: number;
  private readonly maxOpaque: number;

  constructor(opts: ChannelKeyringOptions = {}) {
    this.gen = opts.generation;
    this.maxAlts = opts.maxAltsPerEpoch ?? MAX_ALTS_PER_EPOCH;
    this.maxUntrusted = opts.maxUntrustedEpochsPerScope ?? MAX_UNTRUSTED_EPOCHS_PER_SCOPE;
    this.maxEpochs = opts.maxEpochsPerScope ?? MAX_EPOCHS_PER_SCOPE;
    this.maxSessionHistory = opts.maxSessionHistoryEpochsPerScope ?? MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE;
    this.maxVaultBytes = opts.maxVaultBytes ?? VAULT_CHAN_SOFT_LIMIT_BYTES;
    this.maxMember = opts.maxMemberEpochsPerScope ?? MAX_MEMBER_EPOCHS_PER_SCOPE;
    this.maxOpaque = opts.maxOpaqueEntries ?? MAX_OPAQUE_VAULT_ENTRIES;
  }

  private stale(generation: number | undefined): boolean {
    return this.gen !== undefined && this.gen() !== generation;
  }

  private slot(scopeHex: string, epoch: number): Slot | undefined {
    return this.scopes.get(scopeHex)?.get(epoch);
  }

  private newSlot(scopeHex: string, epoch: number): Slot {
    let m = this.scopes.get(scopeHex);
    if (!m) {
      m = new Map();
      this.scopes.set(scopeHex, m);
    }
    const s: Slot = { entries: [], seq: ++this.seq, nodeNew: false, memberNew: false };
    m.set(epoch, s);
    return s;
  }

  /** Move the best entry to the primary position if it STRICTLY outranks the primary (ties: first seen stays). */
  private reorder(s: Slot): boolean {
    // Only a key STRICTLY better than the primary takes over: the best rank among
    // those, the earliest seen among equals (`seq`, not list position).
    const pr = rank(s.entries[0]!);
    let bi = 0;
    for (let i = 1; i < s.entries.length; i++) {
      const e = s.entries[i]!;
      const r = rank(e);
      if (r <= pr) continue;
      if (bi === 0 || r > rank(s.entries[bi]!) || (r === rank(s.entries[bi]!) && e.seq < s.entries[bi]!.seq)) bi = i;
    }
    if (bi === 0) return false;
    const [b] = s.entries.splice(bi, 1);
    s.entries.unshift(b!);
    return true;
  }

  /**
   * Evict the NEWEST unprotected alternate (never the primary): the first node
   * keys seen for an epoch stay, so a later flood cannot push them out — at a
   * full slot an incoming unprotected key is itself the one shed.
   */
  private evictOne(s: Slot): Entry | null {
    let vi = -1;
    for (let i = 1; i < s.entries.length; i++) {
      const e = s.entries[i]!;
      if (unprotected(e) && (vi < 0 || e.seq > s.entries[vi]!.seq)) vi = i;
    }
    if (vi < 0) return null;
    const [v] = s.entries.splice(vi, 1);
    return v!;
  }

  /**
   * Soft cap: shed unprotected alternates beyond the cap; protected keys may
   * exceed it, so a trusted / own / provisional / vault key is never refused.
   * Once an epoch holds `maxAlts` protected alternates no unprotected one
   * survives a put, so node-served keys we back up stay ≤ 1 + `maxAlts` per
   * epoch over any number of sessions.
   */
  private enforceSoftCap(s: Slot): Entry[] {
    const gone: Entry[] = [];
    while (s.entries.length - 1 > this.maxAlts) {
      const v = this.evictOne(s);
      if (!v) break;
      gone.push(v);
    }
    return gone;
  }

  /**
   * Caps for a NEW node-served epoch: refused at the absolute
   * {@link MAX_EPOCHS_PER_SCOPE}; above the highest trusted epoch, at the
   * untrusted-epoch cap the oldest all-unprotected untrusted epoch above it is
   * evicted, else refused.
   */
  private untrustedRoom(scopeHex: string, epoch: number): boolean {
    const m = this.scopes.get(scopeHex);
    if (!m) return true;
    if (m.size >= this.maxEpochs) return false;
    let floor = -1;
    for (const [ep, s] of m) if (ep > floor && rank(s.entries[0]!) >= 3) floor = ep;
    // Above the trusted epoch: every untrusted epoch counts (restored ones too) against
    // the untrusted cap. At or below it: only epochs a node served NEW in this session
    // count, against the session history budget — restored history is exempt, a burst is not.
    const above = epoch > floor;
    const counts = (ep: number, s: Slot): boolean => untrustedSlot(s) && (above ? ep > floor : ep <= floor && s.nodeNew);
    let count = 0;
    const victims: Array<[number, Slot]> = [];
    for (const [ep, s] of m) {
      if (!counts(ep, s)) continue;
      count++;
      if (s.entries.every(unprotected)) victims.push([ep, s]);
    }
    // Make room for the new epoch by evicting the OLDEST all-unprotected counted epochs —
    // as many as needed (restored node history can push the count over the cap), or none.
    const need = count - (above ? this.maxUntrusted : this.maxSessionHistory) + 1;
    if (need <= 0) return true;
    if (victims.length < need) return false;
    victims.sort((a, b) => a[1].seq - b[1].seq);
    for (const [ep, s] of victims.slice(0, need)) {
      for (const e of s.entries) e.key.fill(0);
      m.delete(ep);
    }
    return true;
  }

  /**
   * Malicious-member caps for another member's `wrap` (not `ownSlot`) — they NEVER evict:
   * beyond a cap the new key is REFUSED, so a hostile member can make further member wraps
   * in that channel be refused, but can never delete a key of ours.
   *  - a NEW epoch above the highest FINAL epoch: at most `maxMemberEpochsPerScope` epochs
   *    there that may be another member's (holding no own / final / provisional key and not
   *    only node keys) — restored keys of unknown provenance count as "maybe member" for this
   *    count after a restart (they are never evicted for it);
   *  - a NEW epoch at or below it: at most `maxSessionHistoryEpochsPerScope` per session;
   *  - an ALTERNATE at an existing epoch: at most `maxAltsPerEpoch` maybe-member keys there.
   */
  private memberRoom(scopeHex: string, epoch: number, existing: Slot | undefined): boolean {
    const m = this.scopes.get(scopeHex);
    const maybeMemberEntry = (e: Entry) => !e.ns && !e.own && !e.final && !e.provisional && e.source !== 'establish';
    if (existing) return existing.entries.filter(maybeMemberEntry).length < this.maxAlts;
    if (!m) return true;
    let finalFloor = -1;
    for (const [ep, s] of m) if (rank(s.entries[0]!) >= 4 && ep > finalFloor) finalFloor = ep;
    const maybeMemberSlot = (s: Slot) => s.entries.some((e) => !e.ns) && s.entries.every((e) => e.ns || maybeMemberEntry(e));
    let count = 0;
    for (const [ep, s] of m) {
      if (!maybeMemberSlot(s)) continue;
      if (epoch > finalFloor ? ep > finalFloor : ep <= finalFloor && s.memberNew) count++;
    }
    return count < (epoch > finalFloor ? this.maxMember : this.maxSessionHistory);
  }

  /** After removing entries: the best rank, earliest seen among equals, becomes primary. */
  private repick(s: Slot): void {
    let bi = 0;
    for (let i = 1; i < s.entries.length; i++) {
      const e = s.entries[i]!;
      const b = s.entries[bi]!;
      if (rank(e) > rank(b) || (rank(e) === rank(b) && e.seq < b.seq)) bi = i;
    }
    if (bi === 0) return;
    const [b] = s.entries.splice(bi, 1);
    s.entries.unshift(b!);
  }

  /**
   * ESCAPE HATCH for a backup that is too large (`vault_too_large`). Outside each scope's
   * `keepLatestPerScope` (default 16) highest epochs — and only in `scopes`, if given — it
   * removes the selected `classes` (default `['nodeServed']`, the zero-risk path: keys a node
   * served that no author vouched for). `restoredAlternates` (may include the user's own
   * outranked keys — `byClass.ownAlternatesAtRisk`), `memberWraps` (other members'
   * non-final wraps) and `restoredPrimaries` (most likely the user's own history: last
   * resort, also via `includeRestoredPrimaries`) only when selected. NEVER removes own keys
   * (`establish`, `ownSlot` wraps), final wraps, provisional keys, a client-put `vault` key
   * that was never backed up, or uninterpretable vault entries. Removed keys are remembered
   * for the session and skipped by `importFromVault`, so "prune → re-import the remote vault
   * → seal" yields a smaller vault (the next successful backup removes them remotely).
   * They can no longer decrypt history they alone covered: clients MUST show a `dryRun`
   * and get the user's explicit confirmation first (and warn when `ownAlternatesAtRisk` > 0).
   * @throws ChannelKeyringError('stale') for an outdated `generation`.
   */
  pruneUnverified(opts: ChannelKeyPruneOptions = {}): ChannelKeyPruneResult {
    if (this.stale(opts.generation)) throw new ChannelKeyringError('stale', 'key prune for an outdated account');
    const keep = Math.max(0, Math.floor(opts.keepLatestPerScope ?? 16));
    const classes = new Set<ChannelKeyPruneClassName>(opts.classes ?? ['nodeServed']);
    if (opts.includeRestoredPrimaries) classes.add('restoredPrimaries');
    const onlyScopes = opts.scopes ? new Set(opts.scopes) : null;
    const z = () => ({ count: 0, bytes: 0 });
    const res: ChannelKeyPruneResult = {
      removedCount: 0, removedBytes: 0,
      byClass: { nodeServed: z(), restoredAlternates: z(), restoredPrimaries: z(), memberWraps: z(), ownAlternatesAtRisk: z() },
    };
    const classOf = (e: Entry): ChannelKeyPruneClassName | null => {
      if (e.own || e.provisional || e.source === 'establish') return null;
      if (e.ns || isNodeServed(e.source)) return 'nodeServed';
      if (e.source === 'wrap') return e.final ? null : 'memberWraps';
      if (!e.wasVault || (e.source === 'vault' && !e.persisted)) return null; // client-put, never backed up
      if (e.aboveCeiling) return 'memberWraps'; // restored above the node's reach: cannot be ours
      return e.aliasOrigin ? 'restoredAlternates' : 'restoredPrimaries';
    };
    for (const [scope, m] of this.scopes) {
      if (onlyScopes && !onlyScopes.has(scope)) continue;
      const eps = [...m.keys()].sort((a, b) => b - a);
      for (const ep of eps.slice(keep)) {
        const s = m.get(ep)!;
        const gone = s.entries.filter((e) => { const c = classOf(e); return c !== null && classes.has(c); });
        if (!gone.length) continue;
        for (const e of gone) {
          const b = entryBytes(e.vaultName ?? `${scope}:${ep}#alt${FIRST_WRITTEN_ALT_INDEX}`);
          const cls = classOf(e)!;
          res.byClass[cls].count++;
          res.byClass[cls].bytes += b;
          if (cls === 'restoredAlternates') { res.byClass.ownAlternatesAtRisk.count++; res.byClass.ownAlternatesAtRisk.bytes += b; }
          res.removedCount++;
          res.removedBytes += b;
        }
        if (opts.dryRun) continue;
        for (const e of gone) {
          this.pruned.add(prunedId(scope, ep, e.key));
          e.key.fill(0);
        }
        s.entries = s.entries.filter((e) => !gone.includes(e));
        if (s.entries.length === 0) m.delete(ep);
        else this.repick(s);
      }
    }
    return res;
  }

  /**
   * For a LEGACY (pre-arbitration, commitment-less) channel only. Returns a key only when the
   * scope holds NOTHING but commitment-less keys a node served THIS session — no own /
   * author-sourced key, no provisional key, no key restored from the vault, no key carrying
   * a commitment anywhere in the scope — and then the highest in-range epoch's primary that
   * `isLegacyEpoch` accepts. `isLegacyEpoch` must NOT come from the serving node alone:
   * derive "legacy" from data the node cannot forge (e.g. the epoch predates the channel's
   * arbitration activation recorded locally, or the channel and its creator data pinned by
   * the client predate key commitments) — and never assume it after a restart.
   */
  bestForSendLegacy(scopeHex: string, q: ChannelKeyLegacyQuery): ChannelKeyHeld | null {
    const m = this.scopes.get(scopeHex);
    if (!m || typeof q?.isLegacyEpoch !== 'function') return null;
    const legacyOnly = (e: Entry) => isNodeServed(e.source) && e.served && !e.pair && !e.wasVault && !e.provisional && !e.own;
    for (const s of m.values()) if (!s.entries.every(legacyOnly)) return null;
    const max = q.maxEpoch ?? Number.POSITIVE_INFINITY;
    let best: { epoch: number; e: Entry } | null = null;
    for (const [epoch, s] of m) {
      if (epoch > max || (best && epoch <= best.epoch)) continue;
      if (q.isLegacyEpoch(epoch)) best = { epoch, e: s.entries[0]! };
    }
    return best ? { ...this.info(best.e, true), epoch: best.epoch } : null;
  }

  /**
   * Hold a key. Never overwrites or loses a held key (module comment). The
   * key and pair are COPIED.
   */
  put(scopeHex: string, epoch: number, key: Uint8Array, opts: ChannelKeyPutOptions): ChannelKeyPutResult {
    if (this.stale(opts.generation)) return 'stale';
    if (typeof scopeHex !== 'string' || !SCOPE_RE.test(scopeHex) || !isEpoch(epoch) || !isKey(key) || !SOURCES.has(opts.source)) return 'invalid';
    if (opts.pair !== undefined && !validPair(opts.pair)) return 'invalid';
    if (opts.source === 'legacy' && opts.pair) return 'invalid';
    const verified = opts.verified === true;
    if (verified && (!opts.pair || !pairMatches(scopeHex, epoch, key, opts.pair))) return 'invalid';
    const final = opts.final === true;
    if (final && !verified) return 'invalid';
    const provisional = opts.provisional === true;
    if (provisional && (opts.source !== 'establish' || final)) return 'invalid';
    const s = this.slot(scopeHex, epoch);
    const mk = (): Entry => ({
      key: key.slice(), source: opts.source, pairOk: verified, pair: opts.pair ? copyPair(opts.pair) : undefined, final,
      provisional, persisted: false, aliasOrigin: false, served: isNodeServed(opts.source), ns: isNodeServed(opts.source),
      own: ownPut, wasVault: opts.source === 'vault', aboveCeiling: false, seq: ++this.seq,
    });
    const ownPut = opts.source === 'establish' || provisional || (opts.source === 'wrap' && opts.ownSlot === true);
    const othersWrap = opts.source === 'wrap' && !ownPut;
    // A FINAL (node-arbitrated, pair-verified) member wrap is exempt from the member caps:
    // it is the channel's key for that epoch, so refusing it would lock the channel.
    const memberPut = othersWrap && !final;
    // Epoch ceiling for keys that are not ours (clients pass node highest + 256).
    if (opts.maxEpoch !== undefined && epoch > opts.maxEpoch && (isNodeServed(opts.source) || othersWrap)) return 'refused';
    if (!s) {
      if (isNodeServed(opts.source) && !this.untrustedRoom(scopeHex, epoch)) return 'refused';
      if (othersWrap && (this.scopes.get(scopeHex)?.size ?? 0) >= this.maxEpochs) return 'refused'; // memory bound
      if (memberPut && !this.memberRoom(scopeHex, epoch, undefined)) return 'refused';
      const ns = this.newSlot(scopeHex, epoch);
      ns.nodeNew = isNodeServed(opts.source);
      ns.memberNew = memberPut;
      ns.entries.push(mk());
      return 'stored';
    }
    const held = s.entries.find((e) => sameBytes(e.key, key));
    if (held) {
      if (SOURCE_RANK[opts.source] > SOURCE_RANK[held.source]) held.source = opts.source;
      if (verified) notePair(held, opts.pair!, final);
      else if (opts.pair && !held.pair) held.pair = copyPair(opts.pair);
      // W1: only an EXPLICIT finalisation clears provisional (never a fetch / vault merge).
      if (isNodeServed(opts.source)) held.served = true;
      if (isAuthor(opts.source)) held.ns = false; // vouched for by an author source: protected from now on
      if (ownPut) held.own = true;
      if (opts.source === 'vault') held.wasVault = true;
      // W1/W-4: only an EXPLICIT finalisation from an author source clears provisional —
      // never a fetch / vault copy, even one claiming `final`.
      if (held.provisional && isAuthor(opts.source) && ((verified && final) || opts.provisional === false)) held.provisional = false;
      return this.reorder(s) && s.entries[0] === held ? 'promoted' : 'stored';
    }
    // M-B2: a commitment-less node-served duplicate is never held (the node can serve it again).
    if (isNodeServed(opts.source) && !opts.pair) return 'refused';
    if (memberPut && !this.memberRoom(scopeHex, epoch, s)) return 'refused';
    const e = mk();
    s.entries.push(e);
    const promoted = this.reorder(s) && s.entries[0] === e;
    const gone = this.enforceSoftCap(s);
    for (const g of gone) g.key.fill(0);
    if (gone.includes(e)) return 'refused';
    return promoted ? 'promoted' : 'conflict';
  }

  /**
   * Record that a held key's pair is PAIR-CONSISTENT (re-hashed here), and
   * optionally FINAL. Only for AUTHOR-VERIFIED keys (`establish` / `wrap`):
   * any other key returns `'needs_author_proof'` and is not changed (a node
   * can compute a consistent pair for its own key) — re-`put` it with
   * `source: 'wrap'` after `verifyChannelKeyWrap`. A key that now outranks
   * the primary is promoted; a final pair also finalises a provisional key.
   */
  markVerified(scopeHex: string, epoch: number, key: Uint8Array, pair: ChannelKeyPair, opts: ChannelKeyMarkOptions = {}): ChannelKeyMarkResult {
    if (this.stale(opts.generation)) return 'stale';
    if (typeof scopeHex !== 'string' || !isEpoch(epoch) || !isKey(key) || !validPair(pair)) return 'invalid';
    const s = this.slot(scopeHex, epoch);
    const e = s?.entries.find((x) => sameBytes(x.key, key));
    if (!s || !e) return 'not_held';
    if (!pairMatches(scopeHex, epoch, key, pair)) return 'pair_mismatch';
    if (!isAuthor(e.source)) return 'needs_author_proof';
    const final = opts.final === true;
    notePair(e, pair, final);
    if (final) e.provisional = false;
    return this.reorder(s) && s.entries[0] === e ? 'promoted' : 'verified';
  }

  private info(e: Entry, primary: boolean): ChannelKeyInfo {
    return {
      key: e.key.slice(), source: e.source, verified: e.pairOk, authorVerified: isAuthor(e.source), trusted: trusted(e),
      final: e.final, pair: e.pair ? copyPair(e.pair) : undefined, provisional: e.provisional,
      exportable: exportable(e), persisted: e.persisted, nodeServed: e.ns, own: e.own, restored: e.wasVault, primary,
    };
  }

  /** Every key held at the epoch for DECRYPTION, primary first (copies). */
  keysAt(scopeHex: string, epoch: number): Uint8Array[] {
    return this.slot(scopeHex, epoch)?.entries.map((e) => e.key.slice()) ?? [];
  }

  /** Every key held at the epoch with its metadata, primary first (copies). */
  entriesAt(scopeHex: string, epoch: number): ChannelKeyInfo[] {
    return this.slot(scopeHex, epoch)?.entries.map((e, i) => this.info(e, i === 0)) ?? [];
  }

  /** Any key held at the epoch (makes THAT epoch known to exist; never global evidence). */
  holds(scopeHex: string, epoch: number): boolean {
    return !!this.slot(scopeHex, epoch);
  }

  /** Epochs held for a scope, ascending. */
  epochs(scopeHex: string): number[] {
    return [...(this.scopes.get(scopeHex)?.keys() ?? [])].sort((a, b) => a - b);
  }

  /** The PRIMARY of the highest epoch ≤ maxEpoch whose primary passes `ok`. */
  private pick(scopeHex: string, maxEpoch: number, ok: (e: Entry) => boolean): ChannelKeyHeld | null {
    let best: { epoch: number; e: Entry } | null = null;
    for (const [epoch, s] of this.scopes.get(scopeHex) ?? []) {
      if (epoch > maxEpoch || (best && epoch <= best.epoch)) continue;
      if (ok(s.entries[0]!)) best = { epoch, e: s.entries[0]! };
    }
    return best ? { ...this.info(best.e, true), epoch: best.epoch } : null;
  }

  /** The highest held epoch (any key; its primary), or null. Not evidence. */
  latest(scopeHex: string): ChannelKeyHeld | null {
    return this.pick(scopeHex, Number.POSITIVE_INFINITY, () => true);
  }

  /** The highest held epoch ≤ `maxEpoch` (e.g. node highest + 256), or null. */
  latestBounded(scopeHex: string, maxEpoch: number): ChannelKeyHeld | null {
    return this.pick(scopeHex, maxEpoch, () => true);
  }

  /**
   * The highest epoch with a TRUSTED key (author-verified + pair-consistent,
   * not provisional) — the SDK's `highestEpochSeen` from held keys and the
   * rotation base. Never a legacy, vault, fetched or provisional key.
   */
  latestVerified(scopeHex: string, q: ChannelKeyQuery = {}): ChannelKeyHeld | null {
    const min = q.finalOnly ? 4 : 3;
    return this.pick(scopeHex, q.maxEpoch ?? Number.POSITIVE_INFINITY, (e) => rank(e) >= min);
  }

  /**
   * The key to SEND (and cover) under: the PRIMARY of the highest epoch whose
   * primary is trusted or our provisional first key (with `finalOnly`: trusted
   * and final). Alternates are never chosen (a slot's primary is trusted
   * whenever any key of it is; final whenever any trusted key is final).
   *
   * `allowUnverified` is ONLY for scopes the caller KNOWS are pre-arbitration
   * (no commitment anywhere) — NEVER because nothing is trusted yet after a
   * restart (re-verify the own-slot wrap and re-`put` it as `wrap` instead).
   * With it and NO trusted epoch in range, the highest primary that was read
   * under the primary vault name or is of own provenance is returned — never
   * a key a node served this session, never one restored from an alias name.
   */
  bestForSend(scopeHex: string, opts: ChannelKeyQuery & { allowUnverified?: boolean } = {}): ChannelKeyHeld | null {
    const max = opts.maxEpoch ?? Number.POSITIVE_INFINITY;
    const min = opts.finalOnly ? 4 : 2;
    const t = this.pick(scopeHex, max, (e) => rank(e) >= min);
    if (t || !opts.allowUnverified) return t;
    // W-1: only a primary read under the PRIMARY vault name or of own provenance, never one
    // a node served in this session nor one restored from an alias name (a laundered node key).
    return this.pick(scopeHex, max, (e) => isAuthor(e.source) || (!isNodeServed(e.source) && !e.ns && !e.served && !e.aliasOrigin));
  }

  /**
   * The vault `chan` record: every held exportable PROTECTED key and every
   * opaque entry, plus unprotected (node-served, never backed up) keys while
   * the estimated size stays within the byte budget — newest left out first;
   * collision-free and in canonical order (module comment). `#pri` copies
   * only for each scope's highest epochs and while the record is within half
   * the budget. Only exported keys are marked persisted (never evicted
   * afterwards); they keep their name on the next export. Returns COPIES.
   * @throws ChannelKeyringError('vault_too_large') when the protected keys
   *   alone exceed the budget (never a silent shrink; surface it).
   * @throws ChannelKeyringError('stale') for an outdated `generation`.
   * @throws ChannelKeyringError('opaque_overflow') when uninterpretable vault
   *   entries beyond the cap were dropped at import: the backup would shrink
   *   the remote vault, so it is refused (surface it) until `clear()`.
   */
  exportForVault(generation?: number): Record<string, Uint8Array> {
    const p = this.prepareExport(generation);
    this.commitExport(p.commitToken, generation);
    return p.chan;
  }

  /**
   * TWO-STEP export, side-effect free: the same record as `exportForVault`, but nothing is
   * marked persisted until `commitExport(commitToken)` — call that ONLY after the sealed
   * vault was published successfully; a failed publish leaves every key as it was.
   * (`exportForVault` = prepare + commit at once; since node-served keys are never
   * protected by being backed up, committing early only pins names and keeps provisional
   * keys exportable — the two-step form is still the recommended one.)
   * @throws like `exportForVault`.
   */
  prepareExport(generation?: number): ChannelKeyPreparedExport {
    if (this.stale(generation)) throw new ChannelKeyringError('stale', 'key vault export for an outdated account');
    if (this.opaqueDropped > 0) {
      throw new ChannelKeyringError('opaque_overflow', `key vault has ${this.opaqueDropped} entries beyond the ${this.maxOpaque} cap; backup refused so it never shrinks`);
    }
    // 1. Name every exportable key (a plan; nothing is marked persisted yet).
    const slots: Array<{ base: string; scope: string; epoch: number; items: Array<{ e: Entry; name: string }>; pri?: { e: Entry; name: string } }> = [];
    for (const [scope, m] of this.scopes) {
      for (const [epoch, s] of m) {
        const base = `${scope}:${epoch}`;
        const used = new Set<string>();
        const names = new Map<Entry, string>();
        const take = (e: Entry, n: string) => { names.set(e, n); used.add(n); };
        const exp = s.entries.filter(exportable);
        // W4: only an own / author-verified key, or a vault key not restored from an alias name,
        // takes it — never a key a node served this session (one that merged into `vault`
        // included; restored in a later session it comes from its alias, so `aliasOrigin`).
        const baseOk = (e: Entry) => !e.ns && (isAuthor(e.source) || (!e.aliasOrigin && e.source === 'vault' && !e.served));
        const p = s.entries[0]!;
        if (exportable(p) && baseOk(p)) take(p, base);
        // Keys keep the name they were read / written under when it is free.
        // (only within the key's provenance class: node-served keys live under `#ns<n>`).
        const nsName = (nm: string) => nm.startsWith(`${base}#ns`);
        for (const e of exp) if (!names.has(e) && e.vaultName && !used.has(e.vaultName) && nsName(e.vaultName) === e.ns) take(e, e.vaultName);
        let n = FIRST_WRITTEN_ALT_INDEX;
        let o = 1;
        let q = 1;
        for (const e of exp) {
          if (names.has(e)) continue;
          if (e.ns) {
            while (used.has(`${base}#ns${q}`)) q++;
            take(e, `${base}#ns${q}`);
            continue;
          }
          if (!used.has(base) && baseOk(e)) { take(e, base); continue; }
          while (n <= MAX_ALT_INDEX && used.has(`${base}#alt${n}`)) n++;
          if (n <= MAX_ALT_INDEX) { take(e, `${base}#alt${n}`); continue; }
          while (used.has(`${base}#ovf${o}`)) o++;
          take(e, `${base}#ovf${o}`);
        }
        // B2: canonical order — primary name, its `#pri` copy, `#alt` ascending, `#ovf` ascending.
        const order = (nm: string): number => {
          if (nm === base) return 0;
          const a = /#alt(\d+)$/.exec(nm);
          if (a) return Number(a[1]);
          const v = /#ovf(\d+)$/.exec(nm);
          if (v) return 1e6 + Number(v[1]);
          return 2e6 + Number(/#ns(\d+)$/.exec(nm)![1]);
        };
        const items = [...names].sort((x, y) => order(x[1]) - order(y[1])).map(([e, name]) => ({ e, name }));
        const baseItem = items.find((x) => x.name === base);
        // W-2: a COPY of the primary-name key under `#pri`, a name no older client places into
        // its slot: if one with a full slot overwrites `S:E`, the value survives.
        slots.push({ base, scope, epoch, items, pri: baseItem ? { e: baseItem.e, name: `${base}#pri` } : undefined });
      }
    }
    // `#pri` copies only for each scope's highest epochs, and a bounded number in total.
    const perScope = new Map<string, number[]>();
    for (const sl of slots) if (sl.pri) perScope.set(sl.scope, [...(perScope.get(sl.scope) ?? []), sl.epoch]);
    const keepPri = new Set<string>();
    for (const [scope, eps] of perScope) for (const ep of eps.sort((a, b) => b - a).slice(0, PRI_COPIES_PER_SCOPE)) keepPri.add(`${scope}:${ep}`);
    let priLeft = MAX_PRI_COPIES;
    for (const sl of slots) if (sl.pri && (!keepPri.has(sl.base) || priLeft-- <= 0)) sl.pri = undefined;

    // 2. Byte budget: protected keys and opaque entries always (else `vault_too_large`, never a
    // silent shrink); node-served (`ns`) keys only while the WHOLE record stays within
    // NODE_SERVED_VAULT_SHARE of the budget, so node junk can never crowd out the user's keys.
    let size = 5;
    for (const sl of slots) for (const it of sl.items) if (!unprotected(it.e)) size += entryBytes(it.name);
    for (const name of this.opaque.keys()) size += entryBytes(name);
    if (size > this.maxVaultBytes) {
      throw new ChannelKeyringError('vault_too_large', `key vault would be ~${size} bytes, over the ${this.maxVaultBytes}-byte budget; backup refused so it never shrinks`);
    }
    // Keep order: backed-up node history first (highest epoch first, so the OLDEST is shed),
    // then keys new this session (earliest first, so the NEWEST is shed).
    const nsItems = slots.flatMap((sl) => sl.items.filter((it) => unprotected(it.e)).map((it) => ({ sl, it })))
      .sort((a, b) => (a.it.e.persisted === b.it.e.persisted
        ? (a.it.e.persisted ? b.sl.epoch - a.sl.epoch || a.it.e.seq - b.it.e.seq : a.it.e.seq - b.it.e.seq)
        : a.it.e.persisted ? -1 : 1));
    const nsCap = this.maxVaultBytes * NODE_SERVED_VAULT_SHARE;
    let full = false;
    for (const c of nsItems) {
      const b = entryBytes(c.it.name);
      if (!full && size + b <= nsCap) { size += b; continue; }
      full = true; // stop at the first that does not fit: deterministic, re-export stable
      c.sl.items.splice(c.sl.items.indexOf(c.it), 1);
    }
    // `#pri` copies are a transitional safety for older clients: only while the whole
    // record (copies included) stays within HALF the budget.
    let priBytes = 0;
    for (const sl of slots) if (sl.pri) priBytes += entryBytes(sl.pri.name);
    if (size + priBytes > this.maxVaultBytes / 2) for (const sl of slots) sl.pri = undefined;

    // 3. Write. Only what is exported becomes persisted — at commit.
    const out: Record<string, Uint8Array> = {};
    const items: Array<{ e: Entry; name: string }> = [];
    for (const sl of slots) {
      for (const it of sl.items) {
        out[it.name] = it.e.key.slice();
        items.push(it);
        if (sl.pri && it.name === sl.base) out[sl.pri.name] = it.e.key.slice();
      }
    }
    // Uninterpretable entries go LAST: an older client reading aliases in record order must see a slot's own aliases first.
    for (const [name, v] of this.opaque) out[name] = v.slice();
    const token = { __channelKeyExportToken: true as const };
    EXPORT_TOKENS.set(token, { ring: this, clears: this.clears, items });
    return { chan: out, commitToken: token };
  }

  /**
   * Mark the keys of a prepared export persisted (and pin their vault names) — after the
   * sealed vault was published. Returns how many keys it marked.
   * @throws ChannelKeyringError('stale') for a token of another keyring, of a state before
   *   `clear()`, or an outdated `generation`.
   */
  commitExport(token: ChannelKeyExportToken, generation?: number): number {
    if (this.stale(generation)) throw new ChannelKeyringError('stale', 'key vault commit for an outdated account');
    const t = EXPORT_TOKENS.get(token);
    if (!t || t.ring !== this || t.clears !== this.clears) throw new ChannelKeyringError('stale', 'export token does not belong to this keyring state');
    EXPORT_TOKENS.delete(token);
    for (const it of t.items) {
      it.e.persisted = true;
      it.e.vaultName = it.name;
    }
    return t.items.length;
  }

  /**
   * Merge a vault `chan` record (keys NOT author-verified). Every 32-byte
   * entry is kept: a parsed name lands in its slot (a different key as an
   * alternate — never refused, never evicted), any other name verbatim (an
   * own `__proto__` name is renamed, see `renameProtoKey`). Returns how many
   * keys were new to the keyring.
   * @throws ChannelKeyringError('stale') for an outdated `generation`.
   */
  importFromVault(record: Record<string, Uint8Array>, generation?: number, opts: ChannelKeyImportOptions = {}): number {
    const ceiling = opts.maxEpoch ?? Number.POSITIVE_INFINITY;
    if (this.stale(generation)) throw new ChannelKeyringError('stale', 'key vault import for an outdated account');
    if (!record || typeof record !== 'object') return 0;
    const parsed: Array<{ name: string; v: Uint8Array; scope: string; epoch: number; kind: number; idx: number; pin?: string }> = [];
    let added = 0;
    for (const [rawName, v] of Object.entries(record)) {
      if (!isKey(v)) continue;
      if (rawName === '__proto__' && [...this.opaque].some(([n, x]) => /^%proto_\d+$/.test(n) && sameBytes(x, v))) continue; // N-1
      const name = rawName === '__proto__' ? renameProtoKey((n) => this.opaque.has(n) || Object.prototype.hasOwnProperty.call(record, n)) : rawName;
      const m = VAULT_NAME_RE.exec(name);
      const epoch = m ? Number(m[2]) : NaN;
      if (!m || !Number.isSafeInteger(epoch)) {
        added += this.keepOpaque(name, v);
        continue;
      }
      const base = `${m[1]}:${m[2]}`;
      // `#alt1..#alt4` (older clients' names) are re-homed to `#alt5+` on export; higher indices are kept.
      const altIdx = Number(m[3]);
      if (m[3] !== undefined) parsed.push({ name, v, scope: m[1]!, epoch, kind: 2, idx: altIdx, pin: altIdx >= FIRST_WRITTEN_ALT_INDEX ? `${base}#alt${m[3]}` : undefined });
      else if (m[4] !== undefined) parsed.push({ name, v, scope: m[1]!, epoch, kind: 3, idx: Number(m[4]) });
      else if (m[5] !== undefined) parsed.push({ name, v, scope: m[1]!, epoch, kind: 4, idx: Number(m[5]), pin: `${base}#ovf${m[5]}` });
      else if (m[6] !== undefined) parsed.push({ name, v, scope: m[1]!, epoch, kind: 1, idx: 0 }); // `#pri` copy of the primary
      else if (m[7] !== undefined) parsed.push({ name, v, scope: m[1]!, epoch, kind: 5, idx: Number(m[7]), pin: `${base}#ns${m[7]}` }); // node-served
      else parsed.push({ name, v, scope: m[1]!, epoch, kind: 0, idx: 0, pin: base });
    }
    // Primary names first, then aliases in index order: a deterministic primary per slot.
    parsed.sort((a, b) => a.kind - b.kind || a.idx - b.idx || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const p of parsed) {
      if (this.pruned.size && this.pruned.has(prunedId(p.scope, p.epoch, p.v))) continue; // pruned this session (A2)
      const s = this.slot(p.scope, p.epoch) ?? this.newSlot(p.scope, p.epoch);
      const held = s.entries.find((e) => sameBytes(e.key, p.v));
      if (held) {
        // A vault copy makes the key exportable again (M20) but never finalises it (W1).
        held.persisted = true;
        held.wasVault = true;
        if (p.epoch > ceiling && !held.own) held.aboveCeiling = true;
        if (SOURCE_RANK.vault > SOURCE_RANK[held.source]) held.source = 'vault';
        if (!held.vaultName && p.pin && (p.kind === 5) === held.ns) held.vaultName = p.pin;
        if (p.kind === 0) held.aliasOrigin = false; // seen under the primary name (a `#pri` copy does not clear it)
        this.reorder(s);
        continue;
      }
      s.entries.push({
        key: p.v.slice(), source: 'vault', pairOk: false, final: false, provisional: false, persisted: true,
        vaultName: p.pin, aliasOrigin: p.kind > 1, served: false, ns: p.kind === 5, own: false, wasVault: true, aboveCeiling: p.epoch > ceiling, seq: ++this.seq,
      });
      added++;
      this.reorder(s);
      for (const g of this.enforceSoftCap(s)) g.key.fill(0);
    }
    return added;
  }

  /** Keep an uninterpretable entry verbatim (a same-named different value under `${name}#dup<n>`). */
  private keepOpaque(name: string, v: Uint8Array): number {
    const cur = this.opaque.get(name);
    if (cur && sameBytes(cur, v)) return 0;
    let n = name;
    if (cur) {
      for (let i = 1; ; i++) {
        n = `${name}#dup${i}`;
        const d = this.opaque.get(n);
        if (!d) break;
        if (sameBytes(d, v)) return 0;
      }
    }
    if (this.opaque.size >= this.maxOpaque) {
      this.opaqueDropped++;
      return 0;
    }
    this.opaque.set(n, v.slice());
    return 1;
  }

  /** Uninterpretable vault entries held (cheap emptiness check without building an export). */
  get opaqueCount(): number {
    return this.opaque.size;
  }

  /** Number of held epochs (slots) over all scopes — same as `size`. */
  get heldEpochCount(): number {
    return this.size;
  }

  /** Uninterpretable vault entries that did not fit the cap (export refused while > 0; reset by `clear()`). */
  get opaqueOverflow(): number {
    return this.opaqueDropped;
  }

  /** Number of held epochs (slots) over all scopes. */
  get size(): number {
    let n = 0;
    for (const m of this.scopes.values()) n += m.size;
    return n;
  }

  /** Zero every held copy and drop everything (sign-out / account switch). Caller buffers are untouched. */
  clear(): void {
    for (const m of this.scopes.values()) {
      for (const s of m.values()) {
        for (const e of s.entries) {
          e.key.fill(0);
          e.pair?.commitment.fill(0);
        }
      }
    }
    for (const v of this.opaque.values()) v.fill(0);
    this.scopes.clear();
    this.opaque.clear();
    this.opaqueDropped = 0;
    this.pruned.clear();
    this.clears++;
  }
}
