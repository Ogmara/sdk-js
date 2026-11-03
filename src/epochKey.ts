/**
 * Shared channel key-epoch establishment protocol for node-arbitrated epochs
 * (sdk-js 0.67.0, l2-node 0.143.0+ `key_commitment_v1`).
 *
 * Why: with per-device first-write-wins storage, concurrent rotators (every
 * online member rotates on a kick) produced PERMANENT key forks per epoch, and
 * no client-side ordering could fix that. The node now arbitrates one winner
 * per `(channel scope, epoch)` by rank `(key_ts, key_commitment)` — lowest
 * wins, superseding only within a 120 s finality horizon — and rejects every
 * other key with 409. This module is the ONE client protocol on top of that
 * rule, shared by web, desktop and mobile:
 *
 * A candidate key is the PAIR `(key_ts, key_commitment)` (the commitment
 * binds `key_ts`); "the winner is ours" always compares the pair.
 *
 *  1. Pre-check: the node's commitment state for the epoch. `legacy` → never
 *     establish (caller rotates). `arbitrated` by another key → wait for the
 *     winner's wrap at our own slot. Our own pending key is the winner → resume.
 *  2. Our own enc-key row must be bound, else `needs_binding`.
 *  3. Reuse the pending `{key, keyTs}` for this epoch, else generate one, and
 *     cache it BEFORE publishing (a retry after a partial publish reuses the
 *     SAME key — never a second key for an epoch it may already have won).
 *     A pending key older than finality/2 (60 s) that is not yet confirmed
 *     published anywhere (the node shows no winner) is discarded and
 *     regenerated: a stalled client must never inject a well-ranked key late.
 *  4. Publish to our OWN device first (this records our commitment on the
 *     home node, or 409s if another key already won).
 *  5. On a 409 anywhere: abandon + zero our key, poll our own slot for a
 *     VERIFIED wrap matching the winner and adopt it; on timeout with a final
 *     winner → `escalate` (the caller rotates to `epoch + 1`, at most once per
 *     channel per 10 min — see {@link EscalationGate}).
 *  6. Wrap the remaining targets in canonical order through the shared token
 *     bucket (429 → sleep `retry_after_ms`, rejected target → skip + log,
 *     transient → bounded backoff, conflict → step 5).
 *  7. Settle: poll the commitment until the node reports it FINAL (see
 *     `confirmMode`) → `established` / `adopted` with `confirmed: true`.
 *     A plain-text duplicate 409 counts as stored only once the winner is our
 *     pair and (own device) our slot verifies; otherwise the wrap is re-signed
 *     with a fresh envelope and republished.
 *
 * All I/O, clock, randomness, timers and the token bucket are injected, so the
 * protocol runs unchanged under the deterministic simulator in
 * `epochKey.sim.test.ts`.
 *
 * Residuals (documented, not prevented): a gossip partition longer than the
 * finality horizon during a concurrent rotation splits that epoch until the
 * next rotation; a malicious MEMBER can wedge an epoch (bogus commitment or a
 * squatted slot) — detectable and attributable (signed), healed by escalation;
 * a hostile HOME node can withhold keys from its own users (never make them
 * adopt a non-member's key — every adopted wrap is author-verified).
 */
import { decode } from '@msgpack/msgpack';
import { unwrapKey, KEY_LEN } from './crypto';
import { computeChannelScope } from './envelope';
import { base64ToBytes } from './invite';
import { MessageType } from './types';
import type { KeyCommitmentInfo, KeyEnvelopeRecord, PublishChannelKeyResult } from './types';
import { verifyEnvelopeBytes, verifyDeviceClaimObject, deviceClaimCovers } from './privateChannelProof';
import {
  computeKeyCommitment,
  isValidKeyCommitment,
  keyCommitmentFromHex,
  keyCommitmentToHex,
  keyCommitmentsEqual,
  KeyCommitmentConflictError,
  KeyEnvelopeRateLimitedError,
  KeyEnvelopeRejectedError,
  KEY_COMMIT_FINALITY_MS,
  PENDING_KEY_MAX_AGE_MS,
  sameCandidate,
  compareRank,
  type KeyRank,
} from './channelKeyCommit';

// --- Small helpers -----------------------------------------------------------------

function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function fromHex(h: unknown, len: number): Uint8Array | null {
  if (typeof h !== 'string' || h.length !== len * 2 || !/^[0-9a-fA-F]*$/.test(h)) return null;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function asBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v) && v.length <= 4096) {
    const out = new Uint8Array(v.length);
    for (let i = 0; i < v.length; i++) {
      const b = v[i];
      if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) return null;
      out[i] = b;
    }
    return out;
  }
  return null;
}

function asSafeU64(v: unknown): number | null {
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? v : null;
  if (typeof v === 'bigint') return v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null;
  return null;
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  return keyCommitmentsEqual(a, b);
}

/** Positional (array-form) field order of the node's `ChannelKeyEnvelopePayload`. */
const KEY_ENVELOPE_FIELDS = [
  'key_scope', 'scope_kind', 'epoch', 'target', 'device_id', 'peer', 'channel_id',
  'eph_pub', 'nonce', 'wrapped', 'key_commitment', 'key_ts',
] as const;

function decodeKeyEnvelopePayload(payload: Uint8Array): Record<string, unknown> | null {
  let raw: unknown;
  try {
    raw = decode(payload, { useBigInt64: true });
  } catch {
    return null;
  }
  if (Array.isArray(raw)) {
    if (raw.length > KEY_ENVELOPE_FIELDS.length) return null;
    const out: Record<string, unknown> = {};
    raw.forEach((v, i) => { out[KEY_ENVELOPE_FIELDS[i]!] = v; });
    return out;
  }
  if (raw && typeof raw === 'object' && !(raw instanceof Uint8Array)) return raw as Record<string, unknown>;
  return null;
}

// --- verifyChannelKeyWrap ------------------------------------------------------------

/** A channel key wrap whose author, fields and commitment all verified. */
export interface VerifiedChannelKeyWrap {
  /** The unwrapped 32-byte channel key (H(key) == keyCommitment). */
  key: Uint8Array;
  keyCommitment: Uint8Array;
  keyTs: number;
  epoch: number;
  /** The wallet the signer resolves to (a verified member). */
  wallet: string;
  /** The raw signing address (`klv1…` wallet or `ogd1…` device). */
  signer: string;
  /** Lowercase hex msg_id of the verified envelope. */
  msgId: string;
}

/** Context for {@link verifyChannelKeyWrap}. */
export interface VerifyChannelKeyWrapContext {
  /** Our wallet (`klv1…`) — the wrap's `target` must be exactly this. */
  self: string;
  /** Our device id (hex of the device signing pubkey) — the wrap's `device_id`. */
  deviceId: string;
  /** Klever network ("testnet"/"mainnet") the envelope's msg_id binds to. */
  network: string;
  /** The channel; the wrap's `key_scope`/`channel_id` must match it. */
  channelId: number;
  /** Our device's X25519 enc secret (to unwrap). Not retained. */
  encPriv: Uint8Array;
  /** When given, the wrap's epoch must equal it. */
  epoch?: number;
  /**
   * Is `wallet` a VERIFIED member of the channel (e.g. `filterVerifiedMembers`
   * / `verifyPrivateMemberProof` for private channels)? Fail closed.
   */
  isVerifiedMember: (wallet: string) => boolean | Promise<boolean>;
}

/** Result of {@link verifyChannelKeyWrap}. */
export type ChannelKeyWrapVerification =
  | { ok: true; wrap: VerifiedChannelKeyWrap }
  | { ok: false; reason: string };

/**
 * Verify a channel key record served with `?proof=1` WITHOUT trusting the
 * node: the signed envelope is a valid 0x61 (msg_id + signature recomputed);
 * every payload field equals the record (`eph_pub`, `nonce`, `wrapped`,
 * `epoch`, `key_commitment`, `key_ts`) and binds to this channel, our wallet
 * and our device; the signer resolves to a wallet (directly, or through a
 * verified device claim covering the envelope's timestamp) that is a verified
 * member; and after unwrapping, `computeKeyCommitment(scope, epoch, key_ts, key)`
 * equals the signed `key_commitment`. A commitment-less (legacy) record is
 * refused. Never throws; the unwrapped key is zeroed on every failure.
 */
export async function verifyChannelKeyWrap(
  record: KeyEnvelopeRecord | null | undefined,
  ctx: VerifyChannelKeyWrapContext,
): Promise<ChannelKeyWrapVerification> {
  let key: Uint8Array | null = null;
  const fail = (reason: string): ChannelKeyWrapVerification => {
    key?.fill(0);
    return { ok: false, reason };
  };
  try {
    if (!record || typeof record !== 'object') return fail('no_record');
    if (typeof record.signed_envelope !== 'string') return fail('no_signed_envelope');
    const raw = base64ToBytes(record.signed_envelope);
    if (!raw) return fail('bad_signed_envelope');
    const v = await verifyEnvelopeBytes(raw, ctx.network, { expectedType: MessageType.ChannelKeyEnvelope });
    if (!v.ok) return fail(`envelope_${v.reason}`);
    const env = v.envelope;
    const p = decodeKeyEnvelopePayload(env.payload);
    if (!p) return fail('bad_payload');

    // Scope / channel / epoch binding.
    if (asSafeU64(p.scope_kind) !== 1) return fail('not_channel_scope');
    const scope = computeChannelScope(ctx.channelId);
    const keyScope = asBytes(p.key_scope);
    if (!keyScope || !bytesEq(keyScope, scope)) return fail('scope_mismatch');
    if (asSafeU64(p.channel_id) !== ctx.channelId) return fail('channel_mismatch');
    const epoch = asSafeU64(p.epoch);
    if (epoch === null || epoch < 1) return fail('bad_epoch');
    if (ctx.epoch !== undefined && epoch !== ctx.epoch) return fail('epoch_mismatch');
    if (record.epoch !== epoch) return fail('record_epoch_mismatch');

    // Recipient binding: exactly our wallet and our device.
    if (p.target !== ctx.self) return fail('target_mismatch');
    if (typeof p.device_id !== 'string' || p.device_id.toLowerCase() !== ctx.deviceId.toLowerCase()) {
      return fail('device_mismatch');
    }

    // The wrapped blob the node served must be the one that was signed.
    const ephPub = asBytes(p.eph_pub);
    const nonce = asBytes(p.nonce);
    const wrapped = asBytes(p.wrapped);
    if (!ephPub || ephPub.length !== 32 || !nonce || nonce.length !== 24 || !wrapped) return fail('bad_wrap');
    const rEph = fromHex(record.eph_pub, 32);
    const rNonce = fromHex(record.nonce, 24);
    const rWrapped = typeof record.wrapped === 'string' && record.wrapped.length <= 512
      ? fromHex(record.wrapped, record.wrapped.length / 2)
      : null;
    if (!rEph || !rNonce || !rWrapped || !bytesEq(rEph, ephPub) || !bytesEq(rNonce, nonce) || !bytesEq(rWrapped, wrapped)) {
      return fail('record_wrap_mismatch');
    }

    // Commitment + rank (STRICT: commitment-less wraps are never adopted here).
    const commitment = asBytes(p.key_commitment);
    const keyTs = asSafeU64(p.key_ts);
    if (!commitment || !isValidKeyCommitment(commitment)) return fail('no_commitment');
    if (keyTs === null || keyTs === 0 || keyTs > env.timestamp) return fail('bad_key_ts');
    // The signed payload is authoritative; the record's copies (null on rows the
    // node could not attribute) must only never CONTRADICT it.
    if (record.key_commitment != null) {
      const rc = keyCommitmentFromHex(record.key_commitment);
      if (!rc || !bytesEq(rc, commitment)) return fail('record_commitment_mismatch');
    }
    if (record.key_ts != null && record.key_ts !== keyTs) return fail('record_key_ts_mismatch');

    // Author: wallet signer directly, or a device whose claim verifies at env.timestamp.
    let wallet: string;
    if (env.author.startsWith('klv1')) {
      wallet = env.author;
    } else {
      if (!record.device_claim) return fail('no_device_claim');
      const dc = await verifyDeviceClaimObject(record.device_claim, ctx.network);
      if (!dc.ok) return fail(`device_claim_${dc.reason}`);
      if (dc.claim.deviceAddress !== env.author) return fail('device_claim_mismatch');
      if (!deviceClaimCovers(dc.claim, env.timestamp)) return fail('outside_delegation_window');
      wallet = dc.claim.wallet;
    }
    if (typeof record.author === 'string' && record.author !== '' && record.author !== wallet) {
      return fail('record_author_mismatch');
    }
    if (!(await ctx.isVerifiedMember(wallet))) return fail('author_not_verified_member');

    // Unwrap and check the key against the signed commitment.
    try {
      key = unwrapKey({ ephPub, nonce, wrapped }, ctx.encPriv, scope);
    } catch {
      return fail('unwrap_failed');
    }
    if (key.length !== KEY_LEN) return fail('bad_key_length');
    // An all-zero key is never a real channel key (a wiped buffer, or a member
    // publishing a known key to wedge the epoch): never adopt it (audit r48 B2).
    if (key.every((b) => b === 0)) return fail('zero_key');
    const h = computeKeyCommitment(scope, epoch, keyTs, key);
    if (!bytesEq(h, commitment)) return fail('commitment_mismatch');
    return {
      ok: true,
      wrap: { key, keyCommitment: commitment, keyTs, epoch, wallet, signer: env.author, msgId: env.msgId },
    };
  } catch {
    return fail('internal_error');
  }
}

// --- Injected primitives ---------------------------------------------------------------

/** A wrap target: one bound device of one verified member. */
export interface EpochKeyTarget {
  /** Recipient wallet (`klv1…`). */
  target: string;
  /** Recipient device id (hex). */
  deviceId: string;
  /** Recipient device X25519 enc pubkey (32 bytes). */
  encPub: Uint8Array;
}

const targetId = (t: { target: string; deviceId: string }): string => `${t.target}:${t.deviceId.toLowerCase()}`;

/** Canonical publish order shared by every establisher (wallet, then device id). */
export function compareTargets(a: EpochKeyTarget, b: EpochKeyTarget): number {
  const ka = targetId(a);
  const kb = targetId(b);
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

/**
 * Token bucket shared across channels (default 3/s, burst 10), with an
 * injected clock and sleep. `take()` resolves when a token is available.
 */
export class TokenBucket {
  private tokens: number;
  private last: number;
  constructor(
    private readonly now: () => number,
    private readonly sleep: (ms: number) => Promise<void>,
    readonly ratePerSec = 3,
    readonly burst = 10,
  ) {
    if (!(ratePerSec > 0) || !(burst >= 1)) throw new Error('invalid token bucket parameters');
    this.tokens = burst;
    this.last = now();
  }

  private refill(): void {
    const t = this.now();
    if (t > this.last) {
      this.tokens = Math.min(this.burst, this.tokens + ((t - this.last) * this.ratePerSec) / 1000);
    }
    this.last = Math.max(this.last, t);
  }

  /** Wait for and consume one token. */
  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      await this.sleep(Math.max(1, Math.ceil(((1 - this.tokens) * 1000) / this.ratePerSec)));
    }
  }
}

/**
 * Escalation limiter: at most one escalation (rotation to `epoch + 1` after
 * an undeliverable winner) per CHANNEL per `intervalMs` (10 min). Keyed by
 * channel only — a kick that raises the private floor must not open a second
 * escalation window. Bounded: when full, only entries whose interval has
 * expired are evicted; an entry still inside its interval is never dropped
 * (dropping it would reset that channel's gate), so a full table refuses new
 * channels until something expires (fail closed).
 */
export class EscalationGate {
  private readonly last = new Map<number, number>();
  constructor(
    private readonly now: () => number,
    readonly intervalMs = 10 * 60_000,
    private readonly maxEntries = 4096,
  ) {}

  /** True (and recorded) when an escalation for this channel is allowed now. */
  tryEscalate(channelId: number): boolean {
    const t = this.now();
    const prev = this.last.get(channelId);
    if (prev !== undefined && t - prev < this.intervalMs) return false;
    if (prev === undefined && this.last.size >= this.maxEntries) {
      for (const [k, v] of this.last) {
        if (t - v >= this.intervalMs) this.last.delete(k);
      }
      if (this.last.size >= this.maxEntries) return false;
    }
    this.last.set(channelId, t);
    return true;
  }

  /** Ms until the next escalation for this channel is allowed (0 = now). */
  remainingMs(channelId: number): number {
    const prev = this.last.get(channelId);
    return prev === undefined ? 0 : Math.max(0, prev + this.intervalMs - this.now());
  }

  get size(): number {
    return this.last.size;
  }
}

/** A key this device generated for an epoch and may already have (partly) published. */
export interface PendingEpochKey {
  key: Uint8Array;
  keyTs: number;
  keyCommitment: Uint8Array;
  /** Target ids (`wallet:device`) the node confirmed for this key. */
  covered: Set<string>;
}

/**
 * In-memory pending keys per `(channel, epoch)` — the "reuse the SAME key on
 * retry" store (contract step 3). Create ONE per account/device and drop it
 * (with {@link PendingEpochKeyStore.clear}) on account switch. Bounded: past
 * `maxEntries` the oldest entry is evicted (and zeroed).
 */
export class PendingEpochKeyStore {
  private readonly map = new Map<string, PendingEpochKey>();
  /** `(channel, epoch)` keys with an `establishEpochKey` call in flight. */
  private readonly locks = new Map<string, { token: number; at: number; staleAfterMs: number }>();
  private lockSeq = 0;
  /** Consecutive establish calls per `(channel, epoch)` that ended without a confirmation. */
  private readonly unconfirmed = new Map<string, number>();
  /** Entries removed while their call was in flight: zeroed when it releases. */
  private readonly deferred = new Map<string, PendingEpochKey[]>();
  constructor(private readonly maxEntries = 256) {}

  private k(channelId: number, epoch: number): string {
    return `${channelId}:${epoch}`;
  }

  /** Zero now, or later if a call for that `(channel, epoch)` is still in flight. */
  private retire(k: string, p: PendingEpochKey): void {
    if (this.locks.has(k)) {
      const list = this.deferred.get(k) ?? [];
      list.push(p);
      this.deferred.set(k, list);
    } else {
      p.key.fill(0);
    }
  }

  get(channelId: number, epoch: number): PendingEpochKey | undefined {
    return this.map.get(this.k(channelId, epoch));
  }

  set(channelId: number, epoch: number, p: PendingEpochKey): void {
    const k = this.k(channelId, epoch);
    const prev = this.map.get(k);
    this.map.delete(k);
    if (prev && prev !== p) this.retire(k, prev);
    while (this.map.size >= this.maxEntries) {
      const [ok, ov] = this.map.entries().next().value as [string, PendingEpochKey];
      this.map.delete(ok);
      this.retire(ok, ov);
    }
    this.map.set(k, p);
  }

  /**
   * Remove; `zero` wipes the key bytes (abandoned keys) — deferred while a
   * call for that `(channel, epoch)` is in flight (it works on its own copy
   * and notices the removal before its next publish).
   */
  delete(channelId: number, epoch: number, zero: boolean): void {
    const k = this.k(channelId, epoch);
    const p = this.map.get(k);
    this.map.delete(k);
    if (p && zero) this.retire(k, p);
  }

  /** Zero and drop everything (account switch / sign-out); in-flight entries are zeroed on release. */
  clear(): void {
    for (const [k, p] of this.map) this.retire(k, p);
    this.map.clear();
  }

  /**
   * Take the in-flight lock for `(channel, epoch)`. Returns a token, or null
   * when another `establishEpochKey` call holds it (that call then returns
   * `waiting` / `in_flight`). `staleAfterMs` is the LOCK OWNER's own bound
   * (stored with the lock): once the lock is older than that (a call whose
   * injected I/O never returned) it is TAKEN OVER, whatever bound the new
   * caller uses; the old call loses ownership and stops before its next publish.
   */
  tryLock(channelId: number, epoch: number, now = 0, staleAfterMs = Infinity): number | null {
    const k = this.k(channelId, epoch);
    const held = this.locks.get(k);
    if (held && now - held.at <= held.staleAfterMs) return null;
    const token = ++this.lockSeq;
    this.locks.set(k, { token, at: now, staleAfterMs });
    return token;
  }

  /** Whether `token` still owns the lock (false after a takeover). */
  holds(channelId: number, epoch: number, token: number): boolean {
    return this.locks.get(this.k(channelId, epoch))?.token === token;
  }

  /** Release the lock (if `token` still owns it) and zero any entry retired while it was held. */
  unlock(channelId: number, epoch: number, token?: number): void {
    const k = this.k(channelId, epoch);
    const held = this.locks.get(k);
    if (held && token !== undefined && held.token !== token) return; // taken over: the new owner releases
    this.locks.delete(k);
    for (const p of this.deferred.get(k) ?? []) p.key.fill(0);
    this.deferred.delete(k);
  }

  /** Count one more unconfirmed call for `(channel, epoch)`; returns the new streak. */
  noteUnconfirmed(channelId: number, epoch: number): number {
    const k = this.k(channelId, epoch);
    const n = (this.unconfirmed.get(k) ?? 0) + 1;
    if (this.unconfirmed.size >= this.maxEntries * 4 && !this.unconfirmed.has(k)) {
      const first = this.unconfirmed.keys().next().value;
      if (first !== undefined) this.unconfirmed.delete(first);
    }
    this.unconfirmed.set(k, n);
    return n;
  }

  /** Reset the unconfirmed streak (a key was confirmed, or the caller moved on). */
  resetUnconfirmed(channelId: number, epoch: number): void {
    this.unconfirmed.delete(this.k(channelId, epoch));
  }

  get size(): number {
    return this.map.size;
  }
}

// --- establishEpochKey ------------------------------------------------------------------

/** Tunables (defaults follow the contract). */
export interface EstablishEpochKeyOptions {
  /** Own-slot poll interval while waiting for a winner (1.5 s). */
  pollMs: number;
  /** Base wait for a winner's wrap before escalating (30 s, plus targets / rate). */
  waitTimeoutMs: number;
  /** Token-bucket rate used to scale the wait timeout (3 /s). */
  publishRatePerSec: number;
  /** Transient failures tolerated per target before giving up on it (4). */
  transientTries: number;
  /** First transient backoff (500 ms, doubling, capped at 8 s). */
  transientBackoffMs: number;
  /** Max 429 waits per target (20). */
  rateLimitRetries: number;
  /**
   * `'final'` (default): `confirmed` only once the node reports the winner
   * FINAL (no further supersede possible on that node). `'quick'`: also
   * confirm once the commitment has stayed ours for `settleMs` — faster, but a
   * better-ranked rival delayed past `settleMs` (gossip backfill, a rival's
   * 429 backoff) can still supersede it; see the simulator's numbers in the
   * CHANGELOG before choosing it.
   */
  confirmMode: 'final' | 'quick';
  /** `'quick'` settle time (10 s). */
  settleMs: number;
  /** Longest single settle poll sleep (10 s). */
  settlePollMaxMs: number;
  /** Re-read the commitment before an own-device retry when older than this (2 s). */
  recheckMs: number;
  /** Hard bound on one establish call (15 min) → `waiting`. */
  maxTotalMs: number;
  /** A pending key not yet confirmed published anywhere is regenerated past this age (60 s = finality/2). */
  pendingMaxAgeMs: number;
  /** Minimum spacing between two winner reads, whatever woke the loop (1 s; >= 250). */
  minReadSpacingMs: number;
  /**
   * Consecutive calls for the same `(channel, epoch)` that may end unconfirmed
   * (`waiting`: `not_final`, `peers_pending`, `winner_not_delivered`) before
   * the call returns `unconfirmed_exhausted` instead (5).
   */
  maxUnconfirmedCalls: number;
  /**
   * How many peers (`peerCommitments`) must report the SAME different final
   * winner before the call returns `split`, and how many must answer for this
   * epoch before a key is confirmed (capped at the number of peer answers
   * returned). Default 1: a single hostile peer can force `split` (a gated
   * rotation, at most once per channel per 10 min). With a quorum > 1 a
   * dissent below the quorum is never confirmed over — the call keeps
   * waiting — so a hostile peer can only DELAY confirmation (about
   * `maxUnconfirmedCalls` × `maxTotalMs`, ~75-90 min per epoch with the
   * defaults) and then `unconfirmed_exhausted`.
   */
  peerQuorum: number;
}

export const DEFAULT_ESTABLISH_OPTIONS: EstablishEpochKeyOptions = {
  pollMs: 1_500,
  waitTimeoutMs: 30_000,
  publishRatePerSec: 3,
  transientTries: 4,
  transientBackoffMs: 500,
  rateLimitRetries: 20,
  confirmMode: 'final',
  settleMs: 10_000,
  settlePollMaxMs: 10_000,
  recheckMs: 2_000,
  maxTotalMs: 15 * 60_000,
  pendingMaxAgeMs: PENDING_KEY_MAX_AGE_MS,
  minReadSpacingMs: 1_000,
  maxUnconfirmedCalls: 5,
  peerQuorum: 1,
};

/** Everything {@link establishEpochKey} touches, injected. */
export interface EstablishEpochKeyDeps {
  channelId: number;
  /** The epoch to establish or adopt (>= 1). */
  epoch: number;
  self: {
    /** Our wallet (`klv1…`). */
    wallet: string;
    /** Our device id (hex). */
    deviceId: string;
    /** The address our envelopes are signed with (`ogd1…` device or the wallet). */
    signingAddress: string;
    /** Our device's X25519 enc pubkey (32 bytes). */
    encPub: Uint8Array;
  };
  /**
   * Node arbitration state (`OgmaraClient.getKeyCommitment`) for `epoch`, or
   * — called with `undefined` — for the node's HIGHEST known epoch (used to
   * bound `highestEpochSeen`). Throw on transport errors.
   */
  getCommitment: (epoch?: number) => Promise<KeyCommitmentInfo>;
  /**
   * Our own slot's wrap at `epoch`, VERIFIED with {@link verifyChannelKeyWrap}
   * (see {@link makeOwnWrapFetcher}); null when absent or unverifiable.
   */
  fetchOwnWrap: (epoch: number) => Promise<VerifiedChannelKeyWrap | null>;
  /** Is our own enc-key row bound (`verifyEncKeyBinding` → `bound`)? */
  isSelfBound: () => Promise<boolean>;
  /** Bound devices of verified members to wrap to (our own may be included; deduped). */
  listTargets: () => Promise<EpochKeyTarget[]>;
  /**
   * Build + publish ONE wrap (`buildChannelEpochKeyEnvelope` →
   * `publishChannelKeyEnvelope`). Throws the typed key-envelope errors.
   * MUST build (sign) a new envelope on every call — never resend cached
   * bytes — and always when `opts.fresh` is set: that is the republish path
   * after an unconfirmable duplicate 409 (a new envelope timestamp gives a new
   * msg_id).
   */
  publish: (
    target: EpochKeyTarget,
    key: Uint8Array,
    keyTs: number,
    epoch: number,
    opts?: { fresh?: boolean },
  ) => Promise<PublishChannelKeyResult>;
  /** Pending-key store (one per account/device). */
  pending: PendingEpochKeyStore;
  /** Fresh 32-byte CSPRNG key. */
  newKey: () => Uint8Array;
  /**
   * The LOCAL wall clock (`Date.now`) — also the `key_ts` source, and it must
   * be the same clock the envelope builder stamps envelopes with (the node
   * requires `key_ts <= envelope.timestamp`). Never a node-supplied time.
   */
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  /**
   * Sleep up to `ms`, resolving early on a `channel_key_commitment` WS event.
   * Always raced with `sleep(ms)`, so a wait that never resolves cannot hang
   * the call; winner reads stay at least `minReadSpacingMs` apart.
   */
  waitForEvent?: (ms: number) => Promise<void>;
  /** Shared token bucket (3/s burst 10 across channels). */
  bucket: { take: () => Promise<void> };
  /**
   * Throws to abort (e.g. the account switched or signed out). Called after
   * every await. Optional in the type, but EVERY real client must pass it:
   * without it a call keeps publishing for an account that is gone.
   * (General rule: every injected async dep must time out by itself; a call
   * whose dep hangs holds the per-epoch lock until it is taken over after
   * `maxTotalMs` + 60 s.)
   */
  guard?: (step: string) => void;
  /** Errors from `publish` that must propagate instead of counting as transient. */
  isFatalError?: (e: unknown) => boolean;
  /** Expected number of targets (scales the winner wait timeout). */
  targetCount?: number;
  /**
   * REQUIRED. Whether the caller knows this epoch was ALREADY established
   * somewhere (a channel message, WS event or another node references it)
   * rather than rotating into a brand-new one. Pass `false` only for a real
   * rotation into an epoch nobody has used yet.
   */
  epochKnownToExist: boolean;
  /**
   * REQUIRED. The highest channel key epoch the caller has AUTHENTICATED
   * evidence of from a source other than this node's key-commitment state:
   * an epoch whose channel message it DECRYPTED, whose wrap it verified
   * (`verifyChannelKeyWrap`), or a commitment it read from another node
   * (0 when none). Never a bare `key_epoch` number from an unverified message
   * — any member can write any number there; that inflation threat is closed
   * ONLY by this contract (the SDK never discards the value, because a fresh
   * or lagging node is exactly the case it exists for). When the home
   * node reports `none` for an epoch `<= highestEpochSeen` (or one
   * `epochKnownToExist`), no key is ever created there — a lagging or fresh
   * node must never open an epoch the mesh may already have finalized (late
   * covers of the real key are refused there with `key_ts_stale`, so a key
   * created there forks the epoch for good). The outcome is `node_lagging`.
   */
  highestEpochSeen: number;
  /**
   * Optional but recommended: read THIS epoch's commitment from one or more
   * OTHER nodes. Before confirming, a different FINAL winner on
   * `peerQuorum` of them yields `split` (the epoch is split across the mesh —
   * e.g. by a partition during the rotation; no node-to-node sync repairs
   * it); a different non-final winner keeps the call waiting (confirmed stays
   * false). Query the peers with `Promise.allSettled` and return the answers
   * you got; THROW only when peers are known but NONE answered (the key then
   * stays unconfirmed); `[]` means "no peer nodes known" and passes. The
   * key-commitment endpoint is member-only: a peer that answers 404 (the
   * caller is not a member there yet) is "no answer", not a veto. Every
   * injected dep — this one included — must time out on its own.
   * A hostile peer can force `split` (and so a gated rotation), never a key.
   */
  peerCommitments?: (epoch: number) => Promise<KeyCommitmentInfo[]>;
  /**
   * Optional: enforce the escalation limit inside the call — an `escalate`
   * the gate refuses becomes `waiting` (`escalation_gated`). Share ONE gate
   * per account across all channels.
   */
  escalationGate?: EscalationGate;
  log?: (step: string, data?: Record<string, unknown>) => void;
  /**
   * Optional early-use hook, called at most ONCE per call when the node's
   * winner is our candidate pair but not yet final (the settle phase, up to
   * ~120 s): `role` says whether it is our key or an adopted one, and `key` is
   * a COPY the caller may use to send immediately ("established-unconfirmed").
   * RESIDUAL RISK — the clients decide: if a better-ranked key still
   * supersedes it before finality, messages sent under this key are orphaned
   * (no member receives it). Treat it as revoked unless the call then returns
   * `established`/`adopted` with the SAME `(keyTs, keyCommitment)`.
   */
  onUnconfirmed?: (u: UnconfirmedEpochKey) => void;
  options?: Partial<EstablishEpochKeyOptions>;
}

/** Passed to {@link EstablishEpochKeyDeps.onUnconfirmed}. */
export interface UnconfirmedEpochKey {
  role: 'established' | 'adopted';
  epoch: number;
  /** A copy of the key (the caller owns it). */
  key: Uint8Array;
  keyTs: number;
  keyCommitment: Uint8Array;
  /** Node-clock ms after which the winner is final (recorded_at + finality). */
  finalAt?: number;
}

/** Outcome of {@link establishEpochKey}. */
export type EstablishEpochKeyOutcome =
  /** We established the epoch's key (our commitment is the node's winner). */
  | {
      kind: 'established';
      epoch: number;
      key: Uint8Array;
      keyTs: number;
      keyCommitment: Uint8Array;
      confirmed: boolean;
      /**
       * Targets not covered (transient failures) — call again later to resume
       * with the same key. Home-node truth only (see the caller contract).
       */
      uncovered: EpochKeyTarget[];
      /** Targets the node rejected permanently (skipped). */
      rejected: EpochKeyTarget[];
    }
  /** Another member's key won; we adopted it from a verified wrap at our own slot. */
  | {
      kind: 'adopted';
      epoch: number;
      key: Uint8Array;
      keyTs: number;
      keyCommitment: Uint8Array;
      author: string;
      confirmed: boolean;
    }
  /** The epoch predates arbitration on this node — use the legacy path / rotate. */
  | { kind: 'legacy'; epoch: number }
  /** Our own enc-key row is not bound — re-bind before establishing. */
  | { kind: 'needs_binding'; epoch: number }
  /**
   * Rotate to `epoch + 1` (gated, at most once per channel per 10 min): the
   * node's FINAL winner never delivered a verifiable wrap to us.
   */
  | { kind: 'escalate'; epoch: number; winner: KeyCommitmentInfo }
  /**
   * Our home node has no state for an epoch the mesh is known to have
   * (`epoch <= highestEpochSeen` or `epochKnownToExist`). No key was created.
   * Recovery is the caller's: rotate to `recoveryEpoch` (= `max(epoch,
   * highestEpochSeen) + 1`) through the {@link EscalationGate}, or use a node
   * that has the epoch. `unrecoverableHere: true` when that epoch is beyond
   * what this node accepts (its highest + 256): rotating here would only be
   * refused (`epochTooHigh`) — switch nodes or surface it. With a supplied
   * `escalationGate` that refuses, the call returns `waiting` /
   * `escalation_gated` instead.
   */
  | { kind: 'node_lagging'; epoch: number; highestEpochSeen: number; recoveryEpoch: number; unrecoverableHere?: boolean }
  /**
   * Another node (from `peerCommitments`) holds a DIFFERENT final winner for
   * this epoch: the epoch is split. Nothing was confirmed; rotate (gated)
   * before sending anything under this epoch.
   */
  | { kind: 'split'; epoch: number; home: KeyCommitmentInfo; peer: KeyCommitmentInfo }
  /**
   * `maxUnconfirmedCalls` calls in a row ended unconfirmed (the winner never
   * became final / the peers never agreed / the wrap never arrived): stop
   * retrying this epoch — rotate (gated) or surface it.
   */
  | { kind: 'unconfirmed_exhausted'; epoch: number; calls: number; lastReason: string }
  /**
   * Nothing decided yet — call again later. `reason`: `not_final`, `peers_pending`,
   * `winner_not_delivered`, `in_flight` (another call for this channel/epoch
   * is running), `pending_lost` (the pending entry was cleared or replaced
   * during the call — e.g. an account switch), `key_integrity`,
   * `non_monotonic_winner` (hostile node), `resume_cap`, `escalation_gated`.
   */
  | { kind: 'waiting'; epoch: number; reason: string }
  /** Our publish was refused or kept failing. `retryable` keeps the pending key for a retry. */
  | {
      kind: 'failed';
      epoch: number;
      reason: string;
      retryable: boolean;
      /**
       * The node refused this epoch outright (`key_epoch_below_floor`,
       * `key_epoch_evicted`): the caller must move to a higher epoch.
       */
      epochTooLow?: boolean;
      /**
       * `key_epoch_too_far`: the epoch is beyond the node's acceptance bound
       * (far ahead of the highest epoch it knows). Do NOT retry at another
       * epoch automatically — surface it to the caller / user.
       */
      epochTooHigh?: boolean;
    };

/**
 * l2-node 0.143.0 400 codes for a channel key envelope: `key_commitment_required`,
 * `key_commitment_invalid`, `key_ts_stale`, `key_epoch_below_floor`,
 * `key_epoch_evicted`, `key_epoch_too_far`, `key_scope_full` (plus
 * `key_sync_not_winner` on sync paths, never seen by clients).
 * `key_epoch_below_floor` / `key_epoch_evicted` mean the epoch is dead on
 * this node — move to a higher one; `key_epoch_too_far` means it is far
 * beyond the node's latest epoch — surface it, never retry automatically.
 */
const EPOCH_TOO_LOW_CODES = new Set(['key_epoch_below_floor', 'key_epoch_evicted']);

type PublishOutcome =
  | { r: 'ok' }
  | { r: 'lost' }
  | { r: 'stale' }
  | { r: 'conflict' }
  | { r: 'rejected'; code: string }
  | { r: 'transient'; reason: string };

/**
 * Establish or adopt the channel key for `deps.epoch` (see the module comment
 * for steps 1-7). Never returns an unverified key: `adopted` keys come from a
 * {@link verifyChannelKeyWrap}-verified wrap whose commitment is the node's
 * winner, `established` keys are our own and the node's winner.
 *
 * Caller contract:
 *  - `established` with `uncovered` non-empty, `failed` (retryable) and
 *    `waiting`: call again for the SAME epoch later (the pending key resumes).
 *  - Persist the epoch number you are establishing (never the key) until a
 *    terminal outcome, and after an app restart call again for THAT epoch
 *    before moving to a higher one: a winner our device signed is then found
 *    in our own slot and resumed, so members not yet covered still receive it
 *    (otherwise they escalate and messages already sent under it stay
 *    unreadable for them).
 *  - `escalate`: rotate to `epoch + 1` at most once per channel per 10 min
 *    ({@link EscalationGate}); `node_lagging`: never create that epoch on
 *    this node — rotate to its `recoveryEpoch` (gated) or use another node;
 *    `failed` with `epochTooLow`: move to a higher epoch; `failed` with
 *    `epochTooHigh`: surface it (no automatic retry); `legacy`: use the
 *    legacy key path / rotate.
 *  - `established.uncovered` / `rejected` (and the pending `covered` set) are
 *    HOME-NODE truth only: a peer
 *    node that never saw the epoch (state `none`) ignores late covers
 *    (`key_ts_stale` there), so members homed on such a node may still need
 *    to rotate (they get `node_lagging`).
 *  - `split` (with `peerCommitments`): `peerQuorum` other nodes finalized a
 *    different key for this epoch — rotate (gated) before sending anything
 *    under it. Our own pending key is kept, so repeated calls do not
 *    re-cover every member. With the default quorum of 1 a single hostile
 *    peer can force this (a gated rotation per 10 min, never a key).
 *  - `unconfirmed_exhausted`: `maxUnconfirmedCalls` calls in a row for this
 *    epoch ended unconfirmed — stop retrying it; rotate (gated) or surface.
 *  - Heal trigger for splits the peer check could not see (no peers, peers
 *    lagging): a channel message at YOUR confirmed epoch that your key cannot
 *    decrypt means another member confirmed a different key → rotate to the
 *    next epoch through the {@link EscalationGate}. Anyone can send garbage
 *    ciphertext to trigger it, so the gate (once per channel per 10 min) is
 *    what rate-limits this.
 *  - `waiting` / `in_flight`: another call for the same channel/epoch is
 *    running (one per account and epoch at a time); `pending_lost`: the
 *    pending store was cleared or the entry replaced during the call (account
 *    switch) — nothing more was published.
 *  - `highestEpochSeen` / `epochKnownToExist` must come from AUTHENTICATED
 *    evidence (decrypted messages, verified wraps, other nodes' commitments);
 *    pass a `guard`; `now` is the local `Date.now`.
 *  - The safe rule is to send under an epoch only after `confirmed: true`.
 *    Callers that cannot wait ~2 min may opt into `onUnconfirmed` and send
 *    earlier, accepting that a late supersede orphans those messages.
 */
export async function establishEpochKey(deps: EstablishEpochKeyDeps): Promise<EstablishEpochKeyOutcome> {
  const o = validateEstablishOptions({ ...DEFAULT_ESTABLISH_OPTIONS, ...(deps.options ?? {}) });
  const { channelId, epoch } = deps;
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('epoch must be a positive safe integer');
  if (!Number.isSafeInteger(channelId) || channelId <= 0) throw new Error('channelId must be a positive safe integer');
  if (!Number.isSafeInteger(deps.highestEpochSeen) || deps.highestEpochSeen < 0) {
    throw new Error('highestEpochSeen must be a non-negative safe integer');
  }
  if (typeof deps.epochKnownToExist !== 'boolean') throw new Error('epochKnownToExist is required');
  // One call per (channel, epoch) at a time: a second concurrent call would
  // share the pending entry with this one (audit r45 B1). A lock older than
  // maxTotalMs + 60 s belongs to a call whose injected I/O never returned: it
  // is taken over, and that call stops before its next publish.
  const token = deps.pending.tryLock(channelId, epoch, deps.now(), o.maxTotalMs + LOCK_TAKEOVER_MARGIN_MS);
  if (token === null) return { kind: 'waiting', epoch, reason: 'in_flight' };
  const copies: Uint8Array[] = [];
  let out: EstablishEpochKeyOutcome;
  try {
    out = await establishLocked(deps, o, token, copies);
  } catch (e) {
    // W3: an abort anywhere (guard, fatal error) wipes every private key copy.
    for (const c of copies) c.fill(0);
    throw e;
  } finally {
    deps.pending.unlock(channelId, epoch, token);
  }
  // Bounded number of calls that end without a confirmation (B3).
  if (out.kind === 'established' || out.kind === 'adopted' || out.kind === 'split' || out.kind === 'escalate' || out.kind === 'node_lagging') {
    deps.pending.resetUnconfirmed(channelId, epoch);
  } else if (out.kind === 'waiting' && UNCONFIRMED_REASONS.has(out.reason)) {
    const n = deps.pending.noteUnconfirmed(channelId, epoch);
    if (n >= o.maxUnconfirmedCalls) {
      deps.pending.resetUnconfirmed(channelId, epoch);
      return { kind: 'unconfirmed_exhausted', epoch, calls: n, lastReason: out.reason };
    }
  }
  return out;
}

/** A lock is taken over once it is older than `maxTotalMs` plus this margin. */
const LOCK_TAKEOVER_MARGIN_MS = 60_000;
/** `waiting` reasons that count toward `unconfirmed_exhausted`. */
const UNCONFIRMED_REASONS = new Set(['not_final', 'peers_pending', 'winner_not_delivered']);

/** Validate tunables (audit r45 W1): nonsense values could spin or never end. */
export function validateEstablishOptions(o: EstablishEpochKeyOptions): EstablishEpochKeyOptions {
  const num = (v: unknown, min: number, max: number, name: string): void => {
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max) {
      throw new Error(`establishEpochKey option ${name} must be a number in [${min}, ${max}]`);
    }
  };
  num(o.pollMs, 250, 60_000, 'pollMs');
  // Raising only pollMs must not make the default settlePollMaxMs invalid.
  if (typeof o.settlePollMaxMs === 'number' && o.settlePollMaxMs < o.pollMs) o = { ...o, settlePollMaxMs: o.pollMs };
  num(o.minReadSpacingMs, 250, 60_000, 'minReadSpacingMs');
  num(o.waitTimeoutMs, 0, 3_600_000, 'waitTimeoutMs');
  num(o.publishRatePerSec, 0.1, 1_000, 'publishRatePerSec');
  num(o.transientTries, 1, 100, 'transientTries');
  num(o.transientBackoffMs, 0, 60_000, 'transientBackoffMs');
  num(o.rateLimitRetries, 0, 1_000, 'rateLimitRetries');
  num(o.settleMs, 0, 3_600_000, 'settleMs');
  num(o.settlePollMaxMs, o.pollMs, 600_000, 'settlePollMaxMs');
  num(o.recheckMs, 0, 600_000, 'recheckMs');
  num(o.maxTotalMs, o.pollMs, 24 * 3_600_000, 'maxTotalMs');
  num(o.pendingMaxAgeMs, 1, KEY_COMMIT_FINALITY_MS, 'pendingMaxAgeMs');
  num(o.maxUnconfirmedCalls, 1, 1_000, 'maxUnconfirmedCalls');
  num(o.peerQuorum, 1, 64, 'peerQuorum');
  if (!Number.isInteger(o.peerQuorum)) throw new Error('establishEpochKey option peerQuorum must be an integer');
  if (o.confirmMode !== 'final' && o.confirmMode !== 'quick') throw new Error('confirmMode must be final or quick');
  return o;
}

/** The node accepts a new epoch at most this far above its highest known epoch (`key_epoch_too_far`). */
const NODE_EPOCH_MAX_AHEAD = 256;

const allZero = (b: Uint8Array): boolean => b.every((x) => x === 0);

async function establishLocked(
  deps: EstablishEpochKeyDeps,
  o: EstablishEpochKeyOptions,
  lockToken: number,
  copies: Uint8Array[],
): Promise<EstablishEpochKeyOutcome> {
  const { channelId, epoch, self } = deps;
  const scope = computeChannelScope(channelId);
  const startedAt = deps.now();
  const guard = (step: string): void => deps.guard?.(step);
  const log = (step: string, data?: Record<string, unknown>): void => deps.log?.(step, { channelId, epoch, ...data });
  // A custom event wait is always raced with a plain sleep so it can never hang (W2).
  const wake = (ms: number): Promise<void> =>
    deps.waitForEvent ? Promise.race([deps.waitForEvent(ms), deps.sleep(ms)]) : deps.sleep(ms);
  const selfTarget: EpochKeyTarget = { target: self.wallet, deviceId: self.deviceId.toLowerCase(), encPub: self.encPub };
  const selfId = targetId(selfTarget);
  const overBudget = (): boolean => deps.now() - startedAt >= o.maxTotalMs;
  const backoff = (n: number): number => Math.min(8_000, o.transientBackoffMs * 2 ** (n - 1));

  let lastInfo: KeyCommitmentInfo | null = null;
  let lastInfoAt = -Infinity;
  let unconfirmedSignalled = false;
  const readInfo = async (step: string): Promise<KeyCommitmentInfo | null> => {
    let info: KeyCommitmentInfo | null = null;
    try {
      info = await deps.getCommitment(epoch);
    } catch (e) {
      guard(step);
      if (deps.isFatalError?.(e)) throw e;
      log('commitment read failed', { err: e instanceof Error ? e.message : String(e) });
      return null;
    }
    guard(step);
    if (info.epoch !== epoch) return null; // a node answering for another epoch is not an answer
    lastInfo = info;
    lastInfoAt = deps.now();
    return info;
  };
  const readOwn = async (step: string): Promise<VerifiedChannelKeyWrap | null> => {
    let w: VerifiedChannelKeyWrap | null = null;
    try {
      w = await deps.fetchOwnWrap(epoch);
    } catch (e) {
      guard(step);
      if (deps.isFatalError?.(e)) throw e;
      return null;
    }
    try {
      guard(step);
    } catch (e) {
      w?.key.fill(0); // W3: never leave an unwrapped key behind on an abort
      throw e;
    }
    if (w && w.epoch !== epoch) {
      w.key.fill(0);
      return null;
    }
    return w;
  };
  /** The node's winning PAIR, or null. */
  const winnerOf = (info: KeyCommitmentInfo | null): KeyRank | null => {
    if (!info || info.state !== 'arbitrated' || typeof info.key_ts !== 'number') return null;
    const c = keyCommitmentFromHex(info.key_commitment);
    return c ? { keyTs: info.key_ts, keyCommitment: c } : null;
  };

  /**
   * Our own key for this call: `entry` is the store's object (shared with a
   * later call that resumes it), `key` a PRIVATE copy only this call uses —
   * nothing else can zero it under us (audit r45 B1).
   */
  type Work = { entry: PendingEpochKey; key: Uint8Array; keyTs: number; keyCommitment: Uint8Array };
  const workOf = (entry: PendingEpochKey): Work => {
    const key = entry.key.slice();
    copies.push(key);
    return { entry, key, keyTs: entry.keyTs, keyCommitment: entry.keyCommitment.slice() };
  };
  /** The store still holds OUR entry and we still own the lock (no takeover since). */
  const stillOurs = (w: Work): boolean =>
    deps.pending.get(channelId, epoch) === w.entry && deps.pending.holds(channelId, epoch, lockToken);
  /** H(scope, epoch, keyTs, key) == commitment and the key is not all-zero. */
  const intact = (key: Uint8Array, keyTs: number, c: Uint8Array): boolean => {
    if (key.length !== KEY_LEN || allZero(key)) return false;
    try {
      return keyCommitmentsEqual(computeKeyCommitment(scope, epoch, keyTs, key), c);
    } catch {
      return false;
    }
  };

  const abandon = (why: string, w?: Work): void => {
    log('abandoning our key', { why });
    if (!w || stillOurs(w)) deps.pending.delete(channelId, epoch, true);
    w?.key.fill(0);
  };
  const lost = (w: Work): EstablishEpochKeyOutcome => {
    log('pending key removed or replaced during the call → stop');
    w.key.fill(0);
    return { kind: 'waiting', epoch, reason: 'pending_lost' };
  };

  /** One target, with 429 / transient / duplicate handling and the own-device pre-publish checks. */
  const publishOne = async (t: EpochKeyTarget, w: Work, isOwn: boolean): Promise<PublishOutcome> => {
    let transient = 0;
    let limited = 0;
    let first = true;
    let fresh = false;
    for (;;) {
      if (overBudget()) return { r: 'transient', reason: 'time_budget' };
      if (isOwn && (!first || deps.now() - lastInfoAt > o.recheckMs || w.entry.covered.size === 0)) {
        // Never introduce our key LATE: before every own-device attempt the
        // node must still show `none` or OUR pair. A key that would only
        // supersede a winner recorded a while ago is abandoned instead (the
        // finality horizons of different nodes differ by the gossip delay).
        const info = first && deps.now() - lastInfoAt <= o.recheckMs ? lastInfo : await readInfo('own pre-publish check');
        if (!info) {
          transient++;
          if (transient >= o.transientTries) return { r: 'transient', reason: 'commitment_unreadable' };
          await deps.sleep(backoff(transient));
          guard('own pre-publish backoff');
          continue;
        }
        if (info.state === 'legacy') return { r: 'rejected', code: 'legacy_epoch' };
        const win = winnerOf(info);
        if (win && !sameCandidate(win, w)) return { r: 'conflict' };
        // A key not yet confirmed anywhere that has gone stale (stalled /
        // backgrounded / long 429s) is regenerated rather than injected late.
        if (!win && w.entry.covered.size === 0 && deps.now() - w.keyTs > o.pendingMaxAgeMs) return { r: 'stale' };
      }
      first = false;
      await deps.bucket.take();
      guard('publish token');
      // The store entry must still be ours right before every publish, and
      // the key we publish is our private, integrity-checked copy.
      if (!stillOurs(w)) return { r: 'lost' };
      if (!intact(w.key, w.keyTs, w.keyCommitment)) return { r: 'lost' };
      let res: PublishChannelKeyResult;
      try {
        res = await deps.publish(t, w.key, w.keyTs, epoch, fresh ? { fresh: true } : undefined);
        guard('publish');
      } catch (e) {
        guard('publish error');
        if (deps.isFatalError?.(e)) throw e;
        if (e instanceof KeyCommitmentConflictError) return { r: 'conflict' };
        if (e instanceof KeyEnvelopeRateLimitedError) {
          limited++;
          if (limited > o.rateLimitRetries) return { r: 'transient', reason: 'rate_limited' };
          log('rate limited, retrying the same key', { retryAfterMs: e.retryAfterMs, own: isOwn });
          await deps.sleep(e.retryAfterMs);
          guard('rate limit wait');
          continue;
        }
        if (e instanceof KeyEnvelopeRejectedError) {
          // `key_ts_stale` is never returned for the CURRENT winning pair, so
          // our pair is not (or no longer) the winner: on the own device (first
          // publish) regenerate with a fresh key_ts; elsewhere re-check as a conflict.
          if (e.code === 'key_ts_stale') return isOwn ? { r: 'stale' } : { r: 'conflict' };
          return { r: 'rejected', code: e.code };
        }
        transient++;
        if (transient >= o.transientTries) {
          return { r: 'transient', reason: e instanceof Error ? e.message : String(e) };
        }
        await deps.sleep(backoff(transient));
        guard('transient backoff');
        continue;
      }
      if (res.status !== 'duplicate') return { r: 'ok' };
      // A plain-text duplicate 409 only says "this exact envelope is in
      // MESSAGES" — a SUPERSEDED loser's envelope stays there after its wrap
      // was deleted. Success only when the node's winner is still OUR pair
      // AND (own device) our slot holds a wrap that verifies; otherwise the
      // wrap is re-signed with a NEW envelope timestamp (new msg_id) and
      // republished.
      const dupInfo = await readInfo('duplicate check');
      const dw = winnerOf(dupInfo);
      if (dw && !sameCandidate(dw, w)) return { r: 'conflict' };
      if (!dw && dupInfo?.state === 'legacy') return { r: 'rejected', code: 'legacy_epoch' };
      if (dw && isOwn) {
        const own = await readOwn('duplicate own-slot check');
        const ok = !!own && sameCandidate(own, w);
        own?.key.fill(0);
        if (ok) return { r: 'ok' };
      }
      log('duplicate not provably stored: re-signing with a fresh envelope', { own: isOwn, target: t.target });
      fresh = true;
      transient++;
      if (transient >= o.transientTries) return { r: 'transient', reason: 'duplicate_unconfirmed' };
    }
  };

  // --- Steps 5-7 as ONE iterative state machine -------------------------------
  // `wait`: poll our own slot for a verified wrap of the node's winning pair.
  // `settle`: wait until the winner is our candidate pair AND final (and, with
  // `peerCommitments`, no other node holds a different winner).
  // Every iteration re-reads the winner at most once, winner reads are at
  // least `minReadSpacingMs` apart, each iteration ends in a wake() that is
  // raced with a plain sleep, and the iteration count is capped — no node,
  // honest or hostile, can make this spin or run unbounded.
  type Cand = { key: Uint8Array; keyTs: number; keyCommitment: Uint8Array; author: string };
  type Phase =
    | { k: 'wait'; deadline: number; hardDeadline: number }
    | { k: 'settle'; role: 'author'; work: Work; extra: { uncovered: EpochKeyTarget[]; rejected: EpochKeyTarget[] }; start: number }
    | { k: 'settle'; role: 'adopter'; cand: Cand; start: number };
  const maxIterations = Math.ceil(o.maxTotalMs / o.pollMs) + 16;
  let iterations = 0;
  let resumes = 0;
  let lastReadAt = -Infinity;
  let peersPending = false;
  /** Best (lowest-rank) winner seen so far: an honest node's winner only moves to a BETTER pair. */
  let bestWinner: KeyRank | null = null;

  const toWait = (): Phase => {
    const n = Math.max(0, deps.targetCount ?? 0);
    const deadline = deps.now() + o.waitTimeoutMs + Math.ceil(n / Math.max(0.1, o.publishRatePerSec)) * 1000;
    return { k: 'wait', deadline, hardDeadline: deadline + KEY_COMMIT_FINALITY_MS + o.pollMs };
  };
  const candOf = (ph: Phase): { key: Uint8Array; keyTs: number; keyCommitment: Uint8Array } | null =>
    ph.k !== 'settle' ? null : ph.role === 'author' ? ph.work : ph.cand;
  /** Drop the current candidate: our own key is abandoned, an adopted one zeroed. */
  const dropCand = (ph: Phase, why: string): void => {
    if (ph.k !== 'settle') return;
    if (ph.role === 'author') abandon(why, ph.work);
    else ph.cand.key.fill(0);
  };
  /** Zero only the call's private bytes (the pending entry stays for a later resume). */
  const releaseCand = (ph: Phase): void => {
    if (ph.k !== 'settle') return;
    if (ph.role === 'author') ph.work.key.fill(0);
    else ph.cand.key.fill(0);
  };
  const isOurs = (signer: string): boolean => signer === self.signingAddress || signer === self.wallet;

  /** Highest epoch the home node knows (for bounding `highestEpochSeen`). */
  const nodeHighest = async (): Promise<number | null> => {
    try {
      const h = await deps.getCommitment(undefined);
      guard('highest epoch');
      return Number.isSafeInteger(h.epoch) && h.epoch >= 0 ? h.epoch : null;
    } catch (e) {
      guard('highest epoch');
      if (deps.isFatalError?.(e)) throw e;
      return null;
    }
  };
  /**
   * `node_lagging` when the home node has no state for an epoch the caller
   * KNOWS exists, or one at or below `highestEpochSeen` (authenticated
   * evidence by contract — decrypted messages, verified wraps, other nodes'
   * commitments — so it is never discarded here). Only the RECOVERY epoch is
   * bounded, by what the node accepts (its highest + 256). If the node's
   * highest epoch cannot be read, the call fails CLOSED (audit r48 B1).
   */
  const lagging = async (): Promise<EstablishEpochKeyOutcome | null> => {
    const seen = deps.highestEpochSeen;
    if (!deps.epochKnownToExist && epoch > seen) return null;
    const nh = await nodeHighest();
    if (nh === null) return { kind: 'failed', epoch, reason: 'commitment_unavailable', retryable: true };
    // The next epoch past everything seen. If even that is beyond what this
    // node accepts (its highest + 256), no rotation on THIS node can catch up:
    // say so (`unrecoverableHere`) instead of a capped epoch <= seen, which
    // would only produce node_lagging again (audit r50 W1).
    const target = Math.min(Number.MAX_SAFE_INTEGER, Math.max(epoch, seen) + 1);
    const unrecoverableHere = target > nh + NODE_EPOCH_MAX_AHEAD;
    if (deps.escalationGate && !deps.escalationGate.tryEscalate(channelId)) {
      return { kind: 'waiting', epoch, reason: 'escalation_gated' };
    }
    return unrecoverableHere
      ? { kind: 'node_lagging', epoch, highestEpochSeen: seen, recoveryEpoch: target, unrecoverableHere: true }
      : { kind: 'node_lagging', epoch, highestEpochSeen: seen, recoveryEpoch: target };
  };

  /** Step 6 for our pending key; returns the next phase (or a terminal outcome). */
  const cover = async (w: Work): Promise<Phase | EstablishEpochKeyOutcome> => {
    let targets: EpochKeyTarget[];
    try {
      targets = await deps.listTargets();
    } catch (e) {
      guard('list targets');
      if (deps.isFatalError?.(e)) throw e;
      w.key.fill(0);
      return { kind: 'failed', epoch, reason: 'targets_unavailable', retryable: true };
    }
    guard('list targets');
    const seen = new Set<string>([selfId]);
    const ordered = targets
      .map((t) => ({ ...t, deviceId: t.deviceId.toLowerCase() }))
      .filter((t) => {
        const id = targetId(t);
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      })
      .sort(compareTargets);
    const uncovered: EpochKeyTarget[] = [];
    const rejected: EpochKeyTarget[] = [];
    for (const t of ordered) {
      if (w.entry.covered.has(targetId(t))) continue;
      const r = await publishOne(t, w, false);
      if (r.r === 'ok') w.entry.covered.add(targetId(t));
      else if (r.r === 'lost') return lost(w);
      else if (r.r === 'conflict' || r.r === 'stale') {
        abandon('409 while covering', w);
        return toWait();
      } else if (r.r === 'rejected') {
        log('target rejected, skipping', { target: t.target, device: t.deviceId, code: r.code });
        rejected.push(t);
      } else {
        uncovered.push(t);
      }
    }
    return { k: 'settle', role: 'author', start: deps.now(), work: w, extra: { uncovered, rejected } };
  };

  /** A winner signed by THIS device (or our wallet key) sits in our slot: resume covering it. */
  const resumeOwn = async (own: VerifiedChannelKeyWrap): Promise<Phase | EstablishEpochKeyOutcome> => {
    const existing = deps.pending.get(channelId, epoch);
    let entry: PendingEpochKey;
    if (existing && sameCandidate(existing, own)) {
      own.key.fill(0);
      entry = existing;
    } else {
      if (existing) deps.pending.delete(channelId, epoch, true);
      entry = { key: own.key, keyTs: own.keyTs, keyCommitment: own.keyCommitment, covered: new Set([selfId]) };
      deps.pending.set(channelId, epoch, entry);
    }
    entry.covered.add(selfId);
    log('resuming our own winning key');
    return cover(workOf(entry));
  };

  /**
   * Read the same epoch on other nodes (B3). `split` when at least
   * `peerQuorum` peers report the SAME different FINAL winner; `pending` when
   * fewer than `min(peerQuorum, peers returned)` answered for this epoch, or
   * ANY peer reports a different winner (final below the quorum, or not yet
   * final); `pass` only when no answering peer dissents.
   */
  const peerCheck = async (
    cand: KeyRank,
  ): Promise<{ v: 'pass' } | { v: 'pending' } | { v: 'split'; peer: KeyCommitmentInfo }> => {
    if (!deps.peerCommitments) return { v: 'pass' };
    let peers: KeyCommitmentInfo[];
    try {
      peers = await deps.peerCommitments(epoch);
    } catch (e) {
      guard('peer commitments');
      if (deps.isFatalError?.(e)) throw e;
      return { v: 'pending' };
    }
    guard('peer commitments');
    const list = Array.isArray(peers) ? peers : [];
    if (list.length === 0) return { v: 'pass' }; // no peer nodes known (e.g. a single-node network)
    const answered = list.filter((p) => p && p.epoch === epoch);
    if (answered.length < Math.min(o.peerQuorum, list.length)) return { v: 'pending' };
    const finals = new Map<string, { n: number; info: KeyCommitmentInfo }>();
    const open = new Map<string, number>();
    for (const p of answered) {
      const pw = winnerOf(p);
      if (!pw || sameCandidate(pw, cand)) continue; // none / legacy / same pair
      const id = `${pw.keyTs}:${keyCommitmentToHex(pw.keyCommitment)}`;
      if (p.final) finals.set(id, { n: (finals.get(id)?.n ?? 0) + 1, info: p });
      else open.set(id, (open.get(id) ?? 0) + 1);
    }
    for (const f of finals.values()) if (f.n >= o.peerQuorum) return { v: 'split', peer: f.info };
    // Any dissent below the quorum — final or not — is never confirmed over:
    // keep waiting (bounded by maxUnconfirmedCalls), audit r50 W2.
    if (finals.size > 0 || open.size > 0) return { v: 'pending' };
    return { v: 'pass' };
  };

  const drive = async (start: Phase): Promise<EstablishEpochKeyOutcome> => {
    let ph: Phase = start;
    try {
      for (;;) {
        if (++iterations > maxIterations || overBudget()) {
          // Budget exhausted: an adopted candidate is zeroed; our own pending
          // key stays cached so the next call resumes with the SAME key.
          releaseCand(ph);
          return {
            kind: 'waiting', epoch,
            reason: ph.k === 'settle' ? (peersPending ? 'peers_pending' : 'not_final') : 'winner_not_delivered',
          };
        }
        // Minimum spacing between winner reads, whatever wakes us (W2).
        const gap = deps.now() - lastReadAt;
        if (gap < o.minReadSpacingMs) {
          await deps.sleep(o.minReadSpacingMs - gap);
          guard('read spacing');
        }
        lastReadAt = deps.now();
        const info = await readInfo(ph.k === 'settle' ? 'settle' : 'wait winner');
        if (info?.state === 'legacy') {
          dropCand(ph, 'epoch became legacy');
          return { kind: 'legacy', epoch };
        }
        const w = winnerOf(info);
        if (w) {
          if (bestWinner && compareRank(w, bestWinner) > 0) {
            // The winner moved to a WORSE pair — impossible on an honest node.
            // Keep our own pending key (W4): the node is lying, not the key.
            log('winner regressed to a worse pair → hostile node, stop');
            releaseCand(ph);
            return { kind: 'waiting', epoch, reason: 'non_monotonic_winner' };
          }
          bestWinner = w;
        }
        let ms = o.pollMs;
        if (ph.k === 'settle') {
          const cand = candOf(ph)!;
          if (w && sameCandidate(w, cand)) {
            if (!info!.final && !unconfirmedSignalled && deps.onUnconfirmed) {
              unconfirmedSignalled = true;
              try {
                deps.onUnconfirmed({
                  role: ph.role === 'author' ? 'established' : 'adopted',
                  epoch, key: cand.key.slice(), keyTs: cand.keyTs, keyCommitment: cand.keyCommitment.slice(),
                  finalAt: info!.recorded_at !== undefined ? info!.recorded_at + info!.finality_ms : undefined,
                });
              } catch (e) {
                log('onUnconfirmed threw (ignored)', { err: e instanceof Error ? e.message : String(e) });
              }
            }
            const quickOk = o.confirmMode === 'quick' && deps.now() - ph.start >= o.settleMs;
            if (info!.final || quickOk) {
              const pc = await peerCheck(cand);
              if (pc.v === 'split') {
                // Another node finalized a DIFFERENT key for this epoch: the
                // epoch is split across the mesh. Never confirm; the caller
                // rotates (gated) before anything is sent under this key. Our
                // own pending key is KEPT (W1): a later call resumes it without
                // re-covering every member.
                log('another node holds a different final winner → split');
                releaseCand(ph);
                if (deps.escalationGate && !deps.escalationGate.tryEscalate(channelId)) {
                  return { kind: 'waiting', epoch, reason: 'escalation_gated' };
                }
                return { kind: 'split', epoch, home: info!, peer: pc.peer };
              }
              peersPending = pc.v === 'pending';
              if (pc.v === 'pass') {
                // Integrity + ownership checks right before returning (B1).
                if (ph.role === 'author' && !stillOurs(ph.work)) return lost(ph.work);
                if (!intact(cand.key, cand.keyTs, cand.keyCommitment)) {
                  if (ph.role === 'author') {
                    releaseCand(ph);
                    return { kind: 'waiting', epoch, reason: 'key_integrity' };
                  }
                  // An adopted wrap that does not hash to the winner (or is an
                  // all-zero key): not a delivered wrap — keep waiting, which
                  // ends in `escalate` once the winner is final (B2).
                  releaseCand(ph);
                  ph = toWait();
                  await wake(ms);
                  guard('state machine wait');
                  continue;
                }
                if (ph.role === 'author') {
                  if (ph.extra.uncovered.length === 0) deps.pending.delete(channelId, epoch, true);
                  // `work.key` is this call's private copy: handed over as is.
                  return {
                    kind: 'established', epoch, key: ph.work.key, keyTs: cand.keyTs,
                    keyCommitment: cand.keyCommitment.slice(), confirmed: true,
                    uncovered: ph.extra.uncovered, rejected: ph.extra.rejected,
                  };
                }
                // A copy: the fetched wrap object belongs to `fetchOwnWrap`; wipe it.
                const key = ph.cand.key.slice();
                ph.cand.key.fill(0);
                return {
                  kind: 'adopted', epoch, key, keyTs: cand.keyTs,
                  keyCommitment: cand.keyCommitment.slice(), author: ph.cand.author, confirmed: true,
                };
              }
              // peers pending: keep confirmed=false and poll again.
            } else {
              const li = info!;
              if (li.recorded_at !== undefined) {
                const remaining = li.recorded_at + (li.finality_ms || KEY_COMMIT_FINALITY_MS) - deps.now() + 250;
                ms = Math.min(o.settlePollMaxMs, Math.max(o.pollMs, remaining));
              }
              if (o.confirmMode === 'quick') ms = Math.min(ms, Math.max(o.pollMs, o.settleMs - (deps.now() - ph.start)));
            }
          } else if (w) {
            // Another PAIR is the winner (a better-ranked key, or someone pairing
            // our public commitment with another key_ts): never confirm.
            log('superseded while settling', { role: ph.role });
            dropCand(ph, 'superseded');
            ph = toWait();
          }
          // state none (inconsistent / hostile node) → keep polling within the budget.
        } else {
          if (w) {
            const own = await readOwn('wait own slot');
            if (own && sameCandidate(own, w) && !intact(own.key, own.keyTs, own.keyCommitment)) {
              own.key.fill(0); // a wrap that does not hash to the winner (or an all-zero key) is no delivery
            } else if (own && sameCandidate(own, w)) {
              if (isOurs(own.signer)) {
                // The winner is a key WE published (a lost response, a restart,
                // or a node that 409'd us falsely): resume covering it.
                if (++resumes > 3) {
                  own.key.fill(0);
                  return { kind: 'waiting', epoch, reason: 'resume_cap' };
                }
                const next = await resumeOwn(own);
                if (!('k' in next)) return next;
                ph = next;
              } else {
                ph = {
                  k: 'settle', role: 'adopter', start: deps.now(),
                  cand: { key: own.key, keyTs: own.keyTs, keyCommitment: own.keyCommitment, author: own.wallet },
                };
              }
            } else {
              own?.key.fill(0);
            }
          }
          if (ph.k === 'wait') {
            const t = deps.now();
            if (t >= ph.deadline) {
              if (info && info.state === 'arbitrated' && info.final) {
                if (deps.escalationGate && !deps.escalationGate.tryEscalate(channelId)) {
                  return { kind: 'waiting', epoch, reason: 'escalation_gated' };
                }
                log('winner final but undeliverable → escalate');
                return { kind: 'escalate', epoch, winner: info };
              }
              if (info && info.state === 'none') {
                // No state for this epoch on our home node after the full wait:
                // never create it here if the mesh may already have it.
                const lag = await lagging();
                if (lag) return lag;
              }
              if (t >= ph.hardDeadline) return { kind: 'waiting', epoch, reason: 'winner_not_delivered' };
            }
          }
        }
        await wake(ms);
        guard('state machine wait');
      }
    } catch (e) {
      releaseCand(ph); // W3: never leave key bytes behind on an abort
      throw e;
    }
  };

  // (1) Pre-check.
  const info = await readInfo('pre-check');
  if (!info) return { kind: 'failed', epoch, reason: 'commitment_unavailable', retryable: true };
  if (info.state === 'legacy') return { kind: 'legacy', epoch };
  if (info.state === 'none') {
    // A lagging / fresh home node must never create an epoch the mesh may
    // already have finalized (late covers of the real key are refused there
    // with key_ts_stale, so a key created here would fork the epoch).
    const lag = await lagging();
    if (lag) {
      log('home node lags behind a known epoch → refuse to create it here');
      return lag;
    }
  }
  let entry = deps.pending.get(channelId, epoch);
  const winner = winnerOf(info);
  if (winner) {
    bestWinner = winner;
    if (entry && sameCandidate(entry, winner)) {
      log('our pending key is the winner → resume');
    } else {
      if (entry) {
        abandon('another key won');
        entry = undefined;
      }
      const own = await readOwn('pre-check own slot');
      if (own && sameCandidate(own, winner) && intact(own.key, own.keyTs, own.keyCommitment)) {
        if (isOurs(own.signer)) {
          resumes++;
          const next = await resumeOwn(own);
          return 'k' in next ? drive(next) : next;
        }
        return drive({
          k: 'settle', role: 'adopter', start: deps.now(),
          cand: { key: own.key, keyTs: own.keyTs, keyCommitment: own.keyCommitment, author: own.wallet },
        });
      }
      own?.key.fill(0);
      return drive(toWait());
    }
  }

  // (2) Our own enc row must be bound before we create a key.
  let bound = false;
  try {
    bound = await deps.isSelfBound();
  } catch (e) {
    guard('binding check');
    if (deps.isFatalError?.(e)) throw e;
    return { kind: 'failed', epoch, reason: 'binding_unavailable', retryable: true };
  }
  guard('binding check');
  if (!bound) return { kind: 'needs_binding', epoch };

  // (3) + (4): reuse the pending key (else generate + cache BEFORE publishing),
  // then publish to our own device FIRST. A pending key that went stale before
  // its first confirmed publish is regenerated (bounded).
  let work: Work | undefined;
  for (let regens = 0; ; regens++) {
    if (!entry) {
      const key = deps.newKey();
      if (!(key instanceof Uint8Array) || key.length !== KEY_LEN || allZero(key)) {
        throw new Error('newKey must return 32 random (non-zero) bytes');
      }
      const keyTs = deps.now();
      entry = { key, keyTs, keyCommitment: computeKeyCommitment(scope, epoch, keyTs, key), covered: new Set() };
      deps.pending.set(channelId, epoch, entry);
      log('generated a new key', { keyTs });
    }
    work = workOf(entry);
    if (!intact(work.key, work.keyTs, work.keyCommitment)) {
      // A stored entry whose bytes no longer match its commitment (zeroed or
      // corrupted) is never published: drop it and start over.
      abandon('pending key failed its integrity check', work);
      entry = undefined;
      if (regens >= 2) return { kind: 'failed', epoch, reason: 'pending_key_corrupt', retryable: true };
      continue;
    }
    if (entry.covered.has(selfId)) break;
    const r = await publishOne(selfTarget, work, true);
    if (r.r === 'ok') {
      entry.covered.add(selfId);
      break;
    }
    if (r.r === 'lost') return lost(work);
    if (r.r === 'stale') {
      abandon('stale before its first publish', work);
      entry = undefined;
      if (regens >= 2) return { kind: 'failed', epoch, reason: 'stale_pending_key', retryable: true };
      continue;
    }
    if (r.r === 'conflict') {
      abandon('409 on own device', work);
      return drive(toWait());
    }
    if (r.r === 'rejected') {
      abandon(`own device rejected: ${r.code}`, work);
      if (r.code === 'legacy_epoch') return { kind: 'legacy', epoch };
      if (EPOCH_TOO_LOW_CODES.has(r.code)) return { kind: 'failed', epoch, reason: r.code, retryable: false, epochTooLow: true };
      if (r.code === 'key_epoch_too_far') return { kind: 'failed', epoch, reason: r.code, retryable: false, epochTooHigh: true };
      return { kind: 'failed', epoch, reason: r.code, retryable: false };
    }
    work.key.fill(0); // the entry stays cached for a retry with the SAME key
    return { kind: 'failed', epoch, reason: r.reason, retryable: true };
  }

  // (6) + (7)
  const next = await cover(work!);
  return 'k' in next ? drive(next) : next;
}

/**
 * Compose the `fetchOwnWrap` dependency from a client: fetch our own slot with
 * `?proof=1` and verify it with {@link verifyChannelKeyWrap}. Returns null
 * when the slot is empty or the wrap does not verify (fail closed).
 */
export function makeOwnWrapFetcher(
  client: {
    getKeyEnvelope: (
      keyScopeHex: string,
      deviceId: string,
      author?: string,
      epoch?: number,
      options?: { proof?: boolean },
    ) => Promise<{ envelope: KeyEnvelopeRecord | null }>;
  },
  ctx: Omit<VerifyChannelKeyWrapContext, 'epoch'>,
  onReject?: (reason: string) => void,
): (epoch: number) => Promise<VerifiedChannelKeyWrap | null> {
  const scopeHex = toHex(computeChannelScope(ctx.channelId));
  return async (epoch: number) => {
    // Channel keys are stored author-agnostically: author = ''.
    const resp = await client.getKeyEnvelope(scopeHex, ctx.deviceId, '', epoch, { proof: true });
    if (!resp.envelope) return null;
    const v = await verifyChannelKeyWrap(resp.envelope, { ...ctx, epoch });
    if (!v.ok) {
      onReject?.(v.reason);
      return null;
    }
    return v.wrap;
  };
}
