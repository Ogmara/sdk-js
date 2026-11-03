/**
 * Channel key commitments + arbitration rank (protocol §8.1, l2-node 0.143.0+
 * "node-arbitrated key epochs").
 *
 * Every channel-scope `ChannelKeyEnvelope` (0x61) carries a `key_commitment`
 * (32 bytes, which binds `key_ts`) and a `key_ts` (u64 ms, a per-KEY constant
 * chosen once by the establisher). A candidate key is the PAIR
 * `(key_ts, key_commitment)`. A node keeps one winning pair per
 * `(scope, epoch)`: the LOWEST rank `(key_ts, key_commitment bytes)`. A
 * better-ranked pair may supersede the recorded winner only within the
 * finality horizon ({@link KEY_COMMIT_FINALITY_MS}) after it was recorded, and
 * never with a commitment already superseded at that epoch. Any envelope with
 * `envelope.timestamp - key_ts >` {@link KEY_TS_MAX_AGE_MS} is refused
 * (`key_ts_stale`) unless its pair is exactly the current winner.
 *
 * The node never sees the key: only clients compute the commitment, and a
 * recipient re-derives it after unwrapping (`verifyChannelKeyWrap`) so a wrap
 * whose key does not match the arbitrated commitment is refused.
 */
import { keccak_256 } from '@noble/hashes/sha3';
import type { KeyCommitmentInfo, KeyCommitmentState, KeyCommitmentWinner } from './types';

/** Domain-separation tag of the key commitment hash. */
export const KEY_COMMITMENT_DOMAIN = 'ogmara-chankey-commit-v1';

/** Length of a key commitment in bytes. */
export const KEY_COMMITMENT_LEN = 32;

/** Node finality horizon: a recorded winner can be superseded only before `recorded_at + 120 s`. */
export const KEY_COMMIT_FINALITY_MS = 120_000;

/**
 * Uniform, content-only freshness rule: an envelope with
 * `envelope.timestamp - key_ts > 15 min` is refused (`400 key_ts_stale`) at
 * create AND supersede, unless its pair is exactly the current winner.
 */
export const KEY_TS_MAX_AGE_MS = 15 * 60_000;

/**
 * Client rule: a pending key older than finality/2 (60 s) that has not been
 * confirmed published anywhere is discarded and regenerated before its first
 * publish — a stalled (backgrounded / rate-limited) client must never inject
 * a well-ranked key late.
 */
export const PENDING_KEY_MAX_AGE_MS = KEY_COMMIT_FINALITY_MS / 2;

/**
 * Node `RateCategory::KeyEnvelope` at the node's own API / WS ingress: 240 key
 * envelopes (0x61, channel AND DM scope) per wallet per 60 s fixed window. A
 * refused (429) attempt consumes nothing. (Gossip between nodes uses separate
 * token buckets — 720 @ 4/s per wallet, 180 @ 1/s per wallet + scope — that
 * clients never see directly.)
 */
export const KEY_ENVELOPE_RATE_LIMIT = { max: 240, windowMs: 60_000 } as const;

/**
 * Node per-(wallet, channel scope) limit at API / WS ingress: 60 channel-scope
 * key envelopes per 60 s fixed window. Both windows are checked before either
 * is counted; a refused (429) attempt consumes no slot in either.
 * Covering a channel with more than ~60 devices therefore takes several
 * windows; `establishEpochKey` waits out each 429's `retry_after_ms`.
 */
export const KEY_ENVELOPE_SCOPE_RATE_LIMIT = { max: 60, windowMs: 60_000 } as const;

/** Node cap on stored channel key rows per scope (lowest epoch evicted). */
export const KEY_SCOPE_ROW_CAP = 512;

/** `/health` `features` entry advertising node-side key arbitration (l2-node 0.143.0+). */
export const FEATURE_KEY_COMMITMENT_V1 = 'key_commitment_v1';

const DOMAIN_BYTES = new TextEncoder().encode(KEY_COMMITMENT_DOMAIN);

/**
 * `keccak256("ogmara-chankey-commit-v1" || channel_scope[32] || epoch_be8 ||
 * key_ts_be8 || channel_key[32])`. Binding `key_ts` into the commitment makes
 * the candidate identity the PAIR `(key_ts, key_commitment)`: nobody can
 * re-rank someone else's key by pairing its public commitment with an earlier
 * `key_ts` and still pass {@link verifyChannelKeyWrap}'s re-derivation.
 *
 * @param scope - the 32-byte channel scope (`computeChannelScope(channelId)`)
 * @param epoch - the key epoch (non-negative safe integer)
 * @param keyTs - the key's establishment timestamp (ms, non-negative safe integer)
 * @param key - the 32-byte channel epoch key
 * @throws on a wrong-length scope/key or an invalid epoch / keyTs
 */
export function computeKeyCommitment(scope: Uint8Array, epoch: number, keyTs: number, key: Uint8Array): Uint8Array {
  if (!(scope instanceof Uint8Array) || scope.length !== 32) throw new Error('channel scope must be 32 bytes');
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('channel key must be 32 bytes');
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error('epoch must be a non-negative safe integer');
  if (!Number.isSafeInteger(keyTs) || keyTs < 0) throw new Error('keyTs must be a non-negative safe integer');
  const buf = new Uint8Array(DOMAIN_BYTES.length + 32 + 8 + 8 + 32);
  let o = 0;
  buf.set(DOMAIN_BYTES, o); o += DOMAIN_BYTES.length;
  buf.set(scope, o); o += 32;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(o, BigInt(epoch)); o += 8;
  dv.setBigUint64(o, BigInt(keyTs)); o += 8;
  buf.set(key, o);
  const out = keccak_256(buf);
  buf.fill(0); // the buffer held the key
  return out;
}

/** One side of an arbitration comparison — a candidate is the PAIR (keyTs, keyCommitment). */
export interface KeyRank {
  /** Establisher-chosen per-key timestamp (ms). */
  keyTs: number;
  /** 32-byte key commitment. */
  keyCommitment: Uint8Array;
}

/**
 * Compare two ranks: negative when `a` ranks BETTER (wins), positive when `b`
 * wins, 0 when identical. Order: `key_ts` ascending, then the commitment bytes
 * lexicographically ascending (unsigned) — exactly the node's rule.
 */
export function compareRank(a: KeyRank, b: KeyRank): number {
  if (a.keyTs !== b.keyTs) return a.keyTs < b.keyTs ? -1 : 1;
  const x = a.keyCommitment;
  const y = b.keyCommitment;
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i]! < y[i]! ? -1 : 1;
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}

/** True when the commitment is 32 bytes and not all-zero (node validation). */
export function isValidKeyCommitment(c: unknown): c is Uint8Array {
  if (!(c instanceof Uint8Array) || c.length !== KEY_COMMITMENT_LEN) return false;
  let acc = 0;
  for (const b of c) acc |= b;
  return acc !== 0;
}

/** True when two candidates are the same PAIR (equal keyTs AND commitment). */
export function sameCandidate(a: KeyRank, b: KeyRank): boolean {
  return a.keyTs === b.keyTs && keyCommitmentsEqual(a.keyCommitment, b.keyCommitment);
}

/** Constant-time-ish equality of two commitments (length-checked). */
export function keyCommitmentsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

// --- Wire parsing (node responses are untrusted input) -------------------------


const HEX32 = /^[0-9a-f]{64}$/;

function isSafeU64(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

/** Decode a lowercase/uppercase 64-char hex commitment, or null. */
export function keyCommitmentFromHex(hex: unknown): Uint8Array | null {
  if (typeof hex !== 'string') return null;
  const h = hex.toLowerCase();
  if (!HEX32.test(h)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Lowercase hex of a commitment. */
export function keyCommitmentToHex(c: Uint8Array): string {
  let s = '';
  for (const b of c) s += b.toString(16).padStart(2, '0');
  return s;
}

/**
 * Validate a `GET /channels/{id}/key-commitment` body. Every node-supplied
 * number must be a non-negative safe integer and an `arbitrated` state must
 * carry a valid commitment + key_ts; anything else returns null (callers fail
 * closed — treat as a transient error, never as "none").
 */
export function parseKeyCommitmentInfo(body: unknown): KeyCommitmentInfo | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  const state = b.state as KeyCommitmentState;
  if (state !== 'none' && state !== 'legacy' && state !== 'arbitrated') return null;
  if (!isSafeU64(b.channel_id) || !isSafeU64(b.epoch)) return null;
  const finality = isSafeU64(b.finality_ms) && b.finality_ms > 0 ? b.finality_ms : KEY_COMMIT_FINALITY_MS;
  const info: KeyCommitmentInfo = {
    channel_id: b.channel_id,
    epoch: b.epoch,
    state,
    final: b.final === true,
    finality_ms: finality,
  };
  if (state === 'arbitrated') {
    const c = keyCommitmentFromHex(b.key_commitment);
    if (!c || !isValidKeyCommitment(c)) return null;
    if (!isSafeU64(b.key_ts) || b.key_ts === 0) return null;
    info.key_commitment = keyCommitmentToHex(c);
    info.key_ts = b.key_ts;
    if (typeof b.author === 'string') info.author = b.author;
    if (typeof b.msg_id === 'string' && HEX32.test(b.msg_id.toLowerCase())) info.msg_id = b.msg_id.toLowerCase();
    if (isSafeU64(b.recorded_at)) info.recorded_at = b.recorded_at;
  }
  return info;
}

/** Validate the `winner` object of a 409 `key_commitment_conflict` body, or null. */
export function parseKeyCommitmentWinner(w: unknown): KeyCommitmentWinner | null {
  if (!w || typeof w !== 'object') return null;
  const o = w as Record<string, unknown>;
  const c = keyCommitmentFromHex(o.key_commitment);
  if (!c || !isValidKeyCommitment(c) || !isSafeU64(o.key_ts) || o.key_ts === 0) return null;
  return {
    key_commitment: keyCommitmentToHex(c),
    key_ts: o.key_ts,
    author: typeof o.author === 'string' ? o.author : '',
    msg_id: typeof o.msg_id === 'string' ? o.msg_id.toLowerCase() : '',
    final: o.final === true,
  };
}

// --- Typed publish errors --------------------------------------------------------

/**
 * 409 `key_commitment_conflict`: the node holds a different winning key for
 * this `(scope, epoch)` that this envelope cannot (or can no longer)
 * supersede. Abandon the key and adopt the winner.
 */
export class KeyCommitmentConflictError extends Error {
  constructor(
    /** The node's winner (null if the body's winner was malformed). */
    readonly winner: KeyCommitmentWinner | null,
    /** `state` from the body (normally `arbitrated`). */
    readonly state: string,
    readonly epoch: number | null,
  ) {
    super('key_commitment_conflict');
    this.name = 'KeyCommitmentConflictError';
  }
}

/** 429 for the node's key-envelope rate category: retry the SAME envelope/key after `retryAfterMs`. */
export class KeyEnvelopeRateLimitedError extends Error {
  constructor(
    readonly retryAfterMs: number,
    /** False when the node gave no `retry_after_ms` (a default was used). */
    readonly fromServer: boolean,
  ) {
    super(`key envelope rate limited (retry after ${retryAfterMs} ms)`);
    this.name = 'KeyEnvelopeRateLimitedError';
  }
}

/**
 * A permanent rejection of this envelope (400, or an unexpected 4xx): e.g.
 * `key_commitment_required`, `key_scope_full`, an epoch below the floor, a
 * non-member target. Retrying the same envelope will not help.
 */
export class KeyEnvelopeRejectedError extends Error {
  constructor(
    readonly status: number,
    /** Machine code when the node sent JSON `{error}`, else the (truncated) text. */
    readonly code: string,
  ) {
    super(`key envelope rejected (${status}): ${code}`);
    this.name = 'KeyEnvelopeRejectedError';
  }
}

/**
 * Transport failure, timeout or 5xx: the envelope MAY have been stored (a
 * lost response after commit). Retry with the SAME key; a later attempt
 * reports `already_present`/`duplicate` if it had landed.
 */
export class KeyEnvelopeTransientError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'KeyEnvelopeTransientError';
  }
}

/** Default wait when a 429 carries no `retry_after_ms`. */
export const DEFAULT_KEY_ENVELOPE_RETRY_MS = 1_000;
/** Upper bound applied to a node-supplied `retry_after_ms` (one rate window). */
export const MAX_KEY_ENVELOPE_RETRY_MS = KEY_ENVELOPE_RATE_LIMIT.windowMs;

/**
 * Map a non-2xx response of a channel-key publish to the typed outcome. Pure
 * (takes status + body text) so it is unit-testable without fetch. Returns
 * `'duplicate'` for the plain-text 409 "message already exists" (the exact
 * envelope is stored — but possibly a superseded loser whose wrap was deleted;
 * confirm before treating it as success), otherwise the error to throw.
 * 400 JSON codes (l2-node 0.143.0): `key_commitment_required`,
 * `key_commitment_invalid`, `key_ts_stale`, `key_epoch_below_floor`,
 * `key_epoch_evicted`, `key_epoch_too_far`, `key_scope_full`.
 */
export function classifyKeyEnvelopeResponse(
  status: number,
  text: string,
):
  | 'duplicate'
  | KeyCommitmentConflictError
  | KeyEnvelopeRateLimitedError
  | KeyEnvelopeRejectedError
  | KeyEnvelopeTransientError {
  let json: Record<string, unknown> | null = null;
  try {
    const parsed = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) json = parsed as Record<string, unknown>;
  } catch {
    json = null;
  }
  if (status === 409) {
    if (json && json.error === 'key_commitment_conflict') {
      const epoch = isSafeU64(json.epoch) ? json.epoch : null;
      return new KeyCommitmentConflictError(
        parseKeyCommitmentWinner(json.winner),
        typeof json.state === 'string' ? json.state : '',
        epoch,
      );
    }
    // The node's plain-text duplicate (routes.rs: "message already exists").
    if (!json && text.trim() === 'message already exists') return 'duplicate';
    return new KeyEnvelopeRejectedError(409, json && typeof json.error === 'string' ? json.error : text.slice(0, 200));
  }
  if (status === 429) {
    const raw = json?.retry_after_ms;
    if (isSafeU64(raw)) {
      return new KeyEnvelopeRateLimitedError(Math.min(Math.max(raw, 1), MAX_KEY_ENVELOPE_RETRY_MS), true);
    }
    return new KeyEnvelopeRateLimitedError(DEFAULT_KEY_ENVELOPE_RETRY_MS, false);
  }
  if (status >= 500 || status === 0 || status === 408) {
    return new KeyEnvelopeTransientError(status, `key envelope publish failed (${status}): ${text.slice(0, 200)}`);
  }
  return new KeyEnvelopeRejectedError(status, json && typeof json.error === 'string' ? json.error : text.slice(0, 200));
}
