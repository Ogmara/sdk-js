/**
 * TEST FIXTURE — a verbatim copy of the OLD desktop src/lib/channelKeyStore.ts (desktop 1.85.x) keyring/vault logic
 * (pre sdk-js 0.68.0), used only by channelKeyring interop tests to prove an
 * older client re-exporting a 0.68.0 backup keeps every key. Never shipped
 * (not under src/, not in the package). Do not edit beyond the import shim.
 */
/**
 * In-memory channel key cache (desktop 1.85.0) — pure, so the account,
 * evidence and never-lose rules are tested by behaviour
 * (channelKeyStore.test.ts).
 *
 * Keys are addressed `${channelScopeHex}:${epoch}`. Each slot has a PRIMARY
 * key (used to send / cover / decrypt first) and recorded where it came from
 * and whether its epoch PAIR `(keyTs, keyCommitment)` is VERIFIED:
 *  - `verified`: a wrap whose author, membership and commitment verified
 *    (`verifyChannelKeyWrap`), or our own confirmed establish / adopt;
 *  - `vault`: restored from our own sealed key vault — the vault does not
 *    record provenance, so it is UNVERIFIED until a pair verifies against it;
 *  - `legacy`: a commitment-less (pre-arbitration) wrap — never verified;
 *  - `provisional`: the creator's not-yet-final first key of a brand-new
 *    channel (never evidence, never backed up).
 *
 * NEVER LOSE A KEY (union, never shrink): a slot is never overwritten with a
 * DIFFERENT key. The held key stays primary and the other one is kept as an
 * ALTERNATE of the slot — tried when decrypting and exported to the vault
 * under the CANONICAL cross-client alias `${slot}#alt${n}`, n = 1..4 (the
 * SDK vault keyring takes free-form keys; the older mobile alias `${slot}~${n}`
 * is read too and rewritten to `#alt` on export), so a
 * backup sealed from this keyring never erases a key another device put in
 * the vault. The one exception is a `provisional` primary: a final key
 * replaces it (the provisional one is kept as a non-exported alternate). A
 * conflict is reported to the caller (log + gated heal).
 *
 * Evidence rule (shared with web / mobile):
 *  - the GLOBAL `highestEpochSeen` counts ONLY primary keys with a VERIFIED
 *    pair; never legacy keys, never vault keys without a verified pair;
 *  - holding ANY key at epoch E only makes E itself "known to exist";
 *  - the heal trigger fires only for a key with a verified pair at the latest
 *    verified epoch.
 */
interface KeyMeta { keyTs: number; keyCommitment: Uint8Array }

export type KeySource = 'verified' | 'vault' | 'legacy' | 'provisional';

interface Alt {
  key: Uint8Array;
  /** False for a superseded provisional key (never backed up). */
  exportable: boolean;
}

export interface KeyEntry {
  key: Uint8Array;
  source: KeySource;
  meta?: KeyMeta;
  /** The pair verified against this key (evidence-grade). Never for provisional / legacy. */
  verified: boolean;
  /** Other keys seen for this slot (at most {@link MAX_ALTS}; overflow is preserved verbatim). */
  alts: Alt[];
  /**
   * The primary came from a vault ALIAS entry for a slot with no primary: it
   * is used, but exported under its alias name again (`#alt1`), never
   * promoted to the primary name in the backup.
   */
  aliasOnly?: boolean;
}

/** Result of {@link ChannelKeyStore.put}. */
export type PutResult =
  /** Stored as the slot's primary (new slot, upgrade of the same key, or a final key replacing a provisional one). */
  | 'stored'
  /** A DIFFERENT key is held: it stays primary, the new key was kept as an alternate. */
  | 'conflict'
  /** Dropped: the account changed (or the input was invalid). */
  | 'stale';

const ck = (scopeHex: string, epoch: number) => `${scopeHex}:${epoch}`;
const ALT_SEP = '#alt';
/** Alternates per slot (shared cross-client cap: aliases `#alt1`..`#alt4`). */
export const MAX_ALTS = 4;
/** `${scopeHex}:${epoch}` with an optional alias `#alt<n>` (canonical) or `~<n>` (older mobile). */
const SLOT_RE = /^(.+:(\d{1,16}))(?:#alt(\d{1,3})|~(\d{1,3}))?$/;
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export class ChannelKeyStore {
  private readonly m = new Map<string, KeyEntry>();
  /** Vault entries whose key string this client does not parse: kept verbatim and re-exported. */
  private readonly opaque = new Map<string, Uint8Array>();
  private readonly generation: () => number;
  private readonly onChange: () => void;

  constructor(generation: () => number, onChange: () => void) {
    this.generation = generation;
    this.onChange = onChange;
  }

  /** Add an alternate; false when the slot is at the cap (the caller must preserve the key otherwise). */
  private addAlt(e: KeyEntry, key: Uint8Array, exportable: boolean): boolean {
    const a = e.alts.find((x) => same(x.key, key));
    if (a) {
      a.exportable ||= exportable;
      return true;
    }
    // An alias-only primary already occupies `#alt1`: at most 4 aliases per epoch in total.
    if (e.alts.length >= MAX_ALTS - (e.aliasOnly ? 1 : 0)) return false;
    e.alts.push({ key, exportable });
    return true;
  }

  /**
   * Write a key. `forGeneration` is the switch generation the caller captured
   * BEFORE its network round trip: a write after an account switch is
   * dropped (the OLD account's in-flight fetch must never land in the NEW
   * account's cache — cross-account key leak, 2026-09-04).
   */
  put(scopeHex: string, epoch: number, key: Uint8Array, forGeneration: number, source: KeySource, meta?: KeyMeta): PutResult {
    if (this.generation() !== forGeneration) return 'stale';
    if (!Number.isSafeInteger(epoch) || epoch < 0 || !(key instanceof Uint8Array) || key.length !== 32) return 'stale';
    const k = ck(scopeHex, epoch);
    const cur = this.m.get(k);
    const verified = source === 'verified' && !!meta;
    if (!cur) {
      this.m.set(k, { key, source, meta, verified, alts: [] });
      this.onChange();
      return 'stored';
    }
    if (same(cur.key, key)) {
      // Same key: only ever an upgrade (verified pair, or provisional → final).
      if (verified && !cur.verified) {
        cur.source = 'verified';
        cur.meta = meta;
        cur.verified = true;
      } else if (cur.source === 'provisional' && source !== 'provisional') {
        cur.source = source;
        cur.meta = meta ?? cur.meta;
        cur.verified = verified;
      }
      this.onChange();
      return 'stored';
    }
    if (cur.source === 'provisional' && source !== 'provisional') {
      // A final key replaces the not-final provisional one (kept, not exported).
      const next: KeyEntry = { key, source, meta, verified, alts: cur.alts };
      this.addAlt(next, cur.key, false);
      this.m.set(k, next);
      this.onChange();
      return 'stored';
    }
    this.addAlt(cur, key, source !== 'provisional');
    this.onChange();
    return 'conflict';
  }

  get(scopeHex: string, epoch: number): KeyEntry | undefined {
    return this.m.get(ck(scopeHex, epoch));
  }

  /** Every key held for the slot, primary first (decrypt tries them in order). */
  keysAt(scopeHex: string, epoch: number): Uint8Array[] {
    const e = this.m.get(ck(scopeHex, epoch));
    return e ? [e.key, ...e.alts.map((a) => a.key)] : [];
  }

  /** Any key held at `epoch` (makes THAT epoch known to exist; never global evidence). */
  holds(scopeHex: string, epoch: number): boolean {
    return this.m.has(ck(scopeHex, epoch));
  }

  /**
   * Mark the held PRIMARY key's pair verified (a pair persisted by a verified
   * path, or our own slot's verified wrap, hashed to THIS key). Generation-guarded.
   */
  markVerified(scopeHex: string, epoch: number, key: Uint8Array, meta: KeyMeta, forGeneration: number): boolean {
    if (this.generation() !== forGeneration) return false;
    const e = this.m.get(ck(scopeHex, epoch));
    if (!e || e.key !== key || e.source === 'legacy' || e.source === 'provisional') return false;
    e.meta = meta;
    e.verified = true;
    return true;
  }

  /** Entries of one scope, `[epoch, entry]`. */
  entries(scopeHex: string): Array<[number, KeyEntry]> {
    const out: Array<[number, KeyEntry]> = [];
    const pre = `${scopeHex}:`;
    for (const [k, e] of this.m) {
      if (!k.startsWith(pre)) continue;
      const epoch = Number(k.slice(pre.length));
      if (Number.isSafeInteger(epoch)) out.push([epoch, e]);
    }
    return out;
  }

  /** Highest epoch of any key (provisional included), or null. */
  latest(scopeHex: string): { key: Uint8Array; epoch: number; entry: KeyEntry } | null {
    let best: { key: Uint8Array; epoch: number; entry: KeyEntry } | null = null;
    for (const [epoch, e] of this.entries(scopeHex)) if (!best || epoch > best.epoch) best = { key: e.key, epoch, entry: e };
    return best;
  }

  /** Highest epoch with a verified pair or the provisional first key, or null. */
  latestTrusted(scopeHex: string): { key: Uint8Array; epoch: number; entry: KeyEntry } | null {
    let t: { key: Uint8Array; epoch: number; entry: KeyEntry } | null = null;
    for (const [epoch, e] of this.entries(scopeHex)) {
      if ((e.verified || e.source === 'provisional') && (!t || epoch > t.epoch)) t = { key: e.key, epoch, entry: e };
    }
    return t;
  }

  /**
   * The key to SEND (and cover) under: the highest key with a verified pair
   * or the provisional first key; only when none exists the highest other
   * key (a pre-arbitration channel has nothing else — existing trust). A
   * higher unverified key never outranks a verified one.
   */
  bestForSend(scopeHex: string): { key: Uint8Array; epoch: number; entry: KeyEntry } | null {
    return this.latestTrusted(scopeHex) ?? this.latest(scopeHex);
  }

  /**
   * The epoch worth ONE proof fetch: the highest held epoch when it is above
   * the highest trusted one (a restored / legacy higher key must not leave
   * sends and covers on a stale verified epoch); null when nothing is higher.
   */
  trustProbeEpoch(scopeHex: string): number | null {
    const l = this.latest(scopeHex);
    if (!l) return null;
    const t = this.latestTrusted(scopeHex);
    return !t || l.epoch > t.epoch ? l.epoch : null;
  }

  /** True when the scope has a key with a verified pair (or the provisional first key). */
  hasTrusted(scopeHex: string): boolean {
    return this.latestTrusted(scopeHex) !== null;
  }

  /** The SDK's `highestEpochSeen`: highest epoch of a key with a VERIFIED pair (0 when none). */
  highestEvidence(scopeHex: string): number {
    let hi = 0;
    for (const [epoch, e] of this.entries(scopeHex)) if (e.verified && e.source !== 'provisional' && epoch > hi) hi = epoch;
    return hi;
  }

  /** Heal trigger eligibility: our key at `epoch` has a verified pair and is the latest verified epoch. */
  healEligible(scopeHex: string, epoch: number): boolean {
    const e = this.m.get(ck(scopeHex, epoch));
    return !!e && e.verified && e.source !== 'provisional' && epoch === this.highestEvidence(scopeHex);
  }

  /**
   * Keys for the vault backup: every non-provisional primary, every
   * exportable alternate (`${slot}#alt${n}`) and every opaque entry restored
   * earlier — the backup never shrinks what this device knows.
   */
  exportForVault(): Record<string, Uint8Array> {
    const out: Record<string, Uint8Array> = {};
    for (const [k, v] of this.opaque) out[k] = v;
    for (const [k, e] of this.m) {
      let n = 1;
      if (e.source !== 'provisional') {
        if (e.aliasOnly) out[`${k}${ALT_SEP}${n++}`] = e.key;
        else out[k] = e.key;
      }
      for (const a of e.alts) if (a.exportable && n <= MAX_ALTS) out[`${k}${ALT_SEP}${n++}`] = a.key;
    }
    return out;
  }

  /**
   * Merge vault-restored keys (UNVERIFIED). A free slot takes the key; a
   * provisional primary is replaced by it; a slot holding a DIFFERENT key keeps
   * its primary and gains the vault key as an exportable alternate. Nothing
   * is ever filtered out: the next backup re-seals this keyring, so anything
   * dropped here would be lost from the vault. Returns how many keys were new.
   */
  importFromVault(rec: Record<string, Uint8Array>): number {
    let added = 0;
    const keep = (rawK: string, v: Uint8Array) => {
      if (!this.opaque.has(rawK)) {
        this.opaque.set(rawK, v);
        added++;
      }
    };
    // Primaries first, then aliases (so an alias lands as an alternate of its slot).
    const items = Object.entries(rec)
      .filter(([, v]) => v instanceof Uint8Array && v.length === 32)
      .map(([rawK, v]) => ({ rawK, v, m: SLOT_RE.exec(rawK) }))
      .sort((x, y) => Number(!!(x.m && (x.m[3] ?? x.m[4]))) - Number(!!(y.m && (y.m[3] ?? y.m[4]))));
    for (const { rawK, v, m } of items) {
      const epoch = m ? Number(m[2]) : NaN;
      if (!m || !Number.isSafeInteger(epoch)) {
        keep(rawK, v); // unknown entry: preserved verbatim, re-exported unchanged
        continue;
      }
      const k = m[1]!;
      const alias = m[3] !== undefined || m[4] !== undefined;
      const cur = this.m.get(k);
      if (!cur) {
        this.m.set(k, { key: v, source: 'vault', verified: false, alts: [], aliasOnly: alias });
        added++;
      } else if (same(cur.key, v) || cur.alts.some((a) => same(a.key, v) && a.exportable)) {
        continue;
      } else if (cur.source === 'provisional') {
        const next: KeyEntry = { key: v, source: 'vault', verified: false, alts: cur.alts, aliasOnly: alias };
        if (!this.addAlt(next, cur.key, false)) next.alts = next.alts.slice(0, MAX_ALTS);
        this.m.set(k, next);
        added++;
      } else if (this.addAlt(cur, v, true)) {
        added++;
      } else {
        keep(rawK, v); // over the per-epoch cap: still never dropped
      }
    }
    return added;
  }

  /** Zero and drop everything (sign-out / account switch). */
  clear(): void {
    for (const e of this.m.values()) {
      e.key.fill(0);
      for (const a of e.alts) a.key.fill(0);
    }
    for (const v of this.opaque.values()) v.fill(0);
    this.m.clear();
    this.opaque.clear();
  }

  get size(): number {
    return this.m.size;
  }
}
