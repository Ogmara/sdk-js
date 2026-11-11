/**
 * Seeded DIFFERENTIAL property test of ChannelKeyring (sdk-js 0.68.0).
 *
 * The reference model below is written from the SPEC (CHANGELOG 0.68.0 /
 * README "Channel keyring"), not from the implementation: it keeps per slot a
 * map of keys with their flags and the current PRIMARY, and applies the spec
 * rules directly ("a strictly better key takes over; among those the best
 * rank, earliest seen"; "beyond the cap the newest unprotected alternate is
 * shed"; ...). It never models list positions or vault names.
 *
 * Operations: honest puts; ADVERSARIAL node puts (node-computed pairs for
 * attacker keys with any keyTs, fabricated commitments, `final` claims,
 * hostile epochs up to Number.MAX_SAFE_INTEGER, planted alternates);
 * MALICIOUS-MEMBER puts (author-verified wraps of member-attacker keys that
 * the node calls final); markVerified; vault imports with arbitrary name
 * mixes (`#alt` 1..999, `~n`, `#ovf`, `#pri`, unknown names); old-backup
 * restores; exports; restarts; OLD-CLIENT round trips (desktop / mobile /
 * web copies in test/interop), with the old client's own slot PRE-FILLED to
 * its cap; clear.
 *
 *  I1  every key put with a protected provenance, imported or exported stays
 *      held and is in every later export (unless provisional and never
 *      finalised / exported, or cleared); checked in memory while an opaque
 *      overflow refuses exports.
 *  I2  export ⊇ imported ∪ previously exported (union never shrinks).
 *  I3  export is collision-free and complete: #names == #opaque + #exportable
 *      held keys + #`#pri` copies; every exportable key under its own slot;
 *      `#pri` exists exactly when the primary name does, with its value.
 *  I4  bestForSend == the spec (strict: highest in-range epoch whose primary
 *      is trusted or provisional; finalOnly: trusted+final; allowUnverified
 *      fallback: highest primary that is author-verified, or not node-served,
 *      not served this session and not restored from an alias name).
 *  I5  a fresh keyring importing an export re-exports it identically.
 *  I6  a held key disappears only if it was UNPROTECTED.
 *  I7  primary, flags and pair == the model.
 *  I8  soft cap: beyond it only protected alternates; protected puts are
 *      never refused.
 *  I9  a NEW node-served epoch above the highest trusted epoch is admitted
 *      only with the scope's untrusted epochs there within the cap (restored
 *      node history beyond it is evicted first); the absolute per-scope cap
 *      holds for node-served epochs.
 *  I10 ADVERSARY: a node attacker key is never trusted, never a strict send
 *      key, never latestVerified, and never the allowUnverified fallback —
 *      except (documented residual) after an OLD MOBILE client re-exported an
 *      alias-only slot, which it writes under the primary name.
 *  I11 an older client re-exporting our export — also with its own slot FULL —
 *      keeps every one of our values (residual: a full slot whose `#pri` copy
 *      was not written loses the primary-name value); our keyring re-importing
 *      that loses nothing else (I1).
 *  I14 node-served keys (`#ns`) never take more than a quarter of the byte
 *      budget in any export, across any number of restarts; `#ns` never
 *      holds a protected key.
 *  I15 pruneUnverified only removes never-author-vouched, non-provisional
 *      keys (and the member cap only other members' non-final wraps); its
 *      count equals the spec model's.
 *  I16 bestForSendLegacy returns a key only for a scope holding nothing but
 *      commitment-less node keys served this session (spec model).
 *  I13 the export's estimated size never exceeds the byte budget; it throws
 *      `vault_too_large` only when the protected keys cannot fit, and never
 *      leaves out a protected key; `#pri` only within half the budget.
 *  I12 canonical export order per slot (base, #pri, #alt asc, #ovf asc;
 *      opaque last); written `#alt` indices ≥ 5; the primary name never holds
 *      a node-served or alias-restored key.
 *
 * KEYRING_PROP_SEQUENCES (default 3000) / KEYRING_PROP_SEED tune the run; the
 * full run uses KEYRING_PROP_SEQUENCES=20000.
 */
import { describe, expect, it } from 'vitest';
import { ChannelKeyring, ChannelKeyringError, estimateVaultChanBytes, type ChannelKeyInfo, type ChannelKeyPair, type ChannelKeySource } from './channelKeyring';
import { computeKeyCommitment } from './channelKeyCommit';
import { ChannelKeyStore as OldDesktop } from '../test/interop/oldDesktopKeyStore';
import { ChannelKeyring as OldMobile } from '../test/interop/oldMobileKeyring';
import { ChannelKeyCache as OldWeb } from '../test/interop/oldWebKeyCache';

const SEQUENCES = Number(process.env.KEYRING_PROP_SEQUENCES ?? 3000) || 3000;
const SEED = Number(process.env.KEYRING_PROP_SEED ?? 0x5eed0068);

function mulberry32(a: number): () => number {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SCOPES = ['aa'.repeat(32), 'bb'.repeat(32)];
const MAXE = Number.MAX_SAFE_INTEGER;
const EPOCHS = [0, 1, 2, 3, 100000, MAXE];
const HONEST = [1, 2, 3, 4, 5, 6];
/** Keys only ever served by a hostile node. */
const NODE_ATTACKER = [101, 102, 103, 104];
/** Keys a malicious MEMBER authors (author-verified wraps). */
const MEMBER_ATTACKER = [201, 202];
/** Keys another device on an OLD client holds. */
const OTHER_DEVICE = [150, 151, 152, 153, 154];
const keyOf = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const HEX2 = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
const hex = (b: Uint8Array): string => { let o = ''; for (let i = 0; i < b.length; i++) o += HEX2[b[i]!]; return o; };
/** Cheap structural equality for hot paths: compare a canonical string, expect() only on mismatch. */
const recStr = (r: Record<string, Uint8Array>): string => Object.entries(r).map(([n, v]) => `${n}=${hex(v)}`).join('|');
const NODE_ATTACKER_HEX = new Set(NODE_ATTACKER.map((n) => hex(keyOf(n))));
const scopeBytes = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
const PAIRS = new Map<string, ChannelKeyPair>();
const pairFor = (s: string, e: number, n: number, ts: number): ChannelKeyPair => {
  const id = `${s}:${e}:${n}:${ts}`;
  let p = PAIRS.get(id);
  if (!p) PAIRS.set(id, (p = { keyTs: ts, commitment: computeKeyCommitment(scopeBytes(s), e, ts, keyOf(n)) }));
  return p;
};
const NAME = /^([0-9A-Za-z]{1,128}):(0|[1-9]\d{0,15})(?:#alt([1-9]\d{0,2})|~([1-9]\d{0,2})|#ovf([1-9]\d{0,5})|(#pri)|#ns([1-9]\d{0,5}))?$/;
const slotOf = (name: string): string | null => {
  const m = NAME.exec(name);
  return m && Number.isSafeInteger(Number(m[2])) ? `${m[1]}:${m[2]}` : null;
};

// ---- the reference model, from the spec ---------------------------------------------------

interface MKey {
  source: ChannelKeySource; pc: boolean; pair?: { keyTs: number; c: string }; final: boolean; prov: boolean;
  persisted: boolean; aliasOrigin: boolean; served: boolean; ns: boolean; own: boolean; wasVault: boolean; above?: boolean; seq: number;
}
interface MSlot { keys: Map<string, MKey>; primary: string; seq: number; nodeNew: boolean; memberNew: boolean }
interface Cfg { maxAltsPerEpoch: number; maxUntrustedEpochsPerScope: number; maxEpochsPerScope: number; maxSessionHistoryEpochsPerScope: number; maxVaultBytes: number; maxMemberEpochsPerScope: number; maxOpaqueEntries: number }

const SOURCE_ORDER: ChannelKeySource[] = ['legacy', 'fetch', 'vault', 'wrap', 'establish'];
const isAuthorSrc = (s: ChannelKeySource) => s === 'establish' || s === 'wrap';
const isNodeSrc = (s: ChannelKeySource) => s === 'fetch' || s === 'legacy';
/** Spec: trusted = author-verified + pair-consistent + not provisional. */
const specTrusted = (k: MKey) => isAuthorSrc(k.source) && k.pc && !k.prov;
/** Spec order: trusted+final > trusted > provisional > own / vault > node-served. */
function specRank(k: MKey): number {
  if (specTrusted(k) && k.final) return 4;
  if (specTrusted(k)) return 3;
  if (k.prov) return 2;
  if (!isNodeSrc(k.source) && !k.ns) return 1;
  return 0;
}
/** Spec: unprotected = node-served, never imported / exported, not provisional. */
/** Spec (r88): unprotected = node-served provenance never vouched for by an author source — backed up or not. */
const specUnprotected = (k: MKey) => k.ns && !k.prov;
const specExportable = (k: MKey) => !k.prov || k.persisted;
const upgradeSource = (a: ChannelKeySource, b: ChannelKeySource) => (SOURCE_ORDER.indexOf(b) > SOURCE_ORDER.indexOf(a) ? b : a);

class Model {
  slots = new Map<string, MSlot>();
  opaque = new Map<string, string>();
  dropped = 0;
  private clock = 0;
  constructor(readonly cfg: Cfg) {}

  scopeOf(slot: string): string { return slot.slice(0, slot.lastIndexOf(':')); }
  epochOf(slot: string): number { return Number(slot.slice(slot.lastIndexOf(':') + 1)); }

  /** "A strictly better key takes over the primary: the best such rank, the earliest seen among equals." */
  private settlePrimary(s: MSlot): boolean {
    const cur = specRank(s.keys.get(s.primary)!);
    let pick: [string, MKey] | null = null;
    for (const [h, k] of s.keys) {
      const r = specRank(k);
      if (r <= cur) continue;
      if (!pick || r > specRank(pick[1]) || (r === specRank(pick[1]) && k.seq < pick[1].seq)) pick = [h, k];
    }
    if (!pick) return false;
    s.primary = pick[0];
    return true;
  }
  /** "Beyond the cap the NEWEST unprotected alternate is shed; protected keys may exceed it." */
  private shed(s: MSlot): string[] {
    const gone: string[] = [];
    while (s.keys.size - 1 > this.cfg.maxAltsPerEpoch) {
      let v: [string, MKey] | null = null;
      for (const [h, k] of s.keys) if (h !== s.primary && specUnprotected(k) && (!v || k.seq > v[1].seq)) v = [h, k];
      if (!v) break;
      s.keys.delete(v[0]);
      gone.push(v[0]);
    }
    return gone;
  }
  private trustedFloor(scope: string): number {
    let f = -1;
    for (const [slot, s] of this.slots) if (this.scopeOf(slot) === scope && specRank(s.keys.get(s.primary)!) >= 3) f = Math.max(f, this.epochOf(slot));
    return f;
  }
  /**
   * Spec: absolute cap per scope; ABOVE the highest trusted epoch, untrusted epochs (restored
   * ones included) are capped; AT OR BELOW it, only epochs a node served new this session count,
   * against the session budget. Beyond a cap the oldest all-unprotected counted epoch goes.
   */
  private admitNodeEpoch(scope: string, epoch: number): boolean {
    const mine = [...this.slots].filter(([slot]) => this.scopeOf(slot) === scope);
    if (mine.length >= this.cfg.maxEpochsPerScope) return false;
    const floor = this.trustedFloor(scope);
    const above = epoch > floor;
    const untrustedOnly = (s: MSlot) => [...s.keys.values()].every((k) => !isAuthorSrc(k.source) && !k.prov);
    const untrusted = mine.filter(([slot, s]) => untrustedOnly(s) && (above ? this.epochOf(slot) > floor : this.epochOf(slot) <= floor && s.nodeNew));
    if (untrusted.length < (above ? this.cfg.maxUntrustedEpochsPerScope : this.cfg.maxSessionHistoryEpochsPerScope)) return true;
    // spec: evict the oldest all-unprotected counted epochs, as many as needed, or none
    const victims = untrusted.filter(([, s]) => [...s.keys.values()].every(specUnprotected)).sort((a, b) => a[1].seq - b[1].seq);
    const need = untrusted.length - (above ? this.cfg.maxUntrustedEpochsPerScope : this.cfg.maxSessionHistoryEpochsPerScope) + 1;
    if (victims.length < need) return false;
    for (const [sl] of victims.slice(0, need)) this.slots.delete(sl);
    return true;
  }
  /** Keys removed by a cap on PROTECTED keys (member cap) or by prune, this step. */
  retired = new Set<string>();
  /**
   * Spec (member caps, refuse-only): another member's wrap (not own) may create a new epoch
   * only while the scope holds fewer than the cap of "maybe member" epochs — above the highest
   * FINAL epoch any such epoch counts (restored ones too), at or below it only those a member
   * created this session; an alternate only while its epoch holds fewer than maxAlts maybe-member
   * keys. "Maybe member" key: not node-served, not own, not final, not provisional, not establish.
   */
  private memberAllowed(scope: string, epoch: number, existing: MSlot | undefined): boolean {
    const mm = (k: MKey) => !k.ns && !k.own && !k.final && !k.prov && k.source !== 'establish';
    if (existing) return [...existing.keys.values()].filter(mm).length < this.cfg.maxAltsPerEpoch;
    const mine = [...this.slots].filter(([slot]) => this.scopeOf(slot) === scope);
    const finalFloor = Math.max(-1, ...mine.filter(([, s]) => specRank(s.keys.get(s.primary)!) >= 4).map(([sl]) => this.epochOf(sl)));
    const mmSlot = (s: MSlot) => [...s.keys.values()].some((k) => !k.ns) && [...s.keys.values()].every((k) => k.ns || mm(k));
    const above = epoch > finalFloor;
    const n = mine.filter(([sl, s]) => mmSlot(s) && (above ? this.epochOf(sl) > finalFloor : this.epochOf(sl) <= finalFloor && s.memberNew)).length;
    return n < (above ? this.cfg.maxMemberEpochsPerScope : this.cfg.maxSessionHistoryEpochsPerScope);
  }
  /** Keys pruned this session: never re-imported. */
  pruned = new Set<string>();
  /**
   * Spec: outside each scope's latest N epochs (only in `onlyScopes`) remove the selected classes —
   * default node-served only; never own / establish / final wraps / provisional / never-backed-up
   * client-put vault keys.
   */
  prune(keep: number, dryRun: boolean, classes: Set<string>, onlyScopes: Set<string> | null): Record<string, number> & { total: number } {
    const classOf = (k: MKey): string | null => {
      if (k.own || k.prov || k.source === 'establish') return null;
      if (k.ns || isNodeSrc(k.source)) return 'nodeServed';
      if (k.source === 'wrap') return k.final ? null : 'memberWraps';
      if (!k.wasVault || (k.source === 'vault' && !k.persisted)) return null;
      if (k.above) return 'memberWraps'; // restored above the import ceiling: cannot be ours
      return k.aliasOrigin ? 'restoredAlternates' : 'restoredPrimaries';
    };
    const doomed = (k: MKey) => { const c = classOf(k); return c !== null && classes.has(c); };
    const counts: Record<string, number> & { total: number } = { total: 0 };
    const scopes = new Set([...this.slots.keys()].map((sl) => this.scopeOf(sl)));
    for (const sc of scopes) {
      if (onlyScopes && !onlyScopes.has(sc)) continue;
      const eps = [...this.slots.keys()].filter((sl) => this.scopeOf(sl) === sc).map((sl) => this.epochOf(sl)).sort((a, b) => b - a);
      for (const ep of eps.slice(keep)) {
        const slot = `${sc}:${ep}`;
        const s = this.slots.get(slot)!;
        const gone = [...s.keys].filter(([, k]) => doomed(k));
        for (const [, k] of gone) { counts.total++; counts[classOf(k)!] = (counts[classOf(k)!] ?? 0) + 1; }
        if (dryRun || !gone.length) continue;
        for (const [h] of gone) { s.keys.delete(h); this.retired.add(`${slot}|${h}`); this.pruned.add(`${slot}|${h}`); }
        if (!s.keys.size) { this.slots.delete(slot); continue; }
        if (!s.keys.has(s.primary)) {
          // the best rank, earliest seen among equals
          let best: [string, MKey] | null = null;
          for (const [h, k] of s.keys) if (!best || specRank(k) > specRank(best[1]) || (specRank(k) === specRank(best[1]) && k.seq < best[1].seq)) best = [h, k];
          s.primary = best![0];
        }
      }
    }
    return counts;
  }
  private notePair(k: MKey, pair: { keyTs: number; c: string }, final: boolean): void {
    if (!k.pc || !k.pair || (final && !k.final)) k.pair = pair;
    k.pc = true;
    if (final) k.final = true;
  }

  put(slot: string, h: string, o: { source: ChannelKeySource; pair?: { keyTs: number; c: string }; verified: boolean; final: boolean; provisional?: boolean; ownSlot?: boolean; maxEpoch?: number }): string {
    const ownPut = o.source === 'establish' || o.provisional === true || (o.source === 'wrap' && o.ownSlot === true);
    const othersWrap = o.source === 'wrap' && !ownPut;
    // spec: a FINAL member wrap is exempt from the member caps (only the absolute cap bounds it)
    const memberPut = othersWrap && !o.final;
    // spec: keys that are not ours above the caller's ceiling are refused
    if (o.maxEpoch !== undefined && this.epochOf(slot) > o.maxEpoch && (isNodeSrc(o.source) || othersWrap)) return 'refused';
    const s = this.slots.get(slot);
    const fresh = (): MKey => ({
      source: o.source, pc: o.verified, pair: o.pair, final: o.final, prov: o.provisional === true,
      persisted: false, aliasOrigin: false, served: isNodeSrc(o.source), ns: isNodeSrc(o.source), own: ownPut, wasVault: o.source === 'vault', seq: 0,
    });
    if (!s) {
      if (isNodeSrc(o.source) && !this.admitNodeEpoch(this.scopeOf(slot), this.epochOf(slot))) return 'refused';
      if (othersWrap && [...this.slots.keys()].filter((sl) => this.scopeOf(sl) === this.scopeOf(slot)).length >= this.cfg.maxEpochsPerScope) return 'refused';
      if (memberPut && !this.memberAllowed(this.scopeOf(slot), this.epochOf(slot), undefined)) return 'refused';
      const slotSeq = ++this.clock;
      const k = fresh();
      k.seq = ++this.clock;
      this.slots.set(slot, { keys: new Map([[h, k]]), primary: h, seq: slotSeq, nodeNew: isNodeSrc(o.source), memberNew: memberPut });
      return 'stored';
    }
    const held = s.keys.get(h);
    if (held) {
      held.source = upgradeSource(held.source, o.source);
      if (o.verified) this.notePair(held, o.pair!, o.final);
      else if (o.pair && !held.pair) held.pair = o.pair;
      if (isNodeSrc(o.source)) held.served = true;
      if (isAuthorSrc(o.source)) held.ns = false;
      if (ownPut) held.own = true;
      if (o.source === 'vault') held.wasVault = true;
      // spec: finalised only by an author source, explicitly or verified + final
      if (held.prov && isAuthorSrc(o.source) && (o.provisional === false || (o.verified && o.final))) held.prov = false;
      return this.settlePrimary(s) && s.primary === h ? 'promoted' : 'stored';
    }
    if (isNodeSrc(o.source) && !o.pair) return 'refused';
    if (memberPut && !this.memberAllowed(this.scopeOf(slot), this.epochOf(slot), s)) return 'refused';
    const k = fresh();
    k.seq = ++this.clock;
    s.keys.set(h, k);
    const promoted = this.settlePrimary(s) && s.primary === h;
    if (this.shed(s).includes(h)) return 'refused';
    return promoted ? 'promoted' : 'conflict';
  }

  mark(slot: string, h: string, good: boolean, pair: { keyTs: number; c: string }, final: boolean): string {
    const s = this.slots.get(slot);
    const k = s?.keys.get(h);
    if (!s || !k) return 'not_held';
    if (!good) return 'pair_mismatch';
    if (!isAuthorSrc(k.source)) return 'needs_author_proof';
    this.notePair(k, pair, final);
    if (final) k.prov = false;
    return this.settlePrimary(s) && s.primary === h ? 'promoted' : 'verified';
  }

  private keepOpaque(name: string, h: string): void {
    const cur = this.opaque.get(name);
    if (cur === h) return;
    let n = name;
    if (cur !== undefined) {
      for (let i = 1; ; i++) {
        n = `${name}#dup${i}`;
        const d = this.opaque.get(n);
        if (d === undefined) break;
        if (d === h) return;
      }
    }
    if (this.opaque.size >= this.cfg.maxOpaqueEntries) { this.dropped++; return; }
    this.opaque.set(n, h);
  }

  import(rec: Record<string, Uint8Array>, ceiling = Number.POSITIVE_INFINITY): void {
    const items: Array<{ name: string; h: string; slot: string; cls: number; idx: number }> = [];
    for (const [name, v] of Object.entries(rec)) {
      const m = NAME.exec(name);
      if (!m || !Number.isSafeInteger(Number(m[2]))) { this.keepOpaque(name, hex(v)); continue; }
      // spec order: primary name, `#pri`, `#alt` by index, `~` by index, `#ovf` by index, then by name
      const cls = m[6] ? 1 : m[3] ? 2 : m[4] ? 3 : m[5] ? 4 : m[7] ? 5 : 0;
      items.push({ name, h: hex(v), slot: `${m[1]}:${m[2]}`, cls, idx: Number(m[3] ?? m[4] ?? m[5] ?? m[7] ?? 0) });
    }
    items.sort((a, b) => a.cls - b.cls || a.idx - b.idx || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const it of items) {
      if (this.pruned.has(`${it.slot}|${it.h}`)) continue;
      let s = this.slots.get(it.slot);
      const underPrimaryName = it.cls <= 1;
      if (!s) {
        const slotSeq = ++this.clock;
        const k: MKey = { source: 'vault', pc: false, final: false, prov: false, persisted: true, aliasOrigin: !underPrimaryName, served: false, ns: it.cls === 5, own: false, wasVault: true, above: this.epochOf(it.slot) > ceiling, seq: ++this.clock };
        this.slots.set(it.slot, { keys: new Map([[it.h, k]]), primary: it.h, seq: slotSeq, nodeNew: false, memberNew: false });
        continue;
      }
      const held = s.keys.get(it.h);
      if (held) {
        held.persisted = true;
        held.wasVault = true;
        if (this.epochOf(it.slot) > ceiling && !held.own) held.above = true;
        held.source = upgradeSource(held.source, 'vault');
        if (it.cls === 0) held.aliasOrigin = false; // a `#pri` copy does not clear it
        this.settlePrimary(s);
        continue;
      }
      s.keys.set(it.h, { source: 'vault', pc: false, final: false, prov: false, persisted: true, aliasOrigin: !underPrimaryName, served: false, ns: it.cls === 5, own: false, wasVault: true, above: this.epochOf(it.slot) > ceiling, seq: ++this.clock });
      this.settlePrimary(s);
      this.shed(s);
    }
  }
  /** Spec: only keys actually written to the vault become persisted. */
  exported(out: Record<string, Uint8Array>): void {
    const present = new Set(Object.entries(out).map(([n, v]) => `${slotOf(n)}|${hex(v)}`));
    for (const [slot, s] of this.slots) for (const [h, k] of s.keys) if (present.has(`${slot}|${h}`)) k.persisted = true;
  }
}

// ---- the test ---------------------------------------------------------------------------

/** Cheap assertion for hot loops: only builds a vitest expectation when it fails. */
function ok(cond: boolean, msg: string): void {
  if (!cond) expect(cond, msg).toBe(true);
}
/** Cheap equality for hot loops. */
function eq<T>(got: T, want: T, msg: string): void {
  if (got !== want) expect(got, msg).toBe(want);
}

function infoMatches(x: ChannelKeyInfo, k: MKey): boolean {
  const pairOk = !k.pair ? x.pair === undefined : !!x.pair && x.pair.keyTs === k.pair.keyTs && hex(x.pair.commitment) === k.pair.c;
  return pairOk && x.source === k.source && x.verified === k.pc && x.final === k.final && x.provisional === k.prov
    && x.persisted === k.persisted && x.nodeServed === k.ns && x.own === k.own && x.restored === k.wasVault && x.exportable === specExportable(k) && x.trusted === specTrusted(k) && x.authorVerified === isAuthorSrc(k.source);
}

/** An OLD client (0 desktop, 1 mobile, 2 web), optionally with its own slot `fill` pre-filled to its cap, re-exports `rec`. */
function oldReexport(which: number, rec: Record<string, Uint8Array>, fill: string | null): Record<string, Uint8Array> {
  const [scope, epoch] = fill ? [fill.slice(0, fill.lastIndexOf(':')), Number(fill.slice(fill.lastIndexOf(':') + 1))] : ['', 0];
  if (which === 0) {
    const d = new OldDesktop(() => 0, () => {});
    if (fill) for (const n of OTHER_DEVICE) d.put(scope, epoch, keyOf(n), 0, 'verified', { keyTs: 1, keyCommitment: keyOf(9) });
    d.importFromVault(rec);
    return d.exportForVault();
  }
  if (which === 1) {
    const m = new OldMobile();
    if (fill) for (const n of OTHER_DEVICE) m.put(fill, keyOf(n), { state: 'confirmed', verified: true });
    m.importVault(rec);
    return m.exportVault();
  }
  const w = new OldWeb(() => {});
  if (fill) for (const n of OTHER_DEVICE) w.put(fill, { key: keyOf(n), source: 'establish', meta: { keyTs: 1, keyCommitment: keyOf(9) }, confirmed: true });
  w.importFromVault(rec);
  return w.exportForVault();
}

function runSequence(seed: number): void {
  const rnd = mulberry32(seed);
  const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
  const small = rnd() < 0.35;
  const cfg: Cfg = small
    ? {
      maxAltsPerEpoch: 1 + Math.floor(rnd() * 3), maxUntrustedEpochsPerScope: 1 + Math.floor(rnd() * 3), maxEpochsPerScope: 3 + Math.floor(rnd() * 4),
      maxSessionHistoryEpochsPerScope: 1 + Math.floor(rnd() * 3), maxVaultBytes: pick([400, 900, 2500, 1_572_864]), maxOpaqueEntries: rnd() < 0.3 ? 2 : 8192,
      maxMemberEpochsPerScope: 1 + Math.floor(rnd() * 3),
    }
    : { maxAltsPerEpoch: 4, maxUntrustedEpochsPerScope: 512, maxEpochsPerScope: 4096, maxSessionHistoryEpochsPerScope: 64, maxVaultBytes: 1_572_864, maxMemberEpochsPerScope: 512, maxOpaqueEntries: 8192 };
  let r = new ChannelKeyring(cfg);
  let model = new Model(cfg);
  const ctx = (op: string) => `seed=${seed} op=${op}`;
  let must = new Set<string>();
  /** RESIDUAL: an OLD MOBILE client re-exports an alias-only slot's first key under the primary name. */
  let mobileLaundered = false;
  const exportsSeen: Array<Record<string, Uint8Array>> = [];
  const snap = () => new Map([...model.slots].map(([k, s]) => [k, new Map([...s.keys].map(([h, x]) => [h, { ...x }]))]));
  let prev = snap();

  const checkExport = (out: Record<string, Uint8Array>, op: string): void => {
    const names = Object.keys(out);
    const got = new Set(names.map((n) => `${slotOf(n) ?? '#opaque'}|${hex(out[n]!)}`));
    for (const p of must) ok(got.has(p), `${ctx(op)} I1/I2 lost ${p}`);
    // I3: every exportable PROTECTED key is in; an unprotected one may be left out (byte budget)
    let present = 0;
    for (const [slot, s] of model.slots) for (const [h, k] of s.keys) if (specExportable(k)) {
      if (got.has(`${slot}|${h}`)) present++;
      else ok(specUnprotected(k), `${ctx(op)} I3 missing protected ${slot}`);
    }
    const pri = names.filter((n) => n.endsWith('#pri'));
    for (const n of pri) expect(hex(out[n]!), `${ctx(op)} I3 #pri value`).toBe(hex(out[n.slice(0, -4)]!));
    expect(names.length, `${ctx(op)} I3 collision`).toBe(model.opaque.size + present + pri.length);
    // I13: byte budget; `#pri` only within half of it, at most 16 per scope
    const est = estimateVaultChanBytes(out);
    ok(est <= cfg.maxVaultBytes, `${ctx(op)} I13 over budget ${est}`);
    // I14: node-served (`#ns`) bytes never exceed their share, across any number of restarts
    const nsOnly = Object.fromEntries(Object.entries(out).filter(([n]) => NAME.exec(n)?.[7] !== undefined));
    ok(estimateVaultChanBytes(nsOnly) <= cfg.maxVaultBytes / 4, `${ctx(op)} I14 node share`);
    for (const n of Object.keys(nsOnly)) ok(model.slots.get(slotOf(n)!)!.keys.get(hex(out[n]!))!.ns, `${ctx(op)} I14 #ns holds a protected key`);
    if (pri.length) ok(est <= cfg.maxVaultBytes / 2, `${ctx(op)} I13 #pri over half budget`);
    for (const sc of SCOPES) ok(pri.filter((n) => n.startsWith(sc)).length <= 16, `${ctx(op)} I13 #pri per scope`);
    let seenOpaque = false;
    let last: { slot: string; ord: number } | null = null;
    for (const n of names) {
      const sl = slotOf(n);
      if (sl === null) { seenOpaque = true; continue; }
      ok(!(seenOpaque), `${ctx(op)} I12 opaque before slot`);
      const m = NAME.exec(n)!;
      expect(m[4], `${ctx(op)} I12 ~ written`).toBeUndefined();
      if (m[3]) ok(Number(m[3]) >= 5, `${ctx(op)} I12 low alias ${n}`);
      const ord = m[6] ? 1 : m[3] ? 10 + Number(m[3]) : m[5] ? 1e6 + Number(m[5]) : m[7] ? 2e6 + Number(m[7]) : 0;
      if (last && last.slot === sl) ok(ord > last.ord, `${ctx(op)} I12 order ${n}`);
      last = { slot: sl, ord };
      if (n === sl) {
        const k = model.slots.get(sl)!.keys.get(hex(out[n]!))!;
        ok(!k.ns && (isAuthorSrc(k.source) || (!isNodeSrc(k.source) && !k.aliasOrigin)), `${ctx(op)} I12 base name holds ${k.source}`);
      }
    }
    const fresh = new ChannelKeyring(cfg);
    fresh.importFromVault(out);
    const again = fresh.exportForVault();
    if (recStr(again) !== recStr(out)) expect(again, `${ctx(op)} I5`).toEqual(out);
    for (const p of got) {
      const [slot, h] = p.split('|') as [string, string];
      if (slot === '#opaque' || !model.slots.get(slot)?.keys.get(h)?.ns) must.add(p); // node keys may be shed
    }
  };

  /** Bytes of opaque entries + every exportable PROTECTED key, each named by `nameOf(slot)`. */
  const protectedBytes = (nameOf: (slot: string) => string): number => {
    const b = (name: string) => { const n = new TextEncoder().encode(name).length; return (n < 32 ? 1 : n < 256 ? 2 : 3) + n + 34; };
    let t = 5;
    for (const name of model.opaque.keys()) t += b(name);
    for (const [slot, s] of model.slots) for (const k of s.keys.values()) if (specExportable(k) && !specUnprotected(k)) t += b(nameOf(slot));
    return t;
  };

  const doExport = (op: string): Record<string, Uint8Array> | null => {
    let out: Record<string, Uint8Array>;
    try {
      out = r.exportForVault();
    } catch (e) {
      expect(e, ctx(op)).toBeInstanceOf(ChannelKeyringError);
      if (model.dropped > 0) expect((e as ChannelKeyringError).code, ctx(op)).toBe('opaque_overflow');
      else {
        expect((e as ChannelKeyringError).code, ctx(op)).toBe('vault_too_large');
        ok(protectedBytes(slotName => slotName + '#ovf999999') > cfg.maxVaultBytes, `${ctx(op)} I13 vault_too_large although protected keys fit`);
      }
      return null;
    }
    expect(model.dropped, `${ctx(op)} export should refuse`).toBe(0);
    ok(protectedBytes((slotName) => slotName) <= cfg.maxVaultBytes, `${ctx(op)} I13 no vault_too_large although protected keys cannot fit`);
    checkExport(out, op);
    model.exported(out);
    exportsSeen.push(out);
    return out;
  };

  const randomVault = (): Record<string, Uint8Array> => {
    const rec: Record<string, Uint8Array> = {};
    const n = 1 + Math.floor(rnd() * 7);
    for (let i = 0; i < n; i++) {
      const s = pick([...SCOPES, 'S']);
      const e = pick(EPOCHS);
      const v = keyOf(rnd() < 0.7 ? pick(HONEST) : pick(NODE_ATTACKER)); // node keys laundered by another device
      const kind = rnd();
      let name: string;
      if (kind < 0.28) name = `${s}:${e}`;
      else if (kind < 0.55) name = `${s}:${e}#alt${pick([1, 2, 3, 4, 5, 7, 12, 63, 64, 65, 999])}`;
      else if (kind < 0.63) name = `${s}:${e}~${pick([1, 2, 3])}`;
      else if (kind < 0.7) name = `${s}:${e}#ovf${pick([1, 2])}`;
      else if (kind < 0.76) name = `${s}:${e}#pri`;
      else if (kind < 0.8) name = `${s}:${e}#ns${pick([1, 2, 7])}`;
      else name = pick(['zzz-unknown', `${s}:${e}#future-alias`, `${s}:0${e}`, `${s}:${e}#alt0`, `${s}:${e}#alt1000`, `odd${i}`, `${s}:${e}#dup1`, `${s}:9007199254740993`]);
      // A node key can only reach a backup through OUR export (never under the primary name) or an
      // old client: other devices' vaults hold node keys under alias names only.
      if (NODE_ATTACKER_HEX.has(hex(v)) && (name === `${s}:${e}` || name.endsWith('#pri'))) name = `${s}:${e}#alt${pick([1, 5, 9])}`;
      rec[name] = v;
    }
    return rec;
  };

  const doImport = (rec: Record<string, Uint8Array>): void => {
    const before = model.dropped;
    const ceiling = rnd() < 0.3 ? pick([2, 100]) : undefined;
    r.importFromVault(rec, undefined, ceiling === undefined ? undefined : { maxEpoch: ceiling });
    model.import(rec, ceiling);
    if (model.dropped > before) return;
    for (const [n, v] of Object.entries(rec)) {
      const sl = slotOf(n);
      if (sl === null) { must.add(`#opaque|${hex(v)}`); continue; }
      const k = model.slots.get(sl)?.keys.get(hex(v));
      if (k && !k.ns) must.add(`${sl}|${hex(v)}`); // a `#ns` key (or one shed at once) is not retained
    }
  };

  const steps = 8 + Math.floor(rnd() * 22);
  /** The slot a node-served put just created (I9). */
  let newNodeSlot: string | null = null;
  for (let step = 0; step < steps; step++) {
    const roll = rnd();
    let op = '';
    if (roll < 0.5) {
      const s = pick(SCOPES);
      const e = rnd() < 0.85 ? pick(EPOCHS.slice(0, 4)) : pick([100000, MAXE]);
      const who = rnd();
      let n: number;
      let source: ChannelKeySource;
      if (who < 0.35) { n = pick(NODE_ATTACKER); source = pick(['fetch', 'legacy', 'fetch'] as const); }
      else if (who < 0.45) { n = pick(MEMBER_ATTACKER); source = 'wrap'; }
      else { n = pick(HONEST); source = pick(['establish', 'wrap', 'fetch', 'vault', 'legacy', 'establish'] as const); }
      const ts = pick([0, 1, 1000, 2000]);
      const withPair = source !== 'legacy' && rnd() < 0.7;
      const good = rnd() < 0.85;
      const pair = withPair ? (good ? pairFor(s, e, n, ts) : { keyTs: ts, commitment: keyOf(7) }) : undefined;
      const verified = withPair && good && rnd() < 0.6;
      const final = verified && rnd() < 0.4;
      const provisional = source === 'establish' && !final ? (rnd() < 0.2 ? true : rnd() < 0.15 ? false : undefined) : rnd() < 0.05 ? false : undefined;
      op = `put ${s.slice(0, 2)}:${e} k${n} ${source}${verified ? ' V' : ''}${final ? ' F' : ''}${provisional ? ' P' : provisional === false ? ' p0' : ''}${pair ? ' pair' : ''}`;
      const buf = keyOf(n);
      const existed = model.slots.has(`${s}:${e}`);
      const ownSlot = source === 'wrap' && n < 100 && rnd() < 0.5 ? true : undefined;
      if (ownSlot) op += ' own';
      const maxEpoch = rnd() < 0.2 ? pick([2, 100]) : undefined;
      if (maxEpoch !== undefined) op += ` max=${maxEpoch}`;
      const res = r.put(s, e, buf, { source, pair, verified, final, provisional, ownSlot, maxEpoch });
      buf.fill(0xee);
      const want = model.put(`${s}:${e}`, hex(keyOf(n)), { source, pair: pair && { keyTs: pair.keyTs, c: hex(pair.commitment) }, verified, final, provisional, ownSlot, maxEpoch });
      expect(res, ctx(op)).toBe(want);
      newNodeSlot = !existed && res !== 'refused' && isNodeSrc(source) ? `${s}:${e}` : null;
      // I8: only node keys and other members' wraps (member caps) are ever refused — never ours
      if (res === 'refused') ok(isNodeSrc(source) || (source === 'wrap' && !ownSlot), `${ctx(op)} I8 refused a protected key`);
      else {
        const k = model.slots.get(`${s}:${e}`)!.keys.get(hex(keyOf(n)))!;
        if (!specUnprotected(k) && specExportable(k)) must.add(`${s}:${e}|${hex(keyOf(n))}`);
      }
    } else if (roll < 0.6) {
      const s = pick(SCOPES);
      const e = pick(EPOCHS);
      const n = pick([...HONEST, ...NODE_ATTACKER, ...MEMBER_ATTACKER]);
      const good = rnd() < 0.85;
      const final = rnd() < 0.4;
      const pair = good ? pairFor(s, e, n, pick([0, 1000, 2000])) : pairFor(s, e, n === 1 ? 2 : 1, 1000);
      op = `mark ${s.slice(0, 2)}:${e} k${n} ${good ? 'good' : 'bad'}${final ? ' F' : ''}`;
      const res = r.markVerified(s, e, keyOf(n), pair, { final });
      expect(res, ctx(op)).toBe(model.mark(`${s}:${e}`, hex(keyOf(n)), good, { keyTs: pair.keyTs, c: hex(pair.commitment) }, final));
      const k = model.slots.get(`${s}:${e}`)?.keys.get(hex(keyOf(n)));
      if (k && !specUnprotected(k) && specExportable(k)) must.add(`${s}:${e}|${hex(keyOf(n))}`);
    } else if (roll < 0.615) {
      const keep = Math.floor(rnd() * 4);
      const dryRun = rnd() < 0.4;
      const includeRestoredPrimaries = rnd() < 0.2;
      const classes = rnd() < 0.5 ? undefined : (['nodeServed', 'restoredAlternates', 'memberWraps', 'restoredPrimaries'] as const).filter(() => rnd() < 0.5);
      const scopes = rnd() < 0.3 ? [pick(SCOPES)] : undefined;
      op = `prune keep=${keep}${dryRun ? ' dry' : ''}${includeRestoredPrimaries ? ' prim' : ''} classes=${classes ? classes.join('+') || 'none' : 'default'}${scopes ? ' scope' : ''}`;
      const res = r.pruneUnverified({ keepLatestPerScope: keep, dryRun, includeRestoredPrimaries, classes: classes ? [...classes] : undefined, scopes });
      const sel = new Set<string>(classes ?? ['nodeServed']);
      if (includeRestoredPrimaries) sel.add('restoredPrimaries');
      const want = model.prune(keep, dryRun, sel, scopes ? new Set(scopes) : null);
      eq(res.removedCount, want.total, `${ctx(op)} prune count`);
      for (const c of ['nodeServed', 'restoredAlternates', 'memberWraps', 'restoredPrimaries'] as const) eq(res.byClass[c].count, want[c] ?? 0, `${ctx(op)} prune ${c}`);
      eq(res.byClass.ownAlternatesAtRisk.count, res.byClass.restoredAlternates.count, `${ctx(op)} at-risk`);
    } else if (roll < 0.69) {
      op = 'import random';
      doImport(randomVault());
    } else if (roll < 0.73 && exportsSeen.length > 0) {
      op = 'import old export';
      doImport(pick(exportsSeen));
    } else if (roll < 0.78) {
      // A1: a prepared export whose publish FAILED changes nothing (flags compared below)
      op = 'prepare-unpublished';
      try { r.prepareExport(); } catch (e) { expect(e, ctx(op)).toBeInstanceOf(ChannelKeyringError); }
    } else if (roll < 0.82) {
      op = 'export';
      doExport(op);
    } else if (roll < 0.92) {
      // I11: another device on an OLD client, its own slot maybe FULL, re-exports our backup; we restore that
      const which = Math.floor(rnd() * 3);
      const slots = [...model.slots.keys()].filter((x) => SCOPES.includes(model.scopeOf(x)));
      const fill = slots.length && rnd() < 0.6 ? pick(slots) : null;
      op = `old-client ${['desktop', 'mobile', 'web'][which]}${fill ? ' full-slot' : ''}`;
      const out = doExport(op);
      if (out) {
        const re = oldReexport(which, out, fill);
        const reVals = new Set(Object.values(re).map(hex));
        // RESIDUAL: without a `#pri` copy (beyond the highest 16 epochs, or over half the byte
        // budget) an old client with that slot FULL overwrites the primary name's value.
        const unguarded = fill && out[fill] && !out[`${fill}#pri`] ? hex(out[fill]!) : null;
        for (const v of Object.values(out)) ok(reVals.has(hex(v)) || hex(v) === unguarded, `${ctx(op)} I11 old client lost a key`);
        r.importFromVault(re);
        model.import(re);
        if (which === 1) mobileLaundered = true;
      }
    } else if (roll < 0.97) {
      op = 'restart';
      const out = doExport(op);
      if (out) {
        r.clear();
        r = new ChannelKeyring(cfg);
        model = new Model(cfg);
        r.importFromVault(out);
        model.import(out);
        prev = snap();
      }
      continue;
    } else {
      op = 'clear';
      r.clear();
      model = new Model(cfg);
      must = new Set();
      mobileLaundered = false;
      exportsSeen.length = 0;
      prev = snap();
      continue;
    }

    // ---- differential + invariants after every step ----------------------------------
    const scopes = new Set([...SCOPES, 'S']);
    const live: string[] = [];
    for (const sc of scopes) for (const ep of r.epochs(sc)) live.push(`${sc}:${ep}`);
    const want = [...model.slots.keys()].sort();
    if (live.sort().join() !== want.join()) expect(live, `${ctx(op)} slot set`).toEqual(want);
    for (const [slot, s] of model.slots) {
      const got = r.entriesAt(model.scopeOf(slot), model.epochOf(slot));
      expect(hex(got[0]!.key), `${ctx(op)} I7 primary ${slot}`).toBe(s.primary);
      const gotKeys = got.map((x) => hex(x.key)).sort();
      const wantKeys = [...s.keys.keys()].sort();
      if (gotKeys.join() !== wantKeys.join()) expect(gotKeys, `${ctx(op)} keys ${slot}`).toEqual(wantKeys);
      for (const x of got) ok(infoMatches(x, s.keys.get(hex(x.key))!), `${ctx(op)} I7 flags ${slot}`);
      if (s.keys.size - 1 > cfg.maxAltsPerEpoch) for (const [h, k] of s.keys) if (h !== s.primary) ok(!(specUnprotected(k)), `${ctx(op)} I8 ${slot}`);
      for (const [h, k] of s.keys) if (NODE_ATTACKER_HEX.has(h)) ok(!(specTrusted(k)), `${ctx(op)} I10 node key trusted`);
    }
    for (const [slot, keys] of prev) {
      const cur = model.slots.get(slot)?.keys;
      for (const [h, k] of keys) {
        if (cur?.has(h)) continue;
        if (model.retired.has(`${slot}|${h}`)) {
          // only prune (never-author-vouched, non-provisional) or the member cap (others' non-final wraps)
          // I15: only prune removes keys of ours' classes — never own, establish, provisional or final wraps
          ok(op.startsWith('prune') && !k.own && !k.prov && k.source !== 'establish' && !(k.source === 'wrap' && k.final), `${ctx(op)} I15 removed an own key ${slot}`);
          if (op.includes('classes=default') && !op.includes('prim')) ok(k.ns || isNodeSrc(k.source), `${ctx(op)} I15 default prune took more than node keys`);
          must.delete(`${slot}|${h}`);
          continue;
        }
        ok(specUnprotected(k), `${ctx(op)} I6 lost protected ${slot}`);
      }
    }
    model.retired.clear();
    for (const p of must) {
      const [slot, h] = p.split('|') as [string, string];
      if (slot === '#opaque') continue;
      ok(model.slots.get(slot)?.keys.has(h), `${ctx(op)} I1 not held ${p}`);
    }
    for (const sc of scopes) {
      const eps = r.epochs(sc);
      const prim = (ep: number) => model.slots.get(`${sc}:${ep}`)!.keys.get(model.slots.get(`${sc}:${ep}`)!.primary)!;
      for (const maxEpoch of [Number.POSITIVE_INFINITY, 2]) {
        for (const finalOnly of maxEpoch === 2 ? [false] : [false, true]) {
          let strictEp: number | null = null;
          let looseEp: number | null = null;
          let verifiedEp: number | null = null;
          for (const ep of eps) {
            if (ep > maxEpoch) continue;
            const p = prim(ep);
            if (specRank(p) >= (finalOnly ? 4 : 2)) strictEp = ep;
            if (specRank(p) >= (finalOnly ? 4 : 3)) verifiedEp = ep;
            if (isAuthorSrc(p.source) || (!isNodeSrc(p.source) && !p.ns && !p.served && !p.aliasOrigin)) looseEp = ep;
          }
          const strict = r.bestForSend(sc, { maxEpoch, finalOnly });
          const loose = r.bestForSend(sc, { maxEpoch, finalOnly, allowUnverified: true });
          expect(strict?.epoch ?? null, `${ctx(op)} I4 strict`).toBe(strictEp);
          expect(loose?.epoch ?? null, `${ctx(op)} I4 loose`).toBe(strictEp ?? looseEp);
          if (strict) ok(!(NODE_ATTACKER_HEX.has(hex(strict.key))), `${ctx(op)} I10 node key send`);
          if (loose && !mobileLaundered) ok(!(NODE_ATTACKER_HEX.has(hex(loose.key))), `${ctx(op)} I10 node key fallback`);
          const lv = r.latestVerified(sc, { maxEpoch, finalOnly });
          expect(lv?.epoch ?? null, `${ctx(op)} latestVerified`).toBe(verifiedEp);
          if (lv) ok(!(NODE_ATTACKER_HEX.has(hex(lv.key))), `${ctx(op)} I10 node key evidence`);
        }
      }
      // I16: bestForSendLegacy == spec — only a scope of nothing but this session's commitment-less node keys
      {
        const isLeg = (ep: number) => ep % 2 === 1 || ep === 0;
        const allLegacy = eps.every((ep) => [...model.slots.get(`${sc}:${ep}`)!.keys.values()]
          .every((k) => isNodeSrc(k.source) && k.served && !k.pair && !k.wasVault && !k.prov && !k.own));
        let want: number | null = null;
        if (allLegacy) for (const ep of eps) if (isLeg(ep)) want = ep;
        eq(r.bestForSendLegacy(sc, { isLegacyEpoch: isLeg })?.epoch ?? null, want, `${ctx(op)} I16 legacy`);
      }
      // I9
      let floor = -1;
      for (const ep of eps) if (specRank(prim(ep)) >= 3) floor = ep;
      const above = eps.filter((ep) => ep > floor && [...model.slots.get(`${sc}:${ep}`)!.keys.values()].every((k) => !isAuthorSrc(k.source) && !k.prov));
      // exempt: epochs holding a PROTECTED restored / client-put vault key (never evicted); node keys are not
      const restored = above.filter((ep) => [...model.slots.get(`${sc}:${ep}`)!.keys.values()].some((k) => !specUnprotected(k)));
      const restoredAll = eps.filter((ep) => [...model.slots.get(`${sc}:${ep}`)!.keys.values()].some((k) => k.persisted || !isNodeSrc(k.source) || k.prov));
      // a NEW node-served epoch above the trusted one is only admitted with the scope within the cap
      if (op.startsWith('put') && op.includes(`${sc.slice(0, 2)}:`) && newNodeSlot && newNodeSlot.startsWith(sc) && Number(newNodeSlot.slice(65)) > floor) {
        ok(above.length <= cfg.maxUntrustedEpochsPerScope, `${ctx(op)} I9 untrusted ${sc}`);
      }
      void restored;
      ok(eps.length - restoredAll.length <= cfg.maxEpochsPerScope, `${ctx(op)} I9 absolute ${sc}`);
    }
    prev = snap();
  }
  doExport('final');
}

describe('ChannelKeyring property test', () => {
  it(`${SEQUENCES} seeded random sequences: keyring == spec model, I1-I12`, () => {
    for (let i = 0; i < SEQUENCES; i++) runSequence((SEED + i * 7919) >>> 0);
  }, 1_800_000);
});
