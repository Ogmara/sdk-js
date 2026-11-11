/**
 * TEST FIXTURE — a verbatim copy of the OLD web src/lib/channelKeyCore.ts ChannelKeyCache section (web 0.85.x) keyring/vault logic
 * (pre sdk-js 0.68.0), used only by channelKeyring interop tests to prove an
 * older client re-exporting a 0.68.0 backup keeps every key. Never shipped
 * (not under src/, not in the package). Do not edit beyond the import shim.
 */
/** Where a cached key came from (decides what it may be used for). */
export type KeySource =
  /** `establishEpochKey` (our own winner, or an author-verified adopted wrap). */
  | 'establish'
  /** Our own slot, author-verified (`verifyChannelKeyWrap`). */
  | 'wrap'
  /** Our own slot, NOT author-verified (decryption only until verified). */
  | 'fetch'
  /** Restored from this wallet's own key vault. */
  | 'vault';

/** Result of checking a cached key against the node's commitment for its epoch. */
export type KeyCheck =
  /** The node's FINAL winner is this key (pair known). */
  | 'sendable'
  /** The node's current, not yet final winner is this key (pair known). */
  | 'unconfirmed'
  /** Pre-arbitration epoch (no commitment), key of our own provenance. */
  | 'legacy'
  /** The node's winner is a DIFFERENT key: ours lost. */
  | 'mismatch'
  /** The commitment could not be read (old node, network) — own-provenance key. */
  | 'unavailable'
  /** The node holds no state for the epoch (lagging) — own-provenance key. */
  | 'none'
  /** Node-served key that could not be verified: decrypt only, never send. */
  | 'unverified';

export interface KeyEntry {
  key: Uint8Array;
  source: KeySource;
  /** The arbitration pair — required to cover at this epoch (strict policy). */
  meta?: { keyTs: number; keyCommitment: Uint8Array };
  /** The node reported this pair FINAL. */
  confirmed?: boolean;
  /** First key of a brand-new channel, used before finality (user decision). */
  early?: boolean;
  /** Pre-arbitration epoch. */
  legacy?: boolean;
  /** Last check (throttles commitment reads for unconfirmed keys). */
  checked?: { at: number; result: KeyCheck };
}

const SOURCE_RANK: Record<KeySource, number> = { fetch: 0, vault: 1, wrap: 2, establish: 3 };

export const bytesEq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** May this entry go into the key vault backup? Everything but a not-yet-final early key. */
export function isBackupable(e: KeyEntry): boolean {
  return !e.early;
}

/** Keys that need an author-verified wrap before they may send, cover or count. */
export function isUnverifiedSource(s: KeySource): boolean {
  return s === 'fetch' || s === 'vault';
}

/**
 * The channel key cache (`${scopeHex}:${epoch}` → entry). `onBackupable`
 * fires when a backupable key appears or an entry BECOMES backupable (an
 * early key confirmed) — never for a not-yet-final early key.
 */
/** Different keys kept per slot besides the primary (never-overwrite rule). Input cap. */
export const MAX_ALTS_PER_SLOT = 4;
/** Vault keyring key of an alternate key: `${scopeHex}:${epoch}#alt${n}` (cross-client format). */
const ALT_SEP = '#alt';

/**
 * Parse a vault `chan` entry name (CROSS-CLIENT VAULT FORMAT): a slot
 * `${scopeHex}:${epoch}`, or an alternate `${slot}#alt${n}` (also the legacy
 * `${slot}~${n}`, normalized to `#alt`). Anything else is OPAQUE: never
 * interpreted, preserved verbatim and re-exported unchanged.
 */
export function parseVaultName(name: string): { slot: string; alt: number | null } | null {
  const m = /^([0-9a-f]{64}:[1-9][0-9]{0,15})(?:(?:#alt|~)([1-9][0-9]{0,3}))?$/.exec(name);
  if (!m) return null;
  const epoch = Number(m[1]!.slice(65));
  if (!Number.isSafeInteger(epoch)) return null;
  return { slot: m[1]!, alt: m[2] ? Number(m[2]) : null };
}

export class ChannelKeyCache {
  private readonly map = new Map<string, KeyEntry>();
  /** Every key the restored vault held, by its CANONICAL vault name — exported again (never shrink). */
  private readonly vaultHeld = new Map<string, Uint8Array>();
  /** Vault entries whose name this client does not understand: re-exported verbatim. */
  private readonly opaque = new Map<string, Uint8Array>();
  /** DIFFERENT keys held for a slot besides its primary entry (never overwritten, never lost). */
  private readonly alts = new Map<string, Uint8Array[]>();
  private readonly onBackupable: () => void;

  constructor(onBackupable: () => void) {
    this.onBackupable = onBackupable;
  }

  get(k: string): KeyEntry | undefined {
    return this.map.get(k);
  }

  has(k: string): boolean {
    return this.map.has(k);
  }

  /** Every key held for a slot: the primary first, then the alternates (decryption tries all). */
  keysFor(k: string): Uint8Array[] {
    const out: Uint8Array[] = [];
    const p = this.map.get(k);
    if (p) out.push(p.key);
    for (const a of this.alts.get(k) ?? []) out.push(a);
    return out;
  }

  /** Keep `key` as an alternate of slot `k` (deduplicated, capped on the input). */
  private addAlt(k: string, key: Uint8Array): boolean {
    const p = this.map.get(k);
    if (p && bytesEq(p.key, key)) return false;
    const list = this.alts.get(k) ?? [];
    if (list.some((x) => bytesEq(x, key))) return false;
    if (list.length >= MAX_ALTS_PER_SLOT) return false;
    list.push(key);
    this.alts.set(k, list);
    return true;
  }

  /**
   * Cache a key. NEVER OVERWRITE a different key held at the same epoch:
   *  - the same bytes MERGE (pair, confirmation, best source; a second buffer is wiped);
   *  - a different early / provisional key never displaces anything (wiped);
   *  - a different key that is a FINAL key with a VERIFIED pair becomes the
   *    primary only over an UNVERIFIED primary (node-served / vault / legacy),
   *    which is kept as an alternate;
   *  - any other different key is kept as an alternate.
   * Alternates stay decryptable and are exported to the vault, so neither key
   * is lost. Returns the slot's PRIMARY entry — the caller compares it with
   * what it cached to detect a conflict (log + gated heal).
   */
  put(k: string, entry: KeyEntry): KeyEntry {
    const prev = this.map.get(k);
    if (prev && bytesEq(prev.key, entry.key)) {
      const was = isBackupable(prev);
      prev.meta ??= entry.meta;
      prev.confirmed = prev.confirmed || entry.confirmed;
      if (prev.confirmed) prev.early = false;
      else if (entry.early) prev.early = true;
      if (SOURCE_RANK[entry.source] > SOURCE_RANK[prev.source]) prev.source = entry.source;
      prev.checked = undefined;
      if (entry.key !== prev.key) entry.key.fill(0);
      if (!was && isBackupable(prev)) this.onBackupable();
      return prev;
    }
    if (!prev) {
      this.map.set(k, entry);
      if (isBackupable(entry)) this.onBackupable();
      return entry;
    }
    if (entry.early) {
      entry.key.fill(0); // a provisional key never clobbers a held one
      return prev;
    }
    if (isVerifiedPair(entry) && entry.confirmed === true && !(isVerifiedPair(prev) && prev.confirmed === true)) {
      this.map.set(k, entry);
      this.addAlt(k, prev.key);
      this.onBackupable();
      return entry;
    }
    if (this.addAlt(k, entry.key)) this.onBackupable();
    else entry.key.fill(0);
    return prev;
  }

  /** Call after mutating an entry in place: notifies if it became backupable. */
  changed(entry: KeyEntry, wasBackupable: boolean): void {
    if (!wasBackupable && isBackupable(entry)) this.onBackupable();
  }

  /** Highest cached epoch for a scope, or null. */
  latest(scopeHex: string): { entry: KeyEntry; epoch: number } | null {
    let best: { entry: KeyEntry; epoch: number } | null = null;
    for (const [epoch, v] of this.entriesFor(scopeHex)) {
      if (!best || epoch > best.epoch) best = { entry: v, epoch };
    }
    return best;
  }

  /** `[epoch, entry]` pairs cached for a scope. */
  *entriesFor(scopeHex: string): IterableIterator<[number, KeyEntry]> {
    for (const [k, v] of this.map) {
      if (k.startsWith(`${scopeHex}:`)) yield [Number(k.slice(scopeHex.length + 1)), v];
    }
  }

  /**
   * Keys for the vault (format unchanged: a `string → 32-byte key` map) — the
   * UNION, NEVER SHRINK, of the restored vault record and every key held: per
   * slot the distinct keys are the primary (if backupable — a not-yet-final
   * early key is held back), the vault-held copy and the alternates. The first
   * is exported under the slot (a VERIFIED primary first, else the vault's
   * copy), the others as `${slot}#altN` (kept by the vault, restored as
   * alternates). The vault is one last-write-wins record: whatever an export
   * omits is lost for good.
   */
  exportForVault(): Record<string, Uint8Array> {
    const out: Record<string, Uint8Array> = {};
    for (const [k, v] of this.opaque) out[k] = v;
    const slots = new Set<string>([...this.map.keys(), ...this.alts.keys()]);
    for (const k of this.vaultHeld.keys()) slots.add(parseVaultName(k)?.slot ?? k);
    for (const slot of slots) {
      const keys: Uint8Array[] = [];
      const add = (x: Uint8Array | undefined) => { if (x && !keys.some((y) => bytesEq(x, y))) keys.push(x); };
      const p = this.map.get(slot);
      const pOk = p && isBackupable(p) ? p : undefined;
      if (pOk && isVerifiedPair(pOk)) add(pOk.key);
      add(this.vaultHeld.get(slot));
      add(pOk?.key);
      // the vault's own alternates of this slot, in their numeric order
      const heldAlts = [...this.vaultHeld].filter(([vk]) => vk.startsWith(slot + ALT_SEP))
        .sort((a, b) => (parseVaultName(a[0])?.alt ?? 0) - (parseVaultName(b[0])?.alt ?? 0));
      for (const [, v] of heldAlts) add(v);
      for (const a of this.alts.get(slot) ?? []) add(a);
      // A slot with only alternates (no primary-level key) keeps them as `#altN`,
      // never promoting an alternate to the slot name.
      const hasPrimary = !!pOk || this.vaultHeld.has(slot);
      keys.forEach((x, i) => {
        const n = hasPrimary ? i : i + 1;
        out[n === 0 ? slot : `${slot}${ALT_SEP}${n}`] = x;
      });
    }
    return out;
  }

  /**
   * Merge vault-restored keys; never clobber a cached key. Every restored key
   * is remembered (`vaultHeld`) — also one shadowed by a cached (even
   * provisional) copy — so the next export still contains it, and a shadowed
   * DIFFERENT key stays decryptable as an alternate.
   */
  importFromVault(rec: Record<string, Uint8Array>): number {
    let added = 0;
    for (const [name, v] of Object.entries(rec)) {
      if (!(v instanceof Uint8Array) || v.length !== 32) continue;
      const parsed = parseVaultName(name);
      if (!parsed) {
        // Unknown shape (future alias, other client): keep verbatim, never interpret.
        const o = this.opaque.get(name);
        if (o && o !== v) o.fill(0);
        this.opaque.set(name, v);
        continue;
      }
      const slot = parsed.slot;
      const vk = parsed.alt === null ? slot : `${slot}${ALT_SEP}${parsed.alt}`; // `~n` → `#altn`
      const held = this.vaultHeld.get(vk);
      if (held && held !== v) held.fill(0);
      this.vaultHeld.set(vk, v);
      const prev = this.map.get(slot);
      if (!prev && parsed.alt === null) {
        this.map.set(slot, { key: v.slice(), source: 'vault' });
        added++;
      } else if (!prev || !bytesEq(prev.key, v)) {
        if (this.addAlt(slot, v.slice())) added++;
      }
    }
    return added;
  }

  /** Wipe every key (cached, alternates, vault-held) and drop everything (disconnect). */
  clear(): void {
    for (const v of this.map.values()) v.key.fill(0);
    for (const v of this.vaultHeld.values()) v.fill(0);
    for (const l of this.alts.values()) for (const v of l) v.fill(0);
    for (const v of this.opaque.values()) v.fill(0);
    this.map.clear();
    this.vaultHeld.clear();
    this.alts.clear();
    this.opaque.clear();
  }
}

export function isVerifiedPair(e: KeyEntry): boolean {
  return !!e.meta && !isUnverifiedSource(e.source) && !e.legacy;
}
