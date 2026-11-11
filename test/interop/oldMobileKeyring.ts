/**
 * TEST FIXTURE — a verbatim copy of the OLD mobile src/lib/channelKeyCore.ts ChannelKeyring section (mobile 0.58.x) keyring/vault logic
 * (pre sdk-js 0.68.0), used only by channelKeyring interop tests to prove an
 * older client re-exporting a 0.68.0 backup keeps every key. Never shipped
 * (not under src/, not in the package). Do not edit beyond the import shim.
 */
// --- Keyring (never overwrite, vault union) ------------------------------------------------------

/** What is known about one held key (see channelCrypto `KeyMeta`). */
export interface KeyringMeta {
  state: 'confirmed' | 'provisional' | 'legacy' | 'unknown';
  keyTs?: number;
  commitment?: Uint8Array;
  verified: boolean;
  early?: boolean;
}

/** Keys kept per `scope:epoch`: the primary + up to 4 alternates (`#alt1`..`#alt4`). */
export const MAX_KEYS_PER_EPOCH = 5;
/**
 * CROSS-CLIENT vault format (binding for web / desktop / mobile): the `chan`
 * map is keyed `${scopeHex}:${epoch}`; alternate keys at the same epoch are
 * EXACTLY `${scopeHex}:${epoch}#alt${n}` (n = 1..4).
 */
export const ALT_TAG = '#alt';
/** Entries of the vault kept verbatim because this client cannot parse them (bounded). */
export const MAX_OPAQUE_VAULT_ENTRIES = 1024;
/**
 * A vault entry name: `<scope>:<epoch>`, `<scope>:<epoch>#alt<n>` or the
 * pre-release mobile `<scope>:<epoch>~<n>` (read only, written as `#alt`).
 */
const VAULT_NAME = /^([0-9A-Za-z]+):(\d{1,15})(?:#alt([1-9]\d{0,2})|~([1-9]\d{0,2}))?$/;

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
const RANK: Record<KeyringMeta['state'], number> = { unknown: 0, legacy: 1, provisional: 2, confirmed: 3 };

/** Result of {@link ChannelKeyring.put}. */
export type PutResult = 'added' | 'same' | 'mismatch' | 'full';

/**
 * The channel key cache. A key already held at an epoch is NEVER replaced by
 * a different one — the newcomer is kept as an alternate (both decrypt, both
 * are exported), the caller logs the mismatch and may heal (gated). The vault
 * export is the UNION of everything held (primary + alternates), so a key
 * cached before a restore (or a provisional / early key) can never make the
 * next backup drop a vault key, and a vault key for an epoch we already hold
 * differently is kept as an alternate instead of being skipped.
 */
export class ChannelKeyring {
  private readonly slots = new Map<string, Array<{ key: Uint8Array; meta: KeyringMeta }>>();
  /**
   * Vault entries this client could not place (unknown name shapes, future
   * aliases, alternates beyond its per-epoch cap): kept VERBATIM and
   * re-exported unchanged, so a backup never drops another client's data.
   */
  private readonly opaque = new Map<string, Uint8Array>();

  /** Merge `meta` into an existing one: never downgrade the state. */
  private static merge(prev: KeyringMeta, next: KeyringMeta): KeyringMeta {
    if (RANK[next.state] < RANK[prev.state]) return prev;
    return { ...prev, ...next, verified: prev.verified || next.verified, early: next.early ?? prev.early };
  }

  put(k: string, key: Uint8Array, meta: KeyringMeta): PutResult {
    const list = this.slots.get(k);
    if (!list) {
      this.slots.set(k, [{ key, meta }]);
      return 'added';
    }
    const same = list.find((e) => sameBytes(e.key, key));
    if (same) {
      same.meta = ChannelKeyring.merge(same.meta, meta);
      return 'same';
    }
    if (list.length >= MAX_KEYS_PER_EPOCH) return 'full';
    list.push({ key, meta });
    return 'mismatch';
  }

  /** Set meta for a held key after a node check (authoritative for that key). */
  setMeta(k: string, key: Uint8Array, meta: KeyringMeta): void {
    const e = this.slots.get(k)?.find((x) => sameBytes(x.key, key));
    if (e) e.meta = { ...meta, early: meta.early ?? e.meta.early };
  }

  candidates(k: string): ReadonlyArray<{ key: Uint8Array; meta: KeyringMeta }> {
    return this.slots.get(k) ?? [];
  }

  primary(k: string): Uint8Array | undefined {
    return this.slots.get(k)?.[0]?.key;
  }

  metaOf(k: string, key: Uint8Array): KeyringMeta | undefined {
    return this.slots.get(k)?.find((x) => sameBytes(x.key, key))?.meta;
  }

  has(k: string): boolean {
    return this.slots.has(k);
  }

  /** Every epoch held for a scope. */
  epochsFor(scopeHex: string): number[] {
    const out: number[] = [];
    for (const k of this.slots.keys()) if (k.startsWith(`${scopeHex}:`)) out.push(Number(k.slice(scopeHex.length + 1)));
    return out.filter((e) => Number.isSafeInteger(e));
  }

  /**
   * Vault export: the UNION of every held key (alternates as `<k>#alt<n>`)
   * plus every entry kept verbatim from an import — it never shrinks.
   */
  exportVault(): Record<string, Uint8Array> {
    const out: Record<string, Uint8Array> = {};
    for (const [k, list] of this.slots) {
      list.forEach((e, i) => { out[i === 0 ? k : `${k}${ALT_TAG}${i}`] = e.key; });
    }
    for (const [name, v] of this.opaque) if (!(name in out)) out[name] = v;
    return out;
  }

  /**
   * Vault import: every key is kept — a different key at a held epoch becomes
   * an alternate, and anything that cannot be placed (unknown name, more
   * alternates than the cap) is kept verbatim for re-export. Returns how many
   * keys were new.
   */
  importVault(rec: Record<string, Uint8Array>): number {
    let added = 0;
    for (const [rk, v] of Object.entries(rec)) {
      if (!(v instanceof Uint8Array) || v.length !== 32) continue;
      const m = VAULT_NAME.exec(rk);
      const r = m ? this.put(`${m[1]}:${m[2]}`, v, { state: 'unknown', verified: false }) : 'full';
      if (r === 'added' || r === 'mismatch') added++;
      else if (r === 'full' && !this.opaque.has(rk) && this.opaque.size < MAX_OPAQUE_VAULT_ENTRIES) {
        this.opaque.set(rk, v);
        added++;
      }
    }
    return added;
  }

  clear(): void {
    for (const list of this.slots.values()) for (const e of list) e.key.fill(0);
    this.slots.clear();
    for (const v of this.opaque.values()) v.fill(0);
    this.opaque.clear();
  }

  get size(): number {
    return this.slots.size;
  }
}
