/**
 * ChannelKeyring regression tests (sdk-js 0.68.0). Every named case is an
 * audit finding against one of the three former client keyrings (desktop
 * ChannelKeyStore, web ChannelKeyCache, mobile ChannelKeyring) or against the
 * first 0.68.0 draft (r75: A, B, N1, N2, B2/G, B3/H, W1/E, W2/C+D, W3/M,
 * W4/F, W5/J); the property test lives in channelKeyring.property.test.ts.
 */
import { describe, expect, it } from 'vitest';
import { decode, encode } from '@msgpack/msgpack';
import {
  ChannelKeyring,
  ChannelKeyringError,
  acceptFetchedEnvelope,
  MAX_ALTS_PER_EPOCH,
  MAX_ALT_INDEX,
  MAX_OPAQUE_VAULT_ENTRIES,
  MAX_UNTRUSTED_EPOCHS_PER_SCOPE,
  MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE,
  PRI_COPIES_PER_SCOPE,
  VAULT_CHAN_SOFT_LIMIT_BYTES,
  estimateVaultChanBytes,
  MAX_PRI_COPIES,
  NODE_SERVED_VAULT_SHARE,
  type ChannelKeyPair,
} from './channelKeyring';
import { computeKeyCommitment } from './channelKeyCommit';
import { openKeyVault, sealKeyVault, renameProtoKeysInVaultPlaintext } from './keyVault';
import { aeadDecrypt, aeadEncrypt } from './crypto';
import { ChannelKeyStore as OldDesktop } from '../test/interop/oldDesktopKeyStore';
import { ChannelKeyring as OldMobile } from '../test/interop/oldMobileKeyring';
import { ChannelKeyCache as OldWeb } from '../test/interop/oldWebKeyCache';

const SA = 'aa'.repeat(32);
const SB = 'bb'.repeat(32);
const k = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const scopeBytes = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
const pairOf = (scope: string, epoch: number, key: Uint8Array, keyTs = 1000): ChannelKeyPair => ({
  keyTs, commitment: computeKeyCommitment(scopeBytes(scope), epoch, keyTs, key),
});
const values = (rec: Record<string, Uint8Array>): Set<string> => new Set(Object.values(rec).map(hex));
/** Our own / author-verified key with a consistent pair. */
const trustedPut = (r: ChannelKeyring, scope: string, epoch: number, key: Uint8Array, keyTs = 1000, final = false) =>
  r.put(scope, epoch, key, { source: 'establish', pair: pairOf(scope, epoch, key, keyTs), verified: true, final });
/** Old-client re-exports of a record (what another device running an older client writes back). */
function oldClientReexports(rec: Record<string, Uint8Array>): Array<[string, Record<string, Uint8Array>]> {
  const d = new OldDesktop(() => 0, () => {});
  d.importFromVault(rec);
  const m = new OldMobile();
  m.importVault(rec);
  const w = new OldWeb(() => {});
  w.importFromVault(rec);
  return [['desktop', d.exportForVault()], ['mobile', m.exportVault()], ['web', w.exportForVault()]];
}

describe('basic put / views', () => {
  it('stores copies; caller buffers are never kept nor zeroed (N-f)', () => {
    const r = new ChannelKeyring();
    const buf = k(7);
    expect(r.put(SA, 1, buf, { source: 'fetch' })).toBe('stored');
    buf.fill(9);
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(7)));
    const mine = k(8);
    r.importFromVault({ [`${SA}:2`]: mine });
    r.clear();
    expect(hex(mine)).toBe(hex(k(8)));
    expect(hex(buf)).toBe(hex(k(9)));
    expect(r.keysAt(SA, 1)).toEqual([]);
  });

  it('returned keys are copies (mutating them changes nothing)', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'fetch' });
    r.keysAt(SA, 1)[0]!.fill(0);
    r.entriesAt(SA, 1)[0]!.key.fill(0);
    r.latest(SA)!.key.fill(0);
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(1)));
  });

  it('validates input', () => {
    const r = new ChannelKeyring();
    expect(r.put(SA, -1, k(1), { source: 'fetch' })).toBe('invalid');
    expect(r.put(SA, 1.5, k(1), { source: 'fetch' })).toBe('invalid');
    expect(r.put(SA, 1, new Uint8Array(31), { source: 'fetch' })).toBe('invalid');
    expect(r.put('a:b', 1, k(1), { source: 'fetch' })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'nope' as never })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'legacy', pair: pairOf(SA, 1, k(1)) })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'establish', verified: true })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'establish', verified: true, pair: pairOf(SA, 1, k(2)) })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'establish', verified: true, pair: pairOf(SA, 2, k(1)) })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'establish', verified: true, pair: pairOf(SB, 1, k(1)) })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'establish', final: true, pair: pairOf(SA, 1, k(1)) })).toBe('invalid');
    expect(r.put(SA, 1, k(1), { source: 'fetch', provisional: true })).toBe('invalid');
    expect(r.size).toBe(0);
  });

  it('drops writes / reads of an outdated account generation (W3: export too)', () => {
    let g = 1;
    const r = new ChannelKeyring({ generation: () => g });
    expect(r.put(SA, 1, k(1), { source: 'establish', pair: pairOf(SA, 1, k(1)), generation: 1 })).toBe('stored');
    expect(Object.keys(r.exportForVault(1))).toEqual([`${SA}:1`, `${SA}:1#pri`]);
    g = 2; // account switched, caller forgot clear()
    expect(r.put(SA, 2, k(2), { source: 'fetch', generation: 1 })).toBe('stale');
    expect(r.put(SA, 2, k(2), { source: 'fetch' })).toBe('stale');
    expect(r.markVerified(SA, 1, k(1), pairOf(SA, 1, k(1)), { generation: 1 })).toBe('stale');
    expect(r.markVerified(SA, 1, k(1), pairOf(SA, 1, k(1)))).toBe('stale');
    expect(() => r.importFromVault({ [`${SA}:3`]: k(3) }, 1)).toThrow(ChannelKeyringError);
    let code = '';
    try { r.exportForVault(1); } catch (e) { code = (e as ChannelKeyringError).code; }
    expect(code).toBe('stale');
    expect(() => r.exportForVault()).toThrow(ChannelKeyringError);
    expect(r.holds(SA, 2) || r.holds(SA, 3)).toBe(false);
  });

  it('acceptFetchedEnvelope: the envelope epoch must equal the requested epoch (EPOCH BINDING)', () => {
    expect(acceptFetchedEnvelope(3, 3)).toBe(true);
    expect(acceptFetchedEnvelope(3, 100000)).toBe(false);
    expect(acceptFetchedEnvelope(3, '3')).toBe(false);
    expect(acceptFetchedEnvelope(3, 3.0000001)).toBe(false);
    expect(acceptFetchedEnvelope(3, 2 ** 53)).toBe(false);
    expect(acceptFetchedEnvelope(-1, -1)).toBe(false);
    expect(acceptFetchedEnvelope(0, 0)).toBe(true);
  });

  it('among equal ranks the FIRST seen key stays primary', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:1`]: k(1) });
    expect(r.put(SA, 1, k(2), { source: 'vault' })).toBe('conflict');
    expect(r.put(SA, 1, k(3), { source: 'wrap' })).toBe('conflict'); // own provenance, no pair: rank 1 too
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(1)));
    trustedPut(r, SA, 1, k(4), 2000);
    expect(trustedPut(r, SA, 1, k(5), 1)).toBe('conflict'); // better-ranked pair, not final: first seen stays
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(4)));
  });
});

describe('r75 B1: a node can never make its own key the send key', () => {
  it('A: a node-served key with a node-computed pair (any keyTs) is never promoted by markVerified', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 5, k(1));
    expect(r.put(SA, 5, k(9), { source: 'fetch', pair: pairOf(SA, 5, k(9), 0) })).toBe('conflict');
    expect(r.markVerified(SA, 5, k(9), pairOf(SA, 5, k(9), 0), { final: true })).toBe('needs_author_proof');
    expect(r.put(SA, 5, k(9), { source: 'fetch', pair: pairOf(SA, 5, k(9), 0), verified: true, final: true })).toBe('stored');
    expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(1)));
    expect(r.entriesAt(SA, 5)[1]!.trusted).toBe(false);
  });

  it('B: a node-served key at a HIGHER epoch never becomes the send key or evidence', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 5, k(1));
    r.put(SA, 6, k(9), { source: 'fetch', pair: pairOf(SA, 6, k(9), 0), verified: true, final: true });
    expect(r.markVerified(SA, 6, k(9), pairOf(SA, 6, k(9), 0))).toBe('needs_author_proof');
    expect(r.bestForSend(SA)!.epoch).toBe(5);
    expect(r.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(5);
    expect(r.latestVerified(SA)!.epoch).toBe(5);
  });

  it('N1: a hostile legacy key at epoch 100000 cannot be marked verified', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 5, k(1));
    expect(r.put(SA, 100000, k(9), { source: 'legacy' })).toBe('stored');
    expect(r.markVerified(SA, 100000, k(9), pairOf(SA, 100000, k(9), 0))).toBe('needs_author_proof');
    expect(r.latestVerified(SA)!.epoch).toBe(5);
    expect(r.bestForSend(SA)!.epoch).toBe(5);
  });

  it('N2: a node key laundered through a backup returns as `vault`, which markVerified cannot trust either', () => {
    const r = new ChannelKeyring();
    r.put(SA, 7, k(8), { source: 'fetch', pair: pairOf(SA, 7, k(8)) });
    const r2 = new ChannelKeyring();
    r2.importFromVault(r.exportForVault());
    expect(r2.entriesAt(SA, 7)[0]!.source).toBe('vault');
    expect(r2.markVerified(SA, 7, k(8), pairOf(SA, 7, k(8)), { final: true })).toBe('needs_author_proof');
    expect(r2.bestForSend(SA)).toBeNull();
    expect(r2.latestVerified(SA)).toBeNull();
    // the documented flow: the client verified the wrap's author, then re-puts as `wrap`
    expect(r2.put(SA, 7, k(8), { source: 'wrap', pair: pairOf(SA, 7, k(8)), verified: true })).toBe('stored');
    expect(r2.bestForSend(SA)!.epoch).toBe(7);
  });

  it('between two trusted keys only the node FINAL winner displaces the first seen (W6)', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 2, k(1), 2000);
    expect(trustedPut(r, SA, 2, k(2), 1000)).toBe('conflict');
    expect(r.markVerified(SA, 2, k(2), pairOf(SA, 2, k(2), 1000), { final: true })).toBe('promoted');
    expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(2)));
    // a non-final trusted key never displaces the final one
    expect(trustedPut(r, SA, 2, k(3), 1)).toBe('conflict');
    expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(2)));
    expect(r.bestForSend(SA, { finalOnly: true })!.epoch).toBe(2);
    expect(r.latestVerified(SA, { finalOnly: true })!.epoch).toBe(2);
    trustedPut(r, SA, 3, k(4));
    expect(r.latestVerified(SA)!.epoch).toBe(3);
    expect(r.latestVerified(SA, { finalOnly: true })!.epoch).toBe(2);
    expect(r.bestForSend(SA, { finalOnly: true })!.epoch).toBe(2);
  });

  it('a re-verification with a worse non-final pair never replaces a recorded pair', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 5, k(1), 1000);
    expect(r.markVerified(SA, 5, k(1), pairOf(SA, 5, k(1), 2000))).toBe('verified');
    expect(r.entriesAt(SA, 5)[0]!.pair!.keyTs).toBe(1000);
    expect(r.markVerified(SA, 5, k(1), pairOf(SA, 5, k(1), 3000), { final: true })).toBe('verified');
    expect(r.entriesAt(SA, 5)[0]!.pair!.keyTs).toBe(3000); // the final pair is the one to cover with
    expect(r.entriesAt(SA, 5)[0]!.final).toBe(true);
  });
});

describe('desktop re-audit', () => {
  it('B-1: export never writes one entry over another (alternates beyond the cap, opaque, mixed aliases)', () => {
    const r = new ChannelKeyring();
    const vault: Record<string, Uint8Array> = {
      [`${SA}:3`]: k(1),
      [`${SA}:3#alt1`]: k(2),
      [`${SA}:3#alt2`]: k(3),
      [`${SA}:3#alt3`]: k(4),
      [`${SA}:3#alt4`]: k(5),
      [`${SA}:3~1`]: k(6),
      [`${SA}:3#alt9`]: k(7),
      'zzz-unknown': k(8),
    };
    r.importFromVault(vault);
    expect(trustedPut(r, SA, 3, k(9))).toBe('promoted');
    const out = r.exportForVault();
    for (const v of [1, 2, 3, 4, 5, 6, 7, 8, 9]) expect(values(out).has(hex(k(v)))).toBe(true);
    expect(Object.keys(out).length).toBe(10); // 9 values + the `#pri` copy of the primary
    expect(hex(out[`${SA}:3`]!)).toBe(hex(k(9)));
    expect(hex(out[`${SA}:3#pri`]!)).toBe(hex(k(9)));
  });

  it('B-1: alias-only primary + a second import of the same alias name', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:7#alt1`]: k(1) });
    r.importFromVault({ [`${SA}:7#alt1`]: k(2) });
    const out = r.exportForVault();
    expect(values(out)).toEqual(new Set([hex(k(1)), hex(k(2))]));
    expect(out[`${SA}:7`]).toBeUndefined();
    expect(Object.keys(out)).toEqual([`${SA}:7#alt5`, `${SA}:7#alt6`]); // `#alt1` re-homed to `#alt5+`
    expect(hex(out[`${SA}:7#alt5`]!)).toBe(hex(k(1)));
  });

  it('B-1: mixed `~n` and `#altN` names for the same n both survive', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:4`]: k(1), [`${SA}:4#alt1`]: k(2), [`${SA}:4~1`]: k(3) });
    const out = r.exportForVault();
    expect(values(out)).toEqual(new Set([hex(k(1)), hex(k(2)), hex(k(3))]));
    expect(Object.keys(out).every((n) => !n.includes('~'))).toBe(true);
  });

  it('B-2: a TRUSTED key becomes primary over an unverified legacy / vault / fetch primary, also after restart', () => {
    for (const src of ['legacy', 'vault', 'fetch'] as const) {
      const r = new ChannelKeyring();
      if (src === 'vault') r.importFromVault({ [`${SA}:5`]: k(1) });
      else r.put(SA, 5, k(1), { source: src });
      expect(trustedPut(r, SA, 5, k(2))).toBe('promoted');
      expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(2)));
      expect(r.entriesAt(SA, 5).map((e) => hex(e.key))).toEqual([hex(k(2)), hex(k(1))]);
      const out = r.exportForVault();
      expect(hex(out[`${SA}:5`]!)).toBe(hex(k(2)));
      const r2 = new ChannelKeyring();
      r2.importFromVault(out);
      expect(r2.bestForSend(SA)).toBeNull();
      // restart: our own key comes back as `vault`; re-verifying our slot's wrap re-puts it as `wrap`
      expect(r2.put(SA, 5, k(2), { source: 'wrap', pair: pairOf(SA, 5, k(2)), verified: true })).toBe('stored');
      expect(hex(r2.bestForSend(SA)!.key)).toBe(hex(k(2)));
    }
  });

  it('B-2: an alternate re-put as an author-verified wrap is promoted; markVerified of an author key promotes too', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:5`]: k(1), [`${SA}:5#alt1`]: k(2) });
    expect(r.markVerified(SA, 5, k(2), pairOf(SA, 5, k(2)))).toBe('needs_author_proof');
    expect(r.put(SA, 5, k(2), { source: 'wrap' })).toBe('stored'); // author-verified, pair not known yet
    expect(r.markVerified(SA, 5, k(2), pairOf(SA, 5, k(1)))).toBe('pair_mismatch');
    expect(r.markVerified(SA, 5, k(3), pairOf(SA, 5, k(3)))).toBe('not_held');
    expect(r.markVerified(SA, 5, k(2), pairOf(SA, 5, k(2)))).toBe('promoted');
    expect(hex(r.keysAt(SA, 5)[0]!)).toBe(hex(k(2)));
    expect(r.latestVerified(SA)!.epoch).toBe(5);
  });

  it('W-a: at the cap an unprotected new key is REFUSED explicitly; a protected one is always kept', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 1, k(1));
    for (let i = 2; i <= 1 + MAX_ALTS_PER_EPOCH; i++) {
      expect(r.put(SA, 1, k(i), { source: 'fetch', pair: pairOf(SA, 1, k(i)) })).toBe('conflict');
    }
    expect(r.put(SA, 1, k(6), { source: 'fetch', pair: pairOf(SA, 1, k(6)) })).toBe('refused');
    expect(r.put(SA, 1, k(20), { source: 'vault' })).toBe('conflict');
    expect(r.keysAt(SA, 1).length).toBe(1 + MAX_ALTS_PER_EPOCH);
    expect(r.keysAt(SA, 1).some((x) => hex(x) === hex(k(20)))).toBe(true);
    expect(r.keysAt(SA, 1).some((x) => hex(x) === hex(k(2)))).toBe(true);
    expect(r.keysAt(SA, 1).some((x) => hex(x) === hex(k(5)))).toBe(false); // newest unprotected yields
    r.exportForVault();
    // node keys stay unprotected even once backed up (B1 r88): still refused / shed first
    expect(r.put(SA, 1, k(21), { source: 'fetch', pair: pairOf(SA, 1, k(21)) })).toBe('refused');
    expect(trustedPut(r, SA, 1, k(22), 999, true)).toBe('promoted');
    expect(r.keysAt(SA, 1).length).toBe(1 + MAX_ALTS_PER_EPOCH);
    for (const n of [1, 20, 22]) expect(r.keysAt(SA, 1).some((x) => hex(x) === hex(k(n)))).toBe(true);
  });

  it('W-a: a flood of node keys never evicts the PRIMARY, even an unprotected one', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'fetch', pair: pairOf(SA, 1, k(1)) });
    for (let i = 2; i <= 12; i++) r.put(SA, 1, k(i), { source: 'fetch', pair: pairOf(SA, 1, k(i)) });
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(1)));
    expect(r.keysAt(SA, 1).length).toBe(1 + MAX_ALTS_PER_EPOCH);
  });

  it('W-b: replacing a provisional primary keeps the provisional key (decrypt) but exports it only once final', () => {
    const r = new ChannelKeyring();
    expect(r.put(SA, 1, k(1), { source: 'establish', provisional: true, pair: pairOf(SA, 1, k(1)) })).toBe('stored');
    expect(r.bestForSend(SA)!.provisional).toBe(true);
    expect(r.exportForVault()).toEqual({});
    expect(trustedPut(r, SA, 1, k(2))).toBe('promoted');
    expect(r.keysAt(SA, 1).map(hex)).toEqual([hex(k(2)), hex(k(1))]);
    expect(values(r.exportForVault())).toEqual(new Set([hex(k(2))]));
    const r2 = new ChannelKeyring();
    r2.put(SA, 1, k(1), { source: 'establish', provisional: true });
    expect(r2.put(SA, 1, k(3), { source: 'fetch', pair: pairOf(SA, 1, k(3)) })).toBe('conflict');
    expect(hex(r2.keysAt(SA, 1)[0]!)).toBe(hex(k(1)));
    // only an EXPLICIT finalisation makes it exportable
    expect(r2.put(SA, 1, k(1), { source: 'establish' })).toBe('stored');
    expect(values(r2.exportForVault()).has(hex(k(1)))).toBe(false);
    expect(r2.put(SA, 1, k(1), { source: 'establish', provisional: false })).toBe('stored');
    expect(values(r2.exportForVault()).has(hex(k(1)))).toBe(true);
  });

  it('M20: a vault key equal to a superseded provisional alternate is re-exported', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'establish', provisional: true });
    trustedPut(r, SA, 1, k(2));
    r.importFromVault({ [`${SA}:1#alt1`]: k(1) });
    expect(values(r.exportForVault())).toEqual(new Set([hex(k(1)), hex(k(2))]));
  });

  it('W1/E: a provisional key keeps its send eligibility through fetch / vault merges of the same bytes', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 1, k(1));
    r.put(SA, 2, k(2), { source: 'establish', provisional: true });
    expect(r.bestForSend(SA)!.epoch).toBe(2);
    r.put(SA, 2, k(2), { source: 'fetch' });
    expect(r.bestForSend(SA)!.epoch).toBe(2);
    r.importFromVault({ [`${SA}:2`]: k(2) });
    expect(r.bestForSend(SA)!.epoch).toBe(2);
    expect(r.entriesAt(SA, 2)[0]!.provisional).toBe(true);
    expect(r.entriesAt(SA, 2)[0]!.exportable).toBe(true); // a vault copy exists: export it (M20)
    // finalised by the node: trusted + final
    expect(r.put(SA, 2, k(2), { source: 'establish', pair: pairOf(SA, 2, k(2)), verified: true, final: true })).toBe('stored');
    expect(r.entriesAt(SA, 2)[0]!.provisional).toBe(false);
    expect(r.latestVerified(SA, { finalOnly: true })!.epoch).toBe(2);
  });
});

describe('W2: untrusted epochs per scope are bounded across sessions', () => {
  it('C: 3000 node-served epochs (fabricated pairs) stop at the cap', () => {
    const r = new ChannelKeyring();
    let refused = 0;
    for (let e = 1; e <= 3000; e++) {
      if (r.put(SA, e, k((e % 250) + 1), { source: 'fetch', pair: { keyTs: 1, commitment: k(7) } }) === 'refused') refused++;
      if (e % 100 === 0) r.exportForVault(); // backups make them persisted
    }
    expect(r.epochs(SA).length).toBeLessThanOrEqual(MAX_UNTRUSTED_EPOCHS_PER_SCOPE);
    expect(refused).toBe(0); // backed-up node epochs stay evictable: the oldest rotate out
    expect(estimateVaultChanBytes(r.exportForVault())).toBeLessThanOrEqual(VAULT_CHAN_SOFT_LIMIT_BYTES / 4);
    // our own keys are never subject to it
    expect(trustedPut(r, SA, 5000, k(1))).toBe('stored');
  });

  it('D: the cap also counts restored (vault) epochs, so a backup cannot grow per session', () => {
    let vault: Record<string, Uint8Array> = {};
    let ep = 1;
    const sizes: number[] = [];
    for (let session = 0; session < 3; session++) {
      const r = new ChannelKeyring({ maxUntrustedEpochsPerScope: 64 });
      r.importFromVault(vault);
      for (let i = 0; i < 100; i++) r.put(SA, ep++, k((ep % 200) + 1), { source: 'legacy' });
      vault = r.exportForVault();
      sizes.push(Object.keys(vault).length);
    }
    expect(sizes).toEqual([64, 64, 64]);
  });

  it('restored history is never evicted; re-verifying the latest own wrap frees it (W-3)', () => {
    const r = new ChannelKeyring({ maxUntrustedEpochsPerScope: 3 });
    r.importFromVault({ [`${SA}:1`]: k(1), [`${SA}:2`]: k(2), [`${SA}:3`]: k(3), [`${SA}:4`]: k(4) });
    expect(r.put(SA, 9, k(9), { source: 'fetch', pair: pairOf(SA, 9, k(9)) })).toBe('refused');
    expect(r.put(SA, 9, k(9), { source: 'legacy' })).toBe('refused');
    expect(r.epochs(SA)).toEqual([1, 2, 3, 4]);
    // re-verifying epoch 4 as our own wrap: everything at or below it stops counting
    r.put(SA, 4, k(4), { source: 'wrap', pair: pairOf(SA, 4, k(4)), verified: true });
    for (const e of [9, 10, 11]) expect(r.put(SA, e, k(e), { source: 'legacy' })).toBe('stored');
    // a node-served epoch BELOW the trusted one never counts
    expect(r.put(SA, 0, k(20), { source: 'fetch', pair: pairOf(SA, 0, k(20)) })).toBe('stored');
    // above it, the oldest unprotected untrusted epoch rotates out
    expect(r.put(SA, 12, k(12), { source: 'legacy' })).toBe('stored');
    expect(r.holds(SA, 9)).toBe(false);
    expect(r.epochs(SA)).toEqual([0, 1, 2, 3, 4, 10, 11, 12]);
    expect(r.put(SB, 1, k(1), { source: 'legacy' })).toBe('stored'); // other scope, own budget
  });

  it('F: 512 restored epochs, then one re-verified own wrap: node-served epochs are accepted again', () => {
    const r = new ChannelKeyring();
    const rec: Record<string, Uint8Array> = {};
    for (let e = 0; e < MAX_UNTRUSTED_EPOCHS_PER_SCOPE; e++) { const b = k(1); b[0] = e & 255; b[1] = e >> 8; rec[`${SA}:${e}`] = b; }
    r.importFromVault(rec);
    expect(r.put(SA, 600, k(5), { source: 'fetch', pair: pairOf(SA, 600, k(5)), verified: true })).toBe('refused');
    const own = k(1); own[0] = 511 & 255; own[1] = 511 >> 8;
    r.put(SA, 511, own, { source: 'wrap', pair: pairOf(SA, 511, own), verified: true });
    expect(r.put(SA, 600, k(5), { source: 'fetch', pair: pairOf(SA, 600, k(5)), verified: true })).toBe('stored');
    expect(r.put(SA, 601, k(6), { source: 'legacy' })).toBe('stored');
  });

  it('the absolute per-scope epoch cap refuses new node-served epochs, never ours', () => {
    const r = new ChannelKeyring({ maxEpochsPerScope: 4 });
    for (const e of [1, 2]) trustedPut(r, SA, e, k(e));
    for (const e of [3, 4]) r.put(SA, e, k(e), { source: 'fetch', pair: pairOf(SA, e, k(e)) });
    expect(r.put(SA, 0, k(9), { source: 'fetch', pair: pairOf(SA, 0, k(9)) })).toBe('refused');
    expect(trustedPut(r, SA, 5, k(5))).toBe('stored');
    r.importFromVault({ [`${SA}:6`]: k(6) });
    expect(r.epochs(SA)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('a hostile legacy key at epoch 100000 is never evidence nor a send key, also after restart', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 4, k(4));
    r.put(SA, 100000, k(9), { source: 'legacy' });
    expect(r.latestVerified(SA)!.epoch).toBe(4);
    expect(r.bestForSend(SA)!.epoch).toBe(4);
    expect(r.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(4);
    expect(r.latest(SA)!.epoch).toBe(100000);
    expect(r.latestBounded(SA, 4 + 256)!.epoch).toBe(4);
    const r2 = new ChannelKeyring();
    r2.importFromVault(r.exportForVault());
    expect(r2.latestVerified(SA)).toBeNull();
    expect(r2.bestForSend(SA)).toBeNull();
    expect(r2.bestForSend(SA, { allowUnverified: true, maxEpoch: 4 + 256 })!.epoch).toBe(4);
    r2.put(SA, 4, k(4), { source: 'wrap', pair: pairOf(SA, 4, k(4)), verified: true });
    expect(r2.latestVerified(SA)!.epoch).toBe(4);
    expect(r2.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(4);
  });
});

describe('web re-audit B1', () => {
  it('a key fetched before the vault restore survives the next backup, and the vault key too', () => {
    const r = new ChannelKeyring();
    r.put(SA, 3, k(1), { source: 'fetch' });
    r.importFromVault({ [`${SA}:3`]: k(2), [`${SA}:2`]: k(3) });
    expect(values(r.exportForVault())).toEqual(new Set([hex(k(1)), hex(k(2)), hex(k(3))]));
  });

  it("readers' keys (older epochs, legacy epochs) are exportable", () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'fetch' });
    r.put(SA, 2, k(2), { source: 'legacy' });
    r.put(SA, 3, k(3), { source: 'wrap', pair: pairOf(SA, 3, k(3)) });
    expect(values(r.exportForVault())).toEqual(new Set([hex(k(1)), hex(k(2)), hex(k(3))]));
  });

  it('a provisional key is held back until final, but the shadowed vault key goes out', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'establish', provisional: true });
    r.importFromVault({ [`${SA}:1`]: k(2) });
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(1)));
    const out = r.exportForVault();
    expect(values(out)).toEqual(new Set([hex(k(2))]));
    expect(hex(out[`${SA}:1`]!)).toBe(hex(k(2)));
  });

  it('W4/F: a node-served key never takes the primary vault name', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:3#alt1`]: k(1) });
    r.put(SA, 3, k(9), { source: 'fetch', pair: pairOf(SA, 3, k(9), 5) });
    const out = r.exportForVault();
    expect(out[`${SA}:3`]).toBeUndefined();
    expect(hex(out[`${SA}:3#alt5`]!)).toBe(hex(k(1)));
    expect(hex(out[`${SA}:3#ns1`]!)).toBe(hex(k(9))); // node-served: its own name class
    const r2 = new ChannelKeyring();
    r2.importFromVault(out);
    expect(hex(r2.keysAt(SA, 3)[0]!)).toBe(hex(k(1)));
    expect(r2.entriesAt(SA, 3).find((x) => hex(x.key) === hex(k(9)))!.nodeServed).toBe(true);
    // a reader's only key (fetched) is backed up as node-served, never as the primary name
    const r3 = new ChannelKeyring();
    r3.put(SA, 1, k(5), { source: 'fetch' });
    expect(Object.keys(r3.exportForVault())).toEqual([`${SA}:1#ns1`]);
  });
});

describe('mobile', () => {
  it('up to 4 alternates per epoch; unknown entries kept and re-exported verbatim', () => {
    const r = new ChannelKeyring();
    const rec: Record<string, Uint8Array> = { [`${SA}:1`]: k(1) };
    for (let i = 1; i <= 4; i++) rec[`${SA}:1#alt${i}`] = k(1 + i);
    rec['future:format/x'] = k(40);
    rec[`${SA}:01`] = k(41);
    rec[`${SA}:1#alt0`] = k(42);
    rec[`${SA}:1#alt1000`] = k(43);
    r.importFromVault(rec);
    expect(r.keysAt(SA, 1).length).toBe(5);
    const out = r.exportForVault();
    expect(values(out)).toEqual(values(rec));
    for (const n of ['future:format/x', `${SA}:01`, `${SA}:1#alt0`, `${SA}:1#alt1000`]) expect(hex(out[n]!)).toBe(hex(rec[n]!));
    expect(Object.keys(out).slice(0, 6)).toEqual([`${SA}:1`, `${SA}:1#pri`, `${SA}:1#alt5`, `${SA}:1#alt6`, `${SA}:1#alt7`, `${SA}:1#alt8`]);
    const again = new ChannelKeyring();
    again.importFromVault(out);
    expect(again.exportForVault()).toEqual(out);
  });

  it('W5: unknown entries beyond the cap REFUSE the backup (never shrink); clear() resets it', () => {
    expect(MAX_OPAQUE_VAULT_ENTRIES).toBe(8192);
    const r = new ChannelKeyring({ maxOpaqueEntries: 3 });
    r.importFromVault({ a: k(1), b: k(2), c: k(3), d: k(4) });
    expect(r.opaqueOverflow).toBe(1);
    let err: unknown;
    try { r.exportForVault(); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(ChannelKeyringError);
    expect((err as ChannelKeyringError).code).toBe('opaque_overflow');
    expect(String((err as Error).message)).not.toMatch(/0404040404/);
    r.clear();
    expect(r.exportForVault()).toEqual({});
    r.importFromVault({ a: k(1), b: k(2) });
    expect(Object.keys(r.exportForVault()).length).toBe(2);
  });

  it('same unknown name with a different value from another vault: all kept (dup chains)', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ X: k(1) });
    r.importFromVault({ X: k(2), 'X#dup1': k(3) });
    r.importFromVault({ 'X#dup1': k(4) });
    r.importFromVault({ X: k(2) });
    expect(values(r.exportForVault()).size).toBe(4);
    expect(Object.keys(r.exportForVault()).length).toBe(4);
  });
});

describe('amendment M-B1 / M-B2', () => {
  it('M-B1: five planted node keys, then the vault restore of the real key: the real key is held and exported', () => {
    const r = new ChannelKeyring();
    for (let i = 1; i <= 5; i++) r.put(SA, 6, k(i), { source: 'fetch', pair: pairOf(SA, 6, k(i)) });
    r.importFromVault({ [`${SA}:6`]: k(50) });
    expect(hex(r.keysAt(SA, 6)[0]!)).toBe(hex(k(50)));
    expect(values(r.exportForVault()).has(hex(k(50)))).toBe(true);
    expect(trustedPut(r, SA, 6, k(51))).toBe('promoted');
  });

  it('M-B1: a full slot of protected keys still takes a trusted / provisional / vault key', () => {
    const r = new ChannelKeyring();
    r.importFromVault(Object.fromEntries([0, 1, 2, 3, 4].map((i) => [i ? `${SA}:6#alt${i}` : `${SA}:6`, k(i + 1)])));
    expect(r.put(SA, 6, k(30), { source: 'establish', provisional: true })).toBe('promoted');
    expect(trustedPut(r, SA, 6, k(31))).toBe('promoted');
    r.importFromVault({ [`${SA}:6#alt3`]: k(32) });
    expect(r.keysAt(SA, 6).length).toBe(8);
    expect(Object.keys(r.exportForVault()).length).toBe(8); // all but the provisional one, + `#pri`
  });

  it('M-B1: an epoch full of backed-up planted keys refuses more node keys but still takes ours', () => {
    const r = new ChannelKeyring();
    for (let i = 1; i <= 8; i++) {
      r.put(SA, 6, k(i), { source: 'fetch', pair: pairOf(SA, 6, k(i)) });
      r.exportForVault();
    }
    expect(r.keysAt(SA, 6).length).toBe(1 + MAX_ALTS_PER_EPOCH);
    expect(r.put(SA, 6, k(7), { source: 'fetch', pair: pairOf(SA, 6, k(7)) })).toBe('refused');
    expect(trustedPut(r, SA, 6, k(18))).toBe('promoted');
    expect(r.put(SA, 6, k(19), { source: 'establish', provisional: true })).toBe('conflict');
    expect(r.put(SA, 6, k(20), { source: 'vault' })).toBe('conflict');
    // backed-up node keys are still node keys: ours displace them under the cap
    expect(r.keysAt(SA, 6).length).toBe(1 + MAX_ALTS_PER_EPOCH);
    for (const n of [18, 19, 20]) expect(r.keysAt(SA, 6).some((x) => hex(x) === hex(k(n)))).toBe(true);
  });

  it('M-B2: a commitment-less node-served key at an occupied epoch is not held; a vault one is', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 2, k(1));
    expect(r.put(SA, 2, k(2), { source: 'legacy' })).toBe('refused');
    expect(r.put(SA, 2, k(3), { source: 'fetch' })).toBe('refused');
    expect(r.put(SA, 2, k(4), { source: 'vault' })).toBe('conflict');
    expect(r.importFromVault({ [`${SA}:2`]: k(5) })).toBe(1);
    expect(r.keysAt(SA, 2).length).toBe(3);
    expect(r.put(SA, 2, k(1), { source: 'legacy' })).toBe('stored');
    expect(r.entriesAt(SA, 2)[0]!.trusted).toBe(true);
    expect(r.entriesAt(SA, 2)[0]!.source).toBe('establish');
  });

  it('M-B2: bestForSend uses PRIMARIES only; an untrusted key never beats a trusted one (I4)', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 2, k(1));
    r.importFromVault({ [`${SA}:3`]: k(2) });
    r.put(SA, 4, k(3), { source: 'fetch', pair: pairOf(SA, 4, k(3)) });
    expect(r.bestForSend(SA)!.epoch).toBe(2);
    expect(r.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(2);
    expect(r.bestForSend(SA, { maxEpoch: 1 })).toBeNull();
    expect(r.bestForSend(SB)).toBeNull();
    const r2 = new ChannelKeyring();
    r2.importFromVault({ [`${SA}:3`]: k(2) });
    expect(r2.bestForSend(SA)).toBeNull();
    expect(r2.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(3);
  });
});

describe('B2: older clients re-exporting a 0.68.0 backup keep every key', () => {
  it('G: more than 4 alternates, some restored out of index order', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:1`]: k(1), [`${SA}:1#alt5`]: k(6) });
    for (let i = 2; i <= 5; i++) r.put(SA, 1, k(i), { source: 'establish' });
    const out = r.exportForVault();
    const names = Object.keys(out);
    expect(names).toEqual([`${SA}:1`, `${SA}:1#pri`, `${SA}:1#alt5`, `${SA}:1#alt6`, `${SA}:1#alt7`, `${SA}:1#alt8`, `${SA}:1#alt9`]);
    for (const [who, re] of oldClientReexports(out)) {
      expect([...values(out)].filter((v) => !values(re).has(v)), who).toEqual([]);
    }
  });

  it('G2: many alternates, gaps, #ovf beyond MAX_ALT_INDEX, an alias-only slot and opaque entries', () => {
    const r = new ChannelKeyring();
    const rec: Record<string, Uint8Array> = { 'zz-opaque': k(200), [`${SA}:2#alt0`]: k(201), [`${SA}:9#alt3`]: k(202), [`${SA}:9#alt7`]: k(203) };
    r.importFromVault(rec);
    r.put(SA, 2, k(1), { source: 'establish' });
    for (let i = 2; i <= MAX_ALT_INDEX + 5; i++) r.put(SA, 2, k(i), { source: 'establish' });
    const out = r.exportForVault();
    // slot 2: primary + MAX_ALT_INDEX + 4 alternates; `#alt5..#alt<MAX>` hold MAX - 4, the rest `#ovf`
    expect(Object.keys(out).filter((n) => n.includes('#ovf')).length).toBe(8);
    expect(Object.keys(out).length).toBe(2 + 2 + 1 + 1 + MAX_ALT_INDEX + 4);
    for (const [who, re] of oldClientReexports(out)) {
      expect([...values(out)].filter((v) => !values(re).has(v)), who).toEqual([]);
      // and the 0.68 keyring reading the old client's re-export loses nothing either
      const back = new ChannelKeyring();
      back.importFromVault(re);
      expect([...values(out)].filter((v) => !values(back.exportForVault()).has(v)), who).toEqual([]);
    }
  });
});

describe('round 3 re-audit', () => {
  it('W-2/D: an OLD client whose own slot is FULL re-exports our backup without losing any of our keys', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 3, k(1));
    r.put(SA, 3, k(2), { source: 'wrap', pair: pairOf(SA, 3, k(2)), verified: true });
    r.put(SA, 3, k(3), { source: 'wrap', pair: pairOf(SA, 3, k(3)), verified: true });
    r.importFromVault({ [`${SA}:3#alt2`]: k(4) }); // an older vault's low alias name
    const ours = r.exportForVault();
    const own = [40, 41, 42, 43, 44];
    const d = new OldDesktop(() => 0, () => {});
    for (const n of own) d.put(SA, 3, k(n), 0, 'verified', { keyTs: 1, keyCommitment: pairOf(SA, 3, k(n), 1).commitment });
    d.importFromVault(ours);
    const m = new OldMobile();
    for (const n of own) m.put(`${SA}:3`, k(n), { state: 'confirmed', verified: true });
    m.importVault(ours);
    const w = new OldWeb(() => {});
    for (const n of own) w.put(`${SA}:3`, { key: k(n), source: 'establish', meta: { keyTs: 1, keyCommitment: k(7) }, confirmed: true });
    w.importFromVault(ours);
    for (const [who, re] of [['desktop', d.exportForVault()], ['mobile', m.exportVault()], ['web', w.exportForVault()]] as const) {
      expect([...values(ours)].filter((v) => !values(re).has(v)), who).toEqual([]);
      // and back into a 0.68 keyring: our keys and the other device's keys are all held
      const back = new ChannelKeyring();
      back.importFromVault(re);
      const held = new Set(back.keysAt(SA, 3).map(hex));
      for (const n of [1, 2, 3, 4, ...own]) expect(held.has(hex(k(n))), `${who} k${n}`).toBe(true);
    }
  });

  it('W-1/exp3: allowUnverified never returns a node key laundered through a backup', () => {
    const r = new ChannelKeyring();
    r.put(SA, 8, k(1), { source: 'wrap', pair: pairOf(SA, 8, k(1)), verified: true, final: true });
    r.put(SA, 9, k(66), { source: 'fetch', pair: pairOf(SA, 9, k(66)), verified: true, final: true });
    expect(r.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(8);
    const out = r.exportForVault();
    expect(out[`${SA}:9`]).toBeUndefined();
    const r2 = new ChannelKeyring();
    r2.importFromVault(out);
    expect(r2.bestForSend(SA)).toBeNull();
    const l = r2.bestForSend(SA, { allowUnverified: true, maxEpoch: 9 + 256 })!;
    expect(l.epoch).toBe(8);
    expect(hex(l.key)).toBe(hex(k(1)));
    // a key a node served in THIS session is never the fallback either, even after a vault copy
    const r3 = new ChannelKeyring();
    r3.put(SA, 5, k(5), { source: 'fetch' });
    r3.importFromVault({ [`${SA}:5`]: k(5) });
    expect(r3.bestForSend(SA, { allowUnverified: true })).toBeNull();
    r3.put(SA, 4, k(4), { source: 'establish' });
    expect(r3.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(4);
  });

  it('W4: a node-served key that merged into `vault` this session never takes the primary name', () => {
    const r = new ChannelKeyring();
    r.put(SA, 4, k(9), { source: 'fetch' });
    r.importFromVault({ [`${SA}:4#alt1`]: k(9) }); // another device backed it up under a low alias
    expect(r.entriesAt(SA, 4)[0]!.source).toBe('vault');
    expect(Object.keys(r.exportForVault())).toEqual([`${SA}:4#ns1`]);
  });

  it('M1: when several keys outrank the primary at once, the EARLIEST seen of the best rank takes over', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'establish', provisional: true });
    expect(r.put(SA, 1, k(2), { source: 'establish', provisional: true })).toBe('conflict');
    expect(r.put(SA, 1, k(3), { source: 'establish', provisional: true })).toBe('conflict');
    // finalising the primary without a pair drops it to rank "own": both others now outrank it
    expect(r.put(SA, 1, k(1), { source: 'establish', provisional: false })).toBe('stored');
    expect(hex(r.keysAt(SA, 1)[0]!)).toBe(hex(k(2)));
  });

  it('W-4/M24: a fetch or vault copy never finalises a provisional key, even claiming final', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'establish', provisional: true });
    expect(r.put(SA, 1, k(1), { source: 'fetch', pair: pairOf(SA, 1, k(1), 5), verified: true, final: true })).toBe('stored');
    expect(r.entriesAt(SA, 1)[0]!.provisional).toBe(true);
    r.importFromVault({ [`${SA}:1`]: k(1) });
    expect(r.entriesAt(SA, 1)[0]!.provisional).toBe(true);
    expect(r.put(SA, 1, k(1), { source: 'vault', provisional: false })).toBe('stored');
    expect(r.entriesAt(SA, 1)[0]!.provisional).toBe(true);
    // an author source finalises: explicitly, or verified + final
    expect(r.put(SA, 1, k(1), { source: 'wrap', pair: pairOf(SA, 1, k(1), 5), verified: true, final: true })).toBe('stored');
    expect(r.entriesAt(SA, 1)[0]!.provisional).toBe(false);
    expect(r.entriesAt(SA, 1)[0]!.trusted).toBe(true);
  });

  it('N-2 residual: a malicious member key the node calls final outranks our non-final key; two finals keep the first seen', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 2, k(1), 100);
    expect(r.put(SA, 2, k(66), { source: 'wrap', pair: pairOf(SA, 2, k(66), 999999), verified: true, final: true })).toBe('promoted');
    expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(66)));
    expect(r.markVerified(SA, 2, k(1), pairOf(SA, 2, k(1), 100), { final: true })).toBe('verified');
    expect(hex(r.bestForSend(SA)!.key)).toBe(hex(k(66)));
    expect(r.keysAt(SA, 2).length).toBe(2); // ours is still held and decrypts
  });

  it('epochs up to Number.MAX_SAFE_INTEGER round-trip; beyond is opaque', () => {
    const r = new ChannelKeyring();
    const E = Number.MAX_SAFE_INTEGER;
    expect(trustedPut(r, SA, E, k(1))).toBe('stored');
    r.importFromVault({ [`${SA}:9007199254740993`]: k(2) });
    const out = r.exportForVault();
    expect(hex(out[`${SA}:${E}`]!)).toBe(hex(k(1)));
    expect(hex(out[`${SA}:9007199254740993`]!)).toBe(hex(k(2)));
    const r2 = new ChannelKeyring();
    r2.importFromVault(out);
    expect(r2.exportForVault()).toEqual(out);
    expect(r2.epochs(SA)).toEqual([E]);
  });
});

describe('round 4 (r85): vault size is bounded', () => {
  const kk = (a: number, b = 0): Uint8Array => { const x = new Uint8Array(32); x[0] = a & 255; x[1] = (a >> 8) & 255; x[2] = (a >> 16) & 255; x[3] = b; x[31] = 7; return x; };
  const sealedBytes = (chan: Record<string, Uint8Array>) => sealKeyVault(new Uint8Array(32).fill(1), { conv: {}, chan }).encrypted_vault.length;

  it('P2: a node flooding history below the trusted epoch is held to the session budget; the vault stays small', () => {
    const r = new ChannelKeyring();
    const own = kk(999999);
    r.put(SA, 5000, own, { source: 'wrap', pair: pairOf(SA, 5000, own, 1), verified: true, final: true });
    for (let e = 0; e < 4200; e++) for (let j = 0; j < 5; j++) {
      r.put(SA, e, kk(e, j + 1), { source: 'fetch', pair: { keyTs: 1, commitment: new Uint8Array(32).fill(j + 1) } });
    }
    expect(r.epochs(SA).length).toBe(MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE + 1);
    const out = r.exportForVault();
    expect(sealedBytes(out)).toBeLessThan(VAULT_CHAN_SOFT_LIMIT_BYTES);
    // after that backup the burst budget still holds: the oldest node epoch rotates out
    expect(r.put(SA, 4300, kk(4300), { source: 'fetch', pair: pairOf(SA, 4300, kk(4300)) })).toBe('stored');
    expect(r.epochs(SA).length).toBe(MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE + 1);
    // a new session restores them (exempt below the trusted epoch) and takes another bounded batch
    const r2 = new ChannelKeyring();
    r2.importFromVault(out);
    r2.put(SA, 5000, own, { source: 'wrap', pair: pairOf(SA, 5000, own, 1), verified: true, final: true });
    expect(r2.put(SA, 4300, kk(4300), { source: 'fetch', pair: pairOf(SA, 4300, kk(4300)) })).toBe('stored');
    // our own key above it is unaffected
    expect(r.put(SA, 5001, kk(5001), { source: 'wrap', pair: pairOf(SA, 5001, kk(5001)), verified: true })).toBe('stored');
  });

  it('P2b: 8 scopes with no trusted key — the export stays under the budget, shedding only unprotected node keys', () => {
    const r = new ChannelKeyring();
    const ours: string[] = [];
    for (let c = 0; c < 8; c++) {
      const sc = (c + 1).toString(16).padStart(2, '0').repeat(32);
      r.importFromVault({ [`${sc}:0`]: kk(900000 + c) }); // a restored key per scope: protected
      ours.push(hex(kk(900000 + c)));
      for (let e = 1; e <= MAX_UNTRUSTED_EPOCHS_PER_SCOPE; e++) for (let j = 0; j < 5; j++) {
        r.put(sc, e, kk(e + c * 10000, j + 1), { source: 'fetch', pair: { keyTs: 1, commitment: new Uint8Array(32).fill(j + 1) } });
      }
    }
    const out = r.exportForVault();
    expect(estimateVaultChanBytes(out)).toBeLessThanOrEqual(VAULT_CHAN_SOFT_LIMIT_BYTES);
    expect(sealedBytes(out)).toBeLessThan(2_097_152);
    for (const v of ours) expect(values(out).has(v)).toBe(true);
    const nodeOnly = Object.fromEntries(Object.entries(out).filter(([n]) => n.includes('#ns')));
    expect(Object.keys(nodeOnly).length).toBeGreaterThan(0);
    expect(estimateVaultChanBytes(nodeOnly)).toBeLessThanOrEqual(VAULT_CHAN_SOFT_LIMIT_BYTES / 4); // node share
    expect(Object.keys(out).filter((n) => n.endsWith('#pri')).length).toBe(8); // still within half the budget
    // left-out keys are still held this session and were NOT marked persisted
    const e1 = r.entriesAt('01'.repeat(32), MAX_UNTRUSTED_EPOCHS_PER_SCOPE);
    expect(e1.length).toBeGreaterThan(0);
    const exported = values(out);
    for (const x of e1) if (!exported.has(hex(x.key))) expect(x.persisted).toBe(false);
  });

  it('protected keys over the budget: the export throws vault_too_large (never sheds them)', () => {
    const r = new ChannelKeyring({ maxVaultBytes: 2000 });
    const rec: Record<string, Uint8Array> = {};
    for (let e = 0; e < 40; e++) rec[`${SA}:${e}`] = kk(e);
    r.importFromVault(rec);
    let code = '';
    try { r.exportForVault(); } catch (e) { code = (e as ChannelKeyringError).code; }
    expect(code).toBe('vault_too_large');
    expect(r.entriesAt(SA, 0)[0]!.persisted).toBe(true); // restored: still protected
    const r2 = new ChannelKeyring({ maxVaultBytes: 2000 });
    for (let e = 0; e < 40; e++) r2.put(SA, e, kk(e), { source: 'fetch', pair: pairOf(SA, e, kk(e)) });
    const out = r2.exportForVault();
    expect(estimateVaultChanBytes(out)).toBeLessThanOrEqual(2000);
    expect(r2.epochs(SA).length).toBe(40);
  });

  it('`#pri` copies only for each scope\'s highest epochs', () => {
    const r = new ChannelKeyring();
    for (let e = 1; e <= 40; e++) trustedPut(r, SA, e, kk(e));
    const pri = Object.keys(r.exportForVault()).filter((n) => n.endsWith('#pri'));
    expect(pri.length).toBe(PRI_COPIES_PER_SCOPE);
    expect(pri).toContain(`${SA}:40#pri`);
    expect(pri).not.toContain(`${SA}:1#pri`);
  });

  it('P1: a legacy-served key re-put by an author source can be the allowUnverified send key in the same session', () => {
    const r = new ChannelKeyring();
    expect(r.put(SA, 3, k(1), { source: 'legacy' })).toBe('stored');
    expect(r.put(SA, 3, k(1), { source: 'wrap' })).toBe('stored');
    expect(r.bestForSend(SA, { allowUnverified: true })!.epoch).toBe(3);
  });

  it('N18: a `#pri` import matching an alias-restored key does not clear its alias origin', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:4#alt5`]: k(9) });
    r.importFromVault({ [`${SA}:4#pri`]: k(9) });
    expect(r.bestForSend(SA, { allowUnverified: true })).toBeNull();
    expect(Object.keys(r.exportForVault())).toEqual([`${SA}:4#alt5`]);
  });
});

describe('round 5 (r88): node junk can never strand the backup', () => {
  const sc = (c: number) => (c + 1).toString(16).padStart(4, '0').repeat(16);
  const kk = (a: number, b = 0, c = 0): Uint8Array => { const x = new Uint8Array(32); x[0] = a & 255; x[1] = (a >> 8) & 255; x[2] = (a >> 16) & 255; x[3] = b; x[4] = c; x[31] = 7; return x; };
  const fake = (j: number) => ({ keyTs: 1, commitment: new Uint8Array(32).fill(j + 1) });
  const nodeBytes = (out: Record<string, Uint8Array>) => estimateVaultChanBytes(Object.fromEntries(Object.entries(out).filter(([n]) => n.includes('#ns'))));
  const own = (r: ChannelKeyring, S: string, e: number, key: Uint8Array, final = true) =>
    r.put(S, e, key, { source: 'wrap', pair: pairOf(S, e, key, 1), verified: true, final });

  it('A: a one-session junk fill across 10 scopes, then genuine growth over many restarts never throws', () => {
    const r = new ChannelKeyring();
    for (let c = 0; c < 10; c++) {
      const S = sc(c);
      own(r, S, 1000, kk(1000, 0, c));
      for (let e = 1001; e < 1601; e++) for (let j = 0; j < 5; j++) r.put(S, e, kk(e, j + 1, c), { source: 'fetch', pair: fake(j) });
      for (let e = 0; e < 200; e++) for (let j = 0; j < 5; j++) r.put(S, e, kk(e, j + 1, c), { source: 'fetch', pair: fake(j) });
    }
    let cur = r.exportForVault();
    expect(nodeBytes(cur)).toBeLessThanOrEqual(VAULT_CHAN_SOFT_LIMIT_BYTES * NODE_SERVED_VAULT_SHARE);
    for (let round = 0; round < 8; round++) {
      const r2 = new ChannelKeyring();
      r2.importFromVault(cur);
      for (let c = 0; c < 10; c++) for (let k2 = 0; k2 < 10; k2++) {
        const e = 2000 + round * 10 + k2;
        own(r2, sc(c), e, kk(e, 200, c));
      }
      cur = r2.exportForVault(); // never vault_too_large: node keys yield
      expect(nodeBytes(cur)).toBeLessThanOrEqual(VAULT_CHAN_SOFT_LIMIT_BYTES * NODE_SERVED_VAULT_SHARE);
    }
    const restored = new ChannelKeyring();
    restored.importFromVault(cur);
    for (let c = 0; c < 10; c++) for (let e = 2000; e < 2080; e++) expect(restored.holds(sc(c), e)).toBe(true);
  });

  it('B: hundreds of sessions of below-floor history never strand the backup', () => {
    const S = sc(50);
    let cur: Record<string, Uint8Array> = {};
    for (let sess = 0; sess < 120; sess++) {
      const r = new ChannelKeyring({ maxVaultBytes: 60_000 });
      r.importFromVault(cur);
      own(r, S, 100000, kk(100000, 9, sess & 255), true);
      for (let i = 0; i < 200; i++) { const e = sess * 200 + i; for (let j = 0; j < 5; j++) r.put(S, e, kk(e, j + 1), { source: 'fetch', pair: fake(j) }); }
      cur = r.exportForVault();
      expect(nodeBytes(cur)).toBeLessThanOrEqual(60_000 * NODE_SERVED_VAULT_SHARE);
    }
  });

  it('D: backed-up node keys are not protected; our later growth still backs up', () => {
    const S = sc(90);
    const r = new ChannelKeyring({ maxVaultBytes: 20000 });
    own(r, S, 10, kk(10, 9), false);
    for (let e = 11; e < 400; e++) r.put(S, e, kk(e, 1), { source: 'fetch', pair: fake(0) });
    const a = r.exportForVault();
    expect(JSON.stringify(Object.keys(r.exportForVault()))).toBe(JSON.stringify(Object.keys(a)));
    for (let e = 500; e < 530; e++) r.put(S, e, kk(e, 9), { source: 'establish', pair: pairOf(S, e, kk(e, 9)), verified: true });
    const c = r.exportForVault();
    for (let e = 500; e < 530; e++) expect(values(c).has(hex(kk(e, 9)))).toBe(true);
    expect(values(c).has(hex(kk(10, 9)))).toBe(true);
  });

  it('shed order: new node keys newest-first; backed-up node history oldest epoch first', () => {
    const S = sc(3);
    const per = estimateVaultChanBytes({ [`${S}:100#ns1`]: k(1) }) - 5;
    const r = new ChannelKeyring({ maxVaultBytes: 4 * (5 + 3 * per) }); // room for exactly 3 node keys
    for (const e of [100, 101, 102, 103, 104]) r.put(S, e, kk(e, 1), { source: 'fetch', pair: fake(0) });
    const out = r.exportForVault();
    expect(Object.keys(out)).toEqual([`${S}:100#ns1`, `${S}:101#ns1`, `${S}:102#ns1`]); // 103, 104 (newest) left out
    // restored: it is history now — under pressure the OLDEST epoch goes first
    const r2 = new ChannelKeyring({ maxVaultBytes: 4 * (5 + 2 * per) });
    r2.importFromVault(out);
    expect(Object.keys(r2.exportForVault())).toEqual([`${S}:101#ns1`, `${S}:102#ns1`]);
  });

  it(`#pri copies stop at MAX_PRI_COPIES (${MAX_PRI_COPIES}) in total`, () => {
    const r = new ChannelKeyring();
    for (let c = 0; c < 40; c++) for (let e = 1; e <= 16; e++) trustedPut(r, sc(c), e, kk(e, 0, c));
    expect(Object.keys(r.exportForVault()).filter((n) => n.endsWith('#pri')).length).toBe(MAX_PRI_COPIES);
  });

  it('W1: at the junk boundary the #pri copies stay, so an old client with full slots loses none of our 11 keys', () => {
    const r = new ChannelKeyring();
    for (let c = 0; c < 10; c++) {
      const S = sc(c);
      for (let e = 990; e <= 1000; e++) own(r, S, e, kk(e, 0, c), e === 1000);
      for (let e = 1001; e < 1601; e++) for (let j = 0; j < 5; j++) r.put(S, e, kk(e, j + 1, c), { source: 'fetch', pair: fake(j) });
    }
    const ex = r.exportForVault();
    const S0 = sc(0);
    const seed: Record<string, Uint8Array> = {};
    for (let e = 990; e <= 1000; e++) { seed[`${S0}:${e}`] = kk(e, 100); for (let j = 1; j <= 4; j++) seed[`${S0}:${e}#alt${j}`] = kk(e, 100 + j); }
    const d = new OldDesktop(() => 0, () => {});
    d.importFromVault(seed);
    d.importFromVault(ex);
    const m = new OldMobile();
    m.importVault(seed);
    m.importVault(ex);
    for (const back of [d.exportForVault(), m.exportVault()]) {
      const bv = values(back);
      for (let e = 990; e <= 1000; e++) expect(bv.has(hex(kk(e, 0, 0)))).toBe(true);
      // W2: re-importing the old client's near-budget vault never throws
      const r2 = new ChannelKeyring();
      r2.importFromVault(back);
      expect(() => r2.exportForVault()).not.toThrow();
    }
  });

  it('`#ns` names survive old clients verbatim', () => {
    const r = new ChannelKeyring();
    r.put(SA, 7, k(9), { source: 'fetch', pair: pairOf(SA, 7, k(9)) });
    trustedPut(r, SA, 8, k(1));
    const ex = r.exportForVault();
    for (const [who, back] of oldClientReexports(ex)) expect(hex(back[`${SA}:7#ns1`]!), who).toBe(hex(k(9)));
  });

  it('a node key re-put by an author source becomes protected and leaves the #ns class', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:7#ns1`]: k(9) });
    expect(r.entriesAt(SA, 7)[0]!.nodeServed).toBe(true);
    r.put(SA, 7, k(9), { source: 'wrap', pair: pairOf(SA, 7, k(9)), verified: true });
    expect(r.entriesAt(SA, 7)[0]!.nodeServed).toBe(false);
    expect(Object.keys(r.exportForVault())).toEqual([`${SA}:7`, `${SA}:7#pri`]);
  });

  it('pruneUnverified: the zero-risk default removes only node-served keys; other classes on request; scopes filter', () => {
    const r = new ChannelKeyring();
    const rec: Record<string, Uint8Array> = {};
    for (let e = 1; e <= 30; e++) rec[`${SA}:${e}`] = kk(e);
    rec[`${SA}:5#ns1`] = kk(5, 1);
    rec[`${SA}:6#alt5`] = kk(6, 2);
    rec[`${SA}:7~1`] = kk(7, 3);
    rec[`${SB}:1#ns1`] = kk(1, 9);
    r.importFromVault(rec);
    r.put(SA, 8, kk(8, 4), { source: 'fetch', pair: pairOf(SA, 8, kk(8, 4)) });
    trustedPut(r, SA, 3, kk(3, 7));
    r.put(SA, 4, kk(4, 7), { source: 'establish', provisional: true });
    r.put(SA, 9, kk(9, 7), { source: 'vault' }); // client-put, never backed up: kept
    r.put(SA, 10, kk(10, 8), { source: 'wrap', pair: pairOf(SA, 10, kk(10, 8)), verified: true }); // a member's wrap
    r.put(SA, 11, kk(11, 8), { source: 'wrap', pair: pairOf(SA, 11, kk(11, 8)), verified: true, ownSlot: true }); // ours
    const dry = r.pruneUnverified({ keepLatestPerScope: 10, dryRun: true, scopes: [SA] });
    expect(dry.byClass.nodeServed.count).toBe(2);
    expect(dry.removedCount).toBe(2);
    expect(dry.byClass.restoredAlternates.count + dry.byClass.memberWraps.count + dry.byClass.restoredPrimaries.count).toBe(0);
    expect(r.pruneUnverified({ keepLatestPerScope: 10, scopes: [SA] })).toEqual(dry);
    expect(r.keysAt(SB, 1).length).toBe(1); // other scope untouched
    const alt = r.pruneUnverified({ keepLatestPerScope: 10, classes: ['restoredAlternates', 'memberWraps'], dryRun: true });
    expect(alt.byClass.restoredAlternates.count).toBe(2);
    expect(alt.byClass.ownAlternatesAtRisk.count).toBe(2); // may be the user's own outranked keys
    expect(alt.byClass.memberWraps.count).toBe(1);
    for (let e = 1; e <= 30; e++) expect(r.keysAt(SA, e).some((x) => hex(x) === hex(kk(e)))).toBe(true);
    const last = r.pruneUnverified({ keepLatestPerScope: 10, includeRestoredPrimaries: true });
    expect(last.byClass.restoredPrimaries.count).toBe(20);
    for (const [e, n] of [[3, 7], [4, 7], [9, 7], [11, 8]] as const) expect(r.keysAt(SA, e).some((x) => hex(x) === hex(kk(e, n)))).toBe(true);
    let g = 1;
    const r3 = new ChannelKeyring({ generation: () => g });
    g = 2;
    expect(() => r3.pruneUnverified({ generation: 1 })).toThrow(ChannelKeyringError);
  });

  it('A2: pruned keys are not re-imported from the remote vault, so the next backup drops them; clear() forgets', () => {
    const r = new ChannelKeyring();
    const rec: Record<string, Uint8Array> = {};
    for (let e = 1; e <= 20; e++) { rec[`${SA}:${e}`] = kk(e); rec[`${SA}:${e}#ns1`] = kk(e, 1); }
    r.importFromVault(rec);
    expect(r.pruneUnverified({ keepLatestPerScope: 4 }).removedCount).toBe(16);
    expect(r.importFromVault(rec)).toBe(0); // refresh before seal: nothing comes back
    const out = r.exportForVault();
    for (let e = 1; e <= 16; e++) expect(values(out).has(hex(kk(e, 1)))).toBe(false);
    for (let e = 1; e <= 20; e++) expect(values(out).has(hex(kk(e)))).toBe(true);
    r.clear();
    expect(r.importFromVault(rec)).toBe(40);
  });

  it('A1: prepareExport is side-effect free; commitExport marks persisted; stale tokens are refused', () => {
    const r = new ChannelKeyring();
    r.put(SA, 1, k(1), { source: 'establish', provisional: true });
    r.importFromVault({ [`${SA}:1`]: k(2) });
    r.put(SA, 2, k(3), { source: 'wrap' });
    const p = r.prepareExport();
    expect(Object.keys(p.chan)).toEqual([`${SA}:1`, `${SA}:1#pri`, `${SA}:2`, `${SA}:2#pri`]);
    expect(r.entriesAt(SA, 2)[0]!.persisted).toBe(false); // publish failed: nothing changed
    expect(r.prepareExport().chan).toEqual(p.chan);
    expect(r.commitExport(p.commitToken)).toBe(2);
    expect(r.entriesAt(SA, 2)[0]!.persisted).toBe(true);
    expect(() => r.commitExport(p.commitToken)).toThrow(ChannelKeyringError); // single use
    const q = r.prepareExport();
    r.clear();
    expect(() => r.commitExport(q.commitToken)).toThrow(ChannelKeyringError);
    const other = new ChannelKeyring();
    expect(() => other.commitExport(r.prepareExport().commitToken)).toThrow(ChannelKeyringError);
  });

  it('A4/W2: bestForSendLegacy only when the scope holds nothing but commitment-less node keys of this session', () => {
    const r = new ChannelKeyring();
    r.put(SA, 3, k(3), { source: 'legacy' });
    r.put(SA, 4, k(4), { source: 'legacy' });
    const isLegacy = (e: number) => e <= 4;
    expect(r.bestForSend(SA, { allowUnverified: true })).toBeNull();
    expect(r.bestForSendLegacy(SA, { isLegacyEpoch: isLegacy })!.epoch).toBe(4);
    expect(r.bestForSendLegacy(SA, { isLegacyEpoch: () => false })).toBeNull();
    expect(r.bestForSendLegacy(SA, { isLegacyEpoch: isLegacy, maxEpoch: 3 })!.epoch).toBe(3);
    expect(r.bestForSendLegacy(SA, {} as never)).toBeNull();
    const variants: Array<[string, (x: ChannelKeyring) => void]> = [
      ['restart in an arbitrated channel (restored keys)', (x) => { x.importFromVault({ [`${SA}:10`]: k(10) }); }],
      ['own provisional key', (x) => { x.put(SA, 11, k(11), { source: 'establish', provisional: true }); }],
      ['trusted key at a lower epoch', (x) => { trustedPut(x, SA, 1, k(1)); }],
      ['author wrap without a verified pair', (x) => { x.put(SA, 11, k(11), { source: 'wrap', pair: pairOf(SA, 11, k(11)) }); }],
      ['a node key carrying a commitment', (x) => { x.put(SA, 5, k(5), { source: 'fetch', pair: pairOf(SA, 5, k(5)) }); }],
      ['a restored primary-name key at a legacy epoch', (x) => { x.importFromVault({ [`${SA}:2`]: k(2) }); }],
      ['a restored key re-served by the node', (x) => { x.importFromVault({ [`${SA}:7`]: k(7) }); x.put(SA, 7, k(7), { source: 'legacy' }); }],
    ];
    for (const [why, add] of variants) {
      const x = new ChannelKeyring();
      x.put(SA, 3, k(3), { source: 'legacy' });
      x.put(SA, 900, k(66), { source: 'legacy' });
      add(x);
      expect(x.bestForSendLegacy(SA, { isLegacyEpoch: () => true }), why).toBeNull();
    }
    const r2 = new ChannelKeyring();
    r2.importFromVault(r.exportForVault()); // restored from `#ns`
    expect(r2.bestForSendLegacy(SA, { isLegacyEpoch: isLegacy })).toBeNull();
  });

  it('node-served keys are kept in strict priority: the first that does not fit stops the fill', () => {
    const long = estimateVaultChanBytes({ [`${SA}:7#ns1`]: k(1) }) - 5;
    const r = new ChannelKeyring({ maxVaultBytes: 4 * (5 + long - 1) }); // the long name does not fit, a short one would
    r.put(SA, 7, k(1), { source: 'fetch', pair: pairOf(SA, 7, k(1)) }); // earlier: kept first
    r.put('S', 7, k(2), { source: 'fetch', pair: { keyTs: 1, commitment: k(9) } });
    expect(Object.keys(r.exportForVault())).toEqual([]);
  });

  it('A5: opaqueCount and heldEpochCount', () => {
    const r = new ChannelKeyring();
    expect(r.opaqueCount + r.heldEpochCount).toBe(0);
    r.importFromVault({ odd: k(1), [`${SA}:1`]: k(2), [`${SA}:2`]: k(3) });
    expect(r.opaqueCount).toBe(1);
    expect(r.heldEpochCount).toBe(2);
    expect(r.heldEpochCount).toBe(r.size);
  });

  it('B1/P3: a member flood never evicts our keys — restored, re-verified (ownSlot), established or plain wraps', () => {
    const own: Array<[number, Uint8Array]> = [];
    for (let e = 10; e < 20; e++) own.push([e, kk(e, 7, 2)]);
    for (const variant of ['restored', 'ownSlot', 'establish', 'plain-wrap'] as const) {
      const r = new ChannelKeyring({ maxMemberEpochsPerScope: 8 });
      for (const [e, key] of own) {
        if (variant === 'establish') r.put(SA, e, key, { source: 'establish', pair: pairOf(SA, e, key), verified: true });
        else {
          r.importFromVault({ [`${SA}:${e}`]: key });
          if (variant !== 'restored') r.put(SA, e, key, { source: 'wrap', pair: pairOf(SA, e, key), verified: true, ownSlot: variant === 'ownSlot' });
        }
      }
      let refused = 0;
      for (let e = 100; e < 700; e++) if (r.put(SA, e, kk(e, 9, 2), { source: 'wrap', pair: pairOf(SA, e, kk(e, 9, 2)), verified: true }) === 'refused') refused++;
      for (const [e, key] of own) expect(r.keysAt(SA, e).some((x) => hex(x) === hex(key)), `${variant} ${e}`).toBe(true);
      expect(refused).toBeGreaterThan(0);
      // our own keys are never refused
      expect(r.put(SA, 800, kk(800), { source: 'wrap', pair: pairOf(SA, 800, kk(800)), verified: true, ownSlot: true })).toBe('stored');
      expect(r.put(SA, 801, kk(801), { source: 'establish', pair: pairOf(SA, 801, kk(801)), verified: true })).toBe('stored');
      expect(r.entriesAt(SA, 800)[0]!.own).toBe(true);
    }
  });

  it('W1: member wraps — alternates per epoch capped; below the final epoch a session budget; across restarts bounded', () => {
    const r = new ChannelKeyring();
    trustedPut(r, SA, 50, k(1), 1000, true);
    let held = 0;
    for (let j = 0; j < 200; j++) if (r.put(SA, 50, kk(50, j + 1), { source: 'wrap', pair: pairOf(SA, 50, kk(50, j + 1)), verified: true }) !== 'refused') held++;
    expect(held).toBe(MAX_ALTS_PER_EPOCH);
    trustedPut(r, SA, 500, k(2), 1000, true); // final epoch 500: member epochs below it get a session budget
    let below = 0;
    for (let e = 100; e < 300; e++) if (r.put(SA, e, kk(e, 3), { source: 'wrap', pair: pairOf(SA, e, kk(e, 3)), verified: true }) !== 'refused') below++;
    expect(below).toBe(MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE);
    // a new session (restored keys do not count below the final epoch) takes another bounded batch
    const r9 = new ChannelKeyring();
    r9.importFromVault(r.exportForVault());
    r9.put(SA, 500, k(2), { source: 'wrap', pair: pairOf(SA, 500, k(2), 1000), verified: true, final: true, ownSlot: true });
    let next = 0;
    for (let e = 300; e < 400; e++) if (r9.put(SA, e, kk(e, 3), { source: 'wrap', pair: pairOf(SA, e, kk(e, 3)), verified: true }) !== 'refused') next++;
    expect(next).toBe(MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE);
    // p95b: a member flooding above our final epoch in every session cannot grow the vault past the cap
    let cur: Record<string, Uint8Array> = {};
    for (let sess = 0; sess < 6; sess++) {
      const x = new ChannelKeyring({ maxMemberEpochsPerScope: 100 });
      x.importFromVault(cur);
      x.put(SA, 5, k(5), { source: 'wrap', pair: pairOf(SA, 5, k(5)), verified: true, final: true, ownSlot: true });
      for (let e = 0; e < 300; e++) { const ep = 10 + sess * 300 + e; x.put(SA, ep, kk(ep, 3), { source: 'wrap', pair: pairOf(SA, ep, kk(ep, 3)), verified: true }); }
      cur = x.exportForVault();
      expect(x.epochs(SA).length).toBeLessThanOrEqual(1 + 100);
    }
  });
});

describe('round 7 (r98): a member flood can never lock the channel', () => {
  const kk = (a: number, b = 0): Uint8Array => { const x = new Uint8Array(32); x[0] = a & 255; x[1] = (a >> 8) & 255; x[2] = (a >> 16) & 255; x[3] = b; x[31] = 9; return x; };
  const wrap = (r: ChannelKeyring, e: number, key: Uint8Array, o: { final?: boolean; ownSlot?: boolean; maxEpoch?: number } = {}) =>
    r.put(SA, e, key, { source: 'wrap', pair: pairOf(SA, e, key), verified: true, ...o });
  const has = (r: ChannelKeyring, e: number, key: Uint8Array) => r.keysAt(SA, e).some((x) => hex(x) === hex(key));

  it('C: after a flood at huge epochs a FINAL member wrap is still accepted, also after a restart; the flood prunes as memberWraps only', () => {
    const r = new ChannelKeyring({ maxMemberEpochsPerScope: 50 });
    expect(wrap(r, 10, kk(10), { final: true, ownSlot: true })).toBe('stored');
    let refused = 0;
    for (let i = 0; i < 80; i++) if (wrap(r, 1_000_000 + i, kk(i, 1)) === 'refused') refused++;
    expect(refused).toBe(30); // the member cap is full
    expect(wrap(r, 11, kk(11, 2), { final: true })).toBe('stored'); // the node's final winner: exempt
    expect(wrap(r, 12, kk(12, 2))).toBe('refused'); // a non-final member wrap: capped (residual)
    expect(r.put(SA, 13, kk(13, 3), { source: 'establish', pair: pairOf(SA, 13, kk(13, 3)), verified: true })).toBe('stored');
    expect(r.put(SA, 14, kk(14, 3), { source: 'establish', provisional: true })).toBe('stored');
    expect(wrap(r, 15, kk(15, 3), { ownSlot: true })).toBe('stored');
    expect(has(r, 10, kk(10))).toBe(true);
    // restart: the flood comes back as vault keys; re-verify our latest own epoch first
    const v = r.exportForVault();
    const r2 = new ChannelKeyring({ maxMemberEpochsPerScope: 50 });
    r2.importFromVault(v, undefined, { maxEpoch: 15 + 256 });
    expect(wrap(r2, 15, kk(15, 3), { ownSlot: true })).toBe('stored');
    expect(wrap(r2, 20, kk(20, 2), { final: true })).toBe('stored');
    // the restored flood (above the ceiling) is prunable as memberWraps — nothing below it is touched
    const before = r2.epochs(SA).filter((e) => e < 1_000_000);
    const dry = r2.pruneUnverified({ dryRun: true, classes: ['memberWraps'], keepLatestPerScope: 0 });
    expect(dry.byClass.memberWraps.count).toBe(50);
    expect(dry.removedCount).toBe(50);
    r2.pruneUnverified({ classes: ['memberWraps'], keepLatestPerScope: 0 });
    expect(r2.epochs(SA)).toEqual(before);
    for (const [e, key] of [[10, kk(10)], [11, kk(11, 2)], [13, kk(13, 3)], [15, kk(15, 3)], [20, kk(20, 2)]] as const) expect(has(r2, e, key)).toBe(true);
    expect(r2.pruneUnverified({ dryRun: true, keepLatestPerScope: 0 }).removedCount).toBe(0); // default: node keys only
    expect(wrap(r2, 21, kk(21, 2))).toBe('stored'); // member cap free again
  });

  it('C with maxEpoch: the flood is refused at put time, ours never', () => {
    const r = new ChannelKeyring({ maxMemberEpochsPerScope: 50 });
    const max = 10 + 256;
    wrap(r, 10, kk(10), { final: true, ownSlot: true, maxEpoch: max });
    let refused = 0;
    for (let i = 0; i < 80; i++) if (wrap(r, 1_000_000 + i, kk(i, 1), { maxEpoch: max }) === 'refused') refused++;
    expect(refused).toBe(80);
    expect(wrap(r, 1_000_001, kk(1, 7), { final: true, maxEpoch: max })).toBe('refused'); // final but beyond the ceiling
    expect(r.put(SA, 1_000_002, kk(2, 7), { source: 'fetch', pair: pairOf(SA, 1_000_002, kk(2, 7)), maxEpoch: max })).toBe('refused');
    expect(wrap(r, 1_000_003, kk(3, 7), { ownSlot: true, maxEpoch: max })).toBe('stored'); // ours: never
    expect(r.put(SA, 1_000_004, kk(4, 7), { source: 'establish', maxEpoch: max })).toBe('stored');
    expect(wrap(r, 12, kk(12, 2), { maxEpoch: max })).toBe('stored');
  });

  it('N2: own (ownSlot) epochs do not count toward the member cap', () => {
    const r = new ChannelKeyring({ maxMemberEpochsPerScope: 20 });
    for (let e = 1; e <= 40; e++) expect(wrap(r, e, kk(e), { ownSlot: true })).toBe('stored');
    expect(wrap(r, 100, kk(100, 2))).toBe('stored');
  });

  it('W2: an own wrap put WITHOUT ownSlot is treated as a member wrap (the documented failure mode)', () => {
    const r = new ChannelKeyring({ maxMemberEpochsPerScope: 2 });
    wrap(r, 1, kk(1, 5));
    wrap(r, 2, kk(2, 5));
    expect(wrap(r, 3, kk(3))).toBe('refused'); // our key, forgotten ownSlot: refused once the cap is full
    expect(wrap(r, 3, kk(3), { ownSlot: true })).toBe('stored'); // re-put correctly
    expect(r.entriesAt(SA, 3)[0]!.own).toBe(true);
    const r2 = new ChannelKeyring();
    wrap(r2, 4, kk(4));
    expect(r2.entriesAt(SA, 4)[0]!.own).toBe(false);
    expect(r2.pruneUnverified({ dryRun: true, classes: ['memberWraps'], keepLatestPerScope: 0 }).removedCount).toBe(1);
    wrap(r2, 4, kk(4), { ownSlot: true });
    expect(r2.pruneUnverified({ dryRun: true, classes: ['memberWraps'], keepLatestPerScope: 0 }).removedCount).toBe(0);
  });

  it('import ceiling: restored keys above it are memberWraps for prune; below it untouched; nothing dropped on import', () => {
    const r = new ChannelKeyring();
    expect(r.importFromVault({ [`${SA}:5`]: kk(5), [`${SA}:900000`]: kk(900000), [`${SA}:900001#alt5`]: kk(900001) }, undefined, { maxEpoch: 300 })).toBe(3);
    const d = r.pruneUnverified({ dryRun: true, classes: ['memberWraps'], keepLatestPerScope: 0 });
    expect(d.byClass.memberWraps.count).toBe(2);
    const n = new ChannelKeyring();
    n.importFromVault({ [`${SA}:900000`]: kk(900000) });
    expect(n.pruneUnverified({ dryRun: true, classes: ['memberWraps'], keepLatestPerScope: 0 }).removedCount).toBe(0); // no ceiling given
  });

  it('a final member wrap is bounded only by the absolute per-scope epoch cap', () => {
    const r = new ChannelKeyring({ maxEpochsPerScope: 5, maxMemberEpochsPerScope: 1 });
    for (let e = 1; e <= 5; e++) expect(wrap(r, e, kk(e, 4), { final: true })).toBe('stored');
    expect(wrap(r, 6, kk(6, 4), { final: true })).toBe('refused');
    expect(wrap(r, 7, kk(7, 4), { ownSlot: true })).toBe('stored');
  });
});

describe('B3: key vault `__proto__` names', () => {
  const bk = new Uint8Array(32).fill(0x42);

  it('sealKeyVault renames an own `__proto__` entry (bytes kept) so the vault opens again', () => {
    const chan: Record<string, Uint8Array> = { [`${SA}:1`]: k(1), '%proto_00': k(5) };
    Object.defineProperty(chan, '__proto__', { value: k(2), enumerable: true, writable: true, configurable: true });
    const opened = openKeyVault(bk, sealKeyVault(bk, { conv: {}, chan }));
    expect(Object.keys(opened.chan).sort()).toEqual(['%proto_00', '%proto_01', `${SA}:1`]);
    expect(hex(opened.chan['%proto_01']!)).toBe(hex(k(2)));
    // the sealed plaintext itself carries no `__proto__` key (decodable without any fix-up)
    const sealed = sealKeyVault(bk, { conv: {}, chan });
    const aad = new Uint8Array([...new TextEncoder().encode('ogmara-keyvault-v1'), 1]);
    const pt = aeadDecrypt(bk, sealed.nonce, sealed.encrypted_vault, aad);
    const raw = decode(pt) as { chan: Record<string, Uint8Array> };
    expect(hex(raw.chan['%proto_01']!)).toBe(hex(k(2)));
  });

  it('a vault sealed BEFORE the fix (raw `__proto__` key) is opened by the in-place fix-up', () => {
    const chan: Record<string, Uint8Array> = { [`${SA}:1`]: k(1) };
    Object.defineProperty(chan, '__proto__', { value: k(2), enumerable: true, writable: true, configurable: true });
    const plaintext = new Uint8Array(encode({ conv: {}, chan }));
    const nonce = new Uint8Array(24).fill(1);
    const aad = new Uint8Array([...new TextEncoder().encode('ogmara-keyvault-v1'), 1]);
    const blob = { encrypted_vault: aeadEncrypt(bk, nonce, plaintext, aad), nonce, format_version: 1 };
    const opened = openKeyVault(bk, blob);
    expect(hex(opened.chan['%proto_00']!)).toBe(hex(k(2)));
    expect(hex(opened.chan[`${SA}:1`]!)).toBe(hex(k(1)));
    expect(renameProtoKeysInVaultPlaintext(new Uint8Array(encode({ conv: {}, chan: { a: k(1) } })))).toBeNull();
  });

  it('the keyring renames an own `__proto__` entry instead of dropping it, and seal / open round-trips', () => {
    const rec: Record<string, Uint8Array> = { [`${SA}:1`]: k(1) };
    Object.defineProperty(rec, '__proto__', { value: k(3), enumerable: true, writable: true, configurable: true });
    const r = new ChannelKeyring();
    expect(r.importFromVault(rec)).toBe(2);
    const out = r.exportForVault();
    expect(Object.keys(out)).toEqual([`${SA}:1`, `${SA}:1#pri`, '%proto_00']);
    // N-1: importing the same raw record again reuses the existing `%proto_NN` entry
    for (let i = 0; i < 3; i++) r.importFromVault(rec);
    r.importFromVault(out);
    expect(Object.keys(r.exportForVault())).toEqual([`${SA}:1`, `${SA}:1#pri`, '%proto_00']);
    const back = openKeyVault(bk, sealKeyVault(bk, { conv: {}, chan: out }));
    expect(back.chan).toEqual(out);
  });
});

describe('fixture vault', () => {
  const fixture = (): Record<string, Uint8Array> => ({
    'S:3': k(1),
    'S:3#alt1': k(2),
    'S:3#alt2': k(3),
    'S:4~1': k(4),
    'zzz-unknown': k(5),
    'S:5#alt7': k(6),
    'S:6#future-alias': k(7),
  });

  it('imports, keeps every value, and round-trips idempotently', () => {
    const r = new ChannelKeyring();
    expect(r.importFromVault(fixture())).toBe(7);
    expect(r.keysAt('S', 3).length).toBe(3);
    expect(r.keysAt('S', 4).map(hex)).toEqual([hex(k(4))]);
    expect(r.keysAt('S', 5).map(hex)).toEqual([hex(k(6))]);
    expect(r.holds('S', 6)).toBe(false);
    const out = r.exportForVault();
    expect(out).toEqual({
      'S:3': k(1), 'S:3#pri': k(1), 'S:3#alt5': k(2), 'S:3#alt6': k(3), 'S:4#alt5': k(4),
      'zzz-unknown': k(5), 'S:5#alt7': k(6), 'S:6#future-alias': k(7),
    });
    expect(Object.keys(out)).toEqual(['S:3', 'S:3#pri', 'S:3#alt5', 'S:3#alt6', 'S:5#alt7', 'S:4#alt5', 'zzz-unknown', 'S:6#future-alias']);
    const r2 = new ChannelKeyring();
    r2.importFromVault(out);
    expect(r2.exportForVault()).toEqual(out);
    expect(r2.importFromVault(out)).toBe(0);
    expect(r2.exportForVault()).toEqual(out);
  });

  it('a key keeps its first vault name across repeated imports', () => {
    const r = new ChannelKeyring();
    r.importFromVault({ [`${SA}:3`]: k(1), [`${SA}:3#alt6`]: k(2) });
    r.importFromVault({ [`${SA}:3#alt7`]: k(2), [`${SA}:3#alt5`]: k(1) });
    const out = r.exportForVault();
    expect(hex(out[`${SA}:3#alt6`]!)).toBe(hex(k(2)));
    expect(Object.keys(out)).toEqual([`${SA}:3`, `${SA}:3#pri`, `${SA}:3#alt6`]);
  });

  it('survives a real seal / open of the key vault (msgpack) unchanged', () => {
    const r = new ChannelKeyring();
    r.importFromVault(fixture());
    trustedPut(r, SA, 2, k(9));
    const out = r.exportForVault();
    const bk = new Uint8Array(32).fill(0x42);
    const opened = openKeyVault(bk, sealKeyVault(bk, { conv: {}, chan: out }));
    const r2 = new ChannelKeyring();
    r2.importFromVault(opened.chan);
    expect(r2.exportForVault()).toEqual(out);
  });

  it('errors never contain key material', () => {
    const r = new ChannelKeyring({ maxOpaqueEntries: 0 });
    r.importFromVault(fixture());
    try {
      r.exportForVault();
      throw new Error('expected a throw');
    } catch (e) {
      const m = String((e as Error).message);
      for (let i = 1; i <= 7; i++) expect(m).not.toContain(hex(k(i)).slice(0, 16));
    }
  });
});
