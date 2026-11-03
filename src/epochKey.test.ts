/**
 * Real-crypto tests for the 0.67.0 key-epoch surface: the channel key
 * envelope builders, `verifyChannelKeyWrap` (author / field / commitment
 * binding — the hostile-node key-injection guard), the typed
 * `publishChannelKeyEnvelope` / `getKeyCommitment` client mapping, and the
 * deterministic branches of `establishEpochKey`. The concurrency protocol
 * itself is exercised by `epochKey.sim.test.ts`.
 */
import { decode } from '@msgpack/msgpack';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WalletSigner, buildDeviceClaim } from './auth';
import { OgmaraClient } from './client';
import { generateDeviceEncKeypair } from './encryption';
import { x25519Public } from './crypto';
import { buildChannelEpochKeyEnvelope, buildChannelKeyEnvelope, KeyScopeKind, wrapConvKey } from './dm';
import { computeChannelScope } from './envelope';
import { bytesToBase64 } from './invite';
import {
  computeKeyCommitment,
  keyCommitmentToHex,
  KeyCommitmentConflictError,
  KeyEnvelopeRateLimitedError,
  KeyEnvelopeRejectedError,
  KeyEnvelopeTransientError,
} from './channelKeyCommit';
import {
  establishEpochKey,
  PendingEpochKeyStore,
  TokenBucket,
  EscalationGate,
  verifyChannelKeyWrap,
  type EstablishEpochKeyDeps,
  type VerifiedChannelKeyWrap,
} from './epochKey';
import type { DeviceClaimObject, KeyCommitmentInfo, KeyEnvelopeRecord } from './types';

const NET = 'testnet';
const CH = 4294967297;
const SCOPE = computeChannelScope(CH);
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

afterEach(() => {
  vi.unstubAllGlobals();
});

async function walletSigner(): Promise<WalletSigner> {
  const s = await WalletSigner.generate();
  s.network = NET;
  return s;
}

/** Turn signed envelope bytes into the node's `?proof=1` record. */
function recordOf(envBytes: Uint8Array, author: string, claim?: DeviceClaimObject): KeyEnvelopeRecord {
  const env = decode(envBytes) as any;
  const p = decode(env.payload) as any;
  return {
    eph_pub: toHex(p.eph_pub),
    nonce: toHex(p.nonce),
    wrapped: toHex(p.wrapped),
    epoch: Number(p.epoch),
    scope_kind: p.scope_kind,
    author,
    timestamp: Number(env.timestamp),
    key_commitment: p.key_commitment ? toHex(p.key_commitment) : undefined,
    key_ts: p.key_ts !== undefined ? Number(p.key_ts) : undefined,
    msg_id: toHex(env.msg_id),
    signed_envelope: bytesToBase64(envBytes),
    device_claim: claim,
  };
}

async function setup() {
  const author = await walletSigner();
  const me = await walletSigner();
  const myDev = generateDeviceEncKeypair();
  const myDeviceId = 'ab'.repeat(32);
  const key = new Uint8Array(32).fill(7);
  const keyTs = Date.now() - 1000;
  const env = await buildChannelEpochKeyEnvelope(author, {
    channelId: CH, epoch: 3, key, keyTs, target: me.address, deviceId: myDeviceId,
    encPub: x25519Public(myDev.privateKey),
  });
  const ctx = {
    self: me.address, deviceId: myDeviceId, network: NET, channelId: CH, encPriv: myDev.privateKey,
    isVerifiedMember: (w: string) => w === author.address || w === me.address,
  };
  return { author, me, myDev, myDeviceId, key, keyTs, env, ctx };
}

describe('channel key envelope builders', () => {
  it('buildChannelEpochKeyEnvelope appends key_commitment (bin32) + key_ts (uint) at the end of the map', async () => {
    const s = await setup();
    const env = decode(s.env) as any;
    const p = decode(env.payload) as Record<string, unknown>;
    const keys = Object.keys(p);
    expect(keys.slice(-2)).toEqual(['key_commitment', 'key_ts']);
    expect(p.key_commitment).toBeInstanceOf(Uint8Array);
    expect(toHex(p.key_commitment as Uint8Array)).toBe(keyCommitmentToHex(computeKeyCommitment(SCOPE, 3, s.keyTs, s.key)));
    expect(p.key_ts).toBe(s.keyTs);
    expect(Number.isInteger(p.key_ts)).toBe(true);
    expect(p.scope_kind).toBe(1);
    expect(p.channel_id).toBe(CH);
    expect(s.key.every((b) => b === 7)).toBe(true); // key not mutated
  });

  it('scopeKind=1 requires both fields; DM refuses them', async () => {
    const s = await walletSigner();
    const wrapped = wrapConvKey(new Uint8Array(32).fill(1), x25519Public(generateDeviceEncKeypair().privateKey), SCOPE);
    const base = { keyScope: SCOPE, scopeKind: KeyScopeKind.Channel, epoch: 1, target: s.address, deviceId: 'aa'.repeat(32), channelId: CH, wrapped };
    await expect(buildChannelKeyEnvelope(s, base)).rejects.toThrow(/keyCommitment/);
    await expect(buildChannelKeyEnvelope(s, { ...base, keyCommitment: new Uint8Array(32).fill(1) })).rejects.toThrow(/keyTs/);
    await expect(buildChannelKeyEnvelope(s, { ...base, keyTs: 5 })).rejects.toThrow(/keyCommitment/);
    await expect(buildChannelKeyEnvelope(s, { ...base, keyCommitment: new Uint8Array(32), keyTs: 5 })).rejects.toThrow(/non-zero/);
    await expect(buildChannelKeyEnvelope(s, { ...base, keyCommitment: new Uint8Array(32).fill(1), keyTs: Date.now() + 60_000 })).rejects.toThrow(/future/);
    await expect(buildChannelKeyEnvelope(s, { ...base, keyCommitment: new Uint8Array(32).fill(1), keyTs: 5 })).resolves.toBeInstanceOf(Uint8Array);
    await expect(buildChannelKeyEnvelope(s, { ...base, scopeKind: KeyScopeKind.DM, keyTs: 5 })).rejects.toThrow(/channel-scope only/);
  });
});

describe('verifyChannelKeyWrap', () => {
  it('accepts a wallet-signed wrap for our device and returns the key', async () => {
    const s = await setup();
    const v = await verifyChannelKeyWrap(recordOf(s.env, s.author.address), s.ctx);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    expect(v.wrap.key).toEqual(s.key);
    expect(v.wrap.wallet).toBe(s.author.address);
    expect(v.wrap.signer).toBe(s.author.address);
    expect(v.wrap.keyTs).toBe(s.keyTs);
    expect(v.wrap.epoch).toBe(3);
  });

  it('accepts a device-signed wrap only with a valid covering device claim', async () => {
    const s = await setup();
    const dev = await WalletSigner.generate();
    dev.walletAddress = s.author.address;
    dev.network = NET;
    const ts = Date.now() - 60_000;
    const claim = buildDeviceClaim(dev.publicKeyHex, s.author.address, NET, ts);
    const msg = new TextEncoder().encode(claim.claimString);
    const dc: DeviceClaimObject = {
      device_address: dev.deviceAddress,
      device_pubkey: dev.publicKeyHex,
      wallet: s.author.address,
      delegations: [{
        timestamp: ts,
        wallet_signature: bytesToBase64(await s.author.signKleverMessage(msg)),
        device_signature: bytesToBase64(await dev.signKleverMessage(msg)),
      }],
      revocations: [],
    };
    const env = await buildChannelEpochKeyEnvelope(dev, {
      channelId: CH, epoch: 3, key: s.key, keyTs: s.keyTs, target: s.me.address, deviceId: s.myDeviceId,
      encPub: x25519Public(s.myDev.privateKey),
    });
    const ok = await verifyChannelKeyWrap(recordOf(env, s.author.address, dc), s.ctx);
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.wrap.signer).toBe(dev.deviceAddress);
    expect((await verifyChannelKeyWrap(recordOf(env, s.author.address), s.ctx)).ok).toBe(false);
    const badClaim = { ...dc, delegations: [{ ...dc.delegations[0]!, timestamp: ts + 1 }] };
    expect((await verifyChannelKeyWrap(recordOf(env, s.author.address, badClaim), s.ctx)).ok).toBe(false);

    // M10: a VALID claim whose delegation post-dates the envelope does not cover it.
    const lateTs = Date.now() + 60_000;
    const lateMsg = new TextEncoder().encode(buildDeviceClaim(dev.publicKeyHex, s.author.address, NET, lateTs).claimString);
    const lateClaim: DeviceClaimObject = {
      ...dc,
      delegations: [{
        timestamp: lateTs,
        wallet_signature: bytesToBase64(await s.author.signKleverMessage(lateMsg)),
        device_signature: bytesToBase64(await dev.signKleverMessage(lateMsg)),
      }],
    };
    expect(await verifyChannelKeyWrap(recordOf(env, s.author.address, lateClaim), s.ctx)).toEqual({ ok: false, reason: 'outside_delegation_window' });
  });

  it('hostile node: non-member author, swapped blob, wrong target/device/epoch/channel, missing proof', async () => {
    const s = await setup();
    const rec = recordOf(s.env, s.author.address);
    const nonMember = await verifyChannelKeyWrap(rec, { ...s.ctx, isVerifiedMember: (w) => w === s.me.address });
    expect(nonMember).toEqual({ ok: false, reason: 'author_not_verified_member' });

    // A node substituting another wrapped blob under the same signed envelope.
    const other = wrapConvKey(new Uint8Array(32).fill(9), x25519Public(s.myDev.privateKey), SCOPE);
    const swapped = { ...rec, eph_pub: toHex(other.ephPub), nonce: toHex(other.nonce), wrapped: toHex(other.wrapped) };
    expect((await verifyChannelKeyWrap(swapped, s.ctx)).ok).toBe(false);

    expect((await verifyChannelKeyWrap(rec, { ...s.ctx, self: s.author.address })).ok).toBe(false);
    expect((await verifyChannelKeyWrap(rec, { ...s.ctx, deviceId: 'cd'.repeat(32) })).ok).toBe(false);
    expect((await verifyChannelKeyWrap(rec, { ...s.ctx, epoch: 4 })).ok).toBe(false);
    expect((await verifyChannelKeyWrap(rec, { ...s.ctx, channelId: CH + 1 })).ok).toBe(false);
    expect((await verifyChannelKeyWrap({ ...rec, signed_envelope: undefined }, s.ctx)).ok).toBe(false);
    expect((await verifyChannelKeyWrap({ ...rec, author: 'klv1someoneelse' }, s.ctx)).ok).toBe(false);
    expect((await verifyChannelKeyWrap({ ...rec, key_ts: s.keyTs + 1 }, s.ctx)).ok).toBe(false);
    expect((await verifyChannelKeyWrap({ ...rec, key_commitment: 'aa'.repeat(32) }, s.ctx)).ok).toBe(false);
    expect((await verifyChannelKeyWrap(null, s.ctx)).ok).toBe(false);

    // Tampered signed bytes.
    const { encode } = await import('@msgpack/msgpack');
    const obj = decode(s.env) as any;
    obj.signature = Uint8Array.from(obj.signature);
    obj.signature[0] ^= 1;
    const bad = encode(obj);
    expect((await verifyChannelKeyWrap({ ...rec, signed_envelope: bytesToBase64(bad) }, s.ctx)).ok).toBe(false);
  });

  it('a member publishing a bogus commitment (C != H(K)) is refused after unwrap', async () => {
    const s = await setup();
    const realKey = new Uint8Array(32).fill(3);
    const env = await buildChannelKeyEnvelope(s.author, {
      keyScope: SCOPE, scopeKind: 1, epoch: 3, target: s.me.address, deviceId: s.myDeviceId, channelId: CH,
      wrapped: wrapConvKey(realKey, x25519Public(s.myDev.privateKey), SCOPE),
      keyCommitment: new Uint8Array(32).fill(0x55), keyTs: s.keyTs,
    });
    expect(await verifyChannelKeyWrap(recordOf(env, s.author.address), s.ctx)).toEqual({ ok: false, reason: 'commitment_mismatch' });
  });

  it('a copied commitment paired with another key_ts never verifies (key_ts is bound into C)', async () => {
    const s = await setup();
    const honestC = computeKeyCommitment(SCOPE, 3, s.keyTs, s.key);
    // The attacker even wraps the REAL key (worst case) but claims an earlier key_ts.
    const env = await buildChannelKeyEnvelope(s.author, {
      keyScope: SCOPE, scopeKind: 1, epoch: 3, target: s.me.address, deviceId: s.myDeviceId, channelId: CH,
      wrapped: wrapConvKey(s.key, x25519Public(s.myDev.privateKey), SCOPE),
      keyCommitment: honestC, keyTs: s.keyTs - 1000,
    });
    expect(await verifyChannelKeyWrap(recordOf(env, s.author.address), s.ctx)).toEqual({ ok: false, reason: 'commitment_mismatch' });
  });

  it('refuses a commitment-less (legacy) wrap', async () => {
    const s = await setup();
    // Hand-built legacy payload (the builder can no longer produce one).
    const { buildEnvelope } = await import('./envelope');
    const w = wrapConvKey(s.key, x25519Public(s.myDev.privateKey), SCOPE);
    const env = await buildEnvelope(s.author, 0x61, {
      key_scope: SCOPE, scope_kind: 1, epoch: 3, target: s.me.address, device_id: s.myDeviceId, peer: null,
      channel_id: CH, eph_pub: w.ephPub, nonce: w.nonce, wrapped: w.wrapped,
    });
    expect(await verifyChannelKeyWrap(recordOf(env, s.author.address), s.ctx)).toEqual({ ok: false, reason: 'no_commitment' });
  });
});

// --- Client transport mapping ---------------------------------------------------

function stubFetch(handler: (url: string, init?: RequestInit) => { status: number; text: string }) {
  const urls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    urls.push(String(url));
    const r = String(url).includes('/api/v1/health')
      ? { status: 200, text: JSON.stringify({ status: 'ok', version: '0', peers: 0, node_id: 'n1', network: NET, features: ['key_commitment_v1'] }) }
      : handler(String(url), init);
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers: { get: () => null },
      body: null,
      json: async () => JSON.parse(r.text),
      text: async () => r.text,
    } as unknown as Response;
  }));
  return urls;
}

describe('OgmaraClient key epoch transport', () => {
  const client = async () => new OgmaraClient({ nodeUrl: 'https://n.example' }).withSigner(await walletSigner());
  const bytes = new Uint8Array([1, 2, 3]);

  it('success statuses', async () => {
    stubFetch(() => ({ status: 200, text: JSON.stringify({ msg_id: 'ab', key_status: 'already_present' }) }));
    expect(await (await client()).publishChannelKeyEnvelope(bytes)).toEqual({ status: 'already_present', msgId: 'ab' });
    stubFetch(() => ({ status: 200, text: JSON.stringify({ msg_id: 'ab' }) }));
    expect((await (await client()).publishChannelKeyEnvelope(bytes)).status).toBe('stored');
    stubFetch(() => ({ status: 409, text: 'message already exists' }));
    expect(await (await client()).publishChannelKeyEnvelope(bytes)).toEqual({ status: 'duplicate' });
  });

  it('typed errors', async () => {
    stubFetch(() => ({ status: 409, text: JSON.stringify({ error: 'key_commitment_conflict', epoch: 2, state: 'arbitrated', winner: { key_commitment: '11'.repeat(32), key_ts: 9, author: 'klv1x', msg_id: '22'.repeat(32), final: false } }) }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toBeInstanceOf(KeyCommitmentConflictError);
    stubFetch(() => ({ status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: 2500 }) }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toMatchObject({ retryAfterMs: 2500 });
    stubFetch(() => ({ status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: 2500 }) }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toBeInstanceOf(KeyEnvelopeRateLimitedError);
    stubFetch(() => ({ status: 400, text: JSON.stringify({ error: 'key_scope_full' }) }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toMatchObject({ code: 'key_scope_full' });
    stubFetch(() => ({ status: 400, text: 'key_commitment_required' }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toBeInstanceOf(KeyEnvelopeRejectedError);
    stubFetch(() => ({ status: 502, text: 'bad gateway' }));
    await expect((await client()).publishChannelKeyEnvelope(bytes)).rejects.toBeInstanceOf(KeyEnvelopeTransientError);
  });

  it('getKeyCommitment validates and getKeyEnvelope sends proof=1', async () => {
    const urls = stubFetch((url) => url.includes('key-commitment')
      ? { status: 200, text: JSON.stringify({ channel_id: CH, epoch: 2, state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, author: 'klv1x', msg_id: '22'.repeat(32), recorded_at: 6, final: true, finality_ms: 120000 }) }
      : { status: 200, text: JSON.stringify({ key_scope: 'x', epoch: null, envelope: null }) });
    const c = await client();
    const info = await c.getKeyCommitment(CH, 2);
    expect(info.final).toBe(true);
    await expect(c.getKeyCommitment(CH, 3)).rejects.toThrow(/malformed/); // node answered another epoch
    await c.getKeyEnvelope('ab'.repeat(32), 'cd'.repeat(32), '', 2, { proof: true });
    expect(urls.some((u) => u.includes('proof=1') && u.includes('author=&') && u.includes('epoch=2'))).toBe(true);
    expect((await c.health()).features).toEqual(['key_commitment_v1']);
  });
});

// --- establishEpochKey deterministic branches -----------------------------------------

function fakeDeps(over: Partial<EstablishEpochKeyDeps> & { info: () => KeyCommitmentInfo }): EstablishEpochKeyDeps {
  let t = 1_000_000;
  const sleep = async (ms: number) => { t += ms; };
  return {
    channelId: CH,
    epoch: 2,
    self: { wallet: 'klv1me', deviceId: 'aa'.repeat(32), signingAddress: 'ogd1me', encPub: new Uint8Array(32) },
    epochKnownToExist: false,
    highestEpochSeen: 0,
    getCommitment: async () => over.info(),
    fetchOwnWrap: async () => null,
    isSelfBound: async () => true,
    listTargets: async () => [],
    publish: async () => ({ status: 'stored' }),
    pending: new PendingEpochKeyStore(),
    newKey: () => new Uint8Array(32).fill(1),
    now: () => t,
    sleep,
    bucket: { take: async () => {} },
    ...over,
  };
}

const none = (): KeyCommitmentInfo => ({ channel_id: CH, epoch: 2, state: 'none', final: false, finality_ms: 120000 });

describe('establishEpochKey branches', () => {
  it('legacy → never establishes', async () => {
    const publish = vi.fn();
    const r = await establishEpochKey(fakeDeps({ info: () => ({ ...none(), state: 'legacy' }), publish }));
    expect(r.kind).toBe('legacy');
    expect(publish).not.toHaveBeenCalled();
  });

  it('unbound self row → needs_binding, no key generated', async () => {
    const newKey = vi.fn(() => new Uint8Array(32).fill(1));
    const r = await establishEpochKey(fakeDeps({ info: none, isSelfBound: async () => false, newKey }));
    expect(r.kind).toBe('needs_binding');
    expect(newKey).not.toHaveBeenCalled();
  });

  it('commitment unreadable → failed retryable', async () => {
    const r = await establishEpochKey(fakeDeps({ info: none, getCommitment: async () => { throw new Error('down'); } }));
    expect(r).toMatchObject({ kind: 'failed', retryable: true });
  });

  it('adopts a verified wrap that matches the winner (and only that)', async () => {
    const k = new Uint8Array(32).fill(4);
    const c = computeKeyCommitment(SCOPE, 2, 5, k);
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    const wrap: VerifiedChannelKeyWrap = { key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1other', signer: 'klv1other', msgId: 'x' };
    const publish = vi.fn();
    const r = await establishEpochKey(fakeDeps({ info, fetchOwnWrap: async () => ({ ...wrap, key: wrap.key.slice() }), publish }));
    expect(r).toMatchObject({ kind: 'adopted', author: 'klv1other', confirmed: true });
    expect(publish).not.toHaveBeenCalled();
  });

  it('final winner never delivered → escalate (bounded wait)', async () => {
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: 1, final: true });
    const r = await establishEpochKey(fakeDeps({ info }));
    expect(r.kind).toBe('escalate');
  });

  it('a 429 on the own-device publish retries the SAME key; a transient-failed call leaves it pending for reuse', async () => {
    const pending = new PendingEpochKeyStore();
    let n = 0;
    const seen: string[] = [];
    let state: KeyCommitmentInfo = none();
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number) => {
      n++;
      seen.push(toHex(key) + ':' + keyTs);
      if (n === 1) throw new KeyEnvelopeRateLimitedError(500, true);
      if (n <= 5) throw new KeyEnvelopeTransientError(503, 'busy');
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
      return { status: 'stored' as const };
    });
    let k = 0;
    const newKey = () => new Uint8Array(32).fill(++k);
    const first = await establishEpochKey(fakeDeps({ info: () => state, publish, pending, newKey }));
    expect(first).toMatchObject({ kind: 'failed', retryable: true });
    expect(pending.size).toBe(1);
    const second = await establishEpochKey(fakeDeps({ info: () => state, publish, pending, newKey }));
    expect(second.kind).toBe('established');
    expect(k).toBe(1);
    expect(new Set(seen).size).toBe(1);
    expect(pending.size).toBe(0);
  });
});

describe('establishEpochKey duplicate / epoch codes', () => {
  it('a duplicate on our own device while ANOTHER key is the winner is a conflict, never success', async () => {
    let calls = 0;
    const other: KeyCommitmentInfo = { ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: 1, final: true };
    const info = () => (calls === 0 ? none() : other);
    // (the duplicate's winner is another pair → conflict → wait for its wrap)
    const r = await establishEpochKey(fakeDeps({ info, publish: async () => { calls++; return { status: 'duplicate' }; } }));
    expect(r.kind).toBe('escalate'); // waited for the other winner's wrap (none came), never "established"
  });
  it('a duplicate on our own device is success only when the commitment is ours AND our slot verifies', async () => {
    const pending = new PendingEpochKeyStore();
    let state: KeyCommitmentInfo = none();
    let ownWrap: VerifiedChannelKeyWrap | null = null;
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number) => {
      const c = computeKeyCommitment(SCOPE, 2, keyTs, key);
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: keyTs, recorded_at: 1, final: true };
      ownWrap = { key: key.slice(), keyCommitment: c, keyTs, epoch: 2, wallet: 'klv1me', signer: 'ogd1me', msgId: 'm' };
      return { status: 'duplicate' as const };
    });
    const r = await establishEpochKey(fakeDeps({
      info: () => state, publish, pending,
      fetchOwnWrap: async () => (ownWrap ? { ...ownWrap, key: ownWrap.key.slice() } : null),
    }));
    expect(r.kind).toBe('established');
  });
  it('a duplicate whose own slot does NOT verify is re-signed fresh and republished', async () => {
    let state: KeyCommitmentInfo = none();
    let slot: VerifiedChannelKeyWrap | null = null;
    const calls: Array<boolean | undefined> = [];
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number, _ep: number, opts?: { fresh?: boolean }) => {
      calls.push(opts?.fresh);
      const c = computeKeyCommitment(SCOPE, 2, keyTs, key);
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: keyTs, recorded_at: 1, final: true };
      if (!opts?.fresh) return { status: 'duplicate' as const }; // slot empty (e.g. deleted)
      slot = { key: key.slice(), keyCommitment: c, keyTs, epoch: 2, wallet: 'klv1me', signer: 'ogd1me', msgId: 'm2' };
      return { status: 'stored' as const };
    });
    const r = await establishEpochKey(fakeDeps({
      info: () => state, publish, fetchOwnWrap: async () => (slot ? { ...slot, key: slot.key.slice() } : null),
    }));
    expect(r.kind).toBe('established');
    expect(calls).toEqual([undefined, true]);
  });

  it('a stale pending key (> 60 s, never confirmed published) is regenerated before its first publish', async () => {
    const pending = new PendingEpochKeyStore();
    let t = 1_000_000;
    const old = new Uint8Array(32).fill(9);
    pending.set(CH, 2, { key: old, keyTs: t - 61_000, keyCommitment: computeKeyCommitment(SCOPE, 2, t - 61_000, old), covered: new Set() });
    let state: KeyCommitmentInfo = none();
    const seenTs: number[] = [];
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number) => {
      seenTs.push(keyTs);
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
      return { status: 'stored' as const };
    });
    const newKey = vi.fn(() => new Uint8Array(32).fill(3));
    const r = await establishEpochKey(fakeDeps({ info: () => state, publish, pending, newKey, now: () => t, sleep: async (ms) => { t += ms; } }));
    expect(r.kind).toBe('established');
    expect(newKey).toHaveBeenCalledTimes(1);
    expect(old.every((b) => b === 0)).toBe(true); // stale key zeroed
    expect(seenTs.every((x) => x >= 1_000_000)).toBe(true);
  });

  it('winner = our commitment paired with ANOTHER key_ts is not ours: never established/confirmed', async () => {
    let state: KeyCommitmentInfo = none();
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number) => {
      const c = computeKeyCommitment(SCOPE, 2, keyTs, key);
      // An attacker paired our public C with an earlier key_ts and won.
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: keyTs - 1, recorded_at: 1, final: true };
      return { status: 'stored' as const };
    });
    const r = await establishEpochKey(fakeDeps({ info: () => state, publish }));
    expect(r.kind).not.toBe('established');
    expect(r.kind).toBe('escalate');
  });

  it('B1: an epoch known to exist / <= highestEpochSeen but unknown to the home node is never created here → node_lagging', async () => {
    // (highestEpochSeen is honoured only up to the node's highest epoch + 2; see Z4)
    for (const over of [{ epochKnownToExist: true }, { highestEpochSeen: 2 }, { highestEpochSeen: 4 }]) {
      const newKey = vi.fn(() => new Uint8Array(32).fill(1));
      const publish = vi.fn();
      const r = await establishEpochKey(fakeDeps({ info: none, newKey, publish, ...over }));
      expect(r).toMatchObject({ kind: 'node_lagging', epoch: 2 });
      expect(newKey).not.toHaveBeenCalled();
      expect(publish).not.toHaveBeenCalled();
    }
    // epoch above everything seen, not known → a real rotation is allowed
    const r = await establishEpochKey(fakeDeps({ info: none, highestEpochSeen: 1 }));
    expect(r.kind).not.toBe('node_lagging');
  });
  it('B1: highestEpochSeen / epochKnownToExist are REQUIRED (no unsafe default)', async () => {
    await expect(establishEpochKey(fakeDeps({ info: none, highestEpochSeen: undefined as any }))).rejects.toThrow(/highestEpochSeen/);
    await expect(establishEpochKey(fakeDeps({ info: none, epochKnownToExist: undefined as any }))).rejects.toThrow(/epochKnownToExist/);
  });
  it('a winner that never shows up (home node stays none) after a 409: waiting, or node_lagging with evidence — never escalate', async () => {
    const pub = async () => { throw new KeyCommitmentConflictError(null, 'arbitrated', 2); };
    expect((await establishEpochKey(fakeDeps({ info: none, publish: pub }))).kind).toBe('waiting');
  });
  it('B1: key_epoch_too_far is surfaced, never retried at another epoch', async () => {
    const publish = vi.fn(async () => { throw new KeyEnvelopeRejectedError(400, 'key_epoch_too_far'); });
    const r = await establishEpochKey(fakeDeps({ info: none, publish }));
    expect(r).toMatchObject({ kind: 'failed', epochTooHigh: true, retryable: false });
    expect(publish).toHaveBeenCalledTimes(1);
  });

  it('key_epoch_too_far on the own device → failed with epochTooHigh', async () => {
    const r = await establishEpochKey(fakeDeps({ info: none, publish: async () => { throw new KeyEnvelopeRejectedError(400, 'key_epoch_too_far'); } }));
    expect(r).toMatchObject({ kind: 'failed', retryable: false, epochTooHigh: true, reason: 'key_epoch_too_far' });
    expect((r as any).epochTooLow).toBeUndefined();
  });
  it('onUnconfirmed fires once with a COPY while the winner is ours but not final; then the confirmed result follows', async () => {
    let polls = 0;
    let state: KeyCommitmentInfo = none();
    const publish = vi.fn(async (_t, key: Uint8Array, keyTs: number) => {
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1_000_000, final: false };
      return { status: 'stored' as const };
    });
    const info = () => {
      if (state.state === 'arbitrated' && ++polls > 3) state = { ...state, final: true };
      return state;
    };
    const seen: any[] = [];
    const r = await establishEpochKey(fakeDeps({ info, publish, onUnconfirmed: (u) => seen.push(u) }));
    expect(r).toMatchObject({ kind: 'established', confirmed: true });
    expect(seen).toHaveLength(1);
    expect(seen[0].role).toBe('established');
    expect(seen[0].keyTs).toBe((r as any).keyTs);
    expect(seen[0].key).toEqual((r as any).key);
    expect(seen[0].key).not.toBe((r as any).key); // a copy
  });

  it('key_epoch_below_floor / key_epoch_evicted on the own device → failed with epochTooLow', async () => {
    for (const code of ['key_epoch_below_floor', 'key_epoch_evicted']) {
      const r = await establishEpochKey(fakeDeps({ info: none, publish: async () => { throw new KeyEnvelopeRejectedError(400, code); } }));
      expect(r).toMatchObject({ kind: 'failed', retryable: false, epochTooLow: true, reason: code });
    }
    const r = await establishEpochKey(fakeDeps({ info: none, publish: async () => { throw new KeyEnvelopeRejectedError(400, 'key_scope_full'); } }));
    expect(r).toMatchObject({ kind: 'failed', retryable: false });
    expect((r as any).epochTooLow).toBeUndefined();
  });
});

describe('TokenBucket / EscalationGate / PendingEpochKeyStore', () => {
  it('bucket allows the burst then paces at the rate', async () => {
    let t = 0;
    const b = new TokenBucket(() => t, async (ms) => { t += ms; }, 3, 10);
    for (let i = 0; i < 10; i++) await b.take();
    expect(t).toBe(0);
    for (let i = 0; i < 3; i++) await b.take();
    expect(t).toBeGreaterThanOrEqual(999);
    expect(t).toBeLessThanOrEqual(1100);
  });
  it('W4 gate: once per CHANNEL per interval (a floor change opens no second window); a full table never evicts a live entry', () => {
    let t = 0;
    const g = new EscalationGate(() => t, 10 * 60_000, 2);
    expect(g.tryEscalate(1)).toBe(true);
    expect(g.tryEscalate(1)).toBe(false);
    expect(g.tryEscalate(2)).toBe(true);
    expect(g.tryEscalate(3)).toBe(false); // full, nothing expired → refused (fail closed)
    expect(g.tryEscalate(1)).toBe(false); // channel 1's entry was NOT evicted/reset
    t += 10 * 60_000;
    expect(g.tryEscalate(3)).toBe(true); // expired entries make room
    expect(g.tryEscalate(1)).toBe(true);
  });
  it('W4 gate enforced inside establishEpochKey: a refused escalation is waiting(escalation_gated)', async () => {
    let t = 1_000_000;
    const g = new EscalationGate(() => t);
    g.tryEscalate(CH);
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: 1, final: true });
    const r = await establishEpochKey(fakeDeps({ info, escalationGate: g, now: () => t, sleep: async (ms) => { t += ms; } }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'escalation_gated' });
  });
  it('pending store zeroes on abandon/evict/clear', () => {
    const s = new PendingEpochKeyStore(2);
    const mk = () => ({ key: new Uint8Array(32).fill(1), keyTs: 1, keyCommitment: new Uint8Array(32), covered: new Set<string>() });
    const a = mk(); const b = mk(); const c = mk();
    s.set(1, 1, a); s.set(1, 2, b); s.set(1, 3, c);
    expect(a.key.every((x) => x === 0)).toBe(true); // evicted oldest
    s.delete(1, 2, true);
    expect(b.key.every((x) => x === 0)).toBe(true);
    s.delete(1, 3, false);
    expect(c.key.every((x) => x === 1)).toBe(true);
    const d = mk(); s.set(2, 1, d); s.clear();
    expect(d.key.every((x) => x === 0)).toBe(true);
  });
});

describe('audit r43 regressions', () => {
  it('B2: a hostile node alternating winners is bounded (sleeps between re-reads, stops on a regressing winner)', async () => {
    let t = 1_000_000;
    const kA = new Uint8Array(32).fill(4);
    const kB = new Uint8Array(32).fill(5);
    const cA = computeKeyCommitment(SCOPE, 2, 5, kA);
    const cB = computeKeyCommitment(SCOPE, 2, 6, kB);
    let n = 0;
    let own = 0;
    const r = await establishEpochKey(fakeDeps({
      info: none,
      now: () => t,
      sleep: async (ms) => { t += ms; },
      getCommitment: async () => {
        n++;
        const a = n % 2 === 1;
        return { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(a ? cA : cB), key_ts: a ? 5 : 6, recorded_at: t, final: false };
      },
      fetchOwnWrap: async () => { own++; return { key: kA.slice(), keyCommitment: cA, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' }; },
    }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'non_monotonic_winner' });
    expect(n).toBeLessThan(10);
    expect(own).toBeLessThan(10);
  });

  it('B2: every winner re-read is separated by a wake (no spin), and the loop is capped', async () => {
    let t = 1_000_000;
    let reads = 0;
    const readsAt: number[] = [];
    const r = await establishEpochKey(fakeDeps({
      info: none,
      now: () => t,
      sleep: async (ms) => { t += ms; },
      getCommitment: async () => {
        reads++;
        readsAt.push(t);
        // Winner never delivered and never final (a withholding node).
        return { ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false };
      },
      options: { maxTotalMs: 60_000, pollMs: 1_500 },
    }));
    expect(r.kind).toBe('waiting');
    for (let i = 2; i < readsAt.length; i++) expect(readsAt[i]! - readsAt[i - 1]!).toBeGreaterThanOrEqual(1_500);
    expect(reads).toBeLessThanOrEqual(Math.ceil(60_000 / 1_500) + 20);
  });

  it('B3: the returned key is a COPY — clearing the pending store (account switch) never zeroes it', async () => {
    let state: KeyCommitmentInfo = none();
    const pending = new PendingEpochKeyStore();
    const other = { target: 'klv1x', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) };
    const r = await establishEpochKey(fakeDeps({
      info: () => state, pending, listTargets: async () => [other],
      publish: async (t, key, keyTs) => {
        if (t.target === 'klv1x') throw new KeyEnvelopeTransientError(503, 'busy');
        state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
        return { status: 'stored' as const };
      },
    }));
    expect(r.kind).toBe('established');
    if (r.kind !== 'established') return;
    expect(r.uncovered).toHaveLength(1);
    const before = Buffer.from(r.key).toString('hex');
    expect(pending.get(CH, 2)!.key).not.toBe(r.key);
    pending.clear();
    expect(Buffer.from(r.key).toString('hex')).toBe(before);
    expect(r.key.some((b) => b !== 0)).toBe(true);
  });

  it('B3: an adopted key is a copy too', async () => {
    const k = new Uint8Array(32).fill(4);
    const c = computeKeyCommitment(SCOPE, 2, 5, k);
    const wrap = { key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' };
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    const r = await establishEpochKey(fakeDeps({ info, fetchOwnWrap: async () => wrap }));
    expect(r.kind).toBe('adopted');
    if (r.kind !== 'adopted') return;
    expect(r.key).not.toBe(wrap.key);
    expect(r.key).toEqual(k);
    expect(wrap.key.every((b) => b === 0)).toBe(true); // the SDK's own copy is wiped
  });

  it('M14: the 429 retry cap holds (rateLimitRetries + 1 attempts, then failed retryable with the key kept)', async () => {
    const publish = vi.fn(async () => { throw new KeyEnvelopeRateLimitedError(100, true); });
    const pending = new PendingEpochKeyStore();
    const r = await establishEpochKey(fakeDeps({ info: none, publish, pending, options: { rateLimitRetries: 4 } }));
    expect(r).toMatchObject({ kind: 'failed', retryable: true, reason: 'rate_limited' });
    expect(publish).toHaveBeenCalledTimes(5);
    expect(pending.size).toBe(1);
  });

  it('M17: key_ts_stale on our OWN device regenerates the key; on another target it is a conflict', async () => {
    let state: KeyCommitmentInfo = none();
    let first = true;
    const newKey = vi.fn(() => new Uint8Array(32).fill(newKey.mock.calls.length + 1));
    const publish = vi.fn(async (t: { target: string }, key: Uint8Array, keyTs: number) => {
      if (t.target === 'klv1me' && first) {
        first = false;
        throw new KeyEnvelopeRejectedError(400, 'key_ts_stale');
      }
      state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
      return { status: 'stored' as const };
    });
    const r = await establishEpochKey(fakeDeps({ info: () => state, publish, newKey }));
    expect(r.kind).toBe('established');
    expect(newKey).toHaveBeenCalledTimes(2);

    // non-own target: key_ts_stale → treated as a conflict (abandon + wait), never established
    let st2: KeyCommitmentInfo = none();
    const logs: string[] = [];
    const r2 = await establishEpochKey(fakeDeps({
      info: () => st2,
      listTargets: async () => [{ target: 'klv1x', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }],
      log: (step, d) => logs.push(d?.why ? `${step}: ${String(d.why)}` : step),
      publish: async (t, key, keyTs) => {
        if (t.target === 'klv1x') throw new KeyEnvelopeRejectedError(400, 'key_ts_stale');
        st2 = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
        return { status: 'stored' as const };
      },
    }));
    expect(r2.kind).not.toBe('established');
    expect(logs).toContain('abandoning our key: 409 while covering');
  });

  it('M19/N3: a winning wrap WE signed (device key, or our wallet key) is resumed (covered), another signer is adopted', async () => {
    for (const [signer, expectKind, expectCover] of [['ogd1me', 'established', true], ['klv1me', 'established', true], ['klv1other', 'adopted', false]] as const) {
      const k = new Uint8Array(32).fill(4);
      const c = computeKeyCommitment(SCOPE, 2, 5, k);
      const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
      const publish = vi.fn(async () => ({ status: 'stored' as const }));
      const r = await establishEpochKey(fakeDeps({
        info, publish,
        listTargets: async () => [{ target: 'klv1x', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }],
        fetchOwnWrap: async () => ({ key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: signer.startsWith('ogd') ? 'klv1me' : signer, signer, msgId: 'm' }),
      }));
      expect(r.kind).toBe(expectKind);
      expect(publish.mock.calls.length > 0).toBe(expectCover);
    }
  });
});

describe('audit r45 regressions', () => {
  const pairInfo = (key: Uint8Array, keyTs: number, over: Partial<KeyCommitmentInfo> = {}): KeyCommitmentInfo => ({
    ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs,
    recorded_at: 1, final: true, ...over,
  });

  it('Z1: pending.clear() during the own-device token wait never publishes a zeroed key (pending_lost)', async () => {
    const pending = new PendingEpochKeyStore();
    const keys: string[] = [];
    let cleared = false;
    const r = await establishEpochKey(fakeDeps({
      info: none, pending,
      bucket: { take: async () => { if (!cleared) { cleared = true; pending.clear(); } } },
      publish: async (_t, key) => { keys.push(toHex(key)); return { status: 'stored' as const }; },
    }));
    expect(keys).toEqual([]);
    expect(r).toMatchObject({ kind: 'waiting', reason: 'pending_lost' });
  });

  it('Z2: a second concurrent call for the same (channel, epoch) is refused (in_flight); no zeroed key is ever published or returned', async () => {
    const pending = new PendingEpochKeyStore();
    let state: KeyCommitmentInfo = none();
    const published: string[] = [];
    let releaseA!: () => void;
    const gateA = new Promise<void>((r) => { releaseA = r; });
    const mk = (slow: boolean, targets: { target: string; deviceId: string; encPub: Uint8Array }[]) => fakeDeps({
      info: () => state, pending,
      listTargets: async () => { if (slow) await gateA; return targets; },
      publish: async (_t, key, keyTs) => {
        published.push(toHex(key));
        if (state.state === 'none') state = pairInfo(key, keyTs);
        return { status: 'stored' as const };
      },
    });
    const A = establishEpochKey(mk(true, []));
    await new Promise((r) => setImmediate(r));
    const rb = await establishEpochKey(mk(false, [{ target: 'klv1bob', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }]));
    releaseA();
    const ra = await A;
    expect(rb).toMatchObject({ kind: 'waiting', reason: 'in_flight' });
    expect(ra.kind).toBe('established');
    if (ra.kind === 'established') expect(ra.key.some((b) => b !== 0)).toBe(true);
    expect(published.every((k) => k !== '00'.repeat(32))).toBe(true);
    // the lock is released afterwards
    const tok = pending.tryLock(CH, 2);
    expect(tok).not.toBeNull();
    pending.unlock(CH, 2, tok!);
  });

  it('Z3: buildChannelEpochKeyEnvelope refuses an all-zero key', async () => {
    const s = await walletSigner();
    await expect(buildChannelEpochKeyEnvelope(s, {
      channelId: CH, epoch: 2, key: new Uint8Array(32), keyTs: Date.now() - 10, target: s.address, deviceId: 'aa'.repeat(32), encPub: new Uint8Array(32).fill(3),
    })).rejects.toThrow(/all-zero/);
  });

  it('B1: newKey returning zeros is refused; a corrupted cached entry is regenerated, never published', async () => {
    await expect(establishEpochKey(fakeDeps({ info: none, newKey: () => new Uint8Array(32) }))).rejects.toThrow(/non-zero/);
    const pending = new PendingEpochKeyStore();
    const k = new Uint8Array(32).fill(7);
    pending.set(CH, 2, { key: new Uint8Array(32), keyTs: 1_000_000, keyCommitment: computeKeyCommitment(SCOPE, 2, 1_000_000, k), covered: new Set() });
    let state: KeyCommitmentInfo = none();
    const keys: string[] = [];
    const r = await establishEpochKey(fakeDeps({
      info: () => state, pending,
      publish: async (_t, key, keyTs) => { keys.push(toHex(key)); state = pairInfo(key, keyTs); return { status: 'stored' as const }; },
    }));
    expect(r.kind).toBe('established');
    expect(keys.every((x) => x !== '00'.repeat(32))).toBe(true);
  });

  it('store: clear/delete/evict of an in-flight entry is deferred (zeroed on unlock)', () => {
    const s = new PendingEpochKeyStore(1);
    const e = { key: new Uint8Array(32).fill(1), keyTs: 1, keyCommitment: new Uint8Array(32), covered: new Set<string>() };
    const tok = s.tryLock(CH, 2);
    expect(tok).not.toBeNull();
    expect(s.tryLock(CH, 2)).toBeNull();
    s.set(CH, 2, e);
    s.clear();
    expect(e.key[0]).toBe(1); // not zeroed while in flight
    expect(s.get(CH, 2)).toBeUndefined();
    s.unlock(CH, 2, tok!);
    expect(e.key.every((b) => b === 0)).toBe(true);
  });

  it('P1/P9 (r48 B1): highestEpochSeen is never discarded; a recovery beyond the node bound is flagged; a failed highest read fails CLOSED', async () => {
    const info10 = (): KeyCommitmentInfo => ({ ...none(), epoch: 10 });
    // a fresh node (highest 0) far behind the evidence: node_lagging, recovery bounded by highest + 256
    const r = await establishEpochKey(fakeDeps({ info: info10, epoch: 10, highestEpochSeen: 10, getCommitment: async (ep?: number) => (ep === undefined ? { ...none(), epoch: 0 } : info10()) }));
    expect(r).toMatchObject({ kind: 'node_lagging', highestEpochSeen: 10, recoveryEpoch: 11 });
    const big = await establishEpochKey(fakeDeps({ info: info10, epoch: 10, highestEpochSeen: 5_000, getCommitment: async (ep?: number) => (ep === undefined ? { ...none(), epoch: 0 } : info10()) }));
    expect(big).toMatchObject({ kind: 'node_lagging', recoveryEpoch: 5_001, unrecoverableHere: true });
    // the highest-epoch read throws → failed (retryable), never a key at a known epoch
    const publish = vi.fn();
    const p1 = await establishEpochKey(fakeDeps({
      info: info10, epoch: 10, highestEpochSeen: 10, publish,
      getCommitment: async (ep?: number) => { if (ep === undefined) throw new Error('503'); return info10(); },
    }));
    expect(p1).toMatchObject({ kind: 'failed', reason: 'commitment_unavailable', retryable: true });
    expect(publish).not.toHaveBeenCalled();
  });

  it('W1: node_lagging and split respect a supplied EscalationGate', async () => {
    let t = 1_000_000;
    const g = new EscalationGate(() => t);
    g.tryEscalate(CH);
    const r = await establishEpochKey(fakeDeps({ info: none, highestEpochSeen: 2, escalationGate: g, getCommitment: async () => none() }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'escalation_gated' });
  });

  it('Z5/N1/W2: a wait that never advances the clock terminates (spacing + iteration cap)', async () => {
    let t = 1_000_000;
    let reads = 0;
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false });
    const r = await establishEpochKey(fakeDeps({
      info, now: () => t, sleep: async (ms) => { t += ms; },
      getCommitment: async () => { reads++; return info(); },
      waitForEvent: async () => {},
    }));
    expect(r.kind).toBe('waiting');
    expect(reads).toBeLessThan(700);
  });

  it('N1: with a frozen clock the iteration cap alone ends the loop', async () => {
    let reads = 0;
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: 1, final: false });
    const r = await establishEpochKey(fakeDeps({
      info, now: () => 1_000_000, sleep: async () => {},
      getCommitment: async () => { reads++; return info(); },
      options: { maxTotalMs: 30_000, pollMs: 1_500 },
    }));
    expect(r).toMatchObject({ kind: 'waiting' });
    expect(reads).toBeLessThanOrEqual(Math.ceil(30_000 / 1_500) + 17);
  });

  it('Z6/W1: invalid options throw', async () => {
    await expect(establishEpochKey(fakeDeps({ info: none, options: { pollMs: 0 } }))).rejects.toThrow(/pollMs/);
    await expect(establishEpochKey(fakeDeps({ info: none, options: { maxTotalMs: 10 } }))).rejects.toThrow(/maxTotalMs/);
    await expect(establishEpochKey(fakeDeps({ info: none, options: { transientTries: 0 } }))).rejects.toThrow(/transientTries/);
    await expect(establishEpochKey(fakeDeps({ info: none, options: { confirmMode: 'x' as any } }))).rejects.toThrow(/confirmMode/);
  });

  it('W2: a custom waitForEvent that never resolves cannot hang the call', async () => {
    let t = 1_000_000;
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false });
    const r = await establishEpochKey(fakeDeps({
      info, now: () => t, sleep: async (ms) => { t += ms; },
      waitForEvent: () => new Promise<void>(() => {}),
      options: { maxTotalMs: 20_000 },
    }));
    expect(r.kind).toBe('waiting');
  });

  it('W3: an abort (guard throw) while settling an adopted key zeroes it', async () => {
    const k = new Uint8Array(32).fill(4);
    const wrapKey = k.slice();
    let reads = 0;
    const info = (): KeyCommitmentInfo => pairInfo(k, 5, { final: false, recorded_at: 1_000_000 });
    await expect(establishEpochKey(fakeDeps({
      info,
      getCommitment: async () => { reads++; return info(); },
      fetchOwnWrap: async () => ({ key: wrapKey, keyCommitment: computeKeyCommitment(SCOPE, 2, 5, k), keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' }),
      guard: (step) => { if (step === 'settle' && reads >= 3) throw new Error('account switched'); },
    }))).rejects.toThrow(/account switched/);
    expect(wrapKey.every((b) => b === 0)).toBe(true);
  });

  it('W4: a non-monotonic (hostile) winner keeps our pending key for a later resume', async () => {
    const pending = new PendingEpochKeyStore();
    let after = 0;
    let mine: KeyCommitmentInfo | null = null;
    const r = await establishEpochKey(fakeDeps({
      info: none, pending,
      getCommitment: async () => {
        if (!mine) return none();
        // after our publish: ours (better) first, then a WORSE pair → regression
        return ++after === 1 ? { ...mine, final: false } : { ...none(), state: 'arbitrated', key_commitment: 'ff'.repeat(32), key_ts: mine.key_ts! + 10_000, recorded_at: 1, final: false };
      },
      publish: async (_t, key, keyTs) => { mine = pairInfo(key, keyTs); return { status: 'stored' as const }; },
    }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'non_monotonic_winner' });
    expect(pending.size).toBe(1);
    expect(pending.get(CH, 2)!.key.some((b) => b !== 0)).toBe(true);
  });

  it('N14: resuming our own winning key is capped (resume_cap), never an endless loop', async () => {
    const k = new Uint8Array(32).fill(4);
    const info = (): KeyCommitmentInfo => pairInfo(k, 5, { final: false });
    let fetches = 0;
    const r = await establishEpochKey(fakeDeps({
      info,
      listTargets: async () => [{ target: 'klv1x', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }],
      fetchOwnWrap: async () => { fetches++; return { key: k.slice(), keyCommitment: computeKeyCommitment(SCOPE, 2, 5, k), keyTs: 5, epoch: 2, wallet: 'klv1me', signer: 'ogd1me', msgId: 'm' }; },
      publish: async () => { throw new KeyCommitmentConflictError(null, 'arbitrated', 2); },
    }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'resume_cap' });
    expect(fetches).toBeLessThanOrEqual(5);
  });

  it('N17: a wait that ends with the home node at `none` for a KNOWN epoch returns node_lagging (not waiting)', async () => {
    let n = 0;
    const other = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: 1, final: false });
    const r = await establishEpochKey(fakeDeps({
      info: none, epochKnownToExist: true,
      getCommitment: async (ep?: number) => (ep === undefined ? none() : ++n === 1 ? other() : none()),
    }));
    expect(r).toMatchObject({ kind: 'node_lagging', epoch: 2 });
  });

  describe('B3: peerCommitments', () => {
    const k = new Uint8Array(32).fill(4);
    const ownWrap = async () => ({ key: k.slice(), keyCommitment: computeKeyCommitment(SCOPE, 2, 5, k), keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' });
    const home = () => pairInfo(k, 5);
    it('a different FINAL winner on a peer → split, nothing confirmed', async () => {
      const r = await establishEpochKey(fakeDeps({
        info: home, fetchOwnWrap: ownWrap,
        peerCommitments: async () => [{ ...none(), state: 'arbitrated', key_commitment: '22'.repeat(32), key_ts: 4, recorded_at: 1, final: true }],
      }));
      expect(r).toMatchObject({ kind: 'split', epoch: 2 });
    });
    it('a peer with the same pair or no state passes; a non-final different winner keeps waiting', async () => {
      const ok = await establishEpochKey(fakeDeps({ info: home, fetchOwnWrap: ownWrap, peerCommitments: async () => [home(), none()] }));
      expect(ok).toMatchObject({ kind: 'adopted', confirmed: true });
      const w = await establishEpochKey(fakeDeps({
        info: home, fetchOwnWrap: ownWrap, options: { maxTotalMs: 20_000 },
        peerCommitments: async () => [{ ...none(), state: 'arbitrated', key_commitment: '22'.repeat(32), key_ts: 4, recorded_at: 1, final: false }],
      }));
      expect(w.kind).toBe('waiting');
    });
    it('peers configured but none answers → never confirmed', async () => {
      const r = await establishEpochKey(fakeDeps({ info: home, fetchOwnWrap: ownWrap, options: { maxTotalMs: 20_000 }, peerCommitments: async () => { throw new Error('down'); } }));
      expect(r.kind).toBe('waiting');
    });
  });
});

describe('audit r45 surviving mutants', () => {
  it('B1f/B2: an adopted wrap whose key does not hash to its commitment is never adopted (escalate once final)', async () => {
    const k = new Uint8Array(32).fill(4);
    const c = computeKeyCommitment(SCOPE, 2, 5, k);
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    // A buggy / hostile fetcher claims the winning pair but carries other key bytes.
    const r = await establishEpochKey(fakeDeps({ info, fetchOwnWrap: async () => ({ key: new Uint8Array(32).fill(9), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' }) }));
    expect(r.kind).toBe('escalate');
  });
  it('P11/M4 (r48 B2): an all-zero key won by a member never wedges adopters — it is not a delivery, they escalate', async () => {
    const z = new Uint8Array(32);
    const c = computeKeyCommitment(SCOPE, 2, 5, z);
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    const r = await establishEpochKey(fakeDeps({ info, fetchOwnWrap: async () => ({ key: new Uint8Array(32), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' }) }));
    expect(r.kind).toBe('escalate');
  });
  it('P11: verifyChannelKeyWrap refuses an all-zero key (zero_key)', async () => {
    const s0 = await setup();
    const zero = new Uint8Array(32);
    const env = await buildChannelKeyEnvelope(s0.author, {
      keyScope: SCOPE, scopeKind: 1, epoch: 3, target: s0.me.address, deviceId: s0.myDeviceId, channelId: CH,
      wrapped: wrapConvKey(zero, x25519Public(s0.myDev.privateKey), SCOPE),
      keyCommitment: computeKeyCommitment(SCOPE, 3, s0.keyTs, zero), keyTs: s0.keyTs,
    });
    expect(await verifyChannelKeyWrap(recordOf(env, s0.author.address), s0.ctx)).toEqual({ ok: false, reason: 'zero_key' });
  });
  it('P5 (r48 W2): a lock held by a call whose I/O never returns is taken over after maxTotalMs + margin', async () => {
    let t = 1_000_000;
    const pending = new PendingEpochKeyStore();
    void establishEpochKey(fakeDeps({ info: none, pending, now: () => t, publish: () => new Promise(() => {}) }));
    await new Promise((r) => setImmediate(r));
    const early = await establishEpochKey(fakeDeps({ info: none, pending, now: () => t }));
    expect(early).toMatchObject({ kind: 'waiting', reason: 'in_flight' });
    t += 15 * 60_000 + 61_000;
    let state: KeyCommitmentInfo = none();
    const late = await establishEpochKey(fakeDeps({
      info: () => state, pending, now: () => t, sleep: async (ms) => { t += ms; },
      publish: async (_t, key, keyTs) => { state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true }; return { status: 'stored' as const }; },
    }));
    expect(late.kind).toBe('established');
  });
  it('P6 (r48 W3): an abort while covering wipes the call\'s private key copy', async () => {
    let state: KeyCommitmentInfo = none();
    let held: Uint8Array | null = null;
    let abort = false;
    await expect(establishEpochKey(fakeDeps({
      info: () => state,
      listTargets: async () => [{ target: 'klv1b', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }],
      publish: async (t, key, keyTs) => {
        held = key;
        if (t.target === 'klv1b') abort = true;
        state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(computeKeyCommitment(SCOPE, 2, keyTs, key)), key_ts: keyTs, recorded_at: 1, final: true };
        return { status: 'stored' as const };
      },
      guard: (step) => { if (abort) throw new Error('aborted at ' + step); },
    }))).rejects.toThrow(/aborted/);
    expect(held!.every((b) => b === 0)).toBe(true);
  });
  it('P2 (r48 W1): repeated split calls do not re-cover every member', async () => {
    let t = 1_000_000;
    const pending = new PendingEpochKeyStore();
    let state: KeyCommitmentInfo = none();
    let own: VerifiedChannelKeyWrap | null = null;
    let n = 0;
    const targets = Array.from({ length: 5 }, (_, i) => ({ target: 'klv1m' + i, deviceId: String(i).repeat(64), encPub: new Uint8Array(32) }));
    const deps = () => fakeDeps({
      info: () => state, pending, now: () => t, sleep: async (ms) => { t += ms; }, listTargets: async () => targets,
      publish: async (tg, key, keyTs) => {
        n++;
        const c = computeKeyCommitment(SCOPE, 2, keyTs, key);
        if (state.state === 'none') state = { ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: keyTs, recorded_at: 1, final: true };
        if (tg.target === 'klv1me') own = { key: key.slice(), keyTs, keyCommitment: c, epoch: 2, wallet: 'klv1me', signer: 'ogd1me', msgId: 'x' };
        return { status: 'stored' as const };
      },
      fetchOwnWrap: async () => own && { ...own, key: own.key.slice() },
      peerCommitments: async () => [{ ...none(), state: 'arbitrated', key_commitment: 'cd'.repeat(32), key_ts: 1, recorded_at: 1, final: true }],
    });
    const first = await establishEpochKey(deps());
    expect(first.kind).toBe('split');
    const firstN = n;
    n = 0;
    const second = await establishEpochKey(deps());
    expect(second.kind).toBe('split');
    expect(firstN).toBe(6);
    expect(n).toBe(0);
  });
  it('B3: unconfirmed_exhausted after maxUnconfirmedCalls calls in a row', async () => {
    let t = 1_000_000;
    const pending = new PendingEpochKeyStore();
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false });
    const kinds: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await establishEpochKey(fakeDeps({ info, pending, now: () => t, sleep: async (ms) => { t += ms; }, options: { maxTotalMs: 10_000, maxUnconfirmedCalls: 3 } }));
      kinds.push(r.kind);
    }
    expect(kinds).toEqual(['waiting', 'waiting', 'unconfirmed_exhausted']);
  });
  it('B3/r50 W2: peerQuorum — a dissent below the quorum is not a split, and is never confirmed over (waits)', async () => {
    const k = new Uint8Array(32).fill(4);
    const c = computeKeyCommitment(SCOPE, 2, 5, k);
    const home = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    const ownWrap = async () => ({ key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' });
    const dissent = { ...none(), state: 'arbitrated' as const, key_commitment: '22'.repeat(32), key_ts: 4, recorded_at: 1, final: true };
    const r1 = await establishEpochKey(fakeDeps({ info: home, fetchOwnWrap: ownWrap, peerCommitments: async () => [dissent, home(), home()], options: { peerQuorum: 2, maxTotalMs: 20_000 } }));
    expect(r1).toMatchObject({ kind: 'waiting', reason: 'peers_pending' });
    const ok = await establishEpochKey(fakeDeps({ info: home, fetchOwnWrap: ownWrap, peerCommitments: async () => [home(), home()], options: { peerQuorum: 2 } }));
    expect(ok).toMatchObject({ kind: 'adopted', confirmed: true });
    const r2 = await establishEpochKey(fakeDeps({ info: home, fetchOwnWrap: ownWrap, peerCommitments: async () => [dissent, dissent, home()], options: { peerQuorum: 2 } }));
    expect(r2.kind).toBe('split');
  });
  it('options: raising only pollMs clamps settlePollMaxMs instead of throwing', async () => {
    const r = await establishEpochKey(fakeDeps({ info: () => ({ ...none(), state: 'legacy' }), options: { pollMs: 20_000 } }));
    expect(r.kind).toBe('legacy');
  });
  it('M15: read spacing holds with an instant waitForEvent and a lazily advancing clock', async () => {
    let t = 1_000_000;
    const at: number[] = [];
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false });
    await establishEpochKey(fakeDeps({
      info, now: () => t,
      sleep: (ms) => new Promise<void>((r) => setImmediate(() => { t += ms; r(); })),
      getCommitment: async () => { at.push(t); return info(); },
      waitForEvent: async () => {},
      options: { maxTotalMs: 20_000, minReadSpacingMs: 1_000 },
    }));
    expect(at.length).toBeGreaterThan(3);
    for (let i = 2; i < at.length; i++) expect(at[i]! - at[i - 1]!).toBeGreaterThanOrEqual(1_000);
  });
  it('W2b: winner reads stay >= minReadSpacingMs apart even when the event wait resolves at once', async () => {
    let t = 1_000_000;
    const at: number[] = [];
    const info = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: '11'.repeat(32), key_ts: 5, recorded_at: t, final: false });
    await establishEpochKey(fakeDeps({
      info, now: () => t, sleep: async (ms) => { t += ms; },
      getCommitment: async () => { at.push(t); return info(); },
      waitForEvent: async () => {},
      options: { maxTotalMs: 30_000, minReadSpacingMs: 1_000 },
    }));
    for (let i = 2; i < at.length; i++) expect(at[i]! - at[i - 1]!).toBeGreaterThanOrEqual(1_000);
  });
});

describe('audit r48 surviving mutants (R4, R7)', () => {
  it('R4: a supplied EscalationGate also gates `split`', async () => {
    let t = 1_000_000;
    const g = new EscalationGate(() => t);
    g.tryEscalate(CH);
    const k = new Uint8Array(32).fill(4);
    const c = computeKeyCommitment(SCOPE, 2, 5, k);
    const home = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
    const r = await establishEpochKey(fakeDeps({
      info: home, escalationGate: g, now: () => t,
      fetchOwnWrap: async () => ({ key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' }),
      peerCommitments: async () => [{ ...none(), state: 'arbitrated', key_commitment: '22'.repeat(32), key_ts: 4, recorded_at: 1, final: true }],
    }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'escalation_gated' });
  });

  it('R7: after a lock takeover the old call publishes nothing more', async () => {
    let t = 1_000_000;
    const pending = new PendingEpochKeyStore();
    let release!: () => void;
    const hold = new Promise<void>((r) => { release = r; });
    const targetsSeen: string[] = [];
    // A's own clock stays put (its budget is not what stops it here): the lock
    // ownership check alone must stop it — defence in depth behind the budget.
    const A = establishEpochKey(fakeDeps({
      info: none, pending, now: () => 1_000_000,
      listTargets: async () => [{ target: 'klv1x', deviceId: 'bb'.repeat(32), encPub: new Uint8Array(32) }],
      publish: async (tg) => { targetsSeen.push(tg.target); if (tg.target === 'klv1me') await hold; return { status: 'stored' as const }; },
    }));
    await new Promise((r) => setImmediate(r));
    t += 15 * 60_000 + 61_000; // A's lock is stale: B takes it over (and fails at its pre-check)
    const B = await establishEpochKey(fakeDeps({ info: none, pending, now: () => t, getCommitment: async () => { throw new Error('down'); } }));
    expect(B).toMatchObject({ kind: 'failed', reason: 'commitment_unavailable' });
    release();
    const ra = await A;
    expect(targetsSeen).toEqual(['klv1me']); // never reached klv1x
    expect(ra).toMatchObject({ kind: 'waiting', reason: 'pending_lost' });
  });
});

describe('audit r50', () => {
  const k = new Uint8Array(32).fill(4);
  const c = computeKeyCommitment(SCOPE, 2, 5, k);
  const home = (): KeyCommitmentInfo => ({ ...none(), state: 'arbitrated', key_commitment: keyCommitmentToHex(c), key_ts: 5, recorded_at: 1, final: true });
  const ownWrap = async () => ({ key: k.slice(), keyCommitment: c, keyTs: 5, epoch: 2, wallet: 'klv1o', signer: 'klv1o', msgId: 'm' });

  it('Q4/W1: evidence beyond what the node accepts → node_lagging with unrecoverableHere (no capped epoch <= seen)', async () => {
    const r = await establishEpochKey(fakeDeps({ info: () => ({ ...none(), epoch: 6 }), epoch: 6, highestEpochSeen: 1000, getCommitment: async (e?: number) => ({ ...none(), epoch: e === undefined ? 5 : 6 }) }));
    expect(r).toMatchObject({ kind: 'node_lagging', recoveryEpoch: 1001, unrecoverableHere: true });
    const r2 = await establishEpochKey(fakeDeps({ info: () => ({ ...none(), epoch: 6 }), epoch: 6, highestEpochSeen: 10, getCommitment: async (e?: number) => ({ ...none(), epoch: e === undefined ? 5 : 6 }) }));
    expect(r2).toMatchObject({ kind: 'node_lagging', recoveryEpoch: 11 });
    expect((r2 as any).unrecoverableHere).toBeUndefined();
  });

  it('takeover uses the lock OWNER\'s bound, not a new caller\'s tiny maxTotalMs', async () => {
    const s0 = new PendingEpochKeyStore();
    const tok = s0.tryLock(CH, 2, 1_000, 15 * 60_000 + 60_000);
    expect(tok).not.toBeNull();
    expect(s0.tryLock(CH, 2, 1_000 + 62_000, 1_000 + 60_000)).toBeNull(); // new caller's small bound is irrelevant
    expect(s0.tryLock(CH, 2, 1_000 + 16 * 60_000 + 1, 1)).not.toBeNull(); // owner's bound passed
  });

  it('N8c: after a takeover the OLD call\'s unlock never frees the new owner\'s lock', () => {
    const s0 = new PendingEpochKeyStore();
    const old = s0.tryLock(CH, 2, 0, 100)!;
    const neu = s0.tryLock(CH, 2, 1_000, 100)!; // takeover
    expect(neu).not.toBe(old);
    s0.unlock(CH, 2, old); // the old call's finally
    expect(s0.tryLock(CH, 2, 1_001, 100)).toBeNull(); // a third call is still refused
    expect(s0.holds(CH, 2, neu)).toBe(true);
  });

  it('N5b/N5c: peers_pending counts toward unconfirmed_exhausted; a success resets the streak', async () => {
    let t = 1_000_000;
    const pending = new PendingEpochKeyStore();
    const pendingPeer = async () => [{ ...none(), state: 'arbitrated' as const, key_commitment: '22'.repeat(32), key_ts: 4, recorded_at: 1, final: false }];
    const call = (peers: typeof pendingPeer | (() => Promise<KeyCommitmentInfo[]>)) => establishEpochKey(fakeDeps({
      info: home, pending, fetchOwnWrap: ownWrap, now: () => t, sleep: async (ms) => { t += ms; },
      peerCommitments: peers, options: { maxTotalMs: 10_000, maxUnconfirmedCalls: 3 },
    }));
    expect((await call(pendingPeer)).kind).toBe('waiting');
    expect((await call(pendingPeer)).kind).toBe('waiting');
    expect((await call(async () => [home()])).kind).toBe('adopted'); // resets
    expect((await call(pendingPeer)).kind).toBe('waiting');
    expect((await call(pendingPeer)).kind).toBe('waiting');
    expect(await call(pendingPeer)).toMatchObject({ kind: 'unconfirmed_exhausted', lastReason: 'peers_pending' });
  });

  it('N6b: with peerQuorum 2, fewer answers for THIS epoch than the quorum keeps the key unconfirmed', async () => {
    const r = await establishEpochKey(fakeDeps({
      info: home, fetchOwnWrap: ownWrap, options: { peerQuorum: 2, maxTotalMs: 20_000 },
      peerCommitments: async () => [home(), { ...none(), epoch: 7 }], // second answer is for another epoch
    }));
    expect(r).toMatchObject({ kind: 'waiting', reason: 'peers_pending' });
  });
});
