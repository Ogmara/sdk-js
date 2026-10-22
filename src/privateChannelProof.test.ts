/**
 * "Verify before cover" (sdk-js 0.66.0): golden-vector parity with the node's
 * join gate (l2-node 0.142.0 `tests/fixtures/phase2/vectors.json`, copied to
 * `fixtures/phase2-vectors.json`) plus negative / edge tests the vectors do
 * not cover.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WalletSigner } from './auth';
import {
  buildAddModerator,
  buildBan,
  buildChannelCreate,
  buildChannelJoin,
  buildEnvelope,
  buildInvite,
  buildKick,
  buildRemoveModerator,
} from './envelope';
import { base64ToBytes, bytesToBase64 } from './invite';
import {
  MAX_VERIFICATIONS_PER_RESPONSE,
  MemberProofCache,
  MemberProofsError,
  budgetOf,
  deviceClaimCovers,
  filterVerifiedMembers,
  legacyJoinActivationMs,
  verifyDeviceClaim,
  verifyDeviceClaimObject,
  verifyEncKeyBinding,
  verifyEnvelopeBytes,
  verifyPrivateMemberProof,
  type PrivateMemberProofBundle,
  type PrivateMemberProofContext,
} from './privateChannelProof';
import { derivePrivateChannelId } from './channelId';
import { MessageType } from './types';
import type { MemberProofsResponse } from './types';
import type { OgmaraClient } from './client';

const FIXTURE = resolve(__dirname, '../fixtures/phase2-vectors.json');
const SIBLING = resolve(__dirname, '../../l2-node/tests/fixtures/phase2/vectors.json');
const V = JSON.parse(readFileSync(FIXTURE, 'utf8'));
const NET: string = V.network;

type Case = (typeof V.cases)[number];

function bundleOf(c: Case, overrides: Partial<PrivateMemberProofBundle> = {}): PrivateMemberProofBundle {
  return {
    address: c.wallet,
    channel_create: c.channel_create,
    join: c.join,
    removals: c.removals,
    moderator_grants: c.moderator_grants,
    moderator_removals: c.moderator_removals,
    device_claims: c.device_claims,
    ...overrides,
  };
}
function ctxOf(c: Case, overrides: Partial<PrivateMemberProofContext> = {}): PrivateMemberProofContext {
  return { channelId: c.channel_id, network: NET, activationMs: c.activation_ms, ...overrides };
}
const caseNamed = (n: string): Case => V.cases.find((c: Case) => c.name === n)!;

afterEach(() => {
  vi.useRealTimers();
});

describe('golden vectors (l2-node 0.142.0)', () => {
  it('fixture copy matches the sibling l2-node checkout when present', () => {
    expect(V.format).toBe('ogmara-phase2-golden-vectors/2');
    if (existsSync(SIBLING)) {
      expect(readFileSync(FIXTURE, 'utf8')).toBe(readFileSync(SIBLING, 'utf8'));
    }
  });

  it('covers every documented case', () => {
    expect(V.cases.length).toBeGreaterThanOrEqual(22);
  });

  /**
   * The node's rejection message (`node_reason`) → the SDK reason for the
   * SAME rule. A vector failing for a different reason than the node's is a
   * parity bug even when the verdict matches. An unmapped node reason fails
   * the test (extend the table when the node adds a case).
   */
  const NODE_TO_SDK_REASON: [RegExp, string][] = [
    [/^private channel: inviter is not creator or moderator$/, 'inviter_not_authorized'],
    [/^invite is addressed to a different wallet$/, 'invite_wrong_target'],
    [/^invite is for a different channel$/, 'invite_wrong_channel'],
    [/^invite has expired$/, 'invite_expired'],
    [/^invite is dated after the join$/, 'invite_after_join'],
    [/^invite predates the joiner's removal from this channel$/, 'invite_predates_removal'],
    [/^join signer does not resolve to the wallet$/, 'join_signer_mismatch'],
    [/^embedded ChannelJoin: msg_id mismatch/, 'join_invalid:msg_id_mismatch'],
    [/^embedded ChannelInvite: msg_id mismatch/, 'invite_invalid:msg_id_mismatch'],
    [/^embedded envelope is ChannelJoin, expected ChannelInvite$/, 'invite_invalid:wrong_msg_type'],
    [/^embedded ChannelInvite exceeds 2048 bytes$/, 'invite_size'],
    [/^private channel: invite proof required$/, 'invite_required'],
  ];
  const sdkReasonFor = (nodeReason: string): string | undefined =>
    NODE_TO_SDK_REASON.find(([re]) => re.test(nodeReason))?.[1];

  for (const c of V.cases as Case[]) {
    it(`${c.name}: ${c.expected}`, async () => {
      const r = await verifyPrivateMemberProof(bundleOf(c), ctxOf(c));
      expect(r.ok, `${c.name}: ${JSON.stringify(r)} (node: ${c.node_reason})`).toBe(c.expected === 'valid');
      if (r.ok) {
        expect(c.node_reason).toBeNull();
        expect(r.creator).toBe(c.creator);
        expect(r.creatorSource).toBe('derived');
      } else {
        const expected = sdkReasonFor(c.node_reason);
        expect(expected, `unmapped node_reason: ${c.node_reason}`).toBeDefined();
        expect(r.reason, `${c.name} (node: ${c.node_reason})`).toBe(expected);
      }
    });
  }

  it('device claims in the vectors follow the time window', async () => {
    for (const c of V.cases as Case[]) {
      for (const dc of Object.values(c.device_claims) as any[]) {
        const joinTs = (await verifyEnvelopeBytesLoose(c.join)).timestamp;
        const r = await verifyDeviceClaim(dc, NET, joinTs);
        expect(r.ok, c.name).toBe(c.expected === 'valid');
      }
    }
  });

  it('enc-binding vector verifies; tampering does not', async () => {
    const e = V.enc_binding;
    const rec = { enc_pub: e.enc_pub, device_id: e.device_id, created_at: e.ts, ts: e.ts, bound: true, wallet_signature: e.wallet_signature };
    expect(await verifyEncKeyBinding(rec, e.wallet, NET)).toEqual({ status: 'bound' });
    expect((await verifyEncKeyBinding({ ...rec, ts: e.ts + 1 }, e.wallet, NET)).status).toBe('invalid');
    expect((await verifyEncKeyBinding({ ...rec, enc_pub: 'ab'.repeat(32) }, e.wallet, NET)).status).toBe('invalid');
    expect((await verifyEncKeyBinding(rec, e.wallet, 'mainnet')).status).toBe('invalid');
    expect((await verifyEncKeyBinding(rec, V.keys.attacker.address, NET)).status).toBe('invalid');
    expect(await verifyEncKeyBinding({ ...rec, bound: false, wallet_signature: undefined }, e.wallet, NET)).toEqual({ status: 'unbound' });
    expect((await verifyEncKeyBinding({ ...rec, revoked: true }, e.wallet, NET)).status).toBe('invalid');
  });
});

async function verifyEnvelopeBytesLoose(b64: string) {
  const r = await verifyEnvelopeBytes(base64ToBytes(b64)!, NET);
  if (!r.ok) throw new Error(r.reason);
  return r.envelope;
}

describe('verification budget', () => {
  it('M15: a caller can lower the budget but never raise it past the clamp', () => {
    expect(budgetOf(5)).toBe(5);
    expect(budgetOf(MAX_VERIFICATIONS_PER_RESPONSE)).toBe(MAX_VERIFICATIONS_PER_RESPONSE);
    expect(budgetOf(MAX_VERIFICATIONS_PER_RESPONSE + 1)).toBe(MAX_VERIFICATIONS_PER_RESPONSE);
    expect(budgetOf(1e12)).toBe(MAX_VERIFICATIONS_PER_RESPONSE);
    for (const bad of [0, -1, Number.NaN, 1.5, undefined]) expect(budgetOf(bad as any)).toBe(MAX_VERIFICATIONS_PER_RESPONSE);
    expect(MAX_VERIFICATIONS_PER_RESPONSE).toBe(2000);
  });

  it('M20: verifying a device claim spends budget (create + join + device claim + invite = 4)', async () => {
    const c = caseNamed('device_signed_join_valid');
    expect(await verifyPrivateMemberProof(bundleOf(c), ctxOf(c, { verificationBudget: 4 }))).toMatchObject({ ok: true });
    expect(await verifyPrivateMemberProof(bundleOf(c), ctxOf(c, { verificationBudget: 3 }))).toMatchObject({
      ok: false,
      reason: 'verification_budget_exhausted',
    });
  });
});

describe('verifyEnvelopeBytes', () => {
  const joinB64 = caseNamed('valid_creator_invite').join;
  const raw = () => base64ToBytes(joinB64)!;

  it('accepts a genuine envelope and reports the form', async () => {
    const r = await verifyEnvelopeBytes(raw(), NET, { expectedType: MessageType.ChannelJoin });
    expect(r.ok && r.envelope.signatureForm).toBe('ogmara');
    expect(r.ok && r.envelope.author).toBe(V.keys.joiner.address);
  });

  it('rejects wrong network, wrong type, oversize and every single-byte flip', async () => {
    expect((await verifyEnvelopeBytes(raw(), 'mainnet')).ok).toBe(false);
    expect((await verifyEnvelopeBytes(raw(), NET, { expectedType: MessageType.ChannelInvite })).ok).toBe(false);
    expect((await verifyEnvelopeBytes(raw(), NET, { maxBytes: 100 })).ok).toBe(false);
    expect((await verifyEnvelopeBytes(new Uint8Array(0), NET)).ok).toBe(false);
    const bytes = raw();
    // `lamport_ts` and `relay_path` are NOT signed (same as the node): skip
    // their bytes. Every other single-bit flip must break verification.
    const enc = new TextEncoder();
    const find = (key: string) => {
      const k = enc.encode(key);
      for (let i = 0; i + k.length <= bytes.length; i++) if (k.every((b, j) => bytes[i + j] === b)) return i + k.length;
      throw new Error(key);
    };
    const lamportValueAt = find('lamport_ts');
    const relayKeyAt = find('relay_path') - 'relay_path'.length - 1;
    for (let i = 0; i < relayKeyAt; i += 3) {
      if (i === lamportValueAt) continue;
      const t = bytes.slice();
      t[i] ^= 0x01;
      expect((await verifyEnvelopeBytes(t, NET)).ok, `flip @${i}`).toBe(false);
    }
  });

  it('never throws on garbage', async () => {
    for (const g of [new Uint8Array([0xc1]), new Uint8Array([0x90]), new Uint8Array(64).fill(0xff)]) {
      expect((await verifyEnvelopeBytes(g, NET)).ok).toBe(false);
    }
  });
});

describe('device claims', () => {
  const dc = caseNamed('device_signed_join_valid').device_claims[V.keys.joiner_device.address];

  it('verifies, and applies the window at its edges', async () => {
    const v = await verifyDeviceClaimObject(dc, NET);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const d = dc.delegations[0].timestamp;
    expect(deviceClaimCovers(v.claim, d - 1)).toBe(false);
    expect(deviceClaimCovers(v.claim, d)).toBe(true);
    const revoked = { ...v.claim, revocationTimestamps: [d + 10] };
    expect(deviceClaimCovers(revoked, d + 9)).toBe(true);
    expect(deviceClaimCovers(revoked, d + 10)).toBe(false);
  });

  it('rejects a swapped address, wrong network, a tampered signature, and malformed revocations', async () => {
    expect((await verifyDeviceClaimObject({ ...dc, device_address: V.keys.forged_device.address }, NET)).ok).toBe(false);
    expect((await verifyDeviceClaimObject(dc, 'mainnet')).ok).toBe(false);
    expect((await verifyDeviceClaimObject({ ...dc, wallet: V.keys.attacker.address }, NET)).ok).toBe(false);
    const sig = base64ToBytes(dc.delegations[0].device_signature)!;
    sig[5] ^= 1;
    const tampered = { ...dc, delegations: [{ ...dc.delegations[0], device_signature: bytesToBase64(sig) }] };
    expect((await verifyDeviceClaimObject(tampered, NET)).ok).toBe(false);
    expect((await verifyDeviceClaimObject({ ...dc, revocations: ['!!!'] }, NET)).ok).toBe(false);
    expect((await verifyDeviceClaimObject({ ...dc, revocations: Array(5).fill(dc.delegations[0].wallet_signature) }, NET)).ok).toBe(false);
  });
});

describe('verifyPrivateMemberProof — vector-derived negatives', () => {
  const valid = caseNamed('valid_creator_invite');

  it('swapped target: the same bundle presented for another wallet fails', async () => {
    const r = await verifyPrivateMemberProof(bundleOf(valid, { address: V.keys.attacker.address }), ctxOf(valid));
    expect(r.ok).toBe(false);
  });

  it('wrong network / wrong channel id fail', async () => {
    expect((await verifyPrivateMemberProof(bundleOf(valid), ctxOf(valid, { network: 'mainnet' }))).ok).toBe(false);
    expect((await verifyPrivateMemberProof(bundleOf(valid), ctxOf(valid, { channelId: valid.channel_id + 1 }))).ok).toBe(false);
  });

  it('tampered join bytes fail', async () => {
    const b = base64ToBytes(valid.join)!;
    b[Math.floor(b.length / 2)] ^= 0x40; // inside the signed payload
    expect((await verifyPrivateMemberProof(bundleOf(valid, { join: bytesToBase64(b) }), ctxOf(valid))).ok).toBe(false);
  });

  it('a missing or forged ChannelCreate fails closed (no creator anchor) — for the right reason', async () => {
    expect(await verifyPrivateMemberProof(bundleOf(valid, { channel_create: null }), ctxOf(valid))).toEqual({
      ok: false,
      reason: 'no_channel_create',
    });
    expect(await verifyPrivateMemberProof(bundleOf(valid, { channel_create: valid.join }), ctxOf(valid))).toEqual({
      ok: false,
      reason: 'channel_create_invalid:wrong_msg_type',
    });
  });

  it('the oversized-invite vector fails at the size gate (invite_size)', async () => {
    const c = caseNamed('oversized_invite');
    expect(await verifyPrivateMemberProof(bundleOf(c), ctxOf(c))).toMatchObject({ ok: false, reason: 'invite_size' });
  });

  it('a creator pin that disagrees with the derived creator fails closed; a matching pin wins', async () => {
    const r = await verifyPrivateMemberProof(bundleOf(valid), ctxOf(valid, { pinnedCreator: V.keys.attacker.address }));
    expect(r).toEqual({ ok: false, reason: 'creator_pin_mismatch' });
    const ok = await verifyPrivateMemberProof(bundleOf(valid), ctxOf(valid, { pinnedCreator: valid.creator }));
    expect(ok).toMatchObject({ ok: true, creatorSource: 'pinned', creator: valid.creator });
    // With a pin, no ChannelCreate is needed at all.
    const noCreate = await verifyPrivateMemberProof(bundleOf(valid, { channel_create: null }), ctxOf(valid, { pinnedCreator: valid.creator }));
    expect(noCreate).toMatchObject({ ok: true, creatorSource: 'pinned' });
  });

  it('the creator verifies without a join; a "creator" basis for anyone else fails', async () => {
    const r = await verifyPrivateMemberProof(bundleOf(valid, { address: valid.creator, join: null, basis: 'creator' }), ctxOf(valid));
    expect(r.ok && r.basis).toBe('creator');
    expect((await verifyPrivateMemberProof(bundleOf(valid, { basis: 'creator' }), ctxOf(valid))).ok).toBe(false);
  });

  it('unavailable members fail with the node reason (truncated, oversized_evidence)', async () => {
    for (const reason of ['truncated', 'oversized_evidence', 'no_join']) {
      const r = await verifyPrivateMemberProof(bundleOf(valid, { basis: 'unavailable', reason }), ctxOf(valid));
      expect(r).toEqual({ ok: false, reason: `unavailable:${reason}` });
    }
  });

  it('seenRemovals: a locally remembered kick after the invite kills it, and new verified kicks are recorded', async () => {
    const inviteTs = V.base_timestamp_ms + 5 * 60_000;
    const seen = new Map([[valid.wallet, inviteTs]]);
    expect((await verifyPrivateMemberProof(bundleOf(valid), ctxOf(valid, { seenRemovals: seen }))).ok).toBe(false);
    const kc = caseNamed('kick_cutoff');
    const rec = new Map<string, number>();
    await verifyPrivateMemberProof(bundleOf(kc), ctxOf(kc, { seenRemovals: rec }));
    expect(rec.get(kc.wallet)).toBe(V.base_timestamp_ms + 7 * 60_000);
  });

  it('a removal list beyond the node cap fails closed', async () => {
    const kc = caseNamed('kicked_then_reinvited');
    const r = await verifyPrivateMemberProof(bundleOf(kc, { removals: Array(17).fill(kc.removals[0]) }), ctxOf(kc));
    expect(r.ok).toBe(false);
  });

  it('legacy activation: mainnet is always enforced; the testnet default is the constant', async () => {
    const lb = caseNamed('legacy_before_activation');
    expect(legacyJoinActivationMs('testnet')).toBe(1793491200000);
    expect(legacyJoinActivationMs('mainnet')).toBe(0);
    // Testnet default (2026-11-01) is after the vector's join → legacy-valid.
    expect((await verifyPrivateMemberProof(bundleOf(lb), ctxOf(lb, { activationMs: undefined }))).ok).toBe(true);
    // A mainnet context ignores any supplied activation.
    expect((await verifyPrivateMemberProof(bundleOf(lb), ctxOf(lb, { network: 'mainnet' }))).ok).toBe(false);
  });

  it('never throws on hostile bundle shapes', async () => {
    const hostile: any[] = [
      null,
      {},
      { ...bundleOf(valid), removals: 'x' },
      { ...bundleOf(valid), device_claims: { [V.keys.joiner_device.address]: null } },
      { ...bundleOf(valid), moderator_grants: { [V.keys.moderator.address]: 7 } },
      { ...bundleOf(valid), join: 12 },
    ];
    for (const h of hostile) {
      await expect(verifyPrivateMemberProof(h, ctxOf(valid))).resolves.toHaveProperty('ok');
    }
  });
});

// --- Scenarios crafted with the vector keys (SDK-built envelopes) -------------

async function signer(seedHex: string, device?: { seedHex: string }, net: string = NET): Promise<WalletSigner> {
  if (device) {
    const s = await WalletSigner.fromHex(device.seedHex);
    s.walletAddress = (await WalletSigner.fromHex(seedHex)).address;
    s.network = net;
    return s;
  }
  const s = await WalletSigner.fromHex(seedHex);
  s.network = net;
  return s;
}

const T0 = 1_800_000_000_000;
const MIN = 60_000;

async function at<T>(ts: number, f: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(ts);
  try {
    return await f();
  } finally {
    vi.useRealTimers();
  }
}

async function world(net: string = NET) {
  const c = await signer(V.keys.creator.seed_hex, undefined, net);
  const m = await signer(V.keys.moderator.seed_hex, undefined, net);
  const j = await signer(V.keys.joiner.seed_hex, undefined, net);
  const x = await signer(V.keys.attacker.seed_hex, undefined, net);
  const { channelId, idDerivationTs } = derivePrivateChannelId(c.address, 'crafted', T0);
  const create = await at(T0, () =>
    buildChannelCreate(c, { channelId, idDerivationTs, slug: 'crafted', channelType: 2 } as any),
  );
  const b64 = bytesToBase64;
  const base = (join: Uint8Array, extra: Partial<PrivateMemberProofBundle> = {}): PrivateMemberProofBundle => ({
    address: j.address,
    channel_create: b64(create),
    join: b64(join),
    removals: [],
    moderator_grants: {},
    moderator_removals: {},
    device_claims: {},
    ...extra,
  });
  const ctx: PrivateMemberProofContext = { channelId, network: net, activationMs: 0 };
  /** A raw Private/other ChannelCreate signed by `by`, optionally with a derivation ts. */
  const rawCreate = (by: WalletSigner, opts: { id?: number; type?: number; dts?: number } = {}) =>
    at(T0, () =>
      buildEnvelope(by, MessageType.ChannelCreate, {
        channel_id: opts.id ?? channelId, slug: 'crafted', channel_type: opts.type ?? 2, display_name: null,
        description: null, content_rating: 0, moderation: { admins: [], rules: null },
        ...(opts.dts !== undefined ? { id_derivation_ts: opts.dts } : {}),
      }),
    );
  return { c, m, j, x, channelId, idDerivationTs, create, base, ctx, b64, rawCreate };
}

describe('verifyPrivateMemberProof — crafted scenarios', () => {
  it('SDK-built creator invite + join verifies (cross-implementation round trip)', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address, 'https://host.example'));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const r = await verifyPrivateMemberProof(w.base(join), w.ctx);
    expect(r).toMatchObject({ ok: true, basis: 'invite', inviter: w.c.address, creatorSource: 'derived' });
  });

  it('a ChannelInvite smuggled into the grant slot is refused (no nesting)', async () => {
    const w = await world();
    const fakeGrant = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.m.address));
    const inv = await at(T0 + 2 * MIN, () =>
      buildInvite(w.m, w.channelId, w.j.address, undefined, { inviterGrant: fakeGrant.slice(0, 1024) }),
    );
    const join = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    expect((await verifyPrivateMemberProof(w.base(join), w.ctx)).ok).toBe(false);
  });

  it('a grant dated after the invite does not authorize it', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.m, w.channelId, w.j.address));
    const g = await at(T0 + 2 * MIN, () => buildAddModerator(w.c, { channelId: w.channelId, targetUser: w.m.address, permissions: perms() } as any));
    const join = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const r = await verifyPrivateMemberProof(w.base(join, { moderator_grants: { [w.m.address]: [w.b64(g)] } }), w.ctx);
    expect(r.ok).toBe(false);
  });

  it('demotion AFTER the invite does not kill it (sync semantics), demotion before does', async () => {
    const w = await world();
    const g = await at(T0 + MIN, () => buildAddModerator(w.c, { channelId: w.channelId, targetUser: w.m.address, permissions: perms() } as any));
    const inv = await at(T0 + 3 * MIN, () => buildInvite(w.m, w.channelId, w.j.address));
    const join = await at(T0 + 4 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const rmLate = await at(T0 + 5 * MIN, () => buildRemoveModerator(w.c, w.channelId, w.m.address));
    const rmEarly = await at(T0 + 2 * MIN, () => buildRemoveModerator(w.c, w.channelId, w.m.address));
    const grants = { [w.m.address]: [w.b64(g)] };
    expect((await verifyPrivateMemberProof(w.base(join, { moderator_grants: grants, moderator_removals: { [w.m.address]: [w.b64(rmLate)] } }), w.ctx)).ok).toBe(true);
    expect((await verifyPrivateMemberProof(w.base(join, { moderator_grants: grants, moderator_removals: { [w.m.address]: [w.b64(rmEarly)] } }), w.ctx)).ok).toBe(false);
    // A RemoveModerator signed by someone other than the creator is not evidence.
    const rmForged = await at(T0 + 2 * MIN, () => buildRemoveModerator(w.x, w.channelId, w.m.address));
    expect((await verifyPrivateMemberProof(w.base(join, { moderator_grants: grants, moderator_removals: { [w.m.address]: [w.b64(rmForged)] } }), w.ctx)).ok).toBe(true);
  });

  it('removals: a kick before the invite is harmless; a ban after the join kills; an unauthorized relevant kick fails closed', async () => {
    const w = await world();
    const inv = await at(T0 + 2 * MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const early = await at(T0 + MIN, () => buildKick(w.c, w.channelId, w.j.address));
    const ban = await at(T0 + 4 * MIN, () => buildBan(w.c, w.channelId, w.j.address, undefined, 0));
    const rogue = await at(T0 + 4 * MIN, () => buildKick(w.x, w.channelId, w.j.address));
    const rogueOld = await at(T0 + MIN, () => buildKick(w.x, w.channelId, w.j.address));
    const otherTarget = await at(T0 + 4 * MIN, () => buildKick(w.c, w.channelId, w.x.address));
    expect((await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(early)] }), w.ctx)).ok).toBe(true);
    expect((await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(ban)] }), w.ctx)).ok).toBe(false);
    expect((await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(rogue)] }), w.ctx)).ok).toBe(false);
    expect((await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(rogueOld), w.b64(otherTarget)] }), w.ctx)).ok).toBe(true);
  });

  it('C1: an underived create is refused by default (creator downgrade), even when the attacker claims basis creator', async () => {
    const w = await world();
    const attackerCreate = await w.rawCreate(w.x); // no id_derivation_ts, signed by the attacker
    const asCreator = w.base(new Uint8Array(0), {
      address: w.x.address, basis: 'creator', join: null, channel_create: w.b64(attackerCreate),
    });
    expect(await verifyPrivateMemberProof(asCreator, w.ctx)).toEqual({ ok: false, reason: 'creator_not_derived' });
    // A pin (from an earlier, derived establishment) beats it too.
    expect(await verifyPrivateMemberProof(asCreator, { ...w.ctx, pinnedCreator: w.c.address })).toEqual({
      ok: false,
      reason: 'creator_pin_mismatch',
    });
  });

  it('C1: pre-0.139 create only with the explicit opt-in: first_seen, then pinned / mismatch', async () => {
    const w = await world();
    const legacyCreate = await w.rawCreate(w.c);
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const b = w.base(join, { channel_create: w.b64(legacyCreate) });
    expect(await verifyPrivateMemberProof(b, w.ctx)).toEqual({ ok: false, reason: 'creator_not_derived' });
    const optIn = { ...w.ctx, allowUnderivedCreator: true };
    expect(await verifyPrivateMemberProof(b, optIn)).toMatchObject({ ok: true, creatorSource: 'first_seen', creator: w.c.address });
    expect(await verifyPrivateMemberProof(b, { ...optIn, pinnedCreator: w.c.address })).toMatchObject({ ok: true, creatorSource: 'pinned' });
    expect(await verifyPrivateMemberProof(b, { ...optIn, pinnedCreator: w.x.address })).toEqual({ ok: false, reason: 'creator_pin_mismatch' });
  });

  it('C1/W4 derivation: a create whose derivation names someone else is refused (channel_id_derivation_mismatch)', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const forged = await w.rawCreate(w.x, { dts: w.idDerivationTs });
    expect(await verifyPrivateMemberProof(w.base(join, { channel_create: w.b64(forged) }), w.ctx)).toEqual({
      ok: false,
      reason: 'channel_id_derivation_mismatch',
    });
    const wrongTs = await w.rawCreate(w.c, { dts: w.idDerivationTs + 1 });
    expect(await verifyPrivateMemberProof(w.base(join, { channel_create: w.b64(wrongTs) }), w.ctx)).toEqual({
      ok: false,
      reason: 'channel_id_derivation_mismatch',
    });
  });

  it('W4 create_channel / create_private', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const other = derivePrivateChannelId(w.c.address, 'crafted', T0 + 50_000);
    const otherCreate = await w.rawCreate(w.c, { id: other.channelId, dts: other.idDerivationTs });
    expect(await verifyPrivateMemberProof(w.base(join, { channel_create: w.b64(otherCreate) }), w.ctx)).toEqual({
      ok: false,
      reason: 'channel_create_wrong_channel',
    });
    const publicCreate = await w.rawCreate(w.c, { type: 0, dts: w.idDerivationTs });
    expect(await verifyPrivateMemberProof(w.base(join, { channel_create: w.b64(publicCreate) }), w.ctx)).toEqual({
      ok: false,
      reason: 'channel_not_private',
    });
  });

  it('W4 grant_target: a creator-signed grant naming someone else does not authorize the inviter', async () => {
    const w = await world();
    const gOther = await at(T0 + MIN, () => buildAddModerator(w.c, { channelId: w.channelId, targetUser: w.x.address, permissions: perms() } as any));
    const inv = await at(T0 + 2 * MIN, () => buildInvite(w.m, w.channelId, w.j.address, undefined, { inviterGrant: gOther }));
    const join = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    expect(await verifyPrivateMemberProof(w.base(join), w.ctx)).toMatchObject({ ok: false, reason: 'inviter_not_authorized' });
    // Control: the same shape with the grant naming the inviter verifies.
    const gM = await at(T0 + MIN, () => buildAddModerator(w.c, { channelId: w.channelId, targetUser: w.m.address, permissions: perms() } as any));
    const invOk = await at(T0 + 2 * MIN, () => buildInvite(w.m, w.channelId, w.j.address, undefined, { inviterGrant: gM }));
    const joinOk = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: invOk }));
    expect(await verifyPrivateMemberProof(w.base(joinOk), w.ctx)).toMatchObject({ ok: true, inviter: w.m.address });
  });

  it('W4 join_channel: a join signed for another channel fails (join_wrong_channel)', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId + 1, { invite: inv }));
    expect(await verifyPrivateMemberProof(w.base(join), w.ctx)).toMatchObject({ ok: false, reason: 'join_wrong_channel' });
  });

  it('W4 legacy activation boundary is strict (<): join.ts == activation fails, activation = join.ts + 1 passes', async () => {
    const w = await world();
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId));
    const jts = T0 + 2 * MIN;
    expect(await verifyPrivateMemberProof(w.base(join), { ...w.ctx, activationMs: jts })).toMatchObject({ ok: false, reason: 'invite_required' });
    expect(await verifyPrivateMemberProof(w.base(join), { ...w.ctx, activationMs: jts + 1 })).toMatchObject({ ok: true, basis: 'legacy' });
  });

  it('W4 mainnet_force: a caller activationMs is ignored on mainnet', async () => {
    const w = await world('mainnet');
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId));
    const huge = Number.MAX_SAFE_INTEGER;
    expect(await verifyPrivateMemberProof(w.base(join), { ...w.ctx, activationMs: huge })).toMatchObject({
      ok: false,
      reason: 'invite_required',
    });
    // Control: the same mainnet evidence with an invite verifies (so the
    // failure above is the activation, not the network).
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const joinInv = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    expect(await verifyPrivateMemberProof(w.base(joinInv), { ...w.ctx, activationMs: huge })).toMatchObject({ ok: true });
  });

  it('W4 removed_after_join: a removal between the join and a later-dated invite still kills it', async () => {
    const w = await world();
    // Invite dated 2 min AFTER the join (inside the 5-min drift allowance).
    const inv = await at(T0 + 4 * MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const kick = await at(T0 + 3 * MIN, () => buildKick(w.c, w.channelId, w.j.address));
    expect(await verifyPrivateMemberProof(w.base(join), w.ctx)).toMatchObject({ ok: true });
    expect(await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(kick)] }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'removed_after_join',
    });
  });

  it('N1: anchor_node prefixes are stripped repeatedly and the length is counted in bytes, like the node', async () => {
    const w = await world();
    for (const anchor of ['https://https://127.0.0.1/', 'https://' + 'é'.repeat(125)]) {
      const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address, anchor));
      const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
      expect(await verifyPrivateMemberProof(w.base(join), w.ctx), anchor).toMatchObject({ ok: false, reason: 'invite_malformed' });
    }
  });

  it('W2: stale removals (before the invite/join) are skipped without signature work; the budget fails closed', async () => {
    const w = await world();
    const inv = await at(T0 + 30 * MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 31 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const stale: string[] = [];
    for (let i = 0; i < 16; i++) stale.push(w.b64(await at(T0 + (i + 1) * MIN, () => buildKick(w.c, w.channelId, w.j.address))));
    // Budget 3 = create + join + invite: passes only if no stale removal is verified.
    expect(await verifyPrivateMemberProof(w.base(join, { removals: stale }), { ...w.ctx, verificationBudget: 3 })).toMatchObject({ ok: true });
    // Budget 2: the invite can no longer be verified → fails closed, never open.
    expect(await verifyPrivateMemberProof(w.base(join), { ...w.ctx, verificationBudget: 2 })).toMatchObject({
      ok: false,
      reason: 'verification_budget_exhausted',
    });
    // A RELEVANT removal refused by the budget must not read as "not genuine".
    const late = await at(T0 + 32 * MIN, () => buildKick(w.c, w.channelId, w.j.address));
    expect(await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(late)] }), { ...w.ctx, verificationBudget: 3 })).toMatchObject({
      ok: false,
      reason: 'verification_budget_exhausted',
    });
  });

  it('W1: a 10 MB nested payload is rejected before any decode', async () => {
    const w = await world();
    const huge = 'kZGR'.repeat(3_500_000); // base64 of 10.5 MB of 0x91 (nested 1-element arrays)
    const start = performance.now();
    expect(await verifyPrivateMemberProof(w.base(new Uint8Array(0), { join: huge }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'join_invalid:size_or_encoding',
    });
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    expect(await verifyPrivateMemberProof(w.base(join, { removals: [huge] }), w.ctx)).toMatchObject({ ok: true });
    expect(await verifyPrivateMemberProof(w.base(join, { channel_create: huge }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'channel_create_invalid:size_or_encoding',
    });
    const bytes = new Uint8Array(10 * 1024 * 1024).fill(0x91);
    expect((await verifyEnvelopeBytes(bytes, NET)).ok).toBe(false);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('a device-signed join without its device claim fails closed', async () => {
    const w = await world();
    const dev = await signer(V.keys.joiner.seed_hex, { seedHex: V.keys.joiner_device.seed_hex });
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(dev, w.channelId, { invite: inv }));
    expect((await verifyPrivateMemberProof(w.base(join), w.ctx)).ok).toBe(false);
  });

  it('an oversized join (> 16 KiB) is refused', async () => {
    const w = await world();
    const big = await at(T0 + MIN, () => buildEnvelope(w.j, MessageType.ChannelJoin, { channel_id: w.channelId, pad: 'a'.repeat(17_000) }));
    expect(big.length).toBeGreaterThan(16 * 1024);
    expect(await verifyPrivateMemberProof(w.base(big), w.ctx)).toMatchObject({
      ok: false,
      reason: 'join_invalid:size_or_encoding',
    });
  });

  it('M12: removal boundaries — a kick exactly at invite.ts or exactly at join.ts kills; one ms before is skipped', async () => {
    const w = await world();
    // invite before join: relevantFrom = invite.ts
    const inv = await at(T0 + 2 * MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const atInvite = await at(T0 + 2 * MIN, () => buildKick(w.c, w.channelId, w.j.address));
    const before = await at(T0 + 2 * MIN - 1, () => buildKick(w.c, w.channelId, w.j.address));
    expect(await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(atInvite)] }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'invite_predates_removal',
    });
    expect(await verifyPrivateMemberProof(w.base(join, { removals: [w.b64(before)] }), w.ctx)).toMatchObject({ ok: true });
    // invite dated after the join (within drift): relevantFrom = join.ts
    const inv2 = await at(T0 + 4 * MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join2 = await at(T0 + 3 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv2 }));
    const atJoin = await at(T0 + 3 * MIN, () => buildKick(w.c, w.channelId, w.j.address));
    const beforeJoin = await at(T0 + 3 * MIN - 1, () => buildKick(w.c, w.channelId, w.j.address));
    expect(await verifyPrivateMemberProof(w.base(join2, { removals: [w.b64(atJoin)] }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'removed_after_join',
    });
    expect(await verifyPrivateMemberProof(w.base(join2, { removals: [w.b64(beforeJoin)] }), w.ctx)).toMatchObject({ ok: true });
  });

  it('M19: anchor_node in 172.16.0.0/12 is refused, neighbours are not', async () => {
    const w = await world();
    const cases: [string, boolean][] = [
      ['https://172.16.0.1/', false],
      ['https://172.31.255.254:8080/', false],
      ['https://172.15.0.1/', true],
      ['https://172.32.0.1/', true],
    ];
    for (const [anchor, ok] of cases) {
      const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address, anchor));
      const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
      const r = await verifyPrivateMemberProof(w.base(join), w.ctx);
      if (ok) expect(r, anchor).toMatchObject({ ok: true });
      else expect(r, anchor).toMatchObject({ ok: false, reason: 'invite_malformed' });
    }
  });

  it('M9: the base64 length gate sits exactly at 16 KiB of decoded bytes', async () => {
    const w = await world();
    const exact = bytesToBase64(new Uint8Array(16 * 1024)); // passes the gate, then fails to decode
    const over = bytesToBase64(new Uint8Array(16 * 1024 + 1));
    const over3 = bytesToBase64(new Uint8Array(16 * 1024 + 3)); // one base64 quantum longer
    expect(await verifyPrivateMemberProof(w.base(new Uint8Array(0), { join: exact }), w.ctx)).toMatchObject({
      ok: false,
      reason: 'join_invalid:not_an_envelope',
    });
    for (const s of [over, over3]) {
      expect(await verifyPrivateMemberProof(w.base(new Uint8Array(0), { join: s }), w.ctx)).toMatchObject({
        ok: false,
        reason: 'join_invalid:size_or_encoding',
      });
    }
  });
});

function perms() {
  return { can_mute: true, can_kick: true, can_ban: true, can_pin: true, can_edit_info: false, can_delete_msgs: false };
}

// --- filterVerifiedMembers -----------------------------------------------------------

function responseFrom(cases: Case[]): MemberProofsResponse {
  const first = cases[0]!;
  return {
    channel_id: first.channel_id,
    creator: first.creator,
    channel_create: first.channel_create,
    truncated: false,
    members: cases.map((c) => ({
      address: c.wallet,
      member: true,
      basis: 'invite',
      reason: null,
      join: c.join,
      removals: c.removals,
      inviter: null,
    })),
    moderator_grants: Object.assign({}, ...cases.map((c) => c.moderator_grants)),
    moderator_removals: Object.assign({}, ...cases.map((c) => c.moderator_removals)),
    device_claims: Object.assign({}, ...cases.map((c) => c.device_claims)),
  };
}

function fakeClient(impl: (id: number, addrs: readonly string[]) => Promise<MemberProofsResponse[]>) {
  const getMemberProofs = vi.fn(impl);
  return {
    client: { getNetwork: async () => NET, getMemberProofs } as unknown as OgmaraClient,
    getMemberProofs,
  };
}

describe('filterVerifiedMembers', () => {
  const valid = caseNamed('valid_creator_invite');

  it('keeps verified members, rejects the rest, never throws, and caches positives only', async () => {
    const bad = { ...caseNamed('wrong_target') };
    const { client, getMemberProofs } = fakeClient(async (_id, addrs) => {
      const resp = responseFrom([valid]);
      resp.members = addrs.map((a) =>
        a === valid.wallet
          ? resp.members[0]!
          : a === valid.creator
            ? { address: a, member: true, basis: 'creator' as const, reason: null, join: null, removals: [], inviter: null }
            : { address: a, member: true, basis: 'invite' as const, reason: null, join: bad.join, removals: [], inviter: null },
      );
      return [resp];
    });
    const cache = new MemberProofCache();
    const wallets = [valid.wallet, valid.creator, V.keys.attacker.address, 'klv1garbage', valid.wallet];
    const r = await filterVerifiedMembers(client, valid.channel_id, wallets, cache, { activationMs: 0 });
    expect(r.verified).toEqual([valid.wallet, valid.creator]);
    expect(r.rejected.map((x) => x.wallet)).toEqual([V.keys.attacker.address, 'klv1garbage']);
    expect(r.rejected[1]!.reason).toBe('invalid_address');
    expect(r.creator).toBe(valid.creator);
    expect(getMemberProofs).toHaveBeenCalledTimes(1);
    expect(getMemberProofs.mock.calls[0]![1]).not.toContain('klv1garbage');
    expect(cache.size).toBe(2); // two positives, the negative is not cached
  });

  it('a cache hit still honours a removal served later', async () => {
    const kc = caseNamed('kick_cutoff');
    let serveKick = false;
    const { client } = fakeClient(async () => {
      const resp = responseFrom([valid]);
      if (serveKick) resp.members[0]!.removals = kc.removals; // creator kick at T+7m >= invite T+5m
      return [resp];
    });
    const cache = new MemberProofCache();
    expect((await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], cache, { activationMs: 0 })).verified).toEqual([valid.wallet]);
    serveKick = true;
    const r = await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], cache, { activationMs: 0 });
    expect(r.verified).toEqual([]);
  });

  it('a cached positive is dropped when the node now reports the member unavailable', async () => {
    let gone = false;
    const { client } = fakeClient(async () => {
      const resp = responseFrom([valid]);
      if (gone) Object.assign(resp.members[0]!, { basis: 'unavailable', reason: 'not_member' });
      return [resp];
    });
    const cache = new MemberProofCache();
    expect((await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], cache, { activationMs: 0 })).verified).toEqual([valid.wallet]);
    gone = true;
    const r = await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], cache, { activationMs: 0 });
    expect(r.verified).toEqual([]);
    expect(r.rejected[0]!.reason).toBe('unavailable:not_member');
  });

  it('fails closed on a 429/503 (incomplete) and on a response for another channel', async () => {
    const { client } = fakeClient(async () => {
      throw new MemberProofsError(429, 'busy');
    });
    const r = await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], new MemberProofCache());
    expect(r).toMatchObject({ verified: [], incomplete: true });
    expect(r.rejected[0]!.reason).toBe('fetch_failed:429');

    const { client: c2 } = fakeClient(async () => [{ ...responseFrom([valid]), channel_id: 1 }]);
    const r2 = await filterVerifiedMembers(c2, valid.channel_id, [valid.wallet], new MemberProofCache());
    expect(r2.verified).toEqual([]);
  });

  it('re-requests truncated members once in a smaller batch', async () => {
    let call = 0;
    const { client, getMemberProofs } = fakeClient(async (_id, addrs) => {
      call++;
      const resp = responseFrom([valid]);
      resp.members = addrs.map((a) =>
        call === 1
          ? { address: a, member: true, basis: 'unavailable' as const, reason: 'truncated', join: null, removals: [], inviter: null }
          : resp.members[0]!,
      );
      return [resp];
    });
    const r = await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], new MemberProofCache(), { activationMs: 0 });
    expect(getMemberProofs).toHaveBeenCalledTimes(2);
    expect(r.verified).toEqual([valid.wallet]);
  });

  it('C1: a later chunk can never establish a different creator than the first chunk', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const attackerCreate = await w.rawCreate(w.x); // underived, signed by the attacker
    const filler: string[] = [];
    for (let i = 0; i < 99; i++) filler.push((await WalletSigner.generate()).address);
    const wallets = [w.j.address, ...filler, w.x.address]; // 101 → two chunks
    let call = 0;
    const { client, getMemberProofs } = fakeClient(async (_id, addrs) => {
      call++;
      const base: MemberProofsResponse = {
        channel_id: w.channelId, creator: null, truncated: false,
        channel_create: call === 1 ? w.b64(w.create) : w.b64(attackerCreate),
        members: [], moderator_grants: {}, moderator_removals: {}, device_claims: {},
      };
      base.members = addrs.map((a) =>
        a === w.j.address
          ? { address: a, member: true, basis: 'invite' as const, reason: null, join: w.b64(join), removals: [], inviter: null }
          : { address: a, member: true, basis: 'creator' as const, reason: null, join: null, removals: [], inviter: null },
      );
      return [base];
    });
    // Even with the opt-in, chunk 2 is pinned to chunk 1's derived creator.
    const r = await filterVerifiedMembers(client, w.channelId, wallets, new MemberProofCache(), {
      network: NET, activationMs: 0, allowUnderivedCreator: true,
    });
    expect(getMemberProofs).toHaveBeenCalledTimes(2);
    expect(r.verified).toEqual([w.j.address]);
    expect(r.creator).toBe(w.c.address);
    expect(r.rejected.find((x) => x.wallet === w.x.address)?.reason).toBe('creator_pin_mismatch');
  });

  it('N-a: creatorSource is the first chunk\'s real source, never "pinned" when the caller passed no pin', async () => {
    const w = await world();
    const inv = await at(T0 + MIN, () => buildInvite(w.c, w.channelId, w.j.address));
    const join = await at(T0 + 2 * MIN, () => buildChannelJoin(w.j, w.channelId, { invite: inv }));
    const filler: string[] = [];
    for (let i = 0; i < 100; i++) filler.push((await WalletSigner.generate()).address);
    let call = 0;
    const { client } = fakeClient(async (_id, addrs) => {
      call++;
      // Chunk 1 answers none of its members; only chunk 2 has a verifiable one.
      const members = call === 1 ? [] : addrs.map((a) => ({ address: a, member: true, basis: 'invite' as const, reason: null, join: w.b64(join), removals: [], inviter: null }));
      return [{ channel_id: w.channelId, creator: null, truncated: false, channel_create: w.b64(w.create), members, moderator_grants: {}, moderator_removals: {}, device_claims: {} }];
    });
    const r = await filterVerifiedMembers(client, w.channelId, [...filler, w.j.address], new MemberProofCache(), { network: NET, activationMs: 0 });
    expect(r.verified).toEqual([w.j.address]);
    expect(r).toMatchObject({ creator: w.c.address, creatorSource: 'derived' });
    // With a caller pin it IS reported as pinned.
    call = 0;
    const r2 = await filterVerifiedMembers(client, w.channelId, [...filler, w.j.address], new MemberProofCache(), {
      network: NET, activationMs: 0, pinnedCreator: w.c.address,
    });
    expect(r2.creatorSource).toBe('pinned');
  });

  it('N4: guards — cache size validation and a non-array getMemberProofs result', async () => {
    expect(() => new MemberProofCache(0)).toThrow(RangeError);
    expect(() => new MemberProofCache(Number.NaN)).toThrow(RangeError);
    expect(() => new MemberProofCache(-1)).toThrow(RangeError);
    const { client } = fakeClient(async () => null as unknown as MemberProofsResponse[]);
    const r = await filterVerifiedMembers(client, valid.channel_id, [valid.wallet], new MemberProofCache());
    expect(r.verified).toEqual([]);
    expect(r.rejected[0]!.reason).toBe('bad_response');
  });

  it('MemberProofCache evicts least-recently-used entries', () => {
    const c = new MemberProofCache(2);
    c.set('a', { basis: 'creator' });
    c.set('b', { basis: 'creator' });
    c.get('a');
    c.set('c', { basis: 'creator' });
    expect(c.get('b')).toBeUndefined();
    expect(c.get('a')).toBeDefined();
  });
});

describe('OgmaraClient.getMemberProofs', () => {
  async function stubbedClient(handler: (body: any) => Response) {
    const { OgmaraClient } = await import('./client');
    const calls: any[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/api/v1/health')) {
        return new Response(JSON.stringify({ node_id: 'n1', network: NET }), { status: 200 });
      }
      const body = JSON.parse(String(init?.body));
      calls.push({ url, body, headers: init?.headers });
      return handler(body);
    }));
    const client = new OgmaraClient({ nodeUrl: 'http://node.test' });
    client.withSigner(await signer(V.keys.joiner.seed_hex));
    return { client, calls };
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dedupes and chunks at 100, sequentially, authenticated', async () => {
    const { client, calls } = await stubbedClient((body) =>
      new Response(JSON.stringify({ ...responseFrom([caseNamed('valid_creator_invite')]), members: body.addresses.map((a: string) => ({ address: a })) }), { status: 200 }),
    );
    const addrs = Array.from({ length: 150 }, (_, i) => `klv1fake${i}`);
    const out = await client.getMemberProofs(42, [...addrs, addrs[0]!]);
    expect(out).toHaveLength(2);
    expect(calls.map((c) => c.body.addresses.length)).toEqual([100, 50]);
    expect(calls[0].url).toBe('http://node.test/api/v1/channels/42/member-proofs');
    expect(calls[0].headers['x-ogmara-auth']).toBeTruthy();
  });

  it('W1/M26: a VALID JSON response over 8 MiB is refused because of the cap; just under it parses', async () => {
    const body = (padLen: number) =>
      JSON.stringify({ channel_id: 42, creator: null, channel_create: null, truncated: false, members: [], moderator_grants: {}, moderator_removals: {}, device_claims: {}, pad: 'x'.repeat(padLen) });
    const LIMIT = 8 * 1024 * 1024;
    const overhead = body(0).length;
    const over = body(LIMIT - overhead + 1);
    const under = body(LIMIT - overhead);
    expect(over.length).toBe(LIMIT + 1);
    expect(() => JSON.parse(over)).not.toThrow(); // genuinely valid JSON
    const { client } = await stubbedClient(() => new Response(over, { status: 200 }));
    const err = await client.getMemberProofs(42, ['klv1x']).catch((e) => e);
    expect(err).toBeInstanceOf(MemberProofsError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/response too large/);
    const { client: c2 } = await stubbedClient(() => new Response(under, { status: 200 }));
    const ok = await c2.getMemberProofs(42, ['klv1x']);
    expect(ok[0]!.members).toEqual([]);
  });

  it('W5: federateChannel aborts when the account switches during the node-binding await', async () => {
    const { OgmaraClient } = await import('./client');
    const a = await signer(V.keys.joiner.seed_hex);
    const b = await signer(V.keys.attacker.seed_hex);
    const client = new OgmaraClient({ nodeUrl: 'http://node.test' });
    const posted: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).endsWith('/api/v1/health')) {
        client.withSigner(b); // account switch while the binding is being fetched
        return new Response(JSON.stringify({ node_id: 'n1', network: NET }), { status: 200 });
      }
      posted.push(String(url));
      return new Response(JSON.stringify({ federated: true, channel_id: 1 }), { status: 200 });
    }));
    client.withSigner(a);
    await expect(client.federateChannel(1, 'https://host.example')).rejects.toThrow(/account changed/);
    expect(posted).toEqual([]);
  });

  it('throws a typed, retryable error on 429 / 503 and a non-retryable one on 403', async () => {
    for (const [status, retryable] of [[429, true], [503, true], [403, false]] as const) {
      const { client } = await stubbedClient(() => new Response('nope', { status }));
      const err = await client.getMemberProofs(42, ['klv1x']).catch((e) => e);
      expect(err).toBeInstanceOf(MemberProofsError);
      expect(err.status).toBe(status);
      expect(err.retryable).toBe(retryable);
    }
  });
});

describe('N2: addressToPubkey exact HRP', () => {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(values: number[]): number {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i]!;
    }
    return chk >>> 0;
  }
  function encode(hrp: string, bytes: Uint8Array): string {
    const words: number[] = [];
    let acc = 0, bits = 0;
    for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; words.push((acc >> bits) & 31); } }
    if (bits > 0) words.push((acc << (5 - bits)) & 31);
    const exp = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
    const pm = polymod([...exp, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
    const cs = Array.from({ length: 6 }, (_, i) => (pm >> (5 * (5 - i))) & 31);
    return hrp + '1' + [...words, ...cs].map((d) => CHARSET[d]).join('');
  }
  it('accepts klv/ogd, refuses a checksum-valid address under any other prefix', async () => {
    const { addressToPubkey } = await import('./encryption');
    const pub = new Uint8Array(32).fill(7);
    expect(addressToPubkey(encode('klv', pub))).toEqual(pub);
    expect(addressToPubkey(encode('ogd', pub))).toEqual(pub);
    expect(() => addressToPubkey(encode('xyz', pub))).toThrow(/prefix/);
    expect(() => addressToPubkey(encode('klvx', pub))).toThrow(/prefix/);
  });
});
