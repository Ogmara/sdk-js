import { describe, it, expect, vi, afterEach } from 'vitest';
import { decode, encode } from '@msgpack/msgpack';
import { WalletSigner } from './auth';
import { buildInvite, buildChannelJoin, buildEnvelope, buildAddModerator } from './envelope';
import { OgmaraClient } from './client';
import { MessageType, type Notification } from './types';
import {
  DEFAULT_INVITE_TTL_MS,
  MAX_INVITE_TTL_MS,
  MAX_INVITE_ENVELOPE_BYTES,
  MAX_INVITER_GRANT_BYTES,
  INVITE_EXPIRY_MARGIN_MS,
  bytesToBase64,
  base64ToBytes,
  decodeChannelInvite,
  encodeInviteForUrl,
  decodeInviteFromUrl,
  buildPrivateChannelInviteUrl,
  selectPendingInvite,
  isPlausibleModeratorGrant,
} from './invite';

const CID = 5_000_000_001; // above the private-id floor (2^32)
const DAY = 24 * 60 * 60 * 1000;

async function newSigner(): Promise<WalletSigner> {
  const s = await WalletSigner.generate();
  s.network = 'testnet';
  return s;
}

function outerOf(env: Uint8Array): Record<string, unknown> {
  return decode(env) as Record<string, unknown>;
}

function payloadOf(env: Uint8Array): Record<string, unknown> {
  return decode(outerOf(env).payload as Uint8Array) as Record<string, unknown>;
}

/** Re-encode a JS (map) envelope in the Rust positional-array form, Vec<u8> as int arrays. */
function toPositional(env: Uint8Array): Uint8Array {
  const o = outerOf(env);
  return encode([
    o.version,
    o.msg_type,
    Array.from(o.msg_id as Uint8Array),
    o.author,
    o.timestamp,
    o.lamport_ts,
    Array.from(o.payload as Uint8Array),
    Array.from(o.signature as Uint8Array),
    [],
  ]);
}

describe('buildInvite — l2-node 0.140.0 fields', () => {
  it('encodes expires_at and inviter_grant (as bin) in a msgpack MAP', async () => {
    const signer = await newSigner();
    const grant = new Uint8Array([1, 2, 3, 4]);
    const exp = Date.now() + DAY;
    const env = await buildInvite(signer, CID, 'klv1target', undefined, { expiresAt: exp, inviterGrant: grant });
    const o = outerOf(env);
    const payloadBytes = o.payload as Uint8Array;
    // fixmap marker 0x80..0x8f — named-field MAP form, not a positional array
    expect(payloadBytes[0]! & 0xf0).toBe(0x80);
    const p = payloadOf(env);
    expect(p.channel_id).toBe(CID);
    expect(p.expires_at).toBe(exp);
    expect(p.inviter_grant).toBeInstanceOf(Uint8Array);
    expect(Array.from(p.inviter_grant as Uint8Array)).toEqual([1, 2, 3, 4]);
    expect(p.anchor_node).toBeNull();
  });

  it('omits expires_at / inviter_grant entirely when undefined (never null)', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1target', 'https://h.example', {});
    const p = payloadOf(env);
    expect(Object.keys(p).sort()).toEqual(['anchor_node', 'channel_id', 'target_user']);
    expect('expires_at' in p).toBe(false);
    expect('inviter_grant' in p).toBe(false);
  });

  it('accepts anchorNode via options (spec form) and refuses a conflicting duplicate', async () => {
    const signer = await newSigner();
    const p = payloadOf(await buildInvite(signer, CID, 'klv1t', undefined, { anchorNode: 'https://a.example' }));
    expect(p.anchor_node).toBe('https://a.example');
    expect('anchorNode' in p).toBe(false);
    await expect(
      buildInvite(signer, CID, 'klv1t', 'https://b.example', { anchorNode: 'https://a.example' }),
    ).rejects.toThrow(/twice/);
  });

  it('rejects a past, non-integer, or > 14-day expiresAt', async () => {
    const signer = await newSigner();
    await expect(buildInvite(signer, CID, 'klv1t', undefined, { expiresAt: Date.now() - 1 })).rejects.toThrow(RangeError);
    await expect(buildInvite(signer, CID, 'klv1t', undefined, { expiresAt: Date.now() + 1.5 })).rejects.toThrow(RangeError);
    await expect(
      buildInvite(signer, CID, 'klv1t', undefined, { expiresAt: Date.now() + MAX_INVITE_TTL_MS + 60_000 }),
    ).rejects.toThrow(RangeError);
  });

  it('rejects an empty or oversized inviterGrant', async () => {
    const signer = await newSigner();
    await expect(
      buildInvite(signer, CID, 'klv1t', undefined, { inviterGrant: new Uint8Array(MAX_INVITER_GRANT_BYTES + 1) }),
    ).rejects.toThrow(RangeError);
    await expect(buildInvite(signer, CID, 'klv1t', undefined, { inviterGrant: new Uint8Array(0) })).rejects.toThrow();
  });

  it('a max-size grant still fits within the 2048-byte invite cap', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1' + 'q'.repeat(58), 'https://host.example', {
      expiresAt: Date.now() + DAY,
      inviterGrant: new Uint8Array(MAX_INVITER_GRANT_BYTES).fill(7),
    });
    expect(env.length).toBeLessThanOrEqual(MAX_INVITE_ENVELOPE_BYTES);
  });
});

describe('buildChannelJoin — invite proof', () => {
  it('carries invite as bin in a MAP payload, byte-for-byte', async () => {
    const signer = await newSigner();
    const invite = await buildInvite(signer, CID, 'klv1target');
    const env = await buildChannelJoin(signer, CID, { invite });
    const o = outerOf(env);
    expect((o.payload as Uint8Array)[0]! & 0xf0).toBe(0x80);
    const p = payloadOf(env);
    expect(p.channel_id).toBe(CID);
    expect(p.invite).toBeInstanceOf(Uint8Array);
    expect(Array.from(p.invite as Uint8Array)).toEqual(Array.from(invite));
  });

  it('omits the invite key when absent (backward-compatible payload)', async () => {
    const signer = await newSigner();
    const p = payloadOf(await buildChannelJoin(signer, 7));
    expect(Object.keys(p)).toEqual(['channel_id']);
  });

  it('rejects an oversized or empty invite before signing', async () => {
    const signer = await newSigner();
    await expect(buildChannelJoin(signer, CID, { invite: new Uint8Array(MAX_INVITE_ENVELOPE_BYTES + 1) })).rejects.toThrow(RangeError);
    await expect(buildChannelJoin(signer, CID, { invite: new Uint8Array(0) })).rejects.toThrow(RangeError);
  });
});

describe('decodeChannelInvite (unverified)', () => {
  it('round-trips a built invite and applies the 7-day default expiry', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1target', 'https://host.example');
    const d = decodeChannelInvite(env)!;
    expect(d).not.toBeNull();
    expect(d.channelId).toBe(CID);
    expect(d.targetUser).toBe('klv1target');
    expect(d.anchorNode).toBe('https://host.example');
    expect(d.inviter).toBe(signer.address);
    expect(d.expiresAt).toBe(d.timestamp + DEFAULT_INVITE_TTL_MS);
    expect(d.hasGrant).toBe(false);
    expect(d.explicitExpiresAt).toBeUndefined();
    expect(d.inviterGrant).toBeUndefined();
    expect(d.msgId).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reads explicit expires_at and the grant; accepts base64 text input', async () => {
    const signer = await newSigner();
    const exp = Date.now() + 2 * DAY;
    const env = await buildInvite(signer, CID, 'klv1target', undefined, { expiresAt: exp, inviterGrant: new Uint8Array([9]) });
    const d = decodeChannelInvite(bytesToBase64(env))!;
    expect(d.expiresAt).toBe(exp);
    expect(d.explicitExpiresAt).toBe(exp);
    expect(Array.from(d.inviterGrant!)).toEqual([9]);
    expect(d.hasGrant).toBe(true);
    expect(d.anchorNode).toBeUndefined();
  });

  it('decodes the positional-array (Rust to_vec) envelope form too', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1target', undefined, { expiresAt: Date.now() + DAY });
    const d = decodeChannelInvite(toPositional(env));
    expect(d?.channelId).toBe(CID);
    expect(d?.targetUser).toBe('klv1target');
  });

  it('decodes a positional-array PAYLOAD', async () => {
    const signer = await newSigner();
    const exp = Date.now() + DAY;
    const env = await buildEnvelope(signer, MessageType.ChannelInvite, {} as Record<string, unknown>);
    // Splice a positional payload in by hand (signature no longer matches —
    // irrelevant for an unverified decode).
    const o = outerOf(env);
    o.payload = encode([CID, 'klv1target', null, exp]);
    const d = decodeChannelInvite(encode(o));
    expect(d?.channelId).toBe(CID);
    expect(d?.expiresAt).toBe(exp);
  });

  it('returns null for other message types, garbage, oversize, and out-of-bounds TTL', async () => {
    const signer = await newSigner();
    expect(decodeChannelInvite(await buildChannelJoin(signer, CID))).toBeNull();
    expect(decodeChannelInvite(new Uint8Array([1, 2, 3]))).toBeNull();
    expect(decodeChannelInvite('not base64 !!')).toBeNull();
    expect(decodeChannelInvite(new Uint8Array(MAX_INVITE_ENVELOPE_BYTES + 1))).toBeNull();
    // Built via the raw builder to bypass buildInvite's own validation.
    const tooLong = await buildEnvelope(signer, MessageType.ChannelInvite, {
      channel_id: CID,
      target_user: 'klv1t',
      anchor_node: null,
      expires_at: Date.now() + MAX_INVITE_TTL_MS + DAY,
    });
    expect(decodeChannelInvite(tooLong)).toBeNull();
    const past = await buildEnvelope(signer, MessageType.ChannelInvite, {
      channel_id: CID,
      target_user: 'klv1t',
      anchor_node: null,
      expires_at: 1000,
    });
    expect(decodeChannelInvite(past)).toBeNull();
  });
});

describe('isPlausibleModeratorGrant', () => {
  it('accepts a ChannelAddModerator for this channel naming the inviter, rejects anything else', async () => {
    const creator = await newSigner();
    const perms = { can_mute: true, can_kick: true, can_ban: true, can_pin: true, can_edit_info: true, can_delete_msgs: true };
    const grant = await buildAddModerator(creator, { channelId: CID, targetUser: 'klv1mod', permissions: perms });
    expect(isPlausibleModeratorGrant(grant, CID, 'klv1mod')).toBe(true);
    expect(isPlausibleModeratorGrant(toPositional(grant), CID, 'klv1mod')).toBe(true);
    expect(isPlausibleModeratorGrant(grant, CID + 1, 'klv1mod')).toBe(false);
    expect(isPlausibleModeratorGrant(grant, CID, 'klv1other')).toBe(false);
    expect(isPlausibleModeratorGrant(await buildInvite(creator, CID, 'klv1mod'), CID, 'klv1mod')).toBe(false);
  });
});

describe('URL helpers', () => {
  it('encodeInviteForUrl / decodeInviteFromUrl round-trip with a URL-safe charset', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1target', 'https://host.example', { expiresAt: Date.now() + DAY });
    const s = encodeInviteForUrl(env);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Array.from(decodeInviteFromUrl(s)!)).toEqual(Array.from(env));
  });

  it('round-trips every length remainder and all byte values', () => {
    for (let len = 1; len <= 7; len++) {
      const b = new Uint8Array(len).map((_, i) => (i * 97 + 251) & 0xff);
      expect(Array.from(decodeInviteFromUrl(encodeInviteForUrl(b))!)).toEqual(Array.from(b));
      expect(Array.from(base64ToBytes(bytesToBase64(b))!)).toEqual(Array.from(b));
    }
    const all = new Uint8Array(256).map((_, i) => i);
    expect(Array.from(decodeInviteFromUrl(encodeInviteForUrl(all))!)).toEqual(Array.from(all));
  });

  it('matches the platform base64 encoder', () => {
    const b = new Uint8Array([0, 255, 62, 63, 128, 7, 99]);
    expect(bytesToBase64(b)).toBe(btoa(String.fromCharCode(...b)));
  });

  it('decodeInviteFromUrl rejects malformed, padded/standard-alphabet, and oversized input', () => {
    expect(decodeInviteFromUrl('')).toBeNull();
    expect(decodeInviteFromUrl('ab+c')).toBeNull();
    expect(decodeInviteFromUrl('abc=')).toBeNull();
    expect(decodeInviteFromUrl('a')).toBeNull(); // impossible length
    expect(decodeInviteFromUrl('ab$c')).toBeNull();
    expect(decodeInviteFromUrl('A'.repeat(3000))).toBeNull();
    // > 2048 decoded bytes
    expect(decodeInviteFromUrl(encodeBig(MAX_INVITE_ENVELOPE_BYTES + 3))).toBeNull();
  });

  it('encodeInviteForUrl refuses an oversized envelope', () => {
    expect(() => encodeInviteForUrl(new Uint8Array(MAX_INVITE_ENVELOPE_BYTES + 1))).toThrow(RangeError);
  });

  it('base64ToBytes rejects mixed alphabets and non-canonical trailing bits', () => {
    expect(base64ToBytes('ab-+')).toBeNull();
    expect(base64ToBytes('QR==')).toBeNull(); // 'R' leaves non-zero trailing bits
    expect(Array.from(base64ToBytes('QQ==')!)).toEqual([65]);
  });

  it('buildPrivateChannelInviteUrl builds the personal link and refuses a mismatched channel', async () => {
    const signer = await newSigner();
    const env = await buildInvite(signer, CID, 'klv1target');
    const url = buildPrivateChannelInviteUrl(CID, env, { hostNodeUrl: 'https://host.example:41721' });
    expect(url.startsWith(`https://ogmara.org/app/#/join/${CID}?node=https%3A%2F%2Fhost.example%3A41721&inv=`)).toBe(true);
    const inv = new URL(url.replace('/#/', '/')).searchParams.get('inv')!;
    expect(Array.from(decodeInviteFromUrl(inv)!)).toEqual(Array.from(env));

    const noHost = buildPrivateChannelInviteUrl(CID, env, { hostNodeUrl: 'javascript:alert(1)', baseUrl: 'https://x.example/app/' });
    expect(noHost.startsWith(`https://x.example/app/#/join/${CID}?inv=`)).toBe(true);

    // spec 05 §8.4 positional form: third argument is the host URL string
    expect(buildPrivateChannelInviteUrl(CID, env, 'https://host.example')).toBe(
      `https://ogmara.org/app/#/join/${CID}?node=https%3A%2F%2Fhost.example&inv=${encodeInviteForUrl(env)}`,
    );
    expect(buildPrivateChannelInviteUrl(CID, env)).toBe(`https://ogmara.org/app/#/join/${CID}?inv=${encodeInviteForUrl(env)}`);
    expect(() => buildPrivateChannelInviteUrl(CID + 1, env)).toThrow(/different channel/);
    expect(() => buildPrivateChannelInviteUrl(0, env)).toThrow(RangeError);
    expect(() => buildPrivateChannelInviteUrl(CID, new Uint8Array([1, 2]))).toThrow();
  });
});

function encodeBig(n: number): string {
  return encodeBase64Url(new Uint8Array(n));
}
function encodeBase64Url(b: Uint8Array): string {
  return bytesToBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

describe('selectPendingInvite', () => {
  async function inviteNotif(
    signer: WalletSigner,
    target: string,
    opts: { cid?: number; exp?: number } = {},
  ): Promise<Notification> {
    const env = await buildInvite(signer, opts.cid ?? CID, target, undefined, opts.exp ? { expiresAt: opts.exp } : undefined);
    return { type: 'channel_invite', from: signer.address, timestamp: Date.now(), invite_envelope: bytesToBase64(env) };
  }

  it('keeps an unexpired invite for this wallet + channel', async () => {
    const s = await newSigner();
    const n = await inviteNotif(s, 'klv1me');
    const r = selectPendingInvite([n], { channelId: CID, wallet: 'klv1me' });
    expect(r?.channelId).toBe(CID);
    expect(r?.invite).toBeInstanceOf(Uint8Array);
  });

  it('skips wrong wallet, wrong channel, absent/null/garbage envelope, and other types', async () => {
    const s = await newSigner();
    const list: Notification[] = [
      await inviteNotif(s, 'klv1other'),
      await inviteNotif(s, 'klv1me', { cid: CID + 1 }),
      { type: 'channel_invite', from: 'x', timestamp: 1 },
      { type: 'channel_invite', from: 'x', timestamp: 1, invite_envelope: null },
      { type: 'channel_invite', from: 'x', timestamp: 1, invite_envelope: 'zz!!' },
      { ...(await inviteNotif(s, 'klv1me')), type: 'mention' },
    ];
    expect(selectPendingInvite(list, { channelId: CID, wallet: 'klv1me' })).toBeNull();
  });

  it('treats an invite as expired INSIDE the client margin (tighter than the node)', async () => {
    const s = await newSigner();
    const exp = Date.now() + DAY;
    const n = await inviteNotif(s, 'klv1me', { exp });
    expect(selectPendingInvite([n], { channelId: CID, wallet: 'klv1me', now: exp - INVITE_EXPIRY_MARGIN_MS - 1 })).not.toBeNull();
    // Node would still accept here (join.ts <= exp) — client already refuses.
    expect(selectPendingInvite([n], { channelId: CID, wallet: 'klv1me', now: exp - INVITE_EXPIRY_MARGIN_MS })).toBeNull();
    expect(selectPendingInvite([n], { channelId: CID, wallet: 'klv1me', now: exp + 1 })).toBeNull();
  });

  it('skips an invite signed too far in the future', async () => {
    const s = await newSigner();
    const n = await inviteNotif(s, 'klv1me');
    expect(selectPendingInvite([n], { channelId: CID, wallet: 'klv1me', now: Date.now() - 10 * 60_000 })).toBeNull();
  });

  it('picks the NEWEST usable invite (spec 05 §8.4), regardless of list order', async () => {
    const s = await newSigner();
    const older = await inviteNotif(s, 'klv1me', { exp: Date.now() + 3 * DAY });
    await new Promise((r) => setTimeout(r, 5));
    const newer = await inviteNotif(s, 'klv1me', { exp: Date.now() + DAY });
    for (const list of [[older, newer], [newer, older]]) {
      const r = selectPendingInvite(list, { channelId: CID, wallet: 'klv1me' });
      expect(r!.msgId).toBe(decodeChannelInvite(newer.invite_envelope!)!.msgId);
    }
  });

  it('returns anchorNode so the caller can federate from a notification', async () => {
    const s = await newSigner();
    const env = await buildInvite(s, CID, 'klv1me', 'https://host.example');
    const n: Notification = { type: 'channel_invite', from: s.address, timestamp: 1, invite_envelope: bytesToBase64(env) };
    expect(selectPendingInvite([n], { channelId: CID, wallet: 'klv1me' })?.anchorNode).toBe('https://host.example');
  });

  it('tolerates a non-array input', () => {
    expect(selectPendingInvite(null as unknown as Notification[], { channelId: CID, wallet: 'klv1me' })).toBeNull();
  });
});

// --- OgmaraClient wiring ---

interface Captured {
  url: string;
  method: string;
  body?: Uint8Array | string;
}

function mockNode(routes: (url: string, method: string) => { status?: number; body: unknown } | undefined): Captured[] {
  const calls: Captured[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      const raw = init?.body;
      calls.push({
        url: String(url),
        method,
        body: raw === undefined ? undefined : typeof raw === 'string' ? raw : new Uint8Array(raw as ArrayBuffer),
      });
      let r: { status?: number; body: unknown } | undefined;
      if (String(url).includes('/api/v1/health')) {
        r = { body: { status: 'ok', version: '0', peers: 0, node_id: 'node1', network: 'testnet' } };
      } else {
        r = routes(String(url), method) ?? { body: { msg_id: 'x' } };
      }
      const status = r.status ?? 200;
      const text = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => null },
        body: null,
        json: async () => JSON.parse(text),
        text: async () => text,
      } as unknown as Response;
    }),
  );
  return calls;
}

describe('OgmaraClient — private join gate', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const channelRoute = (creator: string) => (url: string, method: string) =>
    method === 'GET' && new RegExp(`/api/v1/channels/${CID}$`).test(url)
      ? { body: { channel: { channel_id: CID, creator }, member_count: 1, message_count: 0 } }
      : undefined;

  it('inviteUser (creator): default 7-day expiry, no grant fetch, returns the posted envelope', async () => {
    const signer = await newSigner();
    const calls = mockNode(channelRoute(signer.address));
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(signer);
    const before = Date.now();
    const res = await client.inviteUser(CID, 'klv1target');
    expect(res.expiresAt).toBeGreaterThanOrEqual(before + DEFAULT_INVITE_TTL_MS);
    expect(res.expiresAt).toBeLessThanOrEqual(Date.now() + DEFAULT_INVITE_TTL_MS);
    expect(res.inviterGrantAttached).toBe(false);
    expect(calls.some((c) => c.url.includes('/grant'))).toBe(false);
    const posted = calls.find((c) => c.method === 'POST' && c.url.includes(`/invite/`))!;
    expect(Array.from(posted.body as Uint8Array)).toEqual(Array.from(res.inviteEnvelope));
    const p = payloadOf(res.inviteEnvelope);
    expect(p.expires_at).toBe(res.expiresAt);
    expect('inviter_grant' in p).toBe(false);
  });

  it('inviteUser enforces TTL bounds (max 14 days accepted, beyond/below rejected)', async () => {
    const signer = await newSigner();
    mockNode(channelRoute(signer.address));
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(signer);
    const res = await client.inviteUser(CID, 'klv1target', { ttlMs: MAX_INVITE_TTL_MS });
    expect(decodeChannelInvite(res.inviteEnvelope)).not.toBeNull();
    await expect(client.inviteUser(CID, 'klv1target', { ttlMs: MAX_INVITE_TTL_MS + 1 })).rejects.toThrow(RangeError);
    await expect(client.inviteUser(CID, 'klv1target', { ttlMs: 1000 })).rejects.toThrow(RangeError);
    await expect(client.inviteUser(CID, 'klv1target', { ttlMs: 1.5 * DAY + 0.5 })).rejects.toThrow(RangeError);
  });

  it('inviteUser (moderator): fetches and bundles the grant', async () => {
    const creator = await newSigner();
    const mod = await newSigner();
    const perms = { can_mute: true, can_kick: true, can_ban: true, can_pin: true, can_edit_info: true, can_delete_msgs: true };
    const grant = await buildAddModerator(creator, { channelId: CID, targetUser: mod.address, permissions: perms });
    const calls = mockNode((url, method) => {
      const ch = channelRoute(creator.address)(url, method);
      if (ch) return ch;
      if (url.endsWith(`/api/v1/channels/${CID}/moderators/${mod.address}/grant`)) {
        return { body: { grant_envelope: bytesToBase64(grant) } };
      }
      return undefined;
    });
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(mod);
    const res = await client.inviteUser(CID, 'klv1target', { ttlMs: DAY });
    expect(res.inviterGrantAttached).toBe(true);
    expect(calls.some((c) => c.url.includes('/grant'))).toBe(true);
    expect(Array.from(decodeChannelInvite(res.inviteEnvelope)!.inviterGrant!)).toEqual(Array.from(grant));
  });

  it('inviteUser (moderator): 404 grant → invite without grant; mismatched grant → throws', async () => {
    const creator = await newSigner();
    const mod = await newSigner();
    mockNode((url, method) => channelRoute(creator.address)(url, method) ?? (url.includes('/grant') ? { status: 404, body: 'not found' } : undefined));
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(mod);
    const res = await client.inviteUser(CID, 'klv1target');
    expect(res.inviterGrantAttached).toBe(false);
    vi.unstubAllGlobals();

    const perms = { can_mute: true, can_kick: true, can_ban: true, can_pin: true, can_edit_info: true, can_delete_msgs: true };
    const wrong = await buildAddModerator(creator, { channelId: CID, targetUser: 'klv1someoneelse', permissions: perms });
    mockNode((url, method) => channelRoute(creator.address)(url, method) ?? (url.includes('/grant') ? { body: { grant_envelope: bytesToBase64(wrong) } } : undefined));
    await expect(client.inviteUser(CID, 'klv1target')).rejects.toThrow(/grant/);
  });

  it('inviteUser aborts if the signer is swapped mid-flight', async () => {
    const a = await newSigner();
    const b = await newSigner();
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(a);
    mockNode((url, method) => {
      const r = channelRoute(a.address)(url, method);
      if (r) client.withSigner(b); // account switch while the channel fetch is in flight
      return r;
    });
    await expect(client.inviteUser(CID, 'klv1target')).rejects.toThrow(/account changed/);
  });

  it('joinChannel / federateChannel attach the invite; omit it when absent', async () => {
    const inviter = await newSigner();
    const me = await newSigner();
    const invite = await buildInvite(inviter, CID, me.address);
    const calls = mockNode((url) => (url.includes('/federate') ? { body: { federated: true, channel_id: CID } } : undefined));
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(me);

    await client.federateChannel(CID, 'https://host.example', { invite });
    const fed = calls.find((c) => c.url.includes('/federate'))!;
    expect(JSON.parse(fed.body as string)).toEqual({ host_url: 'https://host.example', invite: bytesToBase64(invite) });

    await client.federateChannel(CID, 'https://host.example');
    const fed2 = calls.filter((c) => c.url.includes('/federate'))[1]!;
    expect(JSON.parse(fed2.body as string)).toEqual({ host_url: 'https://host.example' });

    await client.joinChannel(CID, { invite });
    const join = calls.filter((c) => c.method === 'POST' && c.url.endsWith('/api/v1/messages')).pop()!;
    expect(Array.from(payloadOf(join.body as Uint8Array).invite as Uint8Array)).toEqual(Array.from(invite));

    await client.joinChannel(7);
    const join2 = calls.filter((c) => c.method === 'POST' && c.url.endsWith('/api/v1/messages')).pop()!;
    expect(Object.keys(payloadOf(join2.body as Uint8Array))).toEqual(['channel_id']);
  });

  it('joinChannel / federateChannel refuse an invite for another wallet or channel', async () => {
    const inviter = await newSigner();
    const me = await newSigner();
    mockNode(() => undefined);
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(me);
    const forSomeoneElse = await buildInvite(inviter, CID, 'klv1someoneelse');
    await expect(client.joinChannel(CID, { invite: forSomeoneElse })).rejects.toThrow(/different account/);
    await expect(client.federateChannel(CID, 'https://h.example', { invite: forSomeoneElse })).rejects.toThrow(/different account/);
    const otherChannel = await buildInvite(inviter, CID + 1, me.address);
    await expect(client.joinChannel(CID, { invite: otherChannel })).rejects.toThrow(/different channel/);
  });

  it('getNotifications normalizes null invite fields; findPendingInvite returns the usable invite', async () => {
    const inviter = await newSigner();
    const me = await newSigner();
    const invite = await buildInvite(inviter, CID, me.address, undefined, { expiresAt: Date.now() + DAY });
    const calls = mockNode((url) =>
      url.includes('/api/v1/notifications')
        ? {
            body: {
              notifications: [
                { type: 'channel_invite', from: 'x', timestamp: 1, invite_envelope: null, invite_expires_at: null },
                { type: 'channel_invite', from: inviter.address, timestamp: 2, invite_envelope: bytesToBase64(invite), invite_expires_at: 123 },
              ],
            },
          }
        : undefined,
    );
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(me);
    const resp = await client.getNotifications(undefined, 50, 'channel_invite');
    expect('invite_envelope' in resp.notifications[0]!).toBe(false);
    expect('invite_expires_at' in resp.notifications[0]!).toBe(false);
    expect(resp.notifications[1]!.invite_expires_at).toBe(123);

    const pending = await client.findPendingInvite(CID);
    expect(Array.from(pending!.invite)).toEqual(Array.from(invite));
    expect(pending!.inviter).toBe(inviter.address);
    const q = calls.filter((c) => c.url.includes('/api/v1/notifications')).pop()!.url;
    expect(q).toContain('type=channel_invite');
    expect(q).toContain('limit=200');
    expect(q).toMatch(/since=\d+/);
    expect(await client.findPendingInvite(CID + 1)).toBeNull();
  });
});
