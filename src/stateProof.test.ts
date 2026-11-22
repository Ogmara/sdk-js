import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  verifyStateProof,
  verifyStateProofOnChain,
  stateRecordKey,
  type StateProof,
  type StateProofQuery,
} from './stateProof';
import { getFinalCanonicalAnchor, TRUST_BOUNDARY_BLOCKS, ANCHOR_SETTLE_BLOCKS } from './sc_queries';

/**
 * Known-answer vectors produced by l2-node
 * `api::state_proofs::tests::known_answer_vector` (print them with
 * `OGMARA_PRINT_VECTORS=1 cargo test known_answer_vector -- --nocapture`)
 * against a fixed chain mirror (5 users, 2 channels, 1 delegation; state
 * root v4): a 2-leaf channel proof, the last leaf of the odd 5-leaf users
 * subtree, and a single-leaf delegation proof. If the node test's pinned
 * root changes, regenerate all three.
 */
const CHANNEL: StateProof = {"block_height":500,"canonical_confirmed":false,"key":"630000000000000003","leaf":"c45238dd6a6d83e9c4e5dd20663fa3a6fc85433e5d57fc127ceebf0bcbf7d921","leaf_count":2,"leaf_index":0,"siblings":["384c8f387b2971cb53f371ed6fab0414df18c65c705309daa5576a56466cd4c3"],"state_root":"6cb987a18c71bad25df6d0668029179f0fcdb64affb65db16e10acd9b5b3099c","subtree":"channels","subtrees":[{"count":5,"name":"users","root":"589c1e54e7109290951161bbe6bf180d9db6b62ea8d1f3b484cc947cc3375b6a"},{"count":2,"name":"channels","root":"0ce7899984e0d6656c8cd387fb38f8569dd7de98dccd622e11d126d1d8c0948e"},{"count":1,"name":"delegations","root":"d70daa3e7648e70e6fcdc7d803c9c4bf75e8d386453d4c8161fe48da877607a7"}],"value":"eyJjaGFubmVsX2lkIjozLCJjcmVhdG9yIjoia2x2MXVzZXIxIiwic2x1ZyI6Im5ld3MifQ=="};
const USER: StateProof = {"block_height":500,"canonical_confirmed":false,"key":"756b6c76317573657234","leaf":"ed6a48f6bd73e8433f079e5983248f559d311d6ec6532d51f069f4e0d7582592","leaf_count":5,"leaf_index":4,"siblings":["f6d7535896a83b3bbc8d18390be80e62ba213c656e0157fc75bdc309413ecb3b"],"state_root":"6cb987a18c71bad25df6d0668029179f0fcdb64affb65db16e10acd9b5b3099c","subtree":"users","subtrees":[{"count":5,"name":"users","root":"589c1e54e7109290951161bbe6bf180d9db6b62ea8d1f3b484cc947cc3375b6a"},{"count":2,"name":"channels","root":"0ce7899984e0d6656c8cd387fb38f8569dd7de98dccd622e11d126d1d8c0948e"},{"count":1,"name":"delegations","root":"d70daa3e7648e70e6fcdc7d803c9c4bf75e8d386453d4c8161fe48da877607a7"}],"value":"eyJhZGRyZXNzIjoia2x2MXVzZXI0IiwicHVibGljX2tleSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQifQ=="};
const DELEGATION: StateProof = {"block_height":500,"canonical_confirmed":false,"key":"646b6c763175736572320061626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162","leaf":"d70daa3e7648e70e6fcdc7d803c9c4bf75e8d386453d4c8161fe48da877607a7","leaf_count":1,"leaf_index":0,"siblings":[],"state_root":"6cb987a18c71bad25df6d0668029179f0fcdb64affb65db16e10acd9b5b3099c","subtree":"delegations","subtrees":[{"count":5,"name":"users","root":"589c1e54e7109290951161bbe6bf180d9db6b62ea8d1f3b484cc947cc3375b6a"},{"count":2,"name":"channels","root":"0ce7899984e0d6656c8cd387fb38f8569dd7de98dccd622e11d126d1d8c0948e"},{"count":1,"name":"delegations","root":"d70daa3e7648e70e6fcdc7d803c9c4bf75e8d386453d4c8161fe48da877607a7"}],"value":"eyJjcmVhdGVkX2F0IjoxNzkwMDAwMDAwLCJkZXZpY2Vfa2V5IjoiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYiIsImV4cGlyZXNfYXQiOjAsInBlcm1pc3Npb25zIjo3LCJyZXZva2VkX2F0IjowLCJ1c2VyIjoia2x2MXVzZXIyIn0="};
const ROOT = CHANNEL.state_root;
const CHANNEL_Q: StateProofQuery = { subtree: 'channels', channelId: 3 };
const USER_Q: StateProofQuery = { subtree: 'users', address: 'klv1user4' };
const DELEGATION_Q: StateProofQuery = { subtree: 'delegations', address: 'klv1user2', deviceKey: 'ab'.repeat(32) };

const clone = (p: StateProof): StateProof => JSON.parse(JSON.stringify(p));
const b64json = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64');
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('stateRecordKey', () => {
  it('matches the node mirror keys', () => {
    expect(hex(stateRecordKey(USER_Q))).toBe(USER.key);
    expect(hex(stateRecordKey(CHANNEL_Q))).toBe(CHANNEL.key);
    expect(hex(stateRecordKey(DELEGATION_Q))).toBe(DELEGATION.key);
  });
});

describe('verifyStateProof', () => {
  it('accepts the node known-answer proofs against their root', () => {
    expect(USER.state_root).toBe(ROOT);
    expect(DELEGATION.state_root).toBe(ROOT);
    const c = verifyStateProof(CHANNEL, { stateRoot: ROOT, query: CHANNEL_Q });
    expect(c.ok).toBe(true);
    if (c.ok) {
      expect(c.subtree).toBe('channels');
      expect(c.record).toEqual({ channel_id: 3, creator: 'klv1user1', slug: 'news' });
      expect(c.blockHeight).toBe(500);
    }
    const u = verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q });
    expect(u.ok).toBe(true);
    if (u.ok) expect(u.record).toEqual({ address: 'klv1user4', public_key: '0'.repeat(63) + '4' });
    const d = verifyStateProof(DELEGATION, { stateRoot: ROOT, query: DELEGATION_Q });
    expect(d.ok).toBe(true);
    if (d.ok) expect((d.record as { revoked_at: number }).revoked_at).toBe(0);
  });

  it('accepts an uppercase expected root', () => {
    expect(verifyStateProof(CHANNEL, { stateRoot: ROOT.toUpperCase(), query: CHANNEL_Q }).ok).toBe(true);
  });

  it('rejects a different expected root', () => {
    expect(verifyStateProof(CHANNEL, { stateRoot: 'ab'.repeat(32), query: CHANNEL_Q })).toEqual({
      ok: false,
      reason: 'state_root is not the expected root',
    });
  });

  it('rejects a genuine proof for a different record than the one asked for', () => {
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { subtree: 'users', address: 'klv1user0' } }).ok).toBe(false);
    for (const query of [
      { subtree: 'channels', channelId: 4 },
      { subtree: 'users', address: 'klv1user1' },
      { subtree: 'delegations', address: 'klv1user1', deviceKey: 'ab'.repeat(32) },
    ] as StateProofQuery[]) {
      expect(verifyStateProof(CHANNEL, { stateRoot: ROOT, query }).ok).toBe(false);
    }
    expect(
      verifyStateProof(DELEGATION, { stateRoot: ROOT, query: { ...DELEGATION_Q, deviceKey: 'cd'.repeat(32) } }).ok,
    ).toBe(false);
  });

  it("rejects one user's genuine record relabelled with another user's key", () => {
    // The leaf hashes only the value, so a node can keep klv1user4's
    // genuine value and path but claim the key of klv1user3.
    const p = clone(USER);
    p.key = hex(stateRecordKey({ subtree: 'users', address: 'klv1user3' }));
    expect(verifyStateProof(p, { stateRoot: ROOT, query: { subtree: 'users', address: 'klv1user3' } })).toEqual({
      ok: false,
      reason: 'record does not belong to the queried key',
    });
  });

  it('refuses the removed channel_members subtree', () => {
    const p = clone(CHANNEL) as any;
    p.subtree = 'channel_members';
    expect(verifyStateProof(p, { stateRoot: ROOT, query: CHANNEL_Q }).ok).toBe(false);
  });

  it('rejects an unsafe channel id instead of comparing rounded values', () => {
    const query = { subtree: 'channels', channelId: 2 ** 53 + 1 } as StateProofQuery;
    expect(verifyStateProof(CHANNEL, { stateRoot: ROOT, query })).toEqual({ ok: false, reason: 'bad query' });
  });

  it('binds the requested height and a minimum height', () => {
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { ...USER_Q, height: 501 } }).ok).toBe(false);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { ...USER_Q, height: 500 } }).ok).toBe(true);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q, minBlockHeight: 501 }).ok).toBe(false);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q, minBlockHeight: 500 }).ok).toBe(true);
  });

  it('rejects a tampered value, sibling, index, count or subtree root', () => {
    const cases: Array<[StateProof, StateProofQuery, (p: StateProof) => void]> = [
      [CHANNEL, CHANNEL_Q, (p) => { p.value = b64json({ channel_id: 3, creator: 'klv1mallory', slug: 'news' }); }],
      [USER, USER_Q, (p) => { p.value = b64json({ address: 'klv1user4', public_key: 'ff' }); }],
      [DELEGATION, DELEGATION_Q, (p) => {
        const r = JSON.parse(Buffer.from(p.value, 'base64').toString());
        p.value = b64json({ ...r, revoked_at: 0, expires_at: 1 });
      }],
      [CHANNEL, CHANNEL_Q, (p) => { p.siblings[0] = '00'.repeat(32); }],
      [CHANNEL, CHANNEL_Q, (p) => { p.leaf_index = 1; }],
      [USER, USER_Q, (p) => { p.leaf_index = 3; }],
      [USER, USER_Q, (p) => { p.leaf_count = 6; p.subtrees[0].count = 6; }],
      [CHANNEL, CHANNEL_Q, (p) => { p.subtrees[0].root = '11'.repeat(32); }],
      [CHANNEL, CHANNEL_Q, (p) => { p.subtrees[0].count += 1; }],
      [CHANNEL, CHANNEL_Q, (p) => { p.siblings.push('00'.repeat(32)); }],
      [USER, USER_Q, (p) => { p.siblings.pop(); }],
      [CHANNEL, CHANNEL_Q, (p) => { p.subtrees.reverse(); }],
    ];
    for (const [base, query, mutate] of cases) {
      const p = clone(base);
      mutate(p);
      expect(verifyStateProof(p, { stateRoot: ROOT, query }).ok, mutate.toString()).toBe(false);
    }
  });

  it('rejects malformed fields and expectations instead of throwing', () => {
    const cases: Array<(p: any) => void> = [
      (p) => { p.state_root = 'zz'; },
      (p) => { p.value = '***'; },
      (p) => { p.value = Buffer.from('not json').toString('base64'); },
      (p) => { p.leaf_index = -1; },
      (p) => { p.leaf_index = 1.5; },
      (p) => { p.siblings = 'nope'; },
      (p) => { p.subtrees = []; },
      (p) => { p.subtree = 'messages'; },
    ];
    for (const mutate of cases) {
      const p = clone(CHANNEL);
      mutate(p);
      expect(verifyStateProof(p, { stateRoot: ROOT, query: CHANNEL_Q }).ok).toBe(false);
    }
    expect(verifyStateProof(null as any, { stateRoot: ROOT, query: CHANNEL_Q }).ok).toBe(false);
    expect(verifyStateProof(CHANNEL, undefined as any).ok).toBe(false);
    expect(verifyStateProof(CHANNEL, { stateRoot: 'nope', query: CHANNEL_Q }).ok).toBe(false);
  });
});

// ── getFinalCanonicalAnchor / verifyStateProofOnChain (mocked /vm/query) ──

function b64(bytes: number[]): string {
  return Buffer.from(bytes).toString('base64');
}

function vmOk(returnData: string[]) {
  return {
    ok: true,
    json: async () => ({ data: { data: { returnCode: 'Ok', returnData } } }),
  } as unknown as Response;
}

/** Answer each view from a table (and `/node/overview` with `tip`);
 *  records the view call order. */
function stubViews(table: Record<string, string[] | (() => string[])>, tip = TIP) {
  const calls: string[] = [];
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    if (String(url).endsWith('/node/overview')) {
      return { ok: true, json: async () => ({ data: { overview: { nonce: tip } } }) } as unknown as Response;
    }
    const { funcName } = JSON.parse(String(init!.body));
    calls.push(funcName);
    const entry = table[funcName];
    if (!entry) throw new Error('unexpected view ' + funcName);
    return vmOk(typeof entry === 'function' ? entry() : entry);
  });
  return calls;
}

const utf8b64 = (s: string) => b64(Array.from(Buffer.from(s, 'utf8')));
/** A daily trust boundary, and a chain tip at which it has settled. */
const D = TRUST_BOUNDARY_BLOCKS * 700;
const TIP = D + ANCHOR_SETTLE_BLOCKS;
const TENURED = [b64([3])];
const TOTAL3 = [b64([3])];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getFinalCanonicalAnchor', () => {
  it('returns a settled, tenured root at a daily boundary', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: TENURED, getTenuredVotesAt: TOTAL3 });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBe(ROOT);
  });

  it('returns null when the height is not canonical yet', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [b64([])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('refuses a height off the daily grid without asking the chain', async () => {
    const calls = stubViews({});
    expect(await getFinalCanonicalAnchor('testnet', D + 900)).toBeNull();
    expect(calls).toEqual([]);
  });

  it('refuses a height above the chain tip', async () => {
    stubViews({}, D - 1);
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('refuses a root that has not settled yet', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)] }, D + ANCHOR_SETTLE_BLOCKS - 1);
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('refuses a root without two thirds of the tenured votes', async () => {
    // 3 tenured colluders vs 2 honest tenured votes.
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: TENURED, getTenuredVotesAt: [b64([5])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
    // 4 of 6 is exactly two thirds.
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: [b64([4])], getTenuredVotesAt: [b64([6])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBe(ROOT);
  });

  it('treats an out-of-range tenured count as zero', async () => {
    // The SC returns a u32; 2^32 is malformed and must not pass ≥ 3.
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: [b64([1, 0, 0, 0, 0])], getTenuredVotesAt: TOTAL3 });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('counts an oversized tenured total as dissent', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: TENURED, getTenuredVotesAt: [b64([1, 0, 0, 0, 0, 0, 0, 0, 0])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('refuses a root without tenured quorum', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: [b64([2])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('ignores the provisional answer of an open contest', async () => {
    const calls = stubViews({
      isDivergenceEscalated: [b64([1])],
      getEscalatedCanonical: [b64([])],
      getCanonicalAnchor: [utf8b64(ROOT)],
    });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
    expect(calls).not.toContain('getCanonicalAnchor');
  });

  it('uses the final result of a closed contest when it has tenured quorum', async () => {
    stubViews({ isDivergenceEscalated: [b64([1])], getEscalatedCanonical: [utf8b64(ROOT)], getEligibleAgreementCount: TENURED, getTenuredVotesAt: TOTAL3 });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBe(ROOT);
  });

  it('refuses a contest winner without tenured quorum', async () => {
    stubViews({ isDivergenceEscalated: [b64([1])], getEscalatedCanonical: [utf8b64(ROOT)], getEligibleAgreementCount: [b64([1])] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('fails closed when a view errors', async () => {
    vi.stubGlobal('fetch', async (url: string) => (String(url).endsWith('/node/overview')
      ? { ok: true, json: async () => ({ data: { overview: { nonce: TIP } } }) }
      : { ok: true, json: async () => ({ data: { data: { returnCode: 'UserError', returnMessage: 'misconfigured' } } }) }) as unknown as Response);
    await expect(getFinalCanonicalAnchor('testnet', D)).rejects.toThrow();
  });

  it('passes the height and the hex of the lowercase root string to the tenure view', async () => {
    const seen: string[][] = [];
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      if (String(url).endsWith('/node/overview')) {
        return { ok: true, json: async () => ({ data: { overview: { nonce: TIP } } }) } as unknown as Response;
      }
      const { funcName, args } = JSON.parse(String(init!.body));
      if (funcName === 'getEligibleAgreementCount') seen.push(args);
      const table: Record<string, string[]> = {
        isDivergenceEscalated: [b64([])],
        getCanonicalAnchor: [utf8b64(ROOT.toUpperCase())],
        getEligibleAgreementCount: TENURED,
        getTenuredVotesAt: TOTAL3,
      };
      return vmOk(table[funcName]);
    });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBe(ROOT.toLowerCase());
    expect(seen).toEqual([[D.toString(16).padStart(Math.ceil(D.toString(16).length / 2) * 2, '0'), Buffer.from(ROOT.toLowerCase(), 'utf8').toString('hex')]]);
  });

  it('returns null for a malformed root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64('zz'.repeat(32))] });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });

  it('re-checks escalation after reading the root', async () => {
    let n = 0;
    stubViews({
      isDivergenceEscalated: () => [b64(n++ === 0 ? [] : [1])],
      getCanonicalAnchor: [utf8b64('cd'.repeat(32))],
      getEscalatedCanonical: [b64([])],
    });
    expect(await getFinalCanonicalAnchor('testnet', D)).toBeNull();
  });
});

describe('verifyStateProofOnChain', () => {
  const proof = { ...CHANNEL, block_height: D };

  it('verifies against the on-chain root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)], getEligibleAgreementCount: TENURED, getTenuredVotesAt: TOTAL3 });
    expect((await verifyStateProofOnChain(proof, CHANNEL_Q, 'testnet')).ok).toBe(true);
  });

  it('fails when the chain anchored a different root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64('ef'.repeat(32))], getEligibleAgreementCount: TENURED, getTenuredVotesAt: TOTAL3 });
    expect(await verifyStateProofOnChain(proof, CHANNEL_Q, 'testnet')).toEqual({
      ok: false,
      reason: 'state_root is not the expected root',
    });
  });

  it('reports not_canonical when there is no trusted root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [b64([])] });
    expect(await verifyStateProofOnChain(proof, CHANNEL_Q, 'testnet')).toEqual({ ok: false, reason: 'not_canonical' });
  });
});

