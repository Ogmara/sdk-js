import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  verifyStateProof,
  verifyStateProofOnChain,
  type StateProof,
  type StateProofQuery,
} from './stateProof';
import { getFinalCanonicalAnchor } from './sc_queries';

/**
 * Known-answer vectors produced by l2-node
 * `api::state_proofs::tests::known_answer_vector` (print them with
 * `OGMARA_PRINT_VECTORS=1 cargo test known_answer_vector -- --nocapture`)
 * against a fixed 5-user / 2-channel / 2-membership state: a 2-leaf
 * channel-membership proof and the last leaf of the odd 5-leaf users
 * subtree. If the node test's pinned root changes, regenerate both.
 */
const MEMBER: StateProof = {"block_height":500,"canonical_confirmed":false,"key":"00000000000000036b6c76317573657231","leaf":"04cc4282fbb9ef6dc1e69de83409e26eb8c361846fb6d037378ccded537fcad2","leaf_count":2,"leaf_index":0,"siblings":["d04af2e5bb70005da65bfb52c6f2abd89cc3d302ddaaab0855a159d43a834cea"],"state_root":"099064e5796505367550de365185ed7aed10e3fd80189299012012eb16a4eaef","subtree":"channel_members","subtrees":[{"count":5,"name":"users","root":"75540336d69e8c916f85df8ea06f8860f73f0a44c0e8fde5dcbc93cb17e10fe7"},{"count":2,"name":"channels","root":"590bd089e04f8cbd636df09bac26f51e51df628e0c569e9ceebf3510098a4256"},{"count":0,"name":"delegations","root":"0000000000000000000000000000000000000000000000000000000000000000"},{"count":2,"name":"channel_members","root":"27228e65ed09b02599aeda520b8b49d3d7631efe42586c877debe52e124cf77c"}],"value":"eyJyb2xlIjoibWVtYmVyIn0="};
const USER: StateProof = {"block_height":500,"canonical_confirmed":false,"key":"6b6c76317573657234","leaf":"7eb950275ec6492db4b5f83792d1e3a6c3ba271893e2cc49bb1ce6b93d7a8e9f","leaf_count":5,"leaf_index":4,"siblings":["e9bc6d8b1747632666dd883d993da5f29cb188d842644690eed50ee7901b37d5"],"state_root":"099064e5796505367550de365185ed7aed10e3fd80189299012012eb16a4eaef","subtree":"users","subtrees":[{"count":5,"name":"users","root":"75540336d69e8c916f85df8ea06f8860f73f0a44c0e8fde5dcbc93cb17e10fe7"},{"count":2,"name":"channels","root":"590bd089e04f8cbd636df09bac26f51e51df628e0c569e9ceebf3510098a4256"},{"count":0,"name":"delegations","root":"0000000000000000000000000000000000000000000000000000000000000000"},{"count":2,"name":"channel_members","root":"27228e65ed09b02599aeda520b8b49d3d7631efe42586c877debe52e124cf77c"}],"value":"eyJhZGRyZXNzIjoia2x2MXVzZXI0In0="};
const ROOT = MEMBER.state_root;
const MEMBER_Q: StateProofQuery = { subtree: 'channel_members', channelId: 3, address: 'klv1user1' };
const USER_Q: StateProofQuery = { subtree: 'users', address: 'klv1user4' };

const clone = (p: StateProof): StateProof => JSON.parse(JSON.stringify(p));
const b64json = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64');

describe('verifyStateProof', () => {
  it('accepts the node known-answer proofs against their root', () => {
    expect(USER.state_root).toBe(ROOT);
    const m = verifyStateProof(MEMBER, { stateRoot: ROOT, query: MEMBER_Q });
    expect(m.ok).toBe(true);
    if (m.ok) {
      expect(m.subtree).toBe('channel_members');
      expect(m.record).toEqual({ role: 'member' });
      expect(m.blockHeight).toBe(500);
    }
    const u = verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q });
    expect(u.ok).toBe(true);
    if (u.ok) expect(u.record).toEqual({ address: 'klv1user4' });
  });

  it('accepts an uppercase expected root', () => {
    expect(verifyStateProof(MEMBER, { stateRoot: ROOT.toUpperCase(), query: MEMBER_Q }).ok).toBe(true);
  });

  it('rejects a different expected root', () => {
    expect(verifyStateProof(MEMBER, { stateRoot: 'ab'.repeat(32), query: MEMBER_Q })).toEqual({
      ok: false,
      reason: 'state_root is not the expected root',
    });
  });

  it('rejects a genuine proof for a different record than the one asked for', () => {
    // A valid proof that klv1user4 exists, offered for klv1user0.
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { subtree: 'users', address: 'klv1user0' } }).ok).toBe(false);
    // A valid membership proof, offered for another channel or wallet.
    for (const query of [
      { subtree: 'channel_members', channelId: 4, address: 'klv1user1' },
      { subtree: 'channel_members', channelId: 3, address: 'klv1user2' },
      { subtree: 'users', address: 'klv1user1' },
    ] as StateProofQuery[]) {
      expect(verifyStateProof(MEMBER, { stateRoot: ROOT, query }).ok).toBe(false);
    }
  });

  it("rejects one user's genuine record relabelled with another user's key", () => {
    // The users leaf hashes only the value, so a node can keep klv1user4's
    // genuine value and path but claim the key of klv1user3.
    const p = clone(USER);
    p.key = Buffer.from('klv1user3').toString('hex');
    expect(verifyStateProof(p, { stateRoot: ROOT, query: { subtree: 'users', address: 'klv1user3' } })).toEqual({
      ok: false,
      reason: 'record does not belong to the queried key',
    });
  });

  it('rejects an unsafe channel id instead of comparing rounded values', () => {
    const query = { subtree: 'channel_members', channelId: 2 ** 53 + 1, address: 'klv1user1' } as StateProofQuery;
    expect(verifyStateProof(MEMBER, { stateRoot: ROOT, query })).toEqual({ ok: false, reason: 'bad query' });
  });

  it('binds the requested height and a minimum height', () => {
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { ...USER_Q, height: 501 } }).ok).toBe(false);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: { ...USER_Q, height: 500 } }).ok).toBe(true);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q, minBlockHeight: 501 }).ok).toBe(false);
    expect(verifyStateProof(USER, { stateRoot: ROOT, query: USER_Q, minBlockHeight: 500 }).ok).toBe(true);
  });

  it('rejects a tampered value, sibling, index, count or subtree root', () => {
    const cases: Array<[StateProof, StateProofQuery, (p: StateProof) => void]> = [
      [MEMBER, MEMBER_Q, (p) => { p.value = b64json({ role: 'moderator' }); }],
      [USER, USER_Q, (p) => { p.value = b64json({ address: 'klv1user4', extra: 1 }); }],
      [MEMBER, MEMBER_Q, (p) => { p.siblings[0] = '00'.repeat(32); }],
      [MEMBER, MEMBER_Q, (p) => { p.leaf_index = 1; }],
      [USER, USER_Q, (p) => { p.leaf_index = 3; }],
      [USER, USER_Q, (p) => { p.leaf_count = 6; p.subtrees[0].count = 6; }],
      [MEMBER, MEMBER_Q, (p) => { p.subtrees[0].root = '11'.repeat(32); }],
      [MEMBER, MEMBER_Q, (p) => { p.subtrees[0].count += 1; }],
      [MEMBER, MEMBER_Q, (p) => { p.siblings.push('00'.repeat(32)); }],
      [USER, USER_Q, (p) => { p.siblings.pop(); }],
      [MEMBER, MEMBER_Q, (p) => { p.subtrees.reverse(); }],
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
      const p = clone(MEMBER);
      mutate(p);
      expect(verifyStateProof(p, { stateRoot: ROOT, query: MEMBER_Q }).ok).toBe(false);
    }
    expect(verifyStateProof(null as any, { stateRoot: ROOT, query: MEMBER_Q }).ok).toBe(false);
    expect(verifyStateProof(MEMBER, undefined as any).ok).toBe(false);
    expect(verifyStateProof(MEMBER, { stateRoot: 'nope', query: MEMBER_Q }).ok).toBe(false);
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

/** Answer each view from a table; records the call order. */
function stubViews(table: Record<string, string[] | (() => string[])>) {
  const calls: string[] = [];
  vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
    const { funcName } = JSON.parse(String(init.body));
    calls.push(funcName);
    const entry = table[funcName];
    if (!entry) throw new Error('unexpected view ' + funcName);
    return vmOk(typeof entry === 'function' ? entry() : entry);
  });
  return calls;
}

const utf8b64 = (s: string) => b64(Array.from(Buffer.from(s, 'utf8')));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getFinalCanonicalAnchor', () => {
  it('returns the canonical root for a non-escalated height', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)] });
    expect(await getFinalCanonicalAnchor('testnet', 500)).toBe(ROOT);
  });

  it('returns null when the height is not canonical yet', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [b64([])] });
    expect(await getFinalCanonicalAnchor('testnet', 500)).toBeNull();
  });

  it('ignores the provisional preview of an escalated height', async () => {
    const calls = stubViews({
      isDivergenceEscalated: [b64([1])],
      getEscalatedCanonical: [b64([])],
      getCanonicalAnchor: [utf8b64(ROOT)],
    });
    expect(await getFinalCanonicalAnchor('testnet', 500)).toBeNull();
    expect(calls).not.toContain('getCanonicalAnchor');
  });

  it('uses the materialized resolution of an escalated height', async () => {
    stubViews({ isDivergenceEscalated: [b64([1])], getEscalatedCanonical: [utf8b64(ROOT)] });
    expect(await getFinalCanonicalAnchor('testnet', 500)).toBe(ROOT);
  });

  it('fails closed when the escalation view errors', async () => {
    vi.stubGlobal('fetch', async () => ({
      ok: true,
      json: async () => ({ data: { data: { returnCode: 'UserError', returnMessage: 'misconfigured' } } }),
    }) as unknown as Response);
    await expect(getFinalCanonicalAnchor('testnet', 500)).rejects.toThrow();
  });

  it('re-checks escalation after reading the root', async () => {
    let n = 0;
    stubViews({
      isDivergenceEscalated: () => [b64(n++ === 0 ? [] : [1])],
      getCanonicalAnchor: [utf8b64('cd'.repeat(32))],
      getEscalatedCanonical: [b64([])],
    });
    expect(await getFinalCanonicalAnchor('testnet', 500)).toBeNull();
  });
});

describe('verifyStateProofOnChain', () => {
  it('verifies against the on-chain root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64(ROOT)] });
    expect((await verifyStateProofOnChain(MEMBER, MEMBER_Q, 'testnet')).ok).toBe(true);
  });

  it('fails when the chain anchored a different root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [utf8b64('ef'.repeat(32))] });
    expect(await verifyStateProofOnChain(MEMBER, MEMBER_Q, 'testnet')).toEqual({
      ok: false,
      reason: 'state_root is not the expected root',
    });
  });

  it('reports not_canonical when there is no final root', async () => {
    stubViews({ isDivergenceEscalated: [b64([])], getCanonicalAnchor: [b64([])] });
    expect(await verifyStateProofOnChain(MEMBER, MEMBER_Q, 'testnet')).toEqual({ ok: false, reason: 'not_canonical' });
  });
});
