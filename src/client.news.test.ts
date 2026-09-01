import { describe, it, expect, vi, afterEach } from 'vitest';
import { OgmaraClient } from './client';

/** Capture the URL of the next fetch and reply with `body` (status 200 by default). */
function mockFetchOnce(body: unknown, status = 200): { calls: string[] } {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      calls.push(url);
      return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return { calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('listNews — hashtag filter (l2-node 0.124.0+)', () => {
  const client = new OgmaraClient({ nodeUrl: 'http://n' });

  it('normalizes a single tag before sending it', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0, has_more: false });
    await client.listNews({ tag: '#Klever' });
    expect(calls[0]).toContain('tag=klever');
    expect(calls[0]).not.toContain('Klever');
  });

  it('drops a single tag with no canonical form rather than sending garbage', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0 });
    await client.listNews({ tag: 'bad tag' });
    expect(calls[0]).not.toContain('tag=');
  });

  it('sends ?tags= as a normalized, deduped, comma-joined OR-set', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0 });
    await client.listNews({ tags: ['#Klever', 'klever', 'bad tag', 'DeFi'] });
    const q = new URL(calls[0]).searchParams.get('tags');
    expect(q).toBe('klever,defi');
  });

  it('caps ?tags= at 50 entries', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0 });
    const many = Array.from({ length: 80 }, (_, i) => `tag${i}`);
    await client.listNews({ tags: many });
    const q = new URL(calls[0]).searchParams.get('tags')!;
    expect(q.split(',')).toHaveLength(50);
  });

  it('tags wins over tag when both are given', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0 });
    await client.listNews({ tag: 'solo', tags: ['klever', 'defi'] });
    const p = new URL(calls[0]).searchParams;
    expect(p.get('tags')).toBe('klever,defi');
    expect(p.has('tag')).toBe(false);
  });

  it('an all-invalid tags list falls through to no filter (not to tag)', async () => {
    const { calls } = mockFetchOnce({ posts: [], total: 0 });
    await client.listNews({ tag: 'fallback', tags: ['bad one', 'bad two'] });
    // tags normalized to [] → we then honour `tag`
    expect(new URL(calls[0]).searchParams.get('tag')).toBe('fallback');
  });
});

describe('getHotTopics', () => {
  const client = new OgmaraClient({ nodeUrl: 'http://n' });

  it('requests the 24h window with the given limit', async () => {
    const { calls } = mockFetchOnce({ scope: 'network', topics: [{ hashtag: 'klever', count: 12 }] });
    const res = await client.getHotTopics({ limit: 15 });
    expect(calls[0]).toContain('/api/v1/news/hot-topics?window=24h&limit=15');
    expect(res.scope).toBe('network');
    expect(res.topics[0]).toEqual({ hashtag: 'klever', count: 12 });
  });

  it('degrades to an empty local result on a 404 (old node), without throwing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    mockFetchOnce('not found', 404);
    const res = await client.getHotTopics();
    expect(res).toEqual({ scope: 'local', topics: [] });
    // second call must not re-warn
    mockFetchOnce('not found', 404);
    await client.getHotTopics();
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('re-throws a non-404 error', async () => {
    mockFetchOnce('boom', 500);
    await expect(client.getHotTopics()).rejects.toThrow(/500/);
  });
});
