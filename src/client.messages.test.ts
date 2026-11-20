import { describe, it, expect, vi, afterEach } from 'vitest';
import { OgmaraClient } from './client';

function mockFetch(): { calls: string[] } {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      calls.push(url);
      return new Response(JSON.stringify({ messages: [], has_more: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }),
  );
  return { calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const A = 'ab'.repeat(32);
const B = 'cd'.repeat(32);
const C = 'ef'.repeat(32);
const BASE = 'http://n/api/v1/channels/7/messages';

describe('getChannelMessages — positional form is unchanged', () => {
  const client = new OgmaraClient({ nodeUrl: 'http://n' });

  it.each<[unknown[], string]>([
    [[], `${BASE}?limit=50`],
    [[undefined], `${BASE}?limit=50`],
    [[20], `${BASE}?limit=20`],
    [[20, B], `${BASE}?limit=20&before=${B}`],
    [[50, undefined, A], `${BASE}?limit=50&after=${A}`],
    [[50, B, A], `${BASE}?limit=50&after=${A}`],
    // No validation on the legacy path: passed through encoded, as before.
    [[10, 'not hex'], `${BASE}?limit=10&before=not%20hex`],
    [[10, ''], `${BASE}?limit=10`],
  ])('args %j → %s', async (args, url) => {
    const { calls } = mockFetch();
    await (client.getChannelMessages as (...a: unknown[]) => Promise<unknown>)(7, ...args);
    expect(calls).toEqual([url]);
  });
});

describe('getChannelMessages — options form', () => {
  const client = new OgmaraClient({ nodeUrl: 'http://n' });

  it('defaults to the newest page of 50', async () => {
    const { calls } = mockFetch();
    await client.getChannelMessages(7, {});
    expect(calls).toEqual([`${BASE}?limit=50`]);
  });

  it('sends around, lower-cased', async () => {
    const { calls } = mockFetch();
    await client.getChannelMessages(7, { around: A.toUpperCase(), limit: 30 });
    expect(calls).toEqual([`${BASE}?limit=30&around=${A}`]);
  });

  it('applies precedence around > after > before and sends only the winner', async () => {
    const { calls } = mockFetch();
    await client.getChannelMessages(7, { around: A, after: B, before: C });
    await client.getChannelMessages(7, { after: B, before: C });
    await client.getChannelMessages(7, { before: C });
    expect(calls).toEqual([`${BASE}?limit=50&around=${A}`, `${BASE}?limit=50&after=${B}`, `${BASE}?limit=50&before=${C}`]);
  });

  it('rejects malformed cursors, even losing ones, without a request', async () => {
    const { calls } = mockFetch();
    await expect(client.getChannelMessages(7, { around: 'x' })).rejects.toThrow(RangeError);
    await expect(client.getChannelMessages(7, { around: A, before: `${C}&limit=500` })).rejects.toThrow(RangeError);
    await expect(client.getChannelMessages(7, { after: '' })).rejects.toThrow(RangeError);
    await expect(client.getChannelMessages(7, { before: null as unknown as string })).rejects.toThrow(RangeError);
    await expect(client.getChannelMessages(7, { limit: -1 })).rejects.toThrow(RangeError);
    await expect(client.getChannelMessages(7, { limit: 1.5 })).rejects.toThrow(RangeError);
    expect(calls).toEqual([]);
  });

  it('passes the new response fields through', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({ messages: [], has_more: true, has_more_before: true, has_more_after: false, target_found: false }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      ),
    );
    const r = await client.getChannelMessages(7, { around: A });
    expect(r.target_found).toBe(false);
    expect(r.has_more_before).toBe(true);
    expect(r.has_more_after).toBe(false);
  });
});
