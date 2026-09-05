/**
 * Regression test for the 2026-09-05 cross-account leak: the browser/webview
 * HTTP cache keys a GET response by URL only, blind to the signed auth
 * headers that determine WHO the response is for. Without `cache: 'no-store'`
 * on every request, a second wallet hitting the exact same path (e.g.
 * `GET /api/v1/channels?page=1&limit=50` right after a multi-account switch)
 * could silently receive the FIRST wallet's real response straight from
 * cache — including private channels it was never a member of — with no
 * network round trip and no re-validation against the new auth headers.
 *
 * This asserts the invariant directly rather than the symptom: every single
 * `fetch()` call this client makes must opt out of the HTTP cache.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OgmaraClient } from './client';
import { WalletSigner } from './auth';

const NODE_URL = 'https://test-node.example';

function jsonResponse(body: unknown, ok = true): Response {
  return {
    ok,
    status: ok ? 200 : 500,
    headers: { get: () => null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

describe('OgmaraClient — every fetch() call disables the HTTP cache', () => {
  let calls: RequestInit[] = [];

  beforeEach(() => {
    calls = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      calls.push(init ?? {});
      const url = String(_url);
      if (url.endsWith('/api/v1/health')) {
        return jsonResponse({ status: 'ok', version: '0', peers: 0, node_id: 'node1', network: 'testnet' });
      }
      if (url.includes('/api/v1/channels')) {
        return jsonResponse({ channels: [], total: 0, page: 1 });
      }
      if (url.includes('/api/v1/channels/unread')) {
        return jsonResponse({ unread: {} });
      }
      if (url.includes('/api/v1/messages')) {
        return jsonResponse({ ok: true });
      }
      return jsonResponse({});
    }));
  });

  it('a public GET (listChannels, via get()) opts out of the cache', async () => {
    const client = new OgmaraClient({ nodeUrl: NODE_URL });
    await client.listChannels(1, 50);
    expect(calls.length).toBeGreaterThan(0);
    for (const init of calls) expect(init.cache).toBe('no-store');
  });

  it('an authenticated GET (getUnreadCounts, via getAuthenticated()) opts out of the cache', async () => {
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: NODE_URL }).withSigner(signer);
    await client.getUnreadCounts();
    // Includes the lazy /health call that resolves the node binding.
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const init of calls) expect(init.cache).toBe('no-store');
  });

  it('an authenticated write (joinChannel, via postEnvelope()) opts out of the cache', async () => {
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: NODE_URL }).withSigner(signer);
    await client.joinChannel(1);
    expect(calls.length).toBeGreaterThan(0);
    for (const init of calls) expect(init.cache).toBe('no-store');
  });
});
