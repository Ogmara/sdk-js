import { describe, it, expect, afterEach, vi } from 'vitest';
import { discoverNodesViaSc, discoverNodeUrlsViaSc } from './sc_discovery';

// ── Helpers to build a fake Klever `/vm/query` response ────────────────

function b64(bytes: number[] | Uint8Array): string {
  return Buffer.from(bytes as any).toString('base64');
}

function vmOk(returnData: string[]) {
  return {
    ok: true,
    json: async () => ({ data: { data: { returnCode: 'Ok', returnData } } }),
  } as unknown as Response;
}

function vmRequireFail(message: string) {
  return {
    ok: true,
    json: async () => ({ data: { data: { returnCode: 'UserError', returnMessage: message } } }),
  } as unknown as Response;
}

/** A deterministic 32-byte address whose first byte encodes `id`. */
function addr(id: number): number[] {
  const a = new Array(32).fill(0);
  a[0] = id;
  a[31] = id;
  return a;
}

/** minimal-BE bytes for a small u64 (enough for the test timestamps). */
function tsBytes(v: number): number[] {
  if (v === 0) return [];
  const out: number[] = [];
  let n = v;
  while (n > 0) {
    out.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return out;
}

function utf8(s: string): number[] {
  return Array.from(Buffer.from(s, 'utf8'));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('discoverNodesViaSc', () => {
  it('decodes getActiveNodes + getNodeMetadata and derives HTTPS endpoints', async () => {
    const meta: Record<string, string[]> = {};
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        // Single full-then-short page: two nodes, then stop (pageLimit default 64).
        return vmOk([
          b64(addr(1)), b64(tsBytes(1780000000)),
          b64(addr(2)), b64(tsBytes(1780000001)),
        ]);
      }
      if (body.funcName === 'getNodeMetadata') {
        const walletHex = body.args[0];
        const addrs = meta[walletHex] ?? [];
        return vmOk(addrs.map((m) => b64(utf8(m))));
      }
      throw new Error('unexpected func ' + body.funcName);
    });

    const nodes = await discoverNodesViaSc('testnet');
    expect(nodes).toHaveLength(2);
    // Both addresses bech32-encode to klv1… of the canonical length.
    for (const n of nodes) {
      expect(n.walletAddress).toMatch(/^klv1[0-9a-z]+$/);
      expect(n.walletHex).toHaveLength(64);
    }
    expect(nodes[0].lastAnchorAt).toBe(1780000000);
  });

  it('derives endpoint from a public dns4 multiaddr and the peerId from /p2p', async () => {
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        return vmOk([b64(addr(7)), b64(tsBytes(123))]);
      }
      // metadata: one public multiaddr with a /p2p PeerId
      return vmOk([utf8('/dns4/node.example.org/tcp/41720/p2p/12D3KooWABC')].map((u) => b64(u)));
    });
    const nodes = await discoverNodesViaSc('testnet');
    expect(nodes[0].endpoint).toBe('https://node.example.org');
    expect(nodes[0].peerId).toBe('12D3KooWABC');
  });

  it('SSRF-filters private/loopback/CGNAT hosts → endpoint null', async () => {
    const privateAddrs = [
      '/ip4/127.0.0.1/tcp/41720',
      '/ip4/10.0.0.5/tcp/41720',
      '/ip4/192.168.1.9/tcp/41720',
      '/ip4/100.64.0.1/tcp/41720', // CGNAT (tailscale)
      '/dns4/router.local/tcp/41720',
    ];
    let call = 0;
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        return vmOk([b64(addr(3)), b64(tsBytes(1))]);
      }
      // Return one private multiaddr per node-metadata call (only one node here).
      const m = privateAddrs[call++ % privateAddrs.length];
      return vmOk([b64(utf8(m))]);
    });
    const nodes = await discoverNodesViaSc('testnet');
    expect(nodes[0].endpoint).toBeNull();
  });

  it('SSRF-filters IPv6 embedded-IPv4 + NAT64/6to4 + port-injected DNS (audit C1/W3)', async () => {
    // One node per hostile multiaddr; every derived endpoint must be null.
    const bypass = [
      '/ip6/::ffff:127.0.0.1/tcp/41720',      // IPv4-mapped loopback (dotted)
      '/ip6/::ffff:7f00:1/tcp/41720',          // IPv4-mapped loopback (hex)
      '/ip6/::ffff:169.254.169.254/tcp/41720', // IPv4-mapped cloud metadata
      '/ip6/2002:7f00:1::/tcp/41720',          // 6to4 loopback
      '/ip6/64:ff9b::a00:1/tcp/41720',         // NAT64 → 10.0.0.1
      '/dns4/internal-host:22/tcp/41720',      // port injection
      '/ip4/1.2.3.4:22/tcp/41720',             // ip4 with embedded port
    ];
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        const out: string[] = [];
        for (let i = 0; i < bypass.length; i++) {
          out.push(b64(addr(i + 1)), b64(tsBytes(1)));
        }
        return vmOk(out);
      }
      const id = parseInt(body.args[0].slice(0, 2), 16); // first addr byte = index+1
      return vmOk([b64(utf8(bypass[id - 1]))]);
    });
    const nodes = await discoverNodesViaSc('testnet');
    expect(nodes).toHaveLength(bypass.length);
    for (const n of nodes) expect(n.endpoint).toBeNull();
  });

  it('caps getNodeMetadata entries at 16 (audit W2)', async () => {
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') return vmOk([b64(addr(1)), b64(tsBytes(1))]);
      // 50 multiaddrs returned by a hostile RPC → capped to 16.
      const many = Array.from({ length: 50 }, (_, i) => b64(utf8('/dns4/h' + i + '.example.org/tcp/1')));
      return vmOk(many);
    });
    const nodes = await discoverNodesViaSc('testnet');
    expect(nodes[0].multiaddrs.length).toBe(16);
  });

  it('treats an SC require! failure as the end of pagination (not an error)', async () => {
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        // pageLimit 1 forces a second page; the 2nd page require!-fails.
        const offsetHex = body.args[0];
        if (offsetHex === '00') return vmOk([b64(addr(1)), b64(tsBytes(1))]);
        return vmRequireFail('offset out of range');
      }
      return vmOk([]);
    });
    const nodes = await discoverNodesViaSc('testnet', { pageLimit: 1 });
    expect(nodes).toHaveLength(1);
  });

  it('discoverNodeUrlsViaSc returns deduped non-null endpoints only', async () => {
    vi.stubGlobal('fetch', async (_url: string, opts: any) => {
      const body = JSON.parse(opts.body);
      if (body.funcName === 'getActiveNodes') {
        return vmOk([
          b64(addr(1)), b64(tsBytes(1)),
          b64(addr(2)), b64(tsBytes(2)),
          b64(addr(3)), b64(tsBytes(3)),
        ]);
      }
      // node1 + node2 share a host; node3 has only a private host → dropped.
      const walletHex: string = body.args[0];
      const firstByte = walletHex.slice(0, 2);
      if (firstByte === '03') return vmOk([b64(utf8('/ip4/10.0.0.1/tcp/41720'))]);
      return vmOk([b64(utf8('/dns4/shared.example.org/tcp/41720'))]);
    });
    const urls = await discoverNodeUrlsViaSc('testnet');
    expect(urls).toEqual(['https://shared.example.org']);
  });
});
