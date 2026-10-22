/**
 * Private-channel-sync ("pchansync") backfill authorization claim
 * (sdk-js 0.65.0, l2-node 0.142.0+): claim strings, header attachment,
 * per-signer/per-binding caching, cross-protocol domain separation, WS
 * auth-frame fields and node golden-vector parity.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { WalletSigner, buildDeviceClaim, buildDmSyncAuthClaim, buildPrivateChannelSyncAuthClaim } from './auth';
import { OgmaraClient } from './client';
import { WsSubscription } from './ws';

const KLEVER_PREFIX = new TextEncoder().encode('\x17Klever Signed Message:\n');
function kleverHash(msg: Uint8Array): Uint8Array {
  const lenStr = new TextEncoder().encode(msg.length.toString());
  const data = new Uint8Array(KLEVER_PREFIX.length + lenStr.length + msg.length);
  data.set(KLEVER_PREFIX, 0);
  data.set(lenStr, KLEVER_PREFIX.length);
  data.set(msg, KLEVER_PREFIX.length + lenStr.length);
  return keccak_256(data);
}
function hexToU8(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
}
function b64ToU8(b: string): Uint8Array {
  return Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
}
/** Verify `sigB64` as a Klever-message signature of `message` by `pubHex`. */
function kleverVerify(sigB64: string, message: string, pubHex: string): Promise<boolean> {
  return ed.verifyAsync(b64ToU8(sigB64), kleverHash(new TextEncoder().encode(message)), hexToU8(pubHex));
}

const BINDING = { network: 'testnet', nodeId: 'node-abc' };

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('buildPrivateChannelSyncAuthClaim', () => {
  it('wallet-direct form matches the node string', () => {
    const { claimString, timestamp } = buildPrivateChannelSyncAuthClaim('node-abc', 'klv1wallet', 'testnet', 12345);
    expect(claimString).toBe('ogmara-private-channel-sync-auth:testnet:node-abc:klv1wallet:12345');
    expect(timestamp).toBe(12345);
  });

  it('device-signed form binds the (lowercased) device pubkey', () => {
    const pub = 'AB'.repeat(32);
    const { claimString } = buildPrivateChannelSyncAuthClaim('node-abc', 'klv1wallet', 'testnet', 12345, pub);
    expect(claimString).toBe(
      `ogmara-private-channel-sync-device-auth:testnet:node-abc:klv1wallet:${'ab'.repeat(32)}:12345`,
    );
  });

  it('rejects a malformed device pubkey', () => {
    expect(() => buildPrivateChannelSyncAuthClaim('n', 'klv1w', 'testnet', 1, 'abc')).toThrow(/64 hex/);
    expect(() => buildPrivateChannelSyncAuthClaim('n', 'klv1w', 'testnet', 1, 'zz'.repeat(32))).toThrow(/64 hex/);
  });
});

describe('WalletSigner pchansync headers', () => {
  it('wallet-direct signer attaches a claim that verifies against the node string', async () => {
    const signer = await WalletSigner.generate();
    const h = await signer.signRequest('GET', '/api/v1/health', BINDING);
    const ts = h['x-ogmara-pchansync-auth-timestamp']!;
    expect(ts).toMatch(/^\d+$/);
    const msg = `ogmara-private-channel-sync-auth:testnet:node-abc:${signer.address}:${ts}`;
    expect(await kleverVerify(h['x-ogmara-pchansync-auth']!, msg, signer.publicKeyHex)).toBe(true);
  });

  it('delegated-device signer signs the device form with its OWN key (no wallet prompt), dm-sync stays absent', async () => {
    const wallet = await WalletSigner.generate();
    const device = await WalletSigner.generate();
    device.walletAddress = wallet.address;
    const h = await device.signRequest('GET', '/api/v1/health', BINDING);
    expect(h['x-ogmara-address']).toBe(device.deviceAddress);
    expect(h['x-ogmara-dmsync-auth']).toBeUndefined();
    const ts = h['x-ogmara-pchansync-auth-timestamp']!;
    const msg =
      `ogmara-private-channel-sync-device-auth:testnet:node-abc:${wallet.address}:${device.publicKeyHex}:${ts}`;
    expect(await kleverVerify(h['x-ogmara-pchansync-auth']!, msg, device.publicKeyHex)).toBe(true);
    // Not a wallet-direct claim (and the wallet key never signed anything).
    const direct = `ogmara-private-channel-sync-auth:testnet:node-abc:${wallet.address}:${ts}`;
    expect(await kleverVerify(h['x-ogmara-pchansync-auth']!, direct, wallet.publicKeyHex)).toBe(false);
    expect(await kleverVerify(h['x-ogmara-pchansync-auth']!, direct, device.publicKeyHex)).toBe(false);
  });

  it('sends no claim when the binding has no node identity', async () => {
    const signer = await WalletSigner.generate();
    for (const b of [
      { network: 'testnet', nodeId: '' },
      { network: '', nodeId: 'node-abc' },
    ]) {
      const h = await signer.signRequest('GET', '/api/v1/health', b);
      expect(h['x-ogmara-pchansync-auth']).toBeUndefined();
      expect(h['x-ogmara-pchansync-auth-timestamp']).toBeUndefined();
      expect(h['x-ogmara-auth']).toBeTruthy();
    }
  });

  it('caches per (network, nodeId) and re-signs after the 4-minute TTL', async () => {
    vi.useFakeTimers();
    const signer = await WalletSigner.generate();
    const a = await signer.signRequest('GET', '/api/v1/health', BINDING);
    vi.advanceTimersByTime(3 * 60 * 1000);
    const b = await signer.signRequest('POST', '/api/v1/messages', BINDING);
    expect(b['x-ogmara-pchansync-auth']).toBe(a['x-ogmara-pchansync-auth']);
    expect(b['x-ogmara-pchansync-auth-timestamp']).toBe(a['x-ogmara-pchansync-auth-timestamp']);

    // Another node / network gets its own claim, bound to that identity.
    const other = await signer.signRequest('GET', '/api/v1/health', { network: 'testnet', nodeId: 'node-xyz' });
    expect(other['x-ogmara-pchansync-auth']).not.toBe(a['x-ogmara-pchansync-auth']);
    const otherMsg =
      `ogmara-private-channel-sync-auth:testnet:node-xyz:${signer.address}:${other['x-ogmara-pchansync-auth-timestamp']}`;
    expect(await kleverVerify(other['x-ogmara-pchansync-auth']!, otherMsg, signer.publicKeyHex)).toBe(true);
    const mainnet = await signer.signRequest('GET', '/api/v1/health', { network: 'mainnet', nodeId: 'node-abc' });
    expect(mainnet['x-ogmara-pchansync-auth']).not.toBe(a['x-ogmara-pchansync-auth']);

    vi.advanceTimersByTime(2 * 60 * 1000); // 5 min total, past the TTL
    const c = await signer.signRequest('GET', '/api/v1/health', BINDING);
    expect(c['x-ogmara-pchansync-auth-timestamp']).not.toBe(a['x-ogmara-pchansync-auth-timestamp']);
    const cMsg =
      `ogmara-private-channel-sync-auth:testnet:node-abc:${signer.address}:${c['x-ogmara-pchansync-auth-timestamp']}`;
    expect(await kleverVerify(c['x-ogmara-pchansync-auth']!, cMsg, signer.publicKeyHex)).toBe(true);
  });

  it('never shares a cached claim across signers (account switch)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_790_001_800_000);
    const a = await WalletSigner.generate();
    const b = await WalletSigner.generate();
    const ha = await a.signRequest('GET', '/api/v1/health', BINDING);
    const hb = await b.signRequest('GET', '/api/v1/health', BINDING);
    // Same binding, same timestamp — still each signer's own signature.
    expect(hb['x-ogmara-pchansync-auth-timestamp']).toBe(ha['x-ogmara-pchansync-auth-timestamp']);
    expect(hb['x-ogmara-pchansync-auth']).not.toBe(ha['x-ogmara-pchansync-auth']);
    const ts = hb['x-ogmara-pchansync-auth-timestamp'];
    expect(
      await kleverVerify(hb['x-ogmara-pchansync-auth']!, `ogmara-private-channel-sync-auth:testnet:node-abc:${b.address}:${ts}`, b.publicKeyHex),
    ).toBe(true);
    expect(
      await kleverVerify(hb['x-ogmara-pchansync-auth']!, `ogmara-private-channel-sync-auth:testnet:node-abc:${a.address}:${ts}`, a.publicKeyHex),
    ).toBe(false);
  });

  it('re-signs when walletAddress changes on the same instance (no claim for the previous wallet)', async () => {
    const device = await WalletSigner.generate();
    const w1 = await WalletSigner.generate();
    const w2 = await WalletSigner.generate();
    device.walletAddress = w1.address;
    const h1 = await device.signRequest('GET', '/api/v1/health', BINDING);
    device.walletAddress = w2.address;
    const h2 = await device.signRequest('GET', '/api/v1/health', BINDING);
    const ts = h2['x-ogmara-pchansync-auth-timestamp'];
    expect(h2['x-ogmara-pchansync-auth']).not.toBe(h1['x-ogmara-pchansync-auth']);
    const msg = `ogmara-private-channel-sync-device-auth:testnet:node-abc:${w2.address}:${device.publicKeyHex}:${ts}`;
    expect(await kleverVerify(h2['x-ogmara-pchansync-auth']!, msg, device.publicKeyHex)).toBe(true);
  });

  it('a dm-sync claim never verifies as pchansync, and vice versa', async () => {
    const signer = await WalletSigner.generate();
    const h = await signer.signRequest('GET', '/api/v1/health', BINDING);
    const dmTs = Number(h['x-ogmara-dmsync-auth-timestamp']);
    const pcTs = Number(h['x-ogmara-pchansync-auth-timestamp']);
    const dmAsPc = buildPrivateChannelSyncAuthClaim('node-abc', signer.address, 'testnet', dmTs).claimString;
    const pcAsDm = buildDmSyncAuthClaim('node-abc', signer.address, 'testnet', pcTs).claimString;
    expect(await kleverVerify(h['x-ogmara-dmsync-auth']!, dmAsPc, signer.publicKeyHex)).toBe(false);
    expect(await kleverVerify(h['x-ogmara-pchansync-auth']!, pcAsDm, signer.publicKeyHex)).toBe(false);
    // Sanity: each verifies under its own domain.
    expect(
      await kleverVerify(h['x-ogmara-dmsync-auth']!, buildDmSyncAuthClaim('node-abc', signer.address, 'testnet', dmTs).claimString, signer.publicKeyHex),
    ).toBe(true);
  });

  it('push-gateway claims carry no pchansync headers', async () => {
    const signer = await WalletSigner.generate();
    const { headers } = await signer.signPushClaim('register', 'https://push.example', 'tok');
    expect(headers['x-ogmara-pchansync-auth']).toBeUndefined();
  });
});

/**
 * Golden-vector parity with the node. Values copied verbatim from
 * l2-node/tests/fixtures/phase2/vectors.json (format
 * "ogmara-phase2-golden-vectors/1", generator "l2-node 0.142.0
 * src/api/phase2_fixtures.rs::golden_vectors"), sections `keys.joiner`,
 * `keys.joiner_device` and `claims`. Ed25519 is deterministic, so the SDK
 * must reproduce the node's signatures byte-for-byte. Regenerate there,
 * then update here, if the fixture ever changes.
 */
describe('pchansync golden vectors (l2-node 0.142.0)', () => {
  const NETWORK = 'testnet';
  const NODE_ID = 'ac4j4Z6D8Fa7fKWp2Y1Aw63Pkco';
  const JOINER = {
    address: 'klv1z2jptykgklqh6szeu7efkc0gl7tvws2l97qrxj8j7qt7qku758dql2nl7u',
    pubkeyHex: '12a41592c8b7c17d4059e7b29b61e8ff96c7415f2f803348f2f017e05b9ea1da',
    seedHex: '67'.repeat(32),
  };
  const JOINER_DEVICE = {
    address: 'ogd1udxn5qdkzyhpg2026ctxsszlfm6tunug2w47u5re629vdsfllhgqd9ra2s',
    pubkeyHex: 'e34d3a01b6112e1429ead61668405f4ef4be4f8853abee5079d28ac6c13ffdd0',
    seedHex: '69'.repeat(32),
  };
  const CLAIM_TS = 1790001800000;
  const WALLET_DIRECT = {
    message:
      'ogmara-private-channel-sync-auth:testnet:ac4j4Z6D8Fa7fKWp2Y1Aw63Pkco:klv1z2jptykgklqh6szeu7efkc0gl7tvws2l97qrxj8j7qt7qku758dql2nl7u:1790001800000',
    signatureB64: '/xjWXmWzEu+oJTHlkYnPebsiXlJUCZzHtYHC5ygWsuwEnFkA0Bcae+S4Ntl+ZCLhF+mznqu5k45UwrEwJ1BsCg==',
  };
  const DEVICE_SIGNED = {
    message:
      'ogmara-private-channel-sync-device-auth:testnet:ac4j4Z6D8Fa7fKWp2Y1Aw63Pkco:klv1z2jptykgklqh6szeu7efkc0gl7tvws2l97qrxj8j7qt7qku758dql2nl7u:e34d3a01b6112e1429ead61668405f4ef4be4f8853abee5079d28ac6c13ffdd0:1790001800000',
    signatureB64: 'i/iVeOQDVM2lgdDJPv60duQqYP2CAf9kXZAFdMSx4Wp+5C6UBnx02Tjgmy3w571u0i8QDRVnmbyB4v0P+BplDQ==',
    delegation: {
      message:
        'ogmara-device-claim:testnet:e34d3a01b6112e1429ead61668405f4ef4be4f8853abee5079d28ac6c13ffdd0:klv1z2jptykgklqh6szeu7efkc0gl7tvws2l97qrxj8j7qt7qku758dql2nl7u:1790000060000',
      signatureB64: '7lwdIDV8PEE+Kyrk6WOzhJExcSDsQffoZ/SglMGu1R+3x44p1eFOXPEoD+AFQPtvf6Qga9FKyvb+Jno9xxZYCg==',
      timestamp: 1790000060000,
    },
  };
  const binding = { network: NETWORK, nodeId: NODE_ID };

  it('fixture keys derive the expected addresses', async () => {
    const wallet = await WalletSigner.fromHex(JOINER.seedHex);
    const device = await WalletSigner.fromHex(JOINER_DEVICE.seedHex);
    expect(wallet.address).toBe(JOINER.address);
    expect(wallet.publicKeyHex).toBe(JOINER.pubkeyHex);
    expect(device.deviceAddress).toBe(JOINER_DEVICE.address);
    expect(device.publicKeyHex).toBe(JOINER_DEVICE.pubkeyHex);
  });

  it('wallet-direct claim string + signature match byte-for-byte', async () => {
    expect(buildPrivateChannelSyncAuthClaim(NODE_ID, JOINER.address, NETWORK, CLAIM_TS).claimString).toBe(
      WALLET_DIRECT.message,
    );
    vi.useFakeTimers();
    vi.setSystemTime(CLAIM_TS);
    const wallet = await WalletSigner.fromHex(JOINER.seedHex);
    const h = await wallet.signRequest('GET', '/api/v1/health', binding);
    expect(h['x-ogmara-pchansync-auth-timestamp']).toBe(String(CLAIM_TS));
    expect(h['x-ogmara-pchansync-auth']).toBe(WALLET_DIRECT.signatureB64);
  });

  it('device-signed claim string + signature match byte-for-byte', async () => {
    expect(
      buildPrivateChannelSyncAuthClaim(NODE_ID, JOINER.address, NETWORK, CLAIM_TS, JOINER_DEVICE.pubkeyHex).claimString,
    ).toBe(DEVICE_SIGNED.message);
    vi.useFakeTimers();
    vi.setSystemTime(CLAIM_TS);
    const device = await WalletSigner.fromHex(JOINER_DEVICE.seedHex);
    device.walletAddress = JOINER.address;
    const h = await device.signRequest('GET', '/api/v1/health', binding);
    expect(h['x-ogmara-address']).toBe(JOINER_DEVICE.address);
    expect(h['x-ogmara-pchansync-auth-timestamp']).toBe(String(CLAIM_TS));
    expect(h['x-ogmara-pchansync-auth']).toBe(DEVICE_SIGNED.signatureB64);
  });

  it('the delegation proof the node pairs with it is the wallet-signed device claim', async () => {
    const { claimString } = buildDeviceClaim(
      JOINER_DEVICE.pubkeyHex,
      JOINER.address,
      NETWORK,
      DEVICE_SIGNED.delegation.timestamp,
    );
    expect(claimString).toBe(DEVICE_SIGNED.delegation.message);
    const wallet = await WalletSigner.fromHex(JOINER.seedHex);
    const sig = await wallet.signKleverMessage(new TextEncoder().encode(claimString));
    expect(btoa(String.fromCharCode(...sig))).toBe(DEVICE_SIGNED.delegation.signatureB64);
  });
});

// --- Transport: REST (federate) + WS auth frame ---

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
}

function stubFetch(onRequest?: (url: string) => void): Captured[] {
  const calls: Captured[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({
        url: String(url),
        method: init?.method ?? 'GET',
        headers: { ...((init?.headers as Record<string, string>) ?? {}) },
      });
      onRequest?.(String(url));
      const body = String(url).includes('/api/v1/health')
        ? { status: 'ok', version: '0', peers: 0, node_id: 'node1', network: 'testnet' }
        : { federated: true, channel_id: 5 };
      const text = JSON.stringify(body);
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: null,
        json: async () => JSON.parse(text),
        text: async () => text,
      } as unknown as Response;
    }),
  );
  return calls;
}

describe('OgmaraClient transport', () => {
  it('federateChannel carries a pchansync claim bound to the node and the caller', async () => {
    const calls = stubFetch();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(signer);
    await client.federateChannel(5, 'https://host.example');
    const fed = calls.find((c) => c.url.endsWith('/api/v1/channels/5/federate'))!;
    const ts = fed.headers['x-ogmara-pchansync-auth-timestamp'];
    const msg = `ogmara-private-channel-sync-auth:testnet:node1:${signer.address}:${ts}`;
    expect(await kleverVerify(fed.headers['x-ogmara-pchansync-auth']!, msg, signer.publicKeyHex)).toBe(true);
  });

  it('a client signer swap produces the new signer\'s claim, never the old one', async () => {
    const calls = stubFetch();
    const a = await WalletSigner.generate();
    const b = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://node.example' }).withSigner(a);
    await client.federateChannel(5, 'https://host.example');
    client.withSigner(b);
    await client.federateChannel(5, 'https://host.example');
    const feds = calls.filter((c) => c.url.endsWith('/federate'));
    expect(feds).toHaveLength(2);
    const second = feds[1]!.headers;
    expect(second['x-ogmara-address']).toBe(b.address);
    const msg = `ogmara-private-channel-sync-auth:testnet:node1:${b.address}:${second['x-ogmara-pchansync-auth-timestamp']}`;
    expect(await kleverVerify(second['x-ogmara-pchansync-auth']!, msg, b.publicKeyHex)).toBe(true);
  });
});

describe('WsSubscription auth frame', () => {
  it('includes pchansync_timestamp / pchansync_signature', async () => {
    stubFetch();
    const sent: string[] = [];
    class FakeWebSocket {
      static OPEN = 1;
      readyState = 1;
      onopen: (() => void) | null = null;
      onmessage: unknown = null;
      onclose: unknown = null;
      onerror: unknown = null;
      constructor(public url: string) {
        sockets.push(this);
      }
      send(d: string) {
        sent.push(d);
      }
      close() {}
    }
    const sockets: FakeWebSocket[] = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);

    const device = await WalletSigner.generate();
    const wallet = await WalletSigner.generate();
    device.walletAddress = wallet.address;
    const sub = new WsSubscription({ nodeUrl: 'https://node.example', onEvent: () => {}, signer: device, autoReconnect: false });
    try {
      await vi.waitFor(() => expect(sockets.length).toBe(1));
      await sockets[0]!.onopen!();
      await vi.waitFor(() => expect(sent.length).toBeGreaterThan(0));
      const frame = JSON.parse(sent[0]!);
      expect(frame.address).toBe(device.deviceAddress);
      expect(typeof frame.pchansync_timestamp).toBe('number');
      expect(frame.dm_sync_signature).toBeUndefined();
      const msg =
        `ogmara-private-channel-sync-device-auth:testnet:node1:${wallet.address}:${device.publicKeyHex}:${frame.pchansync_timestamp}`;
      expect(await kleverVerify(frame.pchansync_signature, msg, device.publicKeyHex)).toBe(true);
    } finally {
      sub.close();
    }
  });
});
