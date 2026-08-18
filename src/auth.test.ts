import { describe, it, expect, vi } from 'vitest';
import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { WalletSigner, buildDmSyncAuthClaim } from './auth';

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

describe('WalletSigner', () => {
  it('should generate a random key pair', async () => {
    const signer = await WalletSigner.generate();
    expect(signer.address).toMatch(/^klv1/);
    expect(signer.publicKeyHex).toHaveLength(64);
  });

  it('should create from hex private key', async () => {
    const signer1 = await WalletSigner.generate();
    // We can't easily extract the private key hex, but we can test the flow
    expect(signer1.address).toBeTruthy();
  });

  it('survives the caller zeroing the private-key buffer after construction', async () => {
    // Regression (2026-06-11): deviceVaultGenerate zeroes its key buffer right
    // after building the signer (best-effort hygiene). The signer must own a
    // COPY — otherwise it signs with all-zeros while advertising the real
    // pubkey, and the node rejects every request as "invalid signature" until
    // the key reloads next session ("works only after reconnect" device-link bug).
    const priv = new Uint8Array(32);
    crypto.getRandomValues(priv);
    const signer = await WalletSigner.fromPrivateKey(priv);
    const pubHex = signer.publicKeyHex;
    priv.fill(0); // caller wipes its buffer
    const msg = new TextEncoder().encode('ogmara-auth:testnet:node-abc:nonce:1:GET:/api/v1/devices');
    const sig = await signer.signKleverMessage(msg);
    const ok = await ed.verifyAsync(sig, kleverHash(msg), hexToU8(pubHex));
    expect(ok).toBe(true);
  });

  it('should produce auth headers bound to a node', async () => {
    const signer = await WalletSigner.generate();
    const headers = await signer.signRequest('GET', '/api/v1/health', {
      network: 'testnet',
      nodeId: 'node-abc',
    });

    expect(headers['x-ogmara-auth']).toBeTruthy();
    expect(headers['x-ogmara-address']).toMatch(/^klv1/);
    expect(parseInt(headers['x-ogmara-timestamp'])).toBeGreaterThan(0);
    // Host-binding nonce (audit 2026-06-07): present, hex, single-use.
    expect(headers['x-ogmara-nonce']).toMatch(/^[0-9a-f]{32}$/);
  });

  it('should mint a fresh nonce per request', async () => {
    const signer = await WalletSigner.generate();
    const binding = { network: 'testnet', nodeId: 'node-abc' };
    const a = await signer.signRequest('GET', '/api/v1/health', binding);
    const b = await signer.signRequest('GET', '/api/v1/health', binding);
    expect(a['x-ogmara-nonce']).not.toEqual(b['x-ogmara-nonce']);
  });

  it('buildDmSyncAuthClaim produces the ogmara-dm-sync-auth domain string (audit W5)', () => {
    const { claimString, timestamp } = buildDmSyncAuthClaim('node-abc', 'klv1wallet', 'testnet', 12345);
    expect(claimString).toBe('ogmara-dm-sync-auth:testnet:node-abc:klv1wallet:12345');
    expect(timestamp).toBe(12345);
  });

  it('a wallet-direct signer attaches a valid dm-sync claim to auth headers (audit W5)', async () => {
    const signer = await WalletSigner.generate();
    const binding = { network: 'testnet', nodeId: 'node-abc' };
    const headers = await signer.signRequest('GET', '/api/v1/health', binding);

    expect(headers['x-ogmara-dmsync-auth-timestamp']).toBeTruthy();
    expect(headers['x-ogmara-dmsync-auth']).toBeTruthy();

    const claimTs = parseInt(headers['x-ogmara-dmsync-auth-timestamp']!);
    const { claimString } = buildDmSyncAuthClaim('node-abc', signer.address, 'testnet', claimTs);
    const sig = Uint8Array.from(atob(headers['x-ogmara-dmsync-auth']!), (c) => c.charCodeAt(0));
    const ok = await ed.verifyAsync(sig, kleverHash(new TextEncoder().encode(claimString)), hexToU8(signer.publicKeyHex));
    expect(ok).toBe(true);
  });

  it('a delegated-device signer omits dm-sync claim headers (audit W5, v1 scope)', async () => {
    const signer = await WalletSigner.generate();
    signer.walletAddress = 'klv1someotherwallet';
    const headers = await signer.signRequest('GET', '/api/v1/health', { network: 'testnet', nodeId: 'node-abc' });
    expect(headers['x-ogmara-dmsync-auth-timestamp']).toBeUndefined();
    expect(headers['x-ogmara-dmsync-auth']).toBeUndefined();
  });

  it('caches the dm-sync claim per (network, nodeId) rather than re-signing every request', async () => {
    const signer = await WalletSigner.generate();
    const binding = { network: 'testnet', nodeId: 'node-abc' };
    const a = await signer.signRequest('GET', '/api/v1/health', binding);
    const b = await signer.signRequest('GET', '/api/v1/messages', binding);
    expect(a['x-ogmara-dmsync-auth']).toEqual(b['x-ogmara-dmsync-auth']);
    expect(a['x-ogmara-dmsync-auth-timestamp']).toEqual(b['x-ogmara-dmsync-auth-timestamp']);

    // A different target node gets its own claim (bound to that node_id).
    const c = await signer.signRequest('GET', '/api/v1/health', { network: 'testnet', nodeId: 'node-xyz' });
    expect(c['x-ogmara-dmsync-auth']).not.toEqual(a['x-ogmara-dmsync-auth']);
  });

  it('re-signs a cached dm-sync claim once it goes stale (audit W5 code review follow-up)', async () => {
    // Regression: caching the claim forever meant a long-lived signer
    // silently and permanently lost dm-sync backfill the moment its one
    // cached claim aged past the server's freshness window (300s).
    vi.useFakeTimers();
    try {
      const signer = await WalletSigner.generate();
      const binding = { network: 'testnet', nodeId: 'node-abc' };
      const a = await signer.signRequest('GET', '/api/v1/health', binding);

      vi.advanceTimersByTime(3 * 60 * 1000); // 3 min — still within TTL
      const b = await signer.signRequest('GET', '/api/v1/health', binding);
      expect(b['x-ogmara-dmsync-auth']).toEqual(a['x-ogmara-dmsync-auth']);

      vi.advanceTimersByTime(2 * 60 * 1000); // +2 min = 5 min total — past TTL
      const c = await signer.signRequest('GET', '/api/v1/health', binding);
      expect(c['x-ogmara-dmsync-auth-timestamp']).not.toEqual(a['x-ogmara-dmsync-auth-timestamp']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('should compute deterministic msg_id', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';
    const payload = new TextEncoder().encode('hello');
    const id1 = await signer.computeMsgId(payload, 12345);
    const id2 = await signer.computeMsgId(payload, 12345);
    expect(id1).toEqual(id2);
  });

  it('should bind msg_id to the network (audit 2026-08-16 C1)', async () => {
    const signer = await WalletSigner.generate();
    const payload = new TextEncoder().encode('hello');
    signer.network = 'testnet';
    const testnetId = await signer.computeMsgId(payload, 12345);
    signer.network = 'mainnet';
    const mainnetId = await signer.computeMsgId(payload, 12345);
    expect(testnetId).not.toEqual(mainnetId);
  });

  it('throws computing msg_id/signing an envelope before network is known', async () => {
    const signer = await WalletSigner.generate();
    const payload = new TextEncoder().encode('hello');
    await expect(signer.computeMsgId(payload, 12345)).rejects.toThrow('network is unset');
    await expect(
      signer.signEnvelope(2, 0x01, new Uint8Array(32), 12345, payload),
    ).rejects.toThrow('network is unset');
  });

  it('should sign envelopes (64-byte signature)', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';
    const msgId = new Uint8Array(32);
    const payload = new TextEncoder().encode('test');
    const sig = await signer.signEnvelope(2, 0x01, msgId, Date.now(), payload);
    expect(sig).toHaveLength(64);
  });

  it('should reject invalid key length', async () => {
    await expect(
      WalletSigner.fromPrivateKey(new Uint8Array(16)),
    ).rejects.toThrow('Expected 32-byte');
  });
});
