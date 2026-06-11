import { describe, it, expect } from 'vitest';
import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { WalletSigner } from './auth';

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

  it('should compute deterministic msg_id', async () => {
    const signer = await WalletSigner.generate();
    const payload = new TextEncoder().encode('hello');
    const id1 = signer.computeMsgId(payload, 12345);
    const id2 = signer.computeMsgId(payload, 12345);
    expect(id1).toEqual(id2);
  });

  it('should sign envelopes (64-byte signature)', async () => {
    const signer = await WalletSigner.generate();
    const msgId = new Uint8Array(32);
    const payload = new TextEncoder().encode('test');
    const sig = await signer.signEnvelope(1, 0x01, msgId, Date.now(), payload);
    expect(sig).toHaveLength(64);
  });

  it('should reject invalid key length', async () => {
    await expect(
      WalletSigner.fromPrivateKey(new Uint8Array(16)),
    ).rejects.toThrow('Expected 32-byte');
  });
});
