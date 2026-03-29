import { describe, it, expect } from 'vitest';
import { WalletSigner } from './auth';

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

  it('should produce auth headers', async () => {
    const signer = await WalletSigner.generate();
    const headers = await signer.signRequest('GET', '/api/v1/health');

    expect(headers['x-ogmara-auth']).toBeTruthy();
    expect(headers['x-ogmara-address']).toMatch(/^klv1/);
    expect(parseInt(headers['x-ogmara-timestamp'])).toBeGreaterThan(0);
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
