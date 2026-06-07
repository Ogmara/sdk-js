import { describe, it, expect } from 'vitest';
import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { decode } from '@msgpack/msgpack';
import { WalletSigner } from './auth';
import {
  generateDeviceEncKeypair,
  encPublicKeyHex,
  normalizeWalletSig,
  addressToPubkey,
  encBindClaim,
  buildDeviceEncBinding,
} from './encryption';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const utf8 = (s: string) => new TextEncoder().encode(s);

// Rebuild the exact Klever message hash the L2 node verifies against, so this
// test mirrors `verify_klever_message` byte-for-byte (cross-impl vector).
function kleverHash(msg: string): Uint8Array {
  const m = utf8(msg);
  const prefix = utf8('\x17Klever Signed Message:\n');
  const len = utf8(String(m.length));
  const data = new Uint8Array(prefix.length + len.length + m.length);
  data.set(prefix, 0);
  data.set(len, prefix.length);
  data.set(m, prefix.length + len.length);
  return keccak_256(data);
}

describe('normalizeWalletSig', () => {
  const raw = new Uint8Array(64).map((_, i) => (i * 7) & 0xff);
  const hex = toHex(raw);
  const b64Raw = Buffer.from(raw).toString('base64');
  const b64Hex = Buffer.from(hex, 'utf8').toString('base64'); // K5 double-encoding

  it('accepts raw 64 bytes (local signer)', () => {
    expect(normalizeWalletSig(raw)).toEqual(raw);
  });
  it('accepts 128-char hex (Klever Extension)', () => {
    expect(normalizeWalletSig(hex)).toEqual(raw);
  });
  it('accepts base64-of-hex (K5 mobile)', () => {
    expect(normalizeWalletSig(b64Hex)).toEqual(raw);
  });
  it('accepts base64 of raw bytes', () => {
    expect(normalizeWalletSig(b64Raw)).toEqual(raw);
  });
  it('rejects garbage and wrong-length input', () => {
    expect(() => normalizeWalletSig('not a signature!!')).toThrow();
    expect(() => normalizeWalletSig(new Uint8Array(32))).toThrow();
  });
});

describe('device enc keypair', () => {
  it('derives a 32-byte public key reproducibly', () => {
    const kp = generateDeviceEncKeypair();
    expect(kp.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(encPublicKeyHex(kp.privateKey)).toBe(kp.publicKeyHex);
  });
});

describe('addressToPubkey', () => {
  it('round-trips a generated wallet address to its pubkey', async () => {
    const signer = await WalletSigner.generate();
    expect(toHex(addressToPubkey(signer.signingAddress))).toBe(signer.publicKeyHex.toLowerCase());
  });
});

describe('buildDeviceEncBinding', () => {
  it('produces a wallet-authored envelope the node would accept', async () => {
    const wallet = await WalletSigner.generate();
    const dev = await WalletSigner.generate(); // device signing key = device_id
    const encKp = generateDeviceEncKeypair();
    const ts = 1_717_958_400_000;

    const envelopeBytes = await buildDeviceEncBinding({
      walletAddress: wallet.signingAddress,
      encPubHex: encKp.publicKeyHex,
      deviceIdHex: dev.publicKeyHex,
      walletSign: (claim) => wallet.signKleverMessage(utf8(claim)),
      timestamp: ts,
    });

    const env = decode(envelopeBytes) as Record<string, unknown>;
    expect(env.msg_type).toBe('DeviceEncBinding');
    expect(env.author).toBe(wallet.signingAddress);
    expect(env.timestamp).toBe(ts);

    const payload = decode(env.payload as Uint8Array) as Record<string, string>;
    expect(payload.enc_pub).toBe(encKp.publicKeyHex.toLowerCase());
    expect(payload.device_id).toBe(dev.publicKeyHex.toLowerCase());

    // msg_id = Keccak(walletPubkey || payload || tsBE8) — exactly as the node.
    const tsBytes = new Uint8Array(8);
    new DataView(tsBytes.buffer).setBigUint64(0, BigInt(ts));
    const idData = new Uint8Array(32 + (env.payload as Uint8Array).length + 8);
    idData.set(addressToPubkey(wallet.signingAddress), 0);
    idData.set(env.payload as Uint8Array, 32);
    idData.set(tsBytes, 32 + (env.payload as Uint8Array).length);
    expect(toHex(env.msg_id as Uint8Array)).toBe(toHex(keccak_256(idData)));

    // The wallet signature verifies over the re-derived canonical claim.
    const claim = encBindClaim(encKp.publicKeyHex, dev.publicKeyHex, wallet.signingAddress, ts);
    const ok = await ed.verifyAsync(
      env.signature as Uint8Array,
      kleverHash(claim),
      addressToPubkey(wallet.signingAddress),
    );
    expect(ok).toBe(true);
  });

  // CROSS-IMPL VECTOR — these literals are asserted identically in sdk-rust's
  // encryption tests. Any byte-drift between the two SDKs (or vs the L2 node)
  // breaks one of these suites. Wallet private key = bytes 0x01..0x20.
  it('matches the fixed cross-impl vector (sdk-rust parity)', async () => {
    const walletPriv = new Uint8Array(32).map((_, i) => i + 1);
    const encPub = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const deviceId = 'aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff';
    const ts = 1_717_958_400_000;
    const wallet = await WalletSigner.fromPrivateKey(walletPriv);

    expect(wallet.signingAddress).toBe(
      'klv10x64vt50ue20jsrckyfw32vt57gplpf6u62ma4lquwgshtgyjejq9d4x8v',
    );

    const env = decode(
      await buildDeviceEncBinding({
        walletAddress: wallet.signingAddress,
        encPubHex: encPub,
        deviceIdHex: deviceId,
        walletSign: (c) => wallet.signKleverMessage(utf8(c)),
        timestamp: ts,
      }),
    ) as Record<string, unknown>;

    expect(toHex(env.msg_id as Uint8Array)).toBe(
      '5d9a8ae182c8b7712f4bcf164711fb7cda1107e300a417364fdbc86ed39fa91b',
    );
    expect(toHex(env.signature as Uint8Array)).toBe(
      '0fa1a8132831b3542f8392b2332e9de509c849e0cd7980b5dc63e51acfcc3de19e28f72b61cebcdc8b4a4c8c6477c21e4d1e27a30667388c92a7ff4081f1220c',
    );
  });
});
