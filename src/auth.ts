/**
 * Authentication — Klever wallet signing for API auth headers.
 *
 * Implements the auth header scheme from spec 4.2:
 *   X-Ogmara-Auth:      base64(Ed25519 signature)
 *   X-Ogmara-Address:   klv1... Klever address
 *   X-Ogmara-Timestamp: unix timestamp in milliseconds
 */

import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';

/** Klever message signing prefix (from kos-rs). */
const KLEVER_MSG_PREFIX = new Uint8Array([
  0x17, // 23 decimal = length of "Klever Signed Message:\n"
  ...new TextEncoder().encode('Klever Signed Message:\n'),
]);

/** Auth headers for an API request. */
export interface AuthHeaders {
  'x-ogmara-auth': string;
  'x-ogmara-address': string;
  'x-ogmara-timestamp': string;
}

/**
 * A signer that can produce auth headers for authenticated API calls.
 *
 * Can be created from a private key (for standalone apps) or from
 * the Klever wallet extension's signing interface.
 */
export class WalletSigner {
  private privateKey: Uint8Array;
  private publicKey: Uint8Array;
  readonly address: string;

  private constructor(privateKey: Uint8Array, publicKey: Uint8Array, address: string) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.address = address;
  }

  /** Create a signer from a raw 32-byte Ed25519 private key. */
  static async fromPrivateKey(privateKey: Uint8Array): Promise<WalletSigner> {
    if (privateKey.length !== 32) {
      throw new Error(`Expected 32-byte private key, got ${privateKey.length}`);
    }
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    const address = pubkeyToAddress(publicKey);
    return new WalletSigner(privateKey, publicKey, address);
  }

  /** Create a signer from a hex-encoded private key string. */
  static async fromHex(hexKey: string): Promise<WalletSigner> {
    const bytes = hexToBytes(hexKey);
    return WalletSigner.fromPrivateKey(bytes);
  }

  /** Generate a new random key pair. */
  static async generate(): Promise<WalletSigner> {
    const privateKey = ed.utils.randomPrivateKey();
    return WalletSigner.fromPrivateKey(privateKey);
  }

  /** Get the public key as hex string. */
  get publicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }

  /** Build auth headers for an API request. */
  async signRequest(method: string, path: string): Promise<AuthHeaders> {
    const timestamp = Date.now();
    // Sign path without query string — server verifies req.uri().path() only
    const pathOnly = path.split('?')[0];
    const authString = `ogmara-auth:${timestamp}:${method}:${pathOnly}`;
    const signature = await this.signKleverMessage(new TextEncoder().encode(authString));

    return {
      'x-ogmara-auth': btoa(String.fromCharCode(...signature)),
      'x-ogmara-address': this.address,
      'x-ogmara-timestamp': timestamp.toString(),
    };
  }

  /** Sign using Klever message format: prefix + length + message -> Keccak-256 -> Ed25519. */
  async signKleverMessage(message: Uint8Array): Promise<Uint8Array> {
    const lengthStr = new TextEncoder().encode(message.length.toString());
    const data = new Uint8Array(KLEVER_MSG_PREFIX.length + lengthStr.length + message.length);
    data.set(KLEVER_MSG_PREFIX, 0);
    data.set(lengthStr, KLEVER_MSG_PREFIX.length);
    data.set(message, KLEVER_MSG_PREFIX.length + lengthStr.length);
    const hash = keccak_256(data);
    return ed.signAsync(hash, this.privateKey);
  }

  /** Sign an Ogmara protocol message (for envelope construction). */
  async signEnvelope(
    version: number,
    msgType: number,
    msgId: Uint8Array,
    timestamp: number,
    payload: Uint8Array,
  ): Promise<Uint8Array> {
    const domainSep = new TextEncoder().encode('ogmara-msg:');
    const tsBytes = new Uint8Array(8);
    new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp));

    const data = new Uint8Array(
      domainSep.length + 1 + 1 + 32 + 8 + payload.length,
    );
    let offset = 0;
    data.set(domainSep, offset); offset += domainSep.length;
    data[offset++] = version;
    data[offset++] = msgType;
    data.set(msgId, offset); offset += 32;
    data.set(tsBytes, offset); offset += 8;
    data.set(payload, offset);

    const hash = keccak_256(data);
    return ed.signAsync(hash, this.privateKey);
  }

  /** Compute a message ID: Keccak-256(author_pubkey + payload + timestamp_bytes). */
  computeMsgId(payload: Uint8Array, timestamp: number): Uint8Array {
    const tsBytes = new Uint8Array(8);
    new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp));
    const data = new Uint8Array(32 + payload.length + 8);
    data.set(this.publicKey, 0);
    data.set(payload, 32);
    data.set(tsBytes, 32 + payload.length);
    return keccak_256(data);
  }
}

/**
 * External signer interface for Klever wallet extension integration.
 *
 * Instead of holding a private key, this delegates signing to
 * `window.kleverWeb.signMessage()`.
 */
export interface ExternalSigner {
  address: string;
  signMessage(payload: string): Promise<string>;
}

// --- Helpers ---

function pubkeyToAddress(pubkey: Uint8Array): string {
  // bech32 encode with "klv" prefix
  const words = toWords(pubkey);
  return bech32Encode('klv', words);
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// bech32 encoding (simplified — using 5-bit word conversion)
function toWords(data: Uint8Array): number[] {
  const words: number[] = [];
  let value = 0;
  let bits = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((value >> bits) & 31);
    }
  }
  if (bits > 0) {
    words.push((value << (5 - bits)) & 31);
  }
  return words;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const ret: number[] = [];
  for (let i = 0; i < 6; i++) ret.push((polymod >> (5 * (5 - i))) & 31);
  return ret;
}

function bech32Encode(hrp: string, data: number[]): string {
  const checksum = bech32CreateChecksum(hrp, data);
  const combined = [...data, ...checksum];
  return hrp + '1' + combined.map((d) => BECH32_CHARSET[d]).join('');
}
