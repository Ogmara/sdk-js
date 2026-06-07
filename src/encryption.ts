/**
 * Device encryption keys (E2E P0, protocol §2.4).
 *
 * Each device holds an X25519 *encryption* keypair, distinct from its Ed25519
 * signing key and from the wallet key. The wallet authorizes the binding by
 * signing a canonical claim string (browser/K5 wallets can only `signMessage`),
 * so senders can later wrap message keys to every device of a recipient
 * (multi-device E2E). This module generates the device keypair, normalizes
 * wallet signatures across wallet encodings, and builds the WALLET-authored
 * `DeviceEncBinding` / `DeviceEncRevoke` envelopes the L2 node verifies.
 */
import { getPublicKey as x25519GetPublicKey, randomPrivateKey as x25519Random } from './x25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { encode } from '@msgpack/msgpack';
import { MessageType } from './types';

const MSG_TYPE_NAME: Record<number, string> = {
  [MessageType.DeviceEncBinding]: 'DeviceEncBinding',
  [MessageType.DeviceEncRevoke]: 'DeviceEncRevoke',
};

// --- small helpers ---------------------------------------------------------

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function hexToBytes(h: string): Uint8Array {
  const clean = h.toLowerCase();
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64ToBinary(s: string): string {
  if (typeof atob === 'function') return atob(s);
  // Node fallback (atob exists in Node 16+, but be defensive)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const B: any = (globalThis as any).Buffer;
  if (B) return B.from(s, 'base64').toString('binary');
  throw new Error('no base64 decoder available');
}

// --- device encryption keypair --------------------------------------------

/** A device X25519 encryption keypair. The private key never leaves the device. */
export interface DeviceEncKeypair {
  /** 32-byte X25519 secret key. Persist in the device vault; never transmit. */
  privateKey: Uint8Array;
  /** 32-byte X25519 public key, hex-encoded. Bound to the wallet and published. */
  publicKeyHex: string;
}

/** Generate a fresh device X25519 encryption keypair. */
export function generateDeviceEncKeypair(): DeviceEncKeypair {
  const privateKey = x25519Random();
  return { privateKey, publicKeyHex: toHex(x25519GetPublicKey(privateKey)) };
}

/** Recover the public key hex from a stored 32-byte X25519 secret key. */
export function encPublicKeyHex(privateKey: Uint8Array): string {
  return toHex(x25519GetPublicKey(privateKey));
}

// --- wallet signature normalization ----------------------------------------

/**
 * Normalize a wallet `signMessage` return into the raw 64 Ed25519 signature
 * bytes. The Klever Extension returns 128-char hex; K5 returns base64-of-hex
 * (double-encoded); a local {@link WalletSigner} returns raw bytes. Downstream
 * code MUST use these canonical bytes, never the wallet's string form, so any
 * signature-derived value (e.g. the future key-vault key) reproduces identically
 * across devices and wallets. See `feedback_klever_signmessage_encoding`.
 */
export function normalizeWalletSig(sig: string | Uint8Array): Uint8Array {
  if (sig instanceof Uint8Array) {
    if (sig.length !== 64) throw new Error(`expected 64 signature bytes, got ${sig.length}`);
    return sig;
  }
  // 1. raw 128-char hex — Klever Extension
  if (/^[0-9a-fA-F]{128}$/.test(sig)) return hexToBytes(sig);
  // 2. base64 wrapping
  let bin: string | null = null;
  try {
    bin = base64ToBinary(sig);
  } catch {
    bin = null;
  }
  if (bin !== null) {
    // 2a. base64 of the raw 64 signature bytes
    if (bin.length === 64) {
      const b = new Uint8Array(64);
      for (let i = 0; i < 64; i++) b[i] = bin.charCodeAt(i);
      return b;
    }
    // 2b. base64 of an ASCII hex string — K5 (double-encoded)
    if (/^[0-9a-fA-F]{128}$/.test(bin)) return hexToBytes(bin);
  }
  throw new Error('could not interpret wallet signature');
}

// --- bech32 address → pubkey (for msg_id) ----------------------------------

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/** Decode a bech32 address (`klv1…`/`ogd1…`) to its 32-byte Ed25519 public key. */
export function addressToPubkey(address: string): Uint8Array {
  const sep = address.lastIndexOf('1');
  if (sep < 1) throw new Error('not a bech32 address');
  const data = address.slice(sep + 1, -6); // strip 6-char checksum
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of data) {
    const v = BECH32_CHARSET.indexOf(c);
    if (v === -1) throw new Error('invalid bech32 character');
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// --- canonical claim strings (must match l2-node verify) -------------------

/** Canonical claim the WALLET signs to bind a device encryption key (§2.4). */
export function encBindClaim(
  encPubHex: string,
  deviceIdHex: string,
  wallet: string,
  timestamp: number,
): string {
  return `ogmara-enc-bind:${encPubHex.toLowerCase()}:${deviceIdHex.toLowerCase()}:${wallet}:${timestamp}`;
}

/** Canonical claim the WALLET signs to revoke a device encryption key (§2.4). */
export function encRevokeClaim(encPubHex: string, wallet: string, timestamp: number): string {
  return `ogmara-enc-revoke:${encPubHex.toLowerCase()}:${wallet}:${timestamp}`;
}

// --- wallet-authored envelope builders -------------------------------------

/**
 * Asks the wallet to sign an arbitrary string (the canonical claim). Returns the
 * wallet's signature — hex / base64-of-hex / raw bytes are all accepted (see
 * {@link normalizeWalletSig}). Wire `window.kleverWeb.signMessage` /
 * `window.klever.signMessage`, or a local `WalletSigner.signKleverMessage`.
 */
export type WalletSignFn = (claim: string) => Promise<string | Uint8Array>;

function computeMsgIdForAuthor(
  authorPubkey: Uint8Array,
  payload: Uint8Array,
  timestamp: number,
): Uint8Array {
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp));
  const data = new Uint8Array(32 + payload.length + 8);
  data.set(authorPubkey, 0);
  data.set(payload, 32);
  data.set(tsBytes, 32 + payload.length);
  return keccak_256(data);
}

async function buildEncEnvelope(
  msgType: number,
  walletAddress: string,
  payloadObj: Record<string, unknown>,
  claim: string,
  walletSign: WalletSignFn,
  timestamp: number,
): Promise<Uint8Array> {
  const payloadBytes = new Uint8Array(encode(payloadObj));
  // The envelope is WALLET-authored: author = wallet, msg_id is keyed to the
  // wallet's pubkey, and the signature is the wallet's Klever-message signature
  // over the canonical claim (the node re-derives and verifies it).
  const msgId = computeMsgIdForAuthor(addressToPubkey(walletAddress), payloadBytes, timestamp);
  const signature = normalizeWalletSig(await walletSign(claim));
  const envelope = {
    version: 1,
    msg_type: MSG_TYPE_NAME[msgType],
    msg_id: msgId,
    author: walletAddress,
    timestamp,
    lamport_ts: 0,
    payload: payloadBytes,
    signature,
    relay_path: [] as string[],
  };
  return new Uint8Array(encode(envelope));
}

export interface DeviceEncBindingParams {
  /** Wallet address (`klv1…`) that authorizes and authors the binding. */
  walletAddress: string;
  /** Device X25519 encryption public key, hex (32 bytes). */
  encPubHex: string;
  /** Device Ed25519 signing public key, hex (32 bytes) — the device id. */
  deviceIdHex: string;
  /** Asks the wallet to `signMessage` the canonical claim. */
  walletSign: WalletSignFn;
  /** Defaults to `Date.now()`. Must equal the envelope timestamp the node sees. */
  timestamp?: number;
}

/** Build a wallet-authored `DeviceEncBinding` (0x36) envelope (MessagePack bytes). */
export async function buildDeviceEncBinding(p: DeviceEncBindingParams): Promise<Uint8Array> {
  const ts = p.timestamp ?? Date.now();
  const encPub = p.encPubHex.toLowerCase();
  const deviceId = p.deviceIdHex.toLowerCase();
  const claim = encBindClaim(encPub, deviceId, p.walletAddress, ts);
  return buildEncEnvelope(
    MessageType.DeviceEncBinding,
    p.walletAddress,
    { device_id: deviceId, enc_pub: encPub },
    claim,
    p.walletSign,
    ts,
  );
}

export interface DeviceEncRevokeParams {
  walletAddress: string;
  encPubHex: string;
  walletSign: WalletSignFn;
  timestamp?: number;
}

/** Build a wallet-authored `DeviceEncRevoke` (0x37) envelope (MessagePack bytes). */
export async function buildDeviceEncRevoke(p: DeviceEncRevokeParams): Promise<Uint8Array> {
  const ts = p.timestamp ?? Date.now();
  const encPub = p.encPubHex.toLowerCase();
  const claim = encRevokeClaim(encPub, p.walletAddress, ts);
  return buildEncEnvelope(
    MessageType.DeviceEncRevoke,
    p.walletAddress,
    { enc_pub: encPub },
    claim,
    p.walletSign,
    ts,
  );
}
