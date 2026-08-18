/**
 * Authentication — Klever wallet signing for API auth headers.
 *
 * Implements the auth header scheme from spec 4.2:
 *   X-Ogmara-Auth:      base64(Ed25519 signature)
 *   X-Ogmara-Address:   klv1... (wallet) or ogd1... (device) address
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
  'x-ogmara-nonce': string;
  /**
   * W5 dm-sync backfill authorization — present only when this signer holds
   * the wallet key directly (not a delegated device key; see
   * `buildDmSyncAuthClaim`).
   */
  'x-ogmara-dmsync-auth-timestamp'?: string;
  'x-ogmara-dmsync-auth'?: string;
}

/**
 * The node identity an auth signature is bound to (audit 2026-06-07
 * host-binding). Fetched once from `GET /api/v1/health` and cached by the
 * client. Binding the signature to `{network, nodeId}` means a captured
 * header cannot be replayed against a different node or network.
 */
export interface NodeBinding {
  /** Klever network ("testnet" / "mainnet"), from `/health`. */
  network: string;
  /** Target node's Ogmara `node_id`, from `/health`. */
  nodeId: string;
}

/** Generate a random single-use nonce as a lowercase hex string. */
export function randomNonceHex(byteLen = 16): string {
  const buf = new Uint8Array(byteLen);
  // `globalThis.crypto` is present in browsers, Node 18+, Deno, and
  // workers. We deliberately do NOT fall back to Math.random — a weak
  // nonce would let an attacker pre-compute collisions and defeat the
  // replay cache.
  const c = globalThis.crypto;
  if (!c?.getRandomValues) {
    throw new Error('secure crypto.getRandomValues unavailable — cannot mint auth nonce');
  }
  c.getRandomValues(buf);
  return bytesToHex(buf);
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

  /**
   * Optional wallet address for device-to-wallet mapping.
   *
   * When set, this signer acts as a device key that belongs to the given
   * wallet. The node resolves this device key → wallet address for all
   * storage/indexing. When undefined, this signer IS the wallet (built-in
   * wallet mode — device key equals wallet key).
   */
  walletAddress?: string;

  /**
   * The Klever network ("testnet" / "mainnet") this signer is bound to for
   * envelope construction (`computeMsgId` / `signEnvelope`).
   *
   * Set this directly for offline/CLI signing where the network is known
   * upfront. `OgmaraClient.withSigner` instead wires `networkProvider` so it
   * gets resolved (and cached here) lazily from the target node's
   * `GET /api/v1/health` on first use — callers building envelopes never
   * need to await node discovery themselves.
   */
  network?: string;

  /**
   * Async resolver for `network`, used when it isn't known upfront. Wired by
   * `OgmaraClient.withSigner` to the client's cached node binding.
   */
  networkProvider?: () => Promise<string>;

  /**
   * Resolve `network`, throwing if neither it nor `networkProvider` is set.
   *
   * `computeMsgId`/`signEnvelope` fail loudly rather than sign an unbound
   * preimage — audit 2026-08-16 C1: a signature/msg_id with no network
   * binding can be replayed across testnet/mainnet since both share the
   * same wallet keys.
   */
  private async resolveNetwork(): Promise<string> {
    if (this.network) return this.network;
    if (this.networkProvider) {
      this.network = await this.networkProvider();
      return this.network;
    }
    throw new Error(
      'WalletSigner.network is unset — either set it directly, or attach this signer via ' +
        'OgmaraClient.withSigner() before building/signing an envelope',
    );
  }

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
    // Store a COPY, not the caller's array. Callers legitimately zero their
    // buffer after constructing a signer (best-effort key hygiene, e.g.
    // deviceVaultGenerate). If we kept the reference, that zeroing would wipe
    // the signer's key in-place — it would then sign with all-zeros while still
    // advertising the real public key/address, producing signatures the node
    // rejects as "invalid signature". A freshly-generated signer would fail
    // until the key was reloaded from storage (fromHex) on the next session —
    // exactly the "works only after reconnect" device-link bug (2026-06-11).
    return new WalletSigner(privateKey.slice(), publicKey, address);
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

  /** Get this key's device address (ogd1...). */
  get deviceAddress(): string {
    return devicePubkeyToAddress(this.publicKey);
  }

  /**
   * Get the signing address for auth headers.
   *
   * When `walletAddress` is set, this signer is a delegated device key
   * and uses the ogd1... device address. Otherwise it's the wallet itself
   * and uses the klv1... address.
   */
  get signingAddress(): string {
    return this.walletAddress ? this.deviceAddress : this.address;
  }

  /**
   * Build auth headers for an API request.
   *
   * The signature is bound to the target node's `{network, nodeId}` plus a
   * fresh single-use `nonce` (audit 2026-06-07 host-binding), so a captured
   * header is neither portable to another node nor replayable to this one.
   */
  async signRequest(method: string, path: string, binding: NodeBinding): Promise<AuthHeaders> {
    const timestamp = Date.now();
    // Sign path without query string — server verifies req.uri().path() only
    const pathOnly = path.split('?')[0];
    const nonce = randomNonceHex();
    const authString =
      `ogmara-auth:${binding.network}:${binding.nodeId}:${nonce}:${timestamp}:${method}:${pathOnly}`;
    const signature = await this.signKleverMessage(new TextEncoder().encode(authString));

    const base: AuthHeaders = {
      'x-ogmara-auth': btoa(String.fromCharCode(...signature)),
      'x-ogmara-address': this.signingAddress,
      'x-ogmara-timestamp': timestamp.toString(),
      'x-ogmara-nonce': nonce,
    };
    return { ...base, ...(await this.getDmSyncClaimHeaders(binding)) };
  }

  /**
   * Sign a push-gateway registration claim (audit 2026-06-07 C1/C3).
   *
   * The push gateway is a separate service (no node_id), so registration is
   * bound to the gateway's host + a single-use nonce + the exact `token` being
   * registered. The signed string is:
   *   `ogmara-push:{action}:{gatewayHost}:{nonce}:{timestamp}:{address}:{token}`
   * The gateway requires the signing address to equal the registered address,
   * so `address` here is this signer's `signingAddress` and callers MUST send
   * that same value as the request body's `address`.
   *
   * @param action - "register" or "unregister"
   * @param gatewayHost - the gateway URL the client POSTs to (trailing slash stripped)
   * @param token - the exact push token string sent in the request body
   * @returns the auth headers plus the `address` to put in the body
   */
  async signPushClaim(
    action: 'register' | 'unregister',
    gatewayHost: string,
    token: string,
  ): Promise<{ headers: AuthHeaders; address: string }> {
    const timestamp = Date.now();
    const nonce = randomNonceHex();
    const address = this.signingAddress;
    const host = gatewayHost.replace(/\/$/, '');
    const claim = `ogmara-push:${action}:${host}:${nonce}:${timestamp}:${address}:${token}`;
    const signature = await this.signKleverMessage(new TextEncoder().encode(claim));
    return {
      headers: {
        'x-ogmara-auth': btoa(String.fromCharCode(...signature)),
        'x-ogmara-address': address,
        'x-ogmara-timestamp': timestamp.toString(),
        'x-ogmara-nonce': nonce,
      },
      address,
    };
  }

  /** Sign a raw hash with Ed25519 (no prefix, no additional hashing). Used for TX signing. */
  async signRawHash(hash: Uint8Array): Promise<Uint8Array> {
    return ed.signAsync(hash, this.privateKey);
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

  /**
   * Sign an Ogmara protocol message (for envelope construction).
   *
   * Format (protocol v2, audit 2026-08-16 C1): `"ogmara-msg:" + networkLen(1)
   * + network + version(1) + msgType(1) + msgId(32) + timestamp(8) +
   * payload`. `network` ("testnet"/"mainnet") binds the signature to a
   * single Klever network — mirrors `signing::ogmara_signed_bytes` in the
   * node (l2-node `crypto/signing.rs`); the two must never drift apart.
   */
  async signEnvelope(
    version: number,
    msgType: number,
    msgId: Uint8Array,
    timestamp: number,
    payload: Uint8Array,
  ): Promise<Uint8Array> {
    const network = await this.resolveNetwork();
    const domainSep = new TextEncoder().encode('ogmara-msg:');
    const networkBytes = new TextEncoder().encode(network);
    const tsBytes = new Uint8Array(8);
    new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp));

    const data = new Uint8Array(
      domainSep.length + 1 + networkBytes.length + 1 + 1 + 32 + 8 + payload.length,
    );
    let offset = 0;
    data.set(domainSep, offset); offset += domainSep.length;
    data[offset++] = networkBytes.length;
    data.set(networkBytes, offset); offset += networkBytes.length;
    data[offset++] = version;
    data[offset++] = msgType;
    data.set(msgId, offset); offset += 32;
    data.set(tsBytes, offset); offset += 8;
    data.set(payload, offset);

    const hash = keccak_256(data);
    return ed.signAsync(hash, this.privateKey);
  }

  /**
   * Compute a message ID (protocol v2, audit 2026-08-16 C1):
   * `Keccak-256(networkLen(1) + network + author_pubkey + payload + timestamp_bytes)`.
   * Mirrors `crypto::compute_msg_id` in the node — must never drift apart.
   */
  async computeMsgId(payload: Uint8Array, timestamp: number): Promise<Uint8Array> {
    const network = await this.resolveNetwork();
    const networkBytes = new TextEncoder().encode(network);
    const tsBytes = new Uint8Array(8);
    new DataView(tsBytes.buffer).setBigUint64(0, BigInt(timestamp));
    const data = new Uint8Array(1 + networkBytes.length + 32 + payload.length + 8);
    let offset = 0;
    data[offset++] = networkBytes.length;
    data.set(networkBytes, offset); offset += networkBytes.length;
    data.set(this.publicKey, offset); offset += 32;
    data.set(payload, offset); offset += payload.length;
    data.set(tsBytes, offset);
    return keccak_256(data);
  }

  /**
   * Cached dm-sync backfill authorization claims (audit W5), keyed
   * `${network}:${nodeId}` so a signer reused against a different target
   * node re-signs per-node rather than replaying a claim bound to a stale
   * one.
   */
  private dmSyncClaims = new Map<string, { timestamp: number; signature: string }>();

  /**
   * How long a cached claim is reused before re-signing (audit W5 code
   * review follow-up). MUST stay comfortably under the server's
   * `WALLET_AUTH_MAX_AGE_SECS` (300s, l2-node `dm_sync.rs`) — caching
   * indefinitely (the original v1 behavior) meant a long-lived signer
   * silently and permanently lost dm-sync backfill the moment its one
   * cached claim aged past the server's window, with no error surfaced
   * anywhere. 4 minutes leaves a minute of margin for clock skew/latency.
   */
  private static readonly DM_SYNC_CLAIM_TTL_MS = 4 * 60 * 1000;

  /**
   * Build (and cache) the W5 dm-sync authorization headers for `binding`.
   * Returns `{}` for a delegated-device signer (`walletAddress` set) — v1
   * is wallet-direct only, see `buildDmSyncAuthClaim`.
   */
  private async getDmSyncClaimHeaders(binding: NodeBinding): Promise<Partial<AuthHeaders>> {
    if (this.walletAddress) return {};
    const key = `${binding.network}:${binding.nodeId}`;
    let cached = this.dmSyncClaims.get(key);
    if (!cached || Date.now() - cached.timestamp > WalletSigner.DM_SYNC_CLAIM_TTL_MS) {
      const { claimString, timestamp } = buildDmSyncAuthClaim(binding.nodeId, this.address, binding.network);
      const sig = await this.signKleverMessage(new TextEncoder().encode(claimString));
      cached = { timestamp, signature: btoa(String.fromCharCode(...sig)) };
      this.dmSyncClaims.set(key, cached);
    }
    return {
      'x-ogmara-dmsync-auth-timestamp': cached.timestamp.toString(),
      'x-ogmara-dmsync-auth': cached.signature,
    };
  }
}

/**
 * Build a device claim string for device-to-wallet registration.
 *
 * The claim format is:
 *   `ogmara-device-claim:{network}:{devicePubkeyHex}:{walletAddress}:{timestamp}`
 *
 * This string must be signed by the wallet key (using Klever message signing)
 * to prove the wallet authorized this device.
 *
 * `network` ("testnet"/"mainnet", e.g. from `OgmaraClient.getNetwork()`) binds
 * the claim to a single Klever network (audit 2026-08-16 C1 follow-up) — this
 * claim's signature is the sole authority (it never covers a msg_id), so
 * without `network` a claim captured on one network could be replayed as
 * valid on the other.
 *
 * @param devicePubkeyHex - Hex-encoded device Ed25519 public key (64 chars)
 * @param walletAddress - Wallet's klv1... address
 * @param network - Target node's Klever network ("testnet"/"mainnet")
 * @param timestamp - Unix timestamp in milliseconds (defaults to Date.now())
 * @returns The claim string and timestamp used
 */
export function buildDeviceClaim(
  devicePubkeyHex: string,
  walletAddress: string,
  network: string,
  timestamp?: number,
): { claimString: string; timestamp: number } {
  const ts = timestamp ?? Date.now();
  return {
    claimString: `ogmara-device-claim:${network}:${devicePubkeyHex.toLowerCase()}:${walletAddress}:${ts}`,
    timestamp: ts,
  };
}

/**
 * Build a dm-sync wallet-authorization claim string (audit W5): proves the
 * WALLET at `wallet` authorized `nodeId` SPECIFICALLY to backfill its DM
 * history on its behalf. Wallet-direct only (v1) — no device-delegation
 * support, so a device-key `WalletSigner` (one with `walletAddress` set)
 * never produces this claim (`WalletSigner.signRequest` silently omits the
 * two dm-sync headers for such a signer rather than sign with the wrong
 * key).
 *
 * `nodeId` is the SAME value already fetched via `GET /api/v1/health` for
 * the existing host-bound REST/WS auth (`NodeBinding.nodeId`) — no new
 * node-identity discovery needed.
 *
 * Mirrors `dm_sync::build_wallet_auth_claim` (l2-node) and
 * `build_dm_sync_auth_claim` (sdk-rust) — the three must never drift apart.
 *
 * @param nodeId - Target node's Ogmara `node_id` (from `NodeBinding`)
 * @param wallet - Wallet's klv1... address
 * @param network - Target node's Klever network ("testnet"/"mainnet")
 * @param timestamp - Unix timestamp in milliseconds (defaults to Date.now())
 */
export function buildDmSyncAuthClaim(
  nodeId: string,
  wallet: string,
  network: string,
  timestamp?: number,
): { claimString: string; timestamp: number } {
  const ts = timestamp ?? Date.now();
  return {
    claimString: `ogmara-dm-sync-auth:${network}:${nodeId}:${wallet}:${ts}`,
    timestamp: ts,
  };
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

/** Bech32 HRP for Klever wallet addresses. */
const WALLET_HRP = 'klv';

/** Bech32 HRP for Ogmara device key addresses. */
const DEVICE_HRP = 'ogd';

function pubkeyToAddress(pubkey: Uint8Array): string {
  // bech32 encode with "klv" wallet prefix
  const words = toWords(pubkey);
  return bech32Encode(WALLET_HRP, words);
}

function devicePubkeyToAddress(pubkey: Uint8Array): string {
  // bech32 encode with "ogd" device prefix
  const words = toWords(pubkey);
  return bech32Encode(DEVICE_HRP, words);
}

function hexToBytes(hex: string): Uint8Array {
  // Validate charset + even length BEFORE parsing: `parseInt` on a non-hex
  // pair returns NaN → silently coerced to 0, producing a *different*
  // keypair/signature instead of an error (audit 2026-06-07 W4).
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex string');
  }
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
