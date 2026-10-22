/**
 * Private-channel member-proof verifier — "verify before cover"
 * (sdk-js 0.66.0, l2-node 0.142.0+, protocol §3.9.1 Phase 2).
 *
 * Before a client wraps a private channel's epoch key to the other members it
 * asks its node for the raw signed evidence behind each membership
 * (`OgmaraClient.getMemberProofs`, `POST /channels/{id}/member-proofs`) and
 * re-verifies it HERE, without trusting the node: the creator is anchored by
 * a locally pinned creator, else the `ChannelCreate`'s Keccak id derivation
 * (a create WITHOUT a derivation is refused unless the caller opts in for a
 * channel it already knew before l2-node 0.139 — `allowUnderivedCreator`),
 * every envelope's msg_id and signature are recomputed, and the join is run
 * through the same rules as the node's `verify_private_join` (rules 4-8, SYNC
 * semantics) plus the apply-time "no removal at/after the join" check.
 * Callers must PIN the creator on the first successful establishment (any
 * `creatorSource` while no pin was passed) and pass it on every later call.
 *
 * Everything fails CLOSED: an unverifiable member is simply not covered. A
 * hostile node can therefore make any member fail (withholding evidence, or
 * padding a response past the verification budget) — no new power, since it
 * could always just omit that member.
 *
 * What it does NOT close (residual W3 — forgery closed, withholding only
 * narrowed):
 *  - The verifier has no clock dependence: it judges a join only by the
 *    signed timestamps in the evidence. A node that WITHHOLDS a Kick/Ban
 *    therefore keeps an old, once-valid join covered INDEFINITELY — not just
 *    for the invite's TTL. The caller-kept `seenRemovals` map (removals seen
 *    from any node, any time) narrows this.
 *  - `ChannelLeave` is never considered. A node can keep listing (and so get a
 *    client to cover) a member who has left, as long as their join verifies.
 *  - Testnet legacy (proofless) joins are accepted whenever their SIGNED
 *    timestamp is before the activation constant — a member's own join can be
 *    backdated forever by design (that is what grandfathering means). Mainnet
 *    forces activation 0, so there is no legacy path there.
 *
 * Ground truth: l2-node `src/messages/router.rs` (`verify_embedded_envelope`,
 * `verify_invite_proof`, `verify_moderator_grant`, `verify_inviter_authority`,
 * `verify_private_join`) and `src/api/member_proofs.rs`. Parity is pinned by
 * the node's golden vectors (`tests/fixtures/phase2/vectors.json`).
 */

import { decode } from '@msgpack/msgpack';
import * as ed from '@noble/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import { addressToPubkey, encBindClaim } from './encryption';
import { base64ToBytes } from './invite';
import { MessageType, PROTOCOL_VERSION } from './types';
import type {
  DeviceClaimObject,
  DeviceEncKeyRecord,
  MemberProofEntry,
  MemberProofsResponse,
} from './types';
import type { OgmaraClient } from './client';

// --- Constants (mirror the node; never drift) ---------------------------------

/**
 * Testnet `private_join_proof_activation_ms` (2026-11-01T00:00:00Z): a
 * proofless (legacy) join signed strictly before it is accepted. Mainnet is
 * always 0 (every join needs an invite) — the node forces that too.
 */
export const TESTNET_LEGACY_JOIN_ACTIVATION_MS = 1793491200000;

/** Clock-drift allowance the node applies to signed timestamps (±5 min). */
export const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000;

/** Default invite lifetime when `expires_at` is absent (7 days). */
const DEFAULT_INVITE_TTL_MS = 7 * 24 * 3600 * 1000;
/** Hard upper bound on an invite's lifetime (14 days). */
const MAX_INVITE_TTL_MS = 14 * 24 * 3600 * 1000;
/** Cap on the invite embedded in a join (`MAX_JOIN_INVITE_BYTES`). */
const MAX_JOIN_INVITE_BYTES = 2048;
/** Cap on the grant embedded in an invite (`MAX_INVITER_GRANT_BYTES`). */
const MAX_INVITER_GRANT_BYTES = 1024;
/** Largest evidence envelope the node ever serves (`MAX_EVIDENCE_BYTES`). */
export const MAX_EVIDENCE_BYTES = 16 * 1024;
/** Max removals served per target / moderator removals per inviter. */
const MAX_REMOVALS_PER_TARGET = 16;
/** Grants examined per moderator (the node serves ≤ 4; more is ignored, which only ever fails closed). */
const MAX_GRANTS_EXAMINED = 8;
/** Max delegations / revocations in one device-claim object (node serves ≤ 4). */
const MAX_DEVICE_ITEMS = 4;
/** `Number.MAX_SAFE_INTEGER` — the private channel_id derivation modulus. */
const JS_SAFE_INTEGER_MODULUS = BigInt(Number.MAX_SAFE_INTEGER);
/** Max addresses per `member-proofs` request. */
export const MAX_MEMBER_PROOF_ADDRESSES = 100;
/** Cap on one `member-proofs` HTTP response body (the node's own budget is ~2 MiB). */
export const MAX_MEMBER_PROOFS_RESPONSE_BYTES = 8 * 1024 * 1024;
/**
 * Max distinct (non-memoized) envelope / device-claim verifications per
 * `member-proofs` response (each costs 1-2 Ed25519 verifications). A full
 * legitimate 100-member response needs a few hundred; past this budget every
 * not-yet-decided member fails closed (`verification_budget_exhausted`).
 */
export const MAX_VERIFICATIONS_PER_RESPONSE = 2000;

const KLEVER_MSG_PREFIX = new TextEncoder().encode('\x17Klever Signed Message:\n');
const OGMARA_DOMAIN_SEP = new TextEncoder().encode('ogmara-msg:');

/**
 * Legacy-join activation constant for `network`: testnet
 * {@link TESTNET_LEGACY_JOIN_ACTIVATION_MS}; mainnet and any other network 0
 * (every join needs an invite — fail closed).
 */
export function legacyJoinActivationMs(network: string): number {
  return network === 'testnet' ? TESTNET_LEGACY_JOIN_ACTIVATION_MS : 0;
}

// --- Small helpers -------------------------------------------------------------

const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes32(hex: string): Uint8Array | null {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** A msgpack byte field: `bin`, or (rmp-serde `Vec<u8>`) an array of 0..=255 integers. */
function asBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) {
    const out = new Uint8Array(v.length);
    for (let i = 0; i < v.length; i++) {
      const b = v[i];
      if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) return null;
      out[i] = b;
    }
    return out;
  }
  return null;
}

/** A u64 that fits a JS safe integer (number or bigint from the decoder), else null. */
function asSafeU64(v: unknown): number | null {
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? v : null;
  if (typeof v === 'bigint') return v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null;
  return null;
}

function isU64(v: unknown): boolean {
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0;
  if (typeof v === 'bigint') return v >= 0n && v < 1n << 64n;
  return false;
}

function msgpackDecode(bytes: Uint8Array): unknown {
  // `useBigInt64`: u64 values (timestamps > 2^32 are encoded as uint64) come
  // back exact as bigint instead of a possibly-rounded double.
  return decode(bytes, { useBigInt64: true });
}

/** Decode a struct payload as a named map or a positional array (`fields` gives the slot names). */
function decodeStruct(payload: Uint8Array, fields: readonly string[]): Record<string, unknown> | null {
  let raw: unknown;
  try {
    raw = msgpackDecode(payload);
  } catch {
    return null;
  }
  if (Array.isArray(raw)) {
    if (raw.length > fields.length) return null;
    const out: Record<string, unknown> = {};
    raw.forEach((v, i) => {
      out[fields[i]!] = v;
    });
    return out;
  }
  if (raw && typeof raw === 'object' && !(raw instanceof Uint8Array)) return raw as Record<string, unknown>;
  return null;
}

function isWalletAddress(a: unknown): a is string {
  if (typeof a !== 'string' || !a.startsWith('klv1') || a.length > 128) return false;
  try {
    addressToPubkey(a);
    return true;
  } catch {
    return false;
  }
}

/**
 * Bytes of a raw envelope given as bytes or standard base64, refusing anything
 * over `maxBytes` BEFORE any decode work (a base64 string is length-checked
 * before it is even decoded). Null when malformed or oversized.
 */
function rawBytes(v: unknown, maxBytes: number = MAX_EVIDENCE_BYTES): Uint8Array | null {
  if (v instanceof Uint8Array) return v.length <= maxBytes ? v : null;
  if (typeof v === 'string') {
    if (v.length > Math.ceil(maxBytes / 3) * 4) return null;
    const b = base64ToBytes(v);
    return b && b.length <= maxBytes ? b : null;
  }
  return null;
}

/** `\x17Klever Signed Message:\n` + decimal length + message → Keccak-256. */
function kleverMessageHash(message: Uint8Array): Uint8Array {
  const len = textEncoder.encode(String(message.length));
  const data = new Uint8Array(KLEVER_MSG_PREFIX.length + len.length + message.length);
  data.set(KLEVER_MSG_PREFIX, 0);
  data.set(len, KLEVER_MSG_PREFIX.length);
  data.set(message, KLEVER_MSG_PREFIX.length + len.length);
  return keccak_256(data);
}

async function edVerify(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): Promise<boolean> {
  try {
    return await ed.verifyAsync(sig, msg, pub);
  } catch {
    return false;
  }
}

/** Verify `sig` as a Klever-message signature of the UTF-8 string `message` by `pub`. */
async function verifyKleverString(sig: Uint8Array, message: string, pub: Uint8Array): Promise<boolean> {
  if (sig.length !== 64) return false;
  return edVerify(sig, kleverMessageHash(textEncoder.encode(message)), pub);
}

function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

/** `Keccak-256(networkLen(1) + network + author_pubkey + payload + timestamp_be8)` — node `compute_msg_id`. */
function computeMsgId(network: Uint8Array, authorPub: Uint8Array, payload: Uint8Array, ts: number): Uint8Array {
  const data = new Uint8Array(1 + network.length + 32 + payload.length + 8);
  let o = 0;
  data[o++] = network.length;
  data.set(network, o); o += network.length;
  data.set(authorPub, o); o += 32;
  data.set(payload, o); o += payload.length;
  data.set(u64be(ts), o);
  return keccak_256(data);
}

/** `"ogmara-msg:" + networkLen + network + version + msgType + msgId + ts_be8 + payload` — node `ogmara_signed_bytes`. */
function ogmaraSignedBytes(
  network: Uint8Array,
  version: number,
  msgType: number,
  msgId: Uint8Array,
  ts: number,
  payload: Uint8Array,
): Uint8Array {
  const data = new Uint8Array(OGMARA_DOMAIN_SEP.length + 1 + network.length + 1 + 1 + 32 + 8 + payload.length);
  let o = 0;
  data.set(OGMARA_DOMAIN_SEP, o); o += OGMARA_DOMAIN_SEP.length;
  data[o++] = network.length;
  data.set(network, o); o += network.length;
  data[o++] = version;
  data[o++] = msgType;
  data.set(msgId, o); o += 32;
  data.set(u64be(ts), o); o += 8;
  data.set(payload, o);
  return data;
}

// --- Envelope verification -----------------------------------------------------

/** Numeric msg_type for a Rust variant NAME (the rmp-serde wire form). */
const MSG_TYPE_BY_NAME: Record<string, number> = Object.fromEntries(Object.entries(MessageType));

/**
 * Message types whose `signature` covers a CLAIM STRING, not the envelope
 * preimage (the node verifies them through dedicated claim paths). They are
 * never valid evidence in an embedded/served slot here.
 */
const CLAIM_SIGNED_TYPES = new Set<number>([
  MessageType.DeviceDelegation,
  MessageType.DeviceEncBinding,
  MessageType.DeviceEncRevoke,
]);

/** A cryptographically verified envelope. */
export interface VerifiedEnvelope {
  version: number;
  /** Numeric msg_type (see `MessageType`). */
  msgType: number;
  /** Lowercase hex msg_id (recomputed and matched). */
  msgId: string;
  /** Signing address (`klv1…` wallet or `ogd1…` device), NOT resolved. */
  author: string;
  /** Signed envelope timestamp, unix ms. */
  timestamp: number;
  /** Raw payload bytes (MessagePack). */
  payload: Uint8Array;
  /** Which signing form verified: plain Ogmara preimage, or Klever-message wrapped. */
  signatureForm: 'ogmara' | 'klever';
}

/** Result of {@link verifyEnvelopeBytes}. */
export type EnvelopeVerification =
  | { ok: true; envelope: VerifiedEnvelope }
  | { ok: false; reason: string };

/** Options for {@link verifyEnvelopeBytes}. */
export interface VerifyEnvelopeOptions {
  /** Require exactly this msg_type (type-confusion guard for embedded slots). */
  expectedType?: number;
  /** Size cap on the raw bytes (default {@link MAX_EVIDENCE_BYTES}). */
  maxBytes?: number;
}

interface DecodedEnvelope {
  version: number;
  msgType: number;
  msgId: Uint8Array;
  author: string;
  timestamp: number;
  payload: Uint8Array;
  signature: Uint8Array;
}

/** Structural decode (map or positional-array form). Returns a reason string on failure. */
function decodeEnvelope(raw: Uint8Array): DecodedEnvelope | string {
  let obj: unknown;
  try {
    obj = msgpackDecode(raw);
  } catch {
    return 'not_an_envelope';
  }
  let version: unknown, msgType: unknown, msgId: unknown, author: unknown, timestamp: unknown;
  let lamport: unknown, payload: unknown, signature: unknown, relayPath: unknown;
  if (Array.isArray(obj)) {
    if (obj.length < 8 || obj.length > 9) return 'not_an_envelope';
    [version, msgType, msgId, author, timestamp, lamport, payload, signature, relayPath] = obj;
  } else if (obj && typeof obj === 'object' && !(obj instanceof Uint8Array)) {
    const o = obj as Record<string, unknown>;
    ({
      version,
      msg_type: msgType,
      msg_id: msgId,
      author,
      timestamp,
      lamport_ts: lamport,
      payload,
      signature,
      relay_path: relayPath,
    } = o);
  } else {
    return 'not_an_envelope';
  }
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 0 || version > 255) {
    return 'not_an_envelope';
  }
  // rmp-serde's unit-enum wire form is the variant NAME; an integer would be
  // the serde declaration index, not the u8 discriminant — refused.
  if (typeof msgType !== 'string' || !Object.prototype.hasOwnProperty.call(MSG_TYPE_BY_NAME, msgType)) {
    return 'unknown_msg_type';
  }
  const idBytes = asBytes(msgId);
  const payloadBytes = asBytes(payload);
  const sigBytes = asBytes(signature);
  const ts = asSafeU64(timestamp);
  if (!idBytes || idBytes.length !== 32 || !payloadBytes || !sigBytes || ts === null) return 'not_an_envelope';
  if (typeof author !== 'string' || !isU64(lamport)) return 'not_an_envelope';
  if (relayPath !== undefined) {
    if (!Array.isArray(relayPath) || relayPath.some((r) => typeof r !== 'string')) return 'not_an_envelope';
    if (relayPath.length > 64) return 'relay_path_too_long';
  }
  return {
    version,
    msgType: MSG_TYPE_BY_NAME[msgType]!,
    msgId: idBytes,
    author,
    timestamp: ts,
    payload: payloadBytes,
    signature: sigBytes,
  };
}

/**
 * Decode and cryptographically verify a raw envelope, mirroring the node's
 * `verify_embedded_envelope`: size cap, structure, `version == 2`, 64-byte
 * signature, ≤ 64 relay hops, exact `expectedType`, recomputed msg_id
 * (network-bound) and the signature in BOTH accepted forms — the plain Ogmara
 * preimage (`Keccak-256("ogmara-msg:" + …)`) and the Klever-message wrapping
 * of the same bytes (extension / K5 wallets). Claim-signed types
 * (DeviceDelegation, DeviceEncBinding, DeviceEncRevoke) are refused: their
 * signature does not cover the envelope.
 *
 * Never throws; `network` is the Klever network string ("testnet"/"mainnet").
 */
export async function verifyEnvelopeBytes(
  raw: Uint8Array,
  network: string,
  options: VerifyEnvelopeOptions = {},
): Promise<EnvelopeVerification> {
  try {
    const maxBytes = options.maxBytes ?? MAX_EVIDENCE_BYTES;
    if (!(raw instanceof Uint8Array) || raw.length === 0 || raw.length > maxBytes) {
      return { ok: false, reason: 'size' };
    }
    const net = textEncoder.encode(typeof network === 'string' ? network : '');
    if (net.length === 0 || net.length > 255) return { ok: false, reason: 'bad_network' };
    const env = decodeEnvelope(raw);
    if (typeof env === 'string') return { ok: false, reason: env };
    if (env.signature.length !== 64) return { ok: false, reason: 'bad_signature_length' };
    if (env.version !== PROTOCOL_VERSION) return { ok: false, reason: 'unsupported_version' };
    if (options.expectedType !== undefined && env.msgType !== options.expectedType) {
      return { ok: false, reason: 'wrong_msg_type' };
    }
    if (CLAIM_SIGNED_TYPES.has(env.msgType)) return { ok: false, reason: 'claim_signed_type' };
    if (!env.author.startsWith('klv1') && !env.author.startsWith('ogd1')) return { ok: false, reason: 'bad_author' };
    let pub: Uint8Array;
    try {
      pub = addressToPubkey(env.author);
    } catch {
      return { ok: false, reason: 'bad_author' };
    }
    if (!bytesEqual(computeMsgId(net, pub, env.payload, env.timestamp), env.msgId)) {
      return { ok: false, reason: 'msg_id_mismatch' };
    }
    const signed = ogmaraSignedBytes(net, env.version, env.msgType, env.msgId, env.timestamp, env.payload);
    let form: 'ogmara' | 'klever' | null = null;
    if (await edVerify(env.signature, keccak_256(signed), pub)) form = 'ogmara';
    else if (await edVerify(env.signature, kleverMessageHash(signed), pub)) form = 'klever';
    if (!form) return { ok: false, reason: 'bad_signature' };
    return {
      ok: true,
      envelope: {
        version: env.version,
        msgType: env.msgType,
        msgId: toHex(env.msgId),
        author: env.author,
        timestamp: env.timestamp,
        payload: env.payload,
        signatureForm: form,
      },
    };
  } catch {
    return { ok: false, reason: 'internal_error' };
  }
}

// --- Device claims (plan §6) ---------------------------------------------------

/** A device claim whose delegation signatures verified (see {@link verifyDeviceClaimObject}). */
export interface VerifiedDeviceClaim {
  deviceAddress: string;
  devicePubkeyHex: string;
  /** The wallet that delegated the device (both signatures verified). */
  wallet: string;
  /** Timestamps of the delegations whose wallet AND device signatures verified. */
  delegationTimestamps: number[];
  /** Timestamps of served DeviceRevocation envelopes naming this device (honoured unsigned — fail closed). */
  revocationTimestamps: number[];
}

/** Result of {@link verifyDeviceClaimObject}. */
export type DeviceClaimObjectVerification =
  | { ok: true; claim: VerifiedDeviceClaim }
  | { ok: false; reason: string };

/** The canonical device-delegation claim string (node `device_delegation_claim_string`). */
function deviceClaimString(network: string, devicePubkeyHex: string, wallet: string, ts: number): string {
  return `ogmara-device-claim:${network}:${devicePubkeyHex.toLowerCase()}:${wallet}:${ts}`;
}

/**
 * Verify a device-claim object as served in `member-proofs` `device_claims`
 * (plan §6): `device_address == bech32("ogd", device_pubkey)`, `wallet` is a
 * wallet address, and each delegation is a Klever-message signature over
 * `ogmara-device-claim:{network}:{device_pubkey}:{wallet}:{timestamp}` by the
 * wallet AND by the device. Delegations that do not verify are dropped; none
 * left → not ok. Every served revocation must decode (else the whole claim
 * fails closed); one naming this device contributes its timestamp even though
 * its own signature is not checked (honouring it only ever fails closed).
 */
export async function verifyDeviceClaimObject(
  claim: DeviceClaimObject,
  network: string,
): Promise<DeviceClaimObjectVerification> {
  try {
    if (!claim || typeof claim !== 'object') return { ok: false, reason: 'malformed' };
    const pubHex = typeof claim.device_pubkey === 'string' ? claim.device_pubkey.toLowerCase() : '';
    const devPub = hexToBytes32(pubHex);
    if (!devPub) return { ok: false, reason: 'bad_device_pubkey' };
    if (typeof claim.device_address !== 'string' || !claim.device_address.startsWith('ogd1')) {
      return { ok: false, reason: 'bad_device_address' };
    }
    let addrPub: Uint8Array;
    try {
      addrPub = addressToPubkey(claim.device_address);
    } catch {
      return { ok: false, reason: 'bad_device_address' };
    }
    if (!bytesEqual(addrPub, devPub)) return { ok: false, reason: 'device_address_mismatch' };
    if (!isWalletAddress(claim.wallet)) return { ok: false, reason: 'bad_wallet' };
    const walletPub = addressToPubkey(claim.wallet);
    const dels = Array.isArray(claim.delegations) ? claim.delegations : [];
    const revs = Array.isArray(claim.revocations) ? claim.revocations : [];
    if (dels.length === 0) return { ok: false, reason: 'no_delegation' };
    if (dels.length > MAX_DEVICE_ITEMS || revs.length > MAX_DEVICE_ITEMS) {
      return { ok: false, reason: 'too_many_items' };
    }

    const revocationTimestamps: number[] = [];
    for (const r of revs) {
      const bytes = rawBytes(r);
      if (!bytes || bytes.length === 0 || bytes.length > MAX_EVIDENCE_BYTES) return { ok: false, reason: 'bad_revocation' };
      const env = decodeEnvelope(bytes);
      if (typeof env === 'string' || env.msgType !== MessageType.DeviceRevocation) {
        return { ok: false, reason: 'bad_revocation' };
      }
      const p = decodeStruct(env.payload, ['device_pub_key']);
      if (!p || typeof p.device_pub_key !== 'string') return { ok: false, reason: 'bad_revocation' };
      if (p.device_pub_key.toLowerCase() === pubHex) revocationTimestamps.push(env.timestamp);
    }

    const delegationTimestamps: number[] = [];
    for (const d of dels) {
      const ts = asSafeU64(d?.timestamp);
      const wsig = typeof d?.wallet_signature === 'string' ? base64ToBytes(d.wallet_signature) : null;
      const dsig = typeof d?.device_signature === 'string' ? base64ToBytes(d.device_signature) : null;
      if (ts === null || !wsig || !dsig || wsig.length !== 64 || dsig.length !== 64) continue;
      const msg = deviceClaimString(network, pubHex, claim.wallet, ts);
      if ((await verifyKleverString(wsig, msg, walletPub)) && (await verifyKleverString(dsig, msg, devPub))) {
        delegationTimestamps.push(ts);
      }
    }
    if (delegationTimestamps.length === 0) return { ok: false, reason: 'no_valid_delegation' };
    return {
      ok: true,
      claim: {
        deviceAddress: claim.device_address,
        devicePubkeyHex: pubHex,
        wallet: claim.wallet,
        delegationTimestamps,
        revocationTimestamps,
      },
    };
  } catch {
    return { ok: false, reason: 'internal_error' };
  }
}

/**
 * The plan §6 time window (W4): a verified claim authorizes an envelope the
 * device signed at `ts` iff some verified delegation `d` has `d <= ts` and no
 * revocation `R` has `d <= R <= ts`. A join signed before a later revocation
 * stays verifiable; anything signed at/after the revocation does not.
 */
export function deviceClaimCovers(claim: VerifiedDeviceClaim, ts: number): boolean {
  return claim.delegationTimestamps.some(
    (d) => d <= ts && !claim.revocationTimestamps.some((r) => d <= r && r <= ts),
  );
}

/**
 * Verify a device-claim object and apply the time window for an envelope the
 * device signed at `atTs`. On success returns the wallet the device resolves
 * to at that time. Never throws.
 */
export async function verifyDeviceClaim(
  claim: DeviceClaimObject,
  network: string,
  atTs: number,
): Promise<{ ok: true; wallet: string } | { ok: false; reason: string }> {
  const v = await verifyDeviceClaimObject(claim, network);
  if (!v.ok) return v;
  if (!deviceClaimCovers(v.claim, atTs)) return { ok: false, reason: 'outside_delegation_window' };
  return { ok: true, wallet: v.claim.wallet };
}

// --- Enc-key binding (plan §7) -------------------------------------------------

/** Result of {@link verifyEncKeyBinding}. */
export type EncKeyBindingVerdict =
  | { status: 'bound' }
  /** Stored before l2-node 0.142.0 (no signature retained): trust with a warning until the device re-binds. */
  | { status: 'unbound' }
  | { status: 'invalid'; reason: string };

/**
 * Verify that an enc-key directory row (`GET /users/{address}/enc-keys`) is
 * bound to `wallet`: when `bound: true`, `wallet_signature` must be the
 * wallet's Klever-message signature over
 * `ogmara-enc-bind:{network}:{enc_pub}:{device_id}:{wallet}:{ts}`. A row
 * served `bound: false` (pre-0.142.0) yields `unbound`; a `bound: true` row
 * whose signature does not verify, a revoked row, or a malformed one yields
 * `invalid` — never wrap a key to it.
 */
export async function verifyEncKeyBinding(
  record: DeviceEncKeyRecord,
  wallet: string,
  network: string,
): Promise<EncKeyBindingVerdict> {
  try {
    if (!record || typeof record !== 'object') return { status: 'invalid', reason: 'malformed' };
    if (record.revoked === true) return { status: 'invalid', reason: 'revoked' };
    if (!hexToBytes32(record.enc_pub)) return { status: 'invalid', reason: 'bad_enc_pub' };
    if (record.bound !== true) return { status: 'unbound' };
    if (!isWalletAddress(wallet)) return { status: 'invalid', reason: 'bad_wallet' };
    if (!hexToBytes32(record.device_id)) return { status: 'invalid', reason: 'bad_device_id' };
    const ts = asSafeU64(record.ts);
    if (ts === null) return { status: 'invalid', reason: 'bad_ts' };
    const sig = typeof record.wallet_signature === 'string' ? base64ToBytes(record.wallet_signature) : null;
    if (!sig || sig.length !== 64) return { status: 'invalid', reason: 'bad_signature' };
    const msg = encBindClaim(record.enc_pub, record.device_id, wallet, ts, network);
    if (!(await verifyKleverString(sig, msg, addressToPubkey(wallet)))) {
      return { status: 'invalid', reason: 'bad_signature' };
    }
    return { status: 'bound' };
  } catch {
    return { status: 'invalid', reason: 'internal_error' };
  }
}

// --- Member proofs ---------------------------------------------------------------

/**
 * One member's verification bundle: the member's own items from a
 * `member-proofs` response plus the response's shared items. Build it from a
 * response with {@link memberProofBundle}.
 */
export interface PrivateMemberProofBundle {
  /** The wallet (`klv1…`) being verified. */
  address: string;
  /** The node's basis hint. Only `unavailable` is acted on; the verifier derives the real basis itself. */
  basis?: MemberProofEntry['basis'];
  /** The node's reason for `unavailable` (`not_member`, `no_join`, `oversized_evidence`, `truncated`). */
  reason?: string | null;
  /** Standard base64 raw `ChannelCreate`. */
  channel_create: string | null;
  /** Standard base64 raw `ChannelJoin` (newest indexed). */
  join: string | null;
  /** Standard base64 Kick/Ban envelopes targeting `address`, newest first. */
  removals: string[];
  moderator_grants: Record<string, string[]>;
  moderator_removals: Record<string, string[]>;
  device_claims: Record<string, DeviceClaimObject>;
}

/**
 * Caller-kept removal knowledge for one channel: wallet → latest VERIFIED
 * Kick/Ban timestamp ever seen (from any node). Read as an extra removal
 * cutoff and updated (max) by the verifier; persist it per wallet scope.
 */
export type SeenRemovals = Map<string, number>;

/** Context for {@link verifyPrivateMemberProof}. */
export interface PrivateMemberProofContext {
  /** The private channel being covered. */
  channelId: number;
  /** Klever network ("testnet"/"mainnet") — binds every msg_id and claim. */
  network: string;
  /**
   * The creator pinned locally for this channel. ALWAYS wins: when set, the
   * bundle's `ChannelCreate` (if any) must name the same wallet, or every
   * member fails closed (`creator_pin_mismatch`). Pin the `creator` of the
   * first successful verification (whatever its `creatorSource`) and pass it
   * on every later call.
   */
  pinnedCreator?: string;
  /**
   * Accept a `ChannelCreate` WITHOUT `id_derivation_ts` (pre-l2-node-0.139
   * channels) when no pin exists yet — trust on first use. Default false:
   * such a create is refused (`creator_not_derived`), because anyone can sign
   * an underived create for any channel id. Set it ONLY when the client's OWN
   * stored `ChannelCreate` for this channel (kept since it first learned the
   * channel) itself carries no derivation — never because a node served one.
   *
   * The derivation is a ~53-bit binding (`% (2^53 - 1)`), so it raises the
   * cost of forging a creator for one specific channel id to ~2^53 hashes,
   * not to infeasible. The real defense is the PIN: persist the creator from
   * the client's own first contact with the channel (when it joined or was
   * invited) and pass it as `pinnedCreator` from then on.
   */
  allowUnderivedCreator?: boolean;
  /**
   * Verification budget (default {@link MAX_VERIFICATIONS_PER_RESPONSE});
   * exceeding it fails the member closed. Lower it to bound work further.
   */
  verificationBudget?: number;
  /**
   * Legacy-join activation (unix ms): a proofless join is accepted only when
   * signed strictly before it. Defaults to {@link legacyJoinActivationMs};
   * forced to 0 on mainnet.
   */
  activationMs?: number;
  /** See {@link SeenRemovals}. */
  seenRemovals?: SeenRemovals;
}

/** How the channel creator was established. */
export type CreatorSource = 'derived' | 'pinned' | 'first_seen';

/** Verdict of {@link verifyPrivateMemberProof}. */
export type PrivateMemberProofResult =
  | {
      ok: true;
      basis: 'creator' | 'invite' | 'legacy';
      creator: string;
      /**
       * How `creator` was established: `pinned` (matched the caller's pin),
       * `derived` (Keccak id derivation) or `first_seen` (underived create,
       * accepted only with `allowUnderivedCreator`). When the caller passed no
       * pin, it must pin `creator` now.
       */
      creatorSource: CreatorSource;
      /** Hex msg_id of the verified join (absent for `creator`). */
      joinMsgId?: string;
      joinTimestamp?: number;
      inviteTimestamp?: number;
      /** Resolved inviter wallet (basis `invite`). */
      inviter?: string;
    }
  | { ok: false; reason: string; creator?: string; creatorSource?: CreatorSource };

type Fail = { fail: string };
const fail = (reason: string): Fail => ({ fail: reason });
const isFail = (v: unknown): v is Fail => typeof v === 'object' && v !== null && 'fail' in v;

/**
 * Response-scoped verifier: memoizes envelope verifications, device claims,
 * moderator-removal sets and moderator authority across the members of one
 * `member-proofs` response, so a moderator's grant shared by 100 members is
 * verified once.
 */
class ProofVerifier {
  private readonly envMemo = new Map<string, Promise<EnvelopeVerification>>();
  private readonly claimMemo = new Map<string, Promise<DeviceClaimObjectVerification>>();
  private readonly rmMemo = new Map<string, Promise<number[] | Fail>>();
  private creatorMemo: Promise<{ creator: string; source: CreatorSource } | Fail> | null = null;
  private spent = 0;
  /**
   * Set once the per-response verification budget ran out. Every verdict
   * produced afterwards is forced to fail (a refused verification must never
   * read as "this removal is not genuine" — that would fail OPEN).
   */
  exhausted = false;

  constructor(
    readonly channelId: number,
    readonly network: string,
    readonly pinnedCreator: string | undefined,
    readonly allowUnderivedCreator: boolean,
    readonly shared: Pick<
      PrivateMemberProofBundle,
      'channel_create' | 'moderator_grants' | 'moderator_removals' | 'device_claims'
    >,
    private readonly budget: number = MAX_VERIFICATIONS_PER_RESPONSE,
  ) {}

  /** Take one unit of the verification budget; false (and `exhausted`) when none is left. */
  private spend(): boolean {
    if (this.spent >= this.budget) {
      this.exhausted = true;
      return false;
    }
    this.spent++;
    return true;
  }

  /** Verify a served/embedded envelope (memoized by its bytes). */
  verifyEnv(raw: string | Uint8Array, expectedType: number, maxBytes: number): Promise<EnvelopeVerification> {
    const bytes = rawBytes(raw, maxBytes);
    if (!bytes) return Promise.resolve({ ok: false, reason: 'size_or_encoding' });
    const key = `${expectedType}:${maxBytes}:${typeof raw === 'string' ? raw : toHex(bytes)}`;
    let p = this.envMemo.get(key);
    if (!p) {
      if (!this.spend()) return Promise.resolve({ ok: false, reason: 'verification_budget_exhausted' });
      p = verifyEnvelopeBytes(bytes, this.network, { expectedType, maxBytes });
      this.envMemo.set(key, p);
    }
    return p;
  }

  /**
   * The wallet `author` resolves to for an envelope signed at `ts`: a wallet
   * is itself; a device resolves only through a served, verifying device
   * claim whose window covers `ts`. `null` = unresolvable (callers' identity
   * comparisons then fail closed — mirrors the node resolving an unknown
   * device to itself).
   */
  async resolveSigner(author: string, ts: number): Promise<string | null> {
    if (author.startsWith('klv1')) return author;
    if (!author.startsWith('ogd1')) return null;
    const claims = this.shared.device_claims;
    if (!claims || typeof claims !== 'object' || !Object.prototype.hasOwnProperty.call(claims, author)) return null;
    const obj = claims[author]!;
    if (!obj || obj.device_address !== author) return null;
    let p = this.claimMemo.get(author);
    if (!p) {
      if (!this.spend()) return null;
      p = verifyDeviceClaimObject(obj, this.network);
      this.claimMemo.set(author, p);
    }
    const v = await p;
    return v.ok && deviceClaimCovers(v.claim, ts) ? v.claim.wallet : null;
  }

  /** Establish the channel creator (memoized). */
  creator(): Promise<{ creator: string; source: CreatorSource } | Fail> {
    if (!this.creatorMemo) this.creatorMemo = this.establishCreator();
    return this.creatorMemo;
  }

  private async establishCreator(): Promise<{ creator: string; source: CreatorSource } | Fail> {
    const pinned = this.pinnedCreator;
    if (pinned !== undefined && !isWalletAddress(pinned)) return fail('bad_pinned_creator');
    const createRaw = this.shared.channel_create;
    if (createRaw === null || createRaw === undefined) {
      // The pin always wins; without one there is no creator anchor at all.
      return pinned ? { creator: pinned, source: 'pinned' } : fail('no_channel_create');
    }
    const v = await this.verifyEnv(createRaw, MessageType.ChannelCreate, MAX_EVIDENCE_BYTES);
    if (!v.ok) return fail(`channel_create_invalid:${v.reason}`);
    const p = decodeStruct(v.envelope.payload, [
      'channel_id', 'slug', 'channel_type', 'display_name', 'description', 'content_rating',
      'moderation', 'encryption_enabled', 'history_visibility', 'id_derivation_ts',
    ]);
    if (!p) return fail('channel_create_malformed');
    if (asSafeU64(p.channel_id) !== this.channelId) return fail('channel_create_wrong_channel');
    if (p.channel_type !== 'Private' && p.channel_type !== 2) return fail('channel_not_private');
    const signer = await this.resolveSigner(v.envelope.author, v.envelope.timestamp);
    if (!signer) return fail('channel_create_signer_unresolved');
    if (p.id_derivation_ts !== undefined && p.id_derivation_ts !== null) {
      const dts = asSafeU64(p.id_derivation_ts);
      if (dts === null || typeof p.slug !== 'string') return fail('channel_create_malformed');
      // Keccak-256(wallet + slug + id_derivation_ts) % (2^53 - 1) — node
      // `verify_private_channel_id_derivation`. Self-certifying creatorship.
      const h = keccak_256(textEncoder.encode(`${signer}${p.slug}${dts}`));
      const raw = new DataView(h.buffer, h.byteOffset, h.byteLength).getBigUint64(0);
      if (raw % JS_SAFE_INTEGER_MODULUS !== BigInt(this.channelId)) return fail('channel_id_derivation_mismatch');
      if (pinned) return pinned === signer ? { creator: pinned, source: 'pinned' } : fail('creator_pin_mismatch');
      return { creator: signer, source: 'derived' };
    }
    // No derivation (pre-0.139 create). Anyone can sign such a create for any
    // channel id, so it anchors nothing by itself: only a matching pin, or an
    // explicit caller opt-in for a channel it knew before 0.139 (TOFU).
    if (pinned) return pinned === signer ? { creator: pinned, source: 'pinned' } : fail('creator_pin_mismatch');
    if (!this.allowUnderivedCreator) return fail('creator_not_derived');
    return { creator: signer, source: 'first_seen' };
  }

  /**
   * Verified `ChannelRemoveModerator` timestamps targeting `moderator`
   * (creator-signed, this channel). More served than the node's cap → fail
   * closed (a truncated list could drop the one that kills a grant).
   */
  removeModeratorTimestamps(moderator: string, creator: string): Promise<number[] | Fail> {
    let p = this.rmMemo.get(moderator);
    if (!p) {
      p = (async () => {
        const map = this.shared.moderator_removals;
        const list = map && Object.prototype.hasOwnProperty.call(map, moderator) ? map[moderator] : [];
        if (!Array.isArray(list)) return fail('malformed_moderator_removals');
        if (list.length > MAX_REMOVALS_PER_TARGET) return fail('too_much_evidence');
        const out: number[] = [];
        for (const raw of list) {
          const v = await this.verifyEnv(raw, MessageType.ChannelRemoveModerator, MAX_EVIDENCE_BYTES);
          if (!v.ok) continue; // not genuine — no evidence of anything
          const pl = decodeStruct(v.envelope.payload, ['channel_id', 'target_user']);
          if (!pl || asSafeU64(pl.channel_id) !== this.channelId || pl.target_user !== moderator) continue;
          // Only the creator manages moderators (node `channel_creator_check`).
          if ((await this.resolveSigner(v.envelope.author, v.envelope.timestamp)) !== creator) continue;
          out.push(v.envelope.timestamp);
        }
        return out;
      })();
      this.rmMemo.set(moderator, p);
    }
    return p;
  }

  /**
   * Node `verify_moderator_grant`: a genuine creator-signed
   * `ChannelAddModerator` for this channel naming `moderator`, dated no later
   * than `notAfter`. Returns the grant's timestamp, or null.
   */
  async grantTimestamp(
    raw: string | Uint8Array,
    creator: string,
    moderator: string,
    notAfter: number,
    maxBytes: number,
  ): Promise<number | null> {
    const v = await this.verifyEnv(raw, MessageType.ChannelAddModerator, maxBytes);
    if (!v.ok) return null;
    if ((await this.resolveSigner(v.envelope.author, v.envelope.timestamp)) !== creator) return null;
    const p = decodeStruct(v.envelope.payload, ['channel_id', 'target_user', 'permissions']);
    if (!p || asSafeU64(p.channel_id) !== this.channelId || p.target_user !== moderator) return null;
    if (v.envelope.timestamp > notAfter) return null;
    return v.envelope.timestamp;
  }

  /**
   * Was `who` a moderator at `at` (sync semantics)? Some candidate grant
   * (the embedded one first, then `moderator_grants[who]`) is valid with
   * `grant.ts <= at` and no creator-signed RemoveModerator `m` has
   * `grant.ts < m <= at`.
   */
  async moderatorAt(who: string, creator: string, at: number, embeddedGrant?: Uint8Array): Promise<boolean | Fail> {
    const candidates: { raw: string | Uint8Array; max: number }[] = [];
    if (embeddedGrant) candidates.push({ raw: embeddedGrant, max: MAX_INVITER_GRANT_BYTES });
    const map = this.shared.moderator_grants;
    const served = map && Object.prototype.hasOwnProperty.call(map, who) ? map[who] : undefined;
    if (Array.isArray(served)) {
      for (const g of served.slice(0, MAX_GRANTS_EXAMINED)) candidates.push({ raw: g, max: MAX_EVIDENCE_BYTES });
    }
    if (candidates.length === 0) return false;
    let rms: number[] | Fail | null = null;
    for (const c of candidates) {
      const gts = await this.grantTimestamp(c.raw, creator, who, at, c.max);
      if (gts === null) continue;
      if (rms === null) rms = await this.removeModeratorTimestamps(who, creator);
      if (isFail(rms)) return rms;
      if (!rms.some((m) => m > gts && m <= at)) return true;
    }
    return false;
  }

  /**
   * The member's removal cutoff: the max timestamp of a VERIFIED Kick/Ban of
   * `wallet` in this channel with `ts >= relevantFrom`, signed by the creator
   * or by a moderator valid at the removal's time. Removals dated before
   * `relevantFrom` are skipped unverified (they cannot change the verdict). A
   * genuine relevant removal whose authority cannot be established fails the
   * member closed. Only verified relevant removals reach `seenRemovals`.
   */
  async removalCutoff(
    wallet: string,
    removals: unknown,
    creator: string,
    relevantFrom: number,
  ): Promise<number | null | Fail> {
    if (removals === undefined || removals === null) return null;
    if (!Array.isArray(removals)) return fail('malformed_removals');
    if (removals.length > MAX_REMOVALS_PER_TARGET) return fail('too_much_evidence');
    let cutoff: number | null = null;
    for (const raw of removals) {
      // Size cap BEFORE any base64/msgpack work (W1).
      const bytes = rawBytes(raw, MAX_EVIDENCE_BYTES);
      if (!bytes) continue;
      const env = decodeEnvelope(bytes);
      if (typeof env === 'string') continue;
      const type = env.msgType === MessageType.ChannelKick || env.msgType === MessageType.ChannelBan ? env.msgType : null;
      if (type === null) continue;
      // A removal dated before `relevantFrom` cannot change the verdict
      // (cutoff >= invite.ts / >= join.ts needs ts >= relevantFrom): skip it
      // before any signature work (W2), so stale removals cost nothing.
      if (env.timestamp < relevantFrom) continue;
      const v = await this.verifyEnv(bytes, type, MAX_EVIDENCE_BYTES);
      if (!v.ok) continue; // forged / tampered: not evidence
      const p = decodeStruct(
        v.envelope.payload,
        type === MessageType.ChannelBan
          ? ['channel_id', 'target_user', 'reason', 'duration_secs']
          : ['channel_id', 'target_user', 'reason'],
      );
      if (!p || asSafeU64(p.channel_id) !== this.channelId || p.target_user !== wallet) continue;
      const ts = v.envelope.timestamp;
      const remover = await this.resolveSigner(v.envelope.author, ts);
      let authorized = remover === creator;
      if (!authorized && remover) {
        const m = await this.moderatorAt(remover, creator, ts);
        if (isFail(m)) return m;
        authorized = m;
      }
      // Relevant (ts >= relevantFrom, checked above) but authority unproven:
      // fail closed rather than ignore a removal the node itself honoured.
      if (!authorized) return fail('unverifiable_removal');
      if (cutoff === null || ts > cutoff) cutoff = ts;
    }
    return cutoff;
  }
}

/** Fields of a `ChannelInvite` payload (positional order). */
const INVITE_FIELDS = ['channel_id', 'target_user', 'anchor_node', 'expires_at', 'inviter_grant'] as const;

/** Node `validate_channel_invite`'s anchor_node checks (SSRF-shaped hosts rejected). */
function anchorNodeOk(url: string): boolean {
  // `url.len()` in Rust counts UTF-8 bytes.
  if (textEncoder.encode(url).length > 256) return false;
  if (!url.startsWith('https://') && !url.startsWith('http://')) return false;
  // Rust `trim_start_matches` strips the prefix REPEATEDLY, https first.
  let hostPart = url;
  while (hostPart.startsWith('https://')) hostPart = hostPart.slice('https://'.length);
  while (hostPart.startsWith('http://')) hostPart = hostPart.slice('http://'.length);
  const host = (hostPart.split('/')[0] ?? '').split(':')[0] ?? '';
  if (['localhost', '127.0.0.1', '0.0.0.0', '[::1]'].includes(host)) return false;
  if (host.startsWith('10.') || host.startsWith('192.168.') || host.startsWith('169.254.')) return false;
  for (let i = 16; i <= 31; i++) if (host.startsWith(`172.${i}.`)) return false;
  return true;
}

async function verifyMember(
  pv: ProofVerifier,
  bundle: Pick<PrivateMemberProofBundle, 'address' | 'basis' | 'reason' | 'join' | 'removals'>,
  activationMs: number,
  seenRemovals: SeenRemovals | undefined,
): Promise<PrivateMemberProofResult> {
  const wallet = bundle.address;
  if (!isWalletAddress(wallet)) return { ok: false, reason: 'bad_address' };
  if (bundle.basis === 'unavailable') {
    return { ok: false, reason: `unavailable:${typeof bundle.reason === 'string' ? bundle.reason : 'unknown'}` };
  }
  const c = await pv.creator();
  if (isFail(c)) return { ok: false, reason: c.fail };
  const { creator, source } = c;
  const done = (r: Omit<Extract<PrivateMemberProofResult, { ok: true }>, 'ok' | 'creator' | 'creatorSource'>) =>
    ({ ok: true as const, creator, creatorSource: source, ...r });
  const bad = (reason: string): PrivateMemberProofResult => ({ ok: false, reason, creator, creatorSource: source });

  // Rule 2: the creator needs no join.
  if (wallet === creator) return done({ basis: 'creator' });
  if (bundle.basis === 'creator') return bad('not_creator');

  // The join: genuine, signed by the wallet (or a device delegated to it at
  // the join's time), for this channel.
  if (bundle.join === null || bundle.join === undefined) return bad('no_join');
  const jv = await pv.verifyEnv(bundle.join, MessageType.ChannelJoin, MAX_EVIDENCE_BYTES);
  if (!jv.ok) return bad(`join_invalid:${jv.reason}`);
  const join = jv.envelope;
  if ((await pv.resolveSigner(join.author, join.timestamp)) !== wallet) return bad('join_signer_mismatch');
  const jp = decodeStruct(join.payload, ['channel_id', 'invite']);
  if (!jp || asSafeU64(jp.channel_id) !== pv.channelId) return bad('join_wrong_channel');
  const inviteRaw = jp.invite === undefined || jp.invite === null ? null : asBytes(jp.invite);
  if (jp.invite !== undefined && jp.invite !== null && !inviteRaw) return bad('join_malformed');

  // Rule 3: proofless (legacy) join.
  if (!inviteRaw) {
    if (!(join.timestamp < activationMs)) return bad('invite_required');
    const cut = await pv.removalCutoff(wallet, bundle.removals, creator, join.timestamp);
    if (isFail(cut)) return bad(cut.fail);
    const cutoff = mergeCutoff(cut, wallet, seenRemovals);
    if (cutoff !== null && cutoff >= join.timestamp) return bad('removed_after_join');
    return done({ basis: 'legacy', joinMsgId: join.msgId, joinTimestamp: join.timestamp });
  }

  // Rule 4: a genuine ChannelInvite (exact type, size, msg_id, signature).
  if (inviteRaw.length === 0 || inviteRaw.length > MAX_JOIN_INVITE_BYTES) return bad('invite_size');
  const iv = await pv.verifyEnv(inviteRaw, MessageType.ChannelInvite, MAX_JOIN_INVITE_BYTES);
  if (!iv.ok) return bad(`invite_invalid:${iv.reason}`);
  const invite = iv.envelope;
  const ip = decodeStruct(invite.payload, INVITE_FIELDS);
  if (!ip) return bad('invite_malformed');
  const invChannel = asSafeU64(ip.channel_id);
  if (invChannel === null || invChannel === 0) return bad('invite_malformed');
  if (typeof ip.target_user !== 'string' || !ip.target_user.startsWith('klv1')) return bad('invite_malformed');
  if (ip.anchor_node !== undefined && ip.anchor_node !== null) {
    if (typeof ip.anchor_node !== 'string' || !anchorNodeOk(ip.anchor_node)) return bad('invite_malformed');
  }
  let grant: Uint8Array | undefined;
  if (ip.inviter_grant !== undefined && ip.inviter_grant !== null) {
    const g = asBytes(ip.inviter_grant);
    if (!g || g.length === 0 || g.length > MAX_INVITER_GRANT_BYTES) return bad('invite_malformed');
    grant = g;
  }
  const inviteTs = invite.timestamp;
  let expiry = inviteTs + DEFAULT_INVITE_TTL_MS;
  if (ip.expires_at !== undefined && ip.expires_at !== null) {
    const e = asSafeU64(ip.expires_at);
    if (e === null || e <= inviteTs || e > inviteTs + MAX_INVITE_TTL_MS) return bad('invite_bad_expiry');
    expiry = e;
  }

  // Rule 5: bound to this channel and this joiner.
  if (invChannel !== pv.channelId) return bad('invite_wrong_channel');
  if (ip.target_user !== wallet) return bad('invite_wrong_target');

  // Rule 6: signed timestamps only.
  if (inviteTs > join.timestamp + MAX_TIMESTAMP_DRIFT_MS) return bad('invite_after_join');
  if (join.timestamp > expiry) return bad('invite_expired');

  // Rule 7 (+ the apply-time check): no verified removal at/after the invite
  // or the join.
  const relevantFrom = Math.min(inviteTs, join.timestamp);
  const cut = await pv.removalCutoff(wallet, bundle.removals, creator, relevantFrom);
  if (isFail(cut)) return bad(cut.fail);
  const cutoff = mergeCutoff(cut, wallet, seenRemovals);
  if (cutoff !== null && cutoff >= inviteTs) return bad('invite_predates_removal');
  if (cutoff !== null && cutoff >= join.timestamp) return bad('removed_after_join');

  // Rule 8: the inviter is the creator, or a moderator at invite time.
  const inviter = await pv.resolveSigner(invite.author, inviteTs);
  if (!inviter) return bad('inviter_unresolved');
  if (inviter !== creator) {
    const m = await pv.moderatorAt(inviter, creator, inviteTs, grant);
    if (isFail(m)) return bad(m.fail);
    if (!m) return bad('inviter_not_authorized');
  }
  return done({
    basis: 'invite',
    joinMsgId: join.msgId,
    joinTimestamp: join.timestamp,
    inviteTimestamp: inviteTs,
    inviter,
  });
}

/**
 * Once the response's verification budget is exhausted no verdict can be
 * trusted (a refused verification may have hidden a removal): fail closed.
 */
function budgetGate(pv: ProofVerifier, r: PrivateMemberProofResult): PrivateMemberProofResult {
  if (!pv.exhausted) return r;
  return { ok: false, reason: 'verification_budget_exhausted', creator: r.creator, creatorSource: r.creatorSource };
}

/** Merge a freshly verified cutoff with (and into) the caller's seen removals. */
function mergeCutoff(cut: number | null, wallet: string, seen: SeenRemovals | undefined): number | null {
  const prior = seen?.get(wallet);
  const priorOk = typeof prior === 'number' && Number.isFinite(prior) ? prior : null;
  if (cut !== null && seen && (priorOk === null || cut > priorOk)) seen.set(wallet, cut);
  if (cut === null) return priorOk;
  return priorOk === null ? cut : Math.max(cut, priorOk);
}

function effectiveActivation(network: string, activationMs: number | undefined): number {
  if (network === 'mainnet') return 0;
  const a = activationMs ?? legacyJoinActivationMs(network);
  return typeof a === 'number' && Number.isFinite(a) && a > 0 ? a : 0;
}

/**
 * The effective verification budget for a caller-supplied value: a positive
 * integer is honoured but CLAMPED to {@link MAX_VERIFICATIONS_PER_RESPONSE}
 * (a caller can lower the budget, never raise it); anything else → the max.
 * @internal exported for tests.
 */
export function budgetOf(b: number | undefined): number {
  return typeof b === 'number' && Number.isSafeInteger(b) && b > 0
    ? Math.min(b, MAX_VERIFICATIONS_PER_RESPONSE)
    : MAX_VERIFICATIONS_PER_RESPONSE;
}

function validChannelId(id: unknown): id is number {
  return typeof id === 'number' && Number.isSafeInteger(id) && id > 0;
}

/**
 * Verify one member's membership evidence (see the module doc) with the node's
 * `verify_private_join` rules 4-8 under SYNC semantics:
 *
 * - creator: `pinnedCreator` when given (always wins — a create naming anyone
 *   else fails closed); otherwise the `ChannelCreate` (genuine, Private, this
 *   id) whose Keccak id derivation names the resolved signer. A create without
 *   a derivation is refused unless `allowUnderivedCreator` (pre-0.139 channel
 *   the caller already knew) — then `first_seen`. Pin the returned creator
 *   whenever you passed no pin;
 * - the creator is a member without a join;
 * - otherwise the newest join must be genuine, signed by the wallet (or a
 *   device delegated to it at the join's time, plan §6) and carry an invite:
 *   genuine `ChannelInvite` ≤ 2048 bytes, for this channel and this wallet,
 *   `invite.ts <= join.ts + 5 min`, `join.ts <= expiry`, issued by the
 *   creator or by a moderator holding a creator-signed grant with
 *   `grant.ts <= invite.ts` not killed by a RemoveModerator
 *   `grant.ts < m <= invite.ts`;
 * - a verified Kick/Ban (creator or then-valid moderator) at/after the
 *   invite or the join kills it (plus `ctx.seenRemovals`);
 * - a proofless join is accepted only when `join.ts < activationMs`.
 *
 * Never throws; any doubt → `{ ok: false }`.
 */
export async function verifyPrivateMemberProof(
  bundle: PrivateMemberProofBundle,
  ctx: PrivateMemberProofContext,
): Promise<PrivateMemberProofResult> {
  try {
    if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'malformed_bundle' };
    if (!validChannelId(ctx?.channelId)) return { ok: false, reason: 'bad_channel_id' };
    if (typeof ctx.network !== 'string' || ctx.network.length === 0) return { ok: false, reason: 'bad_network' };
    const pv = new ProofVerifier(
      ctx.channelId,
      ctx.network,
      ctx.pinnedCreator,
      ctx.allowUnderivedCreator === true,
      bundle,
      budgetOf(ctx.verificationBudget),
    );
    return budgetGate(pv, await verifyMember(pv, bundle, effectiveActivation(ctx.network, ctx.activationMs), ctx.seenRemovals));
  } catch {
    return { ok: false, reason: 'internal_error' };
  }
}

/**
 * Extract one member's {@link PrivateMemberProofBundle} from a
 * `member-proofs` response; null when the address is not in it.
 */
export function memberProofBundle(response: MemberProofsResponse, address: string): PrivateMemberProofBundle | null {
  const m = Array.isArray(response?.members) ? response.members.find((x) => x?.address === address) : undefined;
  if (!m) return null;
  return {
    address,
    basis: m.basis,
    reason: m.reason ?? null,
    channel_create: response.channel_create ?? null,
    join: m.join ?? null,
    removals: Array.isArray(m.removals) ? m.removals : [],
    moderator_grants: response.moderator_grants ?? {},
    moderator_removals: response.moderator_removals ?? {},
    device_claims: response.device_claims ?? {},
  };
}

// --- Cache + batch filter ------------------------------------------------------------

interface CachedPositive {
  basis: 'creator' | 'invite' | 'legacy';
  joinTimestamp?: number;
  inviteTimestamp?: number;
}

/**
 * LRU of POSITIVE member verdicts keyed by
 * `(network, channelId, creator, wallet, join msg_id)`. Negatives are never
 * cached (always re-checked). A cache hit skips the join/invite/authority
 * signature work but the member's removals are still re-checked on every
 * call — a kick after the first verification is never masked by the cache.
 * Keep one instance per wallet scope; clear it on account switch.
 */
export class MemberProofCache {
  private readonly map = new Map<string, CachedPositive>();

  constructor(readonly maxEntries = 4096) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) {
      throw new RangeError('MemberProofCache maxEntries must be a positive integer');
    }
  }

  /** @internal */
  get(key: string): CachedPositive | undefined {
    const v = this.map.get(key);
    if (v) {
      this.map.delete(key);
      this.map.set(key, v);
    }
    return v;
  }

  /** @internal */
  set(key: string, v: CachedPositive): void {
    this.map.delete(key);
    this.map.set(key, v);
    while (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }

  /** Drop every entry (account switch, channel key rotation, …). */
  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

/** Options for {@link filterVerifiedMembers}. */
export interface FilterVerifiedMembersOptions {
  /** Defaults to `client.getNetwork()`. */
  network?: string;
  /** See {@link PrivateMemberProofContext.pinnedCreator} — always wins. */
  pinnedCreator?: string;
  /** See {@link PrivateMemberProofContext.allowUnderivedCreator} (default false). */
  allowUnderivedCreator?: boolean;
  /** Per-response budget, see {@link PrivateMemberProofContext.verificationBudget}. */
  verificationBudget?: number;
  activationMs?: number;
  /** Caller-kept removal knowledge for this channel; updated in place. */
  seenRemovals?: SeenRemovals;
}

/** Result of {@link filterVerifiedMembers}. */
export interface FilterVerifiedMembersResult {
  /** Wallets whose membership verified — safe to cover. Input order, deduplicated. */
  verified: string[];
  /** Everyone else, with the reason (never covered). */
  rejected: { wallet: string; reason: string }[];
  /** The proven creator, when the channel's evidence established one. */
  creator?: string;
  /**
   * How `creator` was established by the FIRST response that established it:
   * `derived`, `first_seen` (underived create, opt-in only), or `pinned` —
   * which only happens when YOU passed `pinnedCreator`. Whenever you passed
   * no pin, persist `creator` now (whatever the source) and pass it as
   * `pinnedCreator` on every later call.
   */
  creatorSource?: CreatorSource;
  /** True when some wallets were rejected because the proofs could not be fetched (retry later). */
  incomplete: boolean;
}

/**
 * Verify-before-cover filter for a PRIVATE channel: fetches member proofs
 * from the client's node (`getMemberProofs`, ≤ 100 per request, sequential —
 * the node allows one build per wallet in flight), verifies every member
 * with {@link verifyPrivateMemberProof} and returns only those that verified.
 * Members the node reports `truncated` are re-requested once in smaller
 * batches. Fails CLOSED and never throws for a bad member or a failed fetch:
 * those wallets land in `rejected` (`incomplete` marks fetch failures). The
 * caller's own wallet is NOT special-cased here — include it yourself.
 */
export async function filterVerifiedMembers(
  client: OgmaraClient,
  channelId: number,
  wallets: readonly string[],
  cache: MemberProofCache,
  options: FilterVerifiedMembersOptions = {},
): Promise<FilterVerifiedMembersResult> {
  const result: FilterVerifiedMembersResult = { verified: [], rejected: [], incomplete: false };
  const verdict = new Map<string, string | true>();
  const order: string[] = [];
  for (const w of wallets) {
    if (typeof w !== 'string' || verdict.has(w)) continue;
    order.push(w);
    // An invalid address would make the node 400 the whole batch: never send it.
    verdict.set(w, isWalletAddress(w) ? 'pending' : 'invalid_address');
  }
  const finish = (): FilterVerifiedMembersResult => {
    for (const w of order) {
      const v = verdict.get(w);
      if (v === true) result.verified.push(w);
      else result.rejected.push({ wallet: w, reason: typeof v === 'string' && v !== 'pending' ? v : 'unverified' });
    }
    return result;
  };
  if (!validChannelId(channelId)) {
    for (const w of order) verdict.set(w, 'bad_channel_id');
    return finish();
  }
  let network: string;
  try {
    network = options.network ?? (await client.getNetwork());
  } catch {
    for (const w of order) if (verdict.get(w) === 'pending') verdict.set(w, 'fetch_failed');
    result.incomplete = true;
    return finish();
  }
  const activationMs = effectiveActivation(network, options.activationMs);
  // Every chunk must agree on ONE creator: the first chunk that establishes a
  // creator pins it for all later chunks (and the truncated re-request), so a
  // node cannot serve different creates to different batches. A later chunk
  // that disagrees fails closed (`creator_pin_mismatch`).
  let chunkPin: string | undefined = options.pinnedCreator;

  const verifyResponse = async (resp: MemberProofsResponse, asked: string[]): Promise<string[]> => {
    const truncated: string[] = [];
    if (!resp || typeof resp !== 'object' || resp.channel_id !== channelId || !Array.isArray(resp.members)) {
      for (const w of asked) verdict.set(w, 'bad_response');
      return truncated;
    }
    const pv = new ProofVerifier(channelId, network, chunkPin, options.allowUnderivedCreator === true, {
      channel_create: resp.channel_create ?? null,
      moderator_grants: resp.moderator_grants ?? {},
      moderator_removals: resp.moderator_removals ?? {},
      device_claims: resp.device_claims ?? {},
    }, budgetOf(options.verificationBudget));
    const established = await pv.creator();
    if (!isFail(established)) {
      // Report how the creator was established by the FIRST chunk that did so
      // (`pinned` only if the caller passed a pin) — later chunks run against
      // the chunk pin and would otherwise always say `pinned`.
      if (result.creator === undefined) {
        result.creator = established.creator;
        result.creatorSource = established.source;
      }
      if (chunkPin === undefined) chunkPin = established.creator;
    }
    for (const w of asked) {
      try {
        const bundle = memberProofBundle(resp, w);
        if (!bundle) {
          verdict.set(w, 'missing_from_response');
          continue;
        }
        if (bundle.basis === 'unavailable' && bundle.reason === 'truncated') {
          truncated.push(w);
          verdict.set(w, 'unavailable:truncated');
          continue;
        }
        const r = budgetGate(pv, await verifyCached(pv, bundle, network, activationMs, options.seenRemovals, cache));
        verdict.set(w, r.ok ? true : r.reason);
      } catch {
        verdict.set(w, 'internal_error');
      }
    }
    return truncated;
  };

  const fetchAndVerify = async (addrs: string[], chunk: number): Promise<string[]> => {
    const truncated: string[] = [];
    for (let i = 0; i < addrs.length; i += chunk) {
      const batch = addrs.slice(i, i + chunk);
      let responses: MemberProofsResponse[];
      try {
        responses = await client.getMemberProofs(channelId, batch);
      } catch (e) {
        const status = e instanceof MemberProofsError ? e.status : 0;
        for (const w of addrs.slice(i)) verdict.set(w, `fetch_failed:${status}`);
        result.incomplete = true;
        return truncated; // stop: 429/503 would only repeat
      }
      if (!Array.isArray(responses) || responses.length !== 1) {
        for (const w of batch) verdict.set(w, 'bad_response');
        continue;
      }
      truncated.push(...(await verifyResponse(responses[0]!, batch)));
    }
    return truncated;
  };

  const pending = order.filter((w) => verdict.get(w) === 'pending');
  const truncated = await fetchAndVerify(pending, MAX_MEMBER_PROOF_ADDRESSES);
  if (truncated.length > 0 && !result.incomplete) await fetchAndVerify(truncated, 20);
  return finish();
}

/** Full verification, or a cache hit that still re-checks removals. */
async function verifyCached(
  pv: ProofVerifier,
  bundle: PrivateMemberProofBundle,
  network: string,
  activationMs: number,
  seenRemovals: SeenRemovals | undefined,
  cache: MemberProofCache,
): Promise<PrivateMemberProofResult> {
  // The node's CURRENT view wins over any cached positive: a member it now
  // reports unavailable (left, truncated, evidence gone) is never covered.
  if (bundle.basis === 'unavailable') {
    return { ok: false, reason: `unavailable:${typeof bundle.reason === 'string' ? bundle.reason : 'unknown'}` };
  }
  const c = await pv.creator();
  if (isFail(c)) return { ok: false, reason: c.fail };
  let joinId = 'creator';
  if (bundle.address !== c.creator) {
    // Size cap BEFORE any decode (W1): an oversized join is never even parsed.
    const bytes = bundle.join ? rawBytes(bundle.join, MAX_EVIDENCE_BYTES) : null;
    const env = bytes ? decodeEnvelope(bytes) : null;
    joinId = env && typeof env !== 'string' ? toHex(env.msgId) : '';
  }
  const key = joinId ? `${network}\u0000${pv.channelId}\u0000${c.creator}\u0000${bundle.address}\u0000${joinId}` : '';
  const hit = key ? cache.get(key) : undefined;
  if (hit) {
    if (hit.basis === 'creator') {
      return { ok: true, basis: 'creator', creator: c.creator, creatorSource: c.source };
    }
    const joinTs = hit.joinTimestamp!;
    const relevantFrom = hit.inviteTimestamp !== undefined ? Math.min(hit.inviteTimestamp, joinTs) : joinTs;
    const cut = await pv.removalCutoff(bundle.address, bundle.removals, c.creator, relevantFrom);
    if (isFail(cut)) return { ok: false, reason: cut.fail, creator: c.creator, creatorSource: c.source };
    const cutoff = mergeCutoff(cut, bundle.address, seenRemovals);
    if (cutoff !== null && (cutoff >= joinTs || (hit.inviteTimestamp !== undefined && cutoff >= hit.inviteTimestamp))) {
      return { ok: false, reason: 'removed', creator: c.creator, creatorSource: c.source };
    }
    return {
      ok: true,
      basis: hit.basis,
      creator: c.creator,
      creatorSource: c.source,
      joinMsgId: joinId,
      joinTimestamp: joinTs,
      inviteTimestamp: hit.inviteTimestamp,
    };
  }
  const r = await verifyMember(pv, bundle, activationMs, seenRemovals);
  if (r.ok && key && (r.basis === 'creator' || r.joinMsgId === joinId)) {
    cache.set(key, { basis: r.basis, joinTimestamp: r.joinTimestamp, inviteTimestamp: r.inviteTimestamp });
  }
  return r;
}

// --- Errors ------------------------------------------------------------------------

/**
 * A failed `member-proofs` request. `status` is the HTTP status, 0 for a
 * network error, timeout or malformed/oversized response, 400 for an invalid
 * `channelId` rejected locally. `retryable` is true for 429 (per-wallet limit
 * or a build already in flight), 503 (node-wide build slots busy) and 0
 * (transient transport failure) — callers fail closed now and may retry
 * later; false for every other status (403 not a member, 400, 404 old node).
 */
export class MemberProofsError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'MemberProofsError';
  }

  get retryable(): boolean {
    return this.status === 429 || this.status === 503 || this.status === 0;
  }
}
