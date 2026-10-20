/**
 * Private-channel invite helpers (l2-node 0.140.0+ private join gate).
 *
 * A Private channel can only be joined with a signed `ChannelInvite`
 * envelope that names the joining wallet. The invite is created by the
 * channel creator or a moderator (a moderator bundles the creator-signed
 * `ChannelAddModerator` grant that proves its authority), delivered to the
 * invitee as a `channel_invite` notification and/or a personal invite link,
 * and then attached — byte-for-byte, exactly as signed — to the invitee's
 * `ChannelJoin` and `federate` request. Every honest node verifies it.
 *
 * Everything in this module is a CLIENT-SIDE convenience. Nothing here
 * verifies a signature or the inviter's authority — the node does that.
 * `decodeChannelInvite` exists so a UI can show "invited by X, valid until
 * Y" and decide whether to offer a Join button; it must never be treated as
 * proof that the invite is genuine.
 *
 * Bearer links are NOT supported for Private channels: an invite is bound to
 * one wallet address, so forwarding a personal invite link to someone else
 * gives them nothing.
 */

import { decode } from '@msgpack/msgpack';
import { MessageType, MSG_TYPE_NAME, type Notification } from './types';

// --- Constants (mirror the node's verification rules) ---

/** Invite validity applied by the node when an invite carries no explicit `expires_at`: 7 days. */
export const DEFAULT_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** Upper bound on an invite's validity: `expires_at <= invite.timestamp + 14 days`. */
export const MAX_INVITE_TTL_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Smallest validity `inviteUser` will create (client-side floor, not a node
 * rule). `buildEnvelope` takes the envelope timestamp with `Date.now()`
 * BEFORE signing, only a few ms after `inviteUser` fixes `expiresAt`, so the
 * node's `timestamp < expires_at` holds for any positive TTL. The floor is
 * about usefulness: signing (an extension/hardware wallet can take a while),
 * delivery and the invitee's own join all happen AFTER that timestamp, so a
 * TTL of a few seconds would expire before anyone could realistically use it
 * (and the client margin, `INVITE_EXPIRY_MARGIN_MS`, already hides it).
 */
export const MIN_INVITE_TTL_MS = 60 * 1000;

/** Hard cap on a raw `ChannelInvite` envelope attached to a join (node enforces the same). */
export const MAX_INVITE_ENVELOPE_BYTES = 2048;

/** Hard cap on a raw `ChannelAddModerator` grant bundled into an invite (node enforces the same). */
export const MAX_INVITER_GRANT_BYTES = 1024;

/**
 * Client-side expiry margin: an invite is treated as unusable once
 * `now >= expiresAt - INVITE_EXPIRY_MARGIN_MS` (spec 05 §8.4). Deliberately TIGHTER than the
 * node (which accepts while `join.timestamp <= expiresAt`, with ±5 min clock
 * drift on the live path) so a UI never offers a Join button for an invite
 * that is about to be rejected by the time the join is signed and delivered.
 */
export const INVITE_EXPIRY_MARGIN_MS = 5 * 60 * 1000;

/**
 * How far in the future an invite's signed timestamp may lie relative to the
 * local clock before the client treats it as not-yet-usable. Tighter than the
 * node's 5-minute drift allowance (`invite.ts <= join.ts + 5 min`).
 */
export const INVITE_FUTURE_TOLERANCE_MS = 4 * 60 * 1000;

/**
 * Longest `inv=` URL parameter accepted by {@link decodeInviteFromUrl}:
 * unpadded base64url of {@link MAX_INVITE_ENVELOPE_BYTES} bytes.
 */
const MAX_INVITE_URL_PARAM_LEN = Math.ceil((MAX_INVITE_ENVELOPE_BYTES * 4) / 3);

/** Longest (padded) base64 text that can encode {@link MAX_INVITE_ENVELOPE_BYTES} bytes. */
const MAX_INVITE_B64_LEN = Math.ceil(MAX_INVITE_ENVELOPE_BYTES / 3) * 4;

/** Canonical public base for share/invite links (same host the clients' share links use). */
export const DEFAULT_INVITE_LINK_BASE = 'https://ogmara.org/app';

// --- Base64 (pure JS: no dependency on atob/btoa/Buffer availability) ---

const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function encodeBase64With(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += alphabet[(n >> 18) & 63]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + alphabet[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += alphabet[(n >> 18) & 63]! + alphabet[(n >> 12) & 63]! + (pad ? '==' : '');
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += alphabet[(n >> 18) & 63]! + alphabet[(n >> 12) & 63]! + alphabet[(n >> 6) & 63]! + (pad ? '=' : '');
  }
  return out;
}

/**
 * Strict base64 decoder. Accepts the standard (`+/`) or the URL-safe (`-_`)
 * alphabet — never a mix — with or without `=` padding. Returns null on any
 * malformed input (bad character, impossible length, non-zero trailing bits)
 * rather than silently decoding garbage.
 */
function decodeBase64Strict(input: string): Uint8Array | null {
  if (typeof input !== 'string') return null;
  let s = input;
  const hasStd = /[+/]/.test(s);
  const hasUrl = /[-_]/.test(s);
  if (hasStd && hasUrl) return null;
  const alphabet = hasUrl ? B64_URL : B64_STD;
  // Strip padding (only at the very end, at most 2 chars, and only if it makes the length a multiple of 4).
  const padMatch = /=+$/.exec(s);
  if (padMatch) {
    if (padMatch[0].length > 2 || s.length % 4 !== 0) return null;
    s = s.slice(0, -padMatch[0].length);
  }
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0;
  let buf = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = alphabet.indexOf(s[i]!);
    if (v < 0) return null;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buf >> bits) & 0xff;
    }
    buf &= (1 << bits) - 1;
  }
  // Leftover bits must be zero (canonical encoding).
  if (buf !== 0) return null;
  return out;
}

/** Standard base64 (with padding) — the wire form for JSON fields (`FederateRequest.invite`). */
export function bytesToBase64(bytes: Uint8Array): string {
  return encodeBase64With(bytes, B64_STD, true);
}

/**
 * Decode base64 as served by the node in JSON (`invite_envelope`,
 * `grant_envelope`). Returns null on malformed input.
 */
export function base64ToBytes(b64: string): Uint8Array | null {
  return decodeBase64Strict(b64);
}

/**
 * Encode a raw invite envelope for an `inv=` link parameter: unpadded
 * base64url (`[A-Za-z0-9_-]`), safe in a URL and in a hash-route query
 * without percent-encoding. Throws if the envelope exceeds
 * {@link MAX_INVITE_ENVELOPE_BYTES}.
 */
export function encodeInviteForUrl(inviteEnvelope: Uint8Array): string {
  assertInviteBytes(inviteEnvelope);
  return encodeBase64With(inviteEnvelope, B64_URL, false);
}

/**
 * Decode an `inv=` link parameter produced by {@link encodeInviteForUrl}.
 * Returns null on anything malformed or oversized. The result is RAW,
 * UNVERIFIED bytes — pass them to {@link decodeChannelInvite} to inspect, and
 * to `joinChannel`/`federateChannel` to let the node verify.
 */
export function decodeInviteFromUrl(param: string): Uint8Array | null {
  if (typeof param !== 'string' || param.length === 0 || param.length > MAX_INVITE_URL_PARAM_LEN) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(param)) return null;
  const bytes = decodeBase64Strict(param);
  if (!bytes || bytes.length === 0 || bytes.length > MAX_INVITE_ENVELOPE_BYTES) return null;
  return bytes;
}

/** Throws unless `bytes` is a non-empty Uint8Array within {@link MAX_INVITE_ENVELOPE_BYTES}. */
export function assertInviteBytes(bytes: unknown): asserts bytes is Uint8Array {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('invite must be a Uint8Array (raw signed envelope bytes)');
  if (bytes.length === 0) throw new RangeError('invite envelope is empty');
  if (bytes.length > MAX_INVITE_ENVELOPE_BYTES) {
    throw new RangeError(`invite envelope too large (${bytes.length} bytes, limit ${MAX_INVITE_ENVELOPE_BYTES})`);
  }
}

// --- Envelope decoding (map OR positional-array wire form) ---

/**
 * Coerce a msgpack byte field to a Uint8Array. A JS-built envelope carries
 * `bin`; a Rust-re-encoded one (`rmp_serde::to_vec`, positional) carries
 * `Vec<u8>` as an array of small integers. Both are accepted.
 */
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

function asSafeUint(v: unknown): number | null {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null;
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

interface LooseEnvelope {
  msgTypeName: string;
  msgIdHex: string;
  author: string;
  timestamp: number;
  payload: Uint8Array;
}

/**
 * Decode an envelope's outer fields without verifying anything. Accepts the
 * named-map form (JS SDK) and the positional-array form (Rust `to_vec`):
 * `[version, msg_type, msg_id, author, timestamp, lamport_ts, payload, signature, relay_path?]`.
 * Returns null on any structural problem.
 */
function decodeEnvelopeLoose(bytes: Uint8Array): LooseEnvelope | null {
  let raw: unknown;
  try {
    raw = decode(bytes);
  } catch {
    return null;
  }
  let msgType: unknown, msgId: unknown, author: unknown, timestamp: unknown, payload: unknown;
  if (Array.isArray(raw)) {
    if (raw.length < 8 || raw.length > 9) return null;
    [, msgType, msgId, author, timestamp, , payload] = raw;
  } else if (raw && typeof raw === 'object' && !(raw instanceof Uint8Array)) {
    const o = raw as Record<string, unknown>;
    ({ msg_type: msgType, msg_id: msgId, author, timestamp, payload } = o);
  } else {
    return null;
  }
  // rmp-serde's wire form for a unit enum is the variant NAME. A bare integer
  // would be the serde declaration-order index (not the u8 discriminant), so
  // it is refused rather than guessed at.
  if (typeof msgType !== 'string') return null;
  const idBytes = asBytes(msgId);
  const payloadBytes = asBytes(payload);
  const ts = asSafeUint(timestamp);
  if (!idBytes || idBytes.length !== 32 || !payloadBytes || typeof author !== 'string' || ts === null) return null;
  return { msgTypeName: msgType, msgIdHex: toHex(idBytes), author, timestamp: ts, payload: payloadBytes };
}

/** Decode a payload as either a named map or a positional array, mapping array slots to `fields`. */
function decodePayloadFields(payload: Uint8Array, fields: readonly string[]): Record<string, unknown> | null {
  let raw: unknown;
  try {
    raw = decode(payload);
  } catch {
    return null;
  }
  if (Array.isArray(raw)) {
    if (raw.length > fields.length) return null;
    const out: Record<string, unknown> = {};
    raw.forEach((v, i) => { out[fields[i]!] = v; });
    return out;
  }
  if (raw && typeof raw === 'object' && !(raw instanceof Uint8Array)) return raw as Record<string, unknown>;
  return null;
}

// --- Invite decoding (UI only, UNVERIFIED) ---

/**
 * Fields of a `ChannelInvite` envelope, as decoded WITHOUT any verification.
 *
 * **Not proof of anything.** The signature, the inviter's authority (creator
 * or moderator with a valid grant), and removal/ban state are checked only by
 * the node. Use this to render UI ("invited by X, expires Y") and to pre-check
 * channel/wallet binding before a round trip — never to grant access.
 */
export interface DecodedChannelInvite {
  /** Hex msg_id of the invite envelope. */
  msgId: string;
  /** Envelope author — the inviter's SIGNING address (may be a device key, not resolved to a wallet). */
  inviter: string;
  /** Signed envelope timestamp of the invite (unix ms) — the node's `invite.ts`. */
  timestamp: number;
  channelId: number;
  /** Wallet address the invite is bound to. */
  targetUser: string;
  anchorNode?: string;
  /** Effective expiry: explicit `expires_at`, else `timestamp + DEFAULT_INVITE_TTL_MS`. */
  expiresAt: number;
  /** The explicit `expires_at` field, when the inviter set one. */
  explicitExpiresAt?: number;
  /** Whether a moderator grant (`inviter_grant`) is bundled. */
  hasGrant: boolean;
  /** Raw creator-signed `ChannelAddModerator` grant, present when a moderator invited. */
  inviterGrant?: Uint8Array;
}

const INVITE_PAYLOAD_FIELDS = ['channel_id', 'target_user', 'anchor_node', 'expires_at', 'inviter_grant'] as const;
const ADD_MODERATOR_PAYLOAD_FIELDS = ['channel_id', 'target_user', 'permissions'] as const;

/**
 * Decode a raw `ChannelInvite` envelope (bytes, or base64/base64url text) for
 * display. Returns null when the input is oversized, structurally invalid,
 * not a `ChannelInvite`, or violates the TTL bounds the node enforces
 * (`timestamp < expiresAt <= timestamp + MAX_INVITE_TTL_MS`).
 *
 * UNVERIFIED — see {@link DecodedChannelInvite}.
 */
export function decodeChannelInvite(input: Uint8Array | string): DecodedChannelInvite | null {
  if (typeof input === 'string' && input.length > MAX_INVITE_B64_LEN) return null;
  const bytes = typeof input === 'string' ? decodeBase64Strict(input) : input;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_INVITE_ENVELOPE_BYTES) return null;
  const env = decodeEnvelopeLoose(bytes);
  if (!env || env.msgTypeName !== MSG_TYPE_NAME[MessageType.ChannelInvite]) return null;
  const p = decodePayloadFields(env.payload, INVITE_PAYLOAD_FIELDS);
  if (!p) return null;
  const channelId = asSafeUint(p.channel_id);
  if (channelId === null || channelId === 0 || typeof p.target_user !== 'string' || p.target_user.length === 0) return null;
  if (p.anchor_node !== undefined && p.anchor_node !== null && typeof p.anchor_node !== 'string') return null;

  let explicitExpiresAt: number | undefined;
  if (p.expires_at !== undefined && p.expires_at !== null) {
    const e = asSafeUint(p.expires_at);
    if (e === null) return null;
    explicitExpiresAt = e;
  }
  let inviterGrant: Uint8Array | undefined;
  if (p.inviter_grant !== undefined && p.inviter_grant !== null) {
    const g = asBytes(p.inviter_grant);
    if (!g || g.length === 0 || g.length > MAX_INVITER_GRANT_BYTES) return null;
    inviterGrant = g;
  }
  const expiresAt = explicitExpiresAt ?? env.timestamp + DEFAULT_INVITE_TTL_MS;
  if (!(env.timestamp < expiresAt && expiresAt <= env.timestamp + MAX_INVITE_TTL_MS)) return null;

  const out: DecodedChannelInvite = {
    msgId: env.msgIdHex,
    inviter: env.author,
    timestamp: env.timestamp,
    channelId,
    targetUser: p.target_user,
    expiresAt,
    hasGrant: inviterGrant !== undefined,
  };
  if (typeof p.anchor_node === 'string') out.anchorNode = p.anchor_node;
  if (explicitExpiresAt !== undefined) out.explicitExpiresAt = explicitExpiresAt;
  if (inviterGrant) out.inviterGrant = inviterGrant;
  return out;
}

/**
 * Structural sanity check for a moderator grant fetched from the caller's own
 * node before bundling it into an invite: must be a `ChannelAddModerator` for
 * `channelId` naming `inviterWallet`, within {@link MAX_INVITER_GRANT_BYTES}.
 * Does NOT verify the creator's signature (the node does). Internal helper,
 * exported for tests.
 */
export function isPlausibleModeratorGrant(grant: Uint8Array, channelId: number, inviterWallet: string): boolean {
  if (!(grant instanceof Uint8Array) || grant.length === 0 || grant.length > MAX_INVITER_GRANT_BYTES) return false;
  const env = decodeEnvelopeLoose(grant);
  if (!env || env.msgTypeName !== MSG_TYPE_NAME[MessageType.ChannelAddModerator]) return false;
  const p = decodePayloadFields(env.payload, ADD_MODERATOR_PAYLOAD_FIELDS);
  if (!p) return false;
  return asSafeUint(p.channel_id) === channelId && p.target_user === inviterWallet;
}

// --- Pending-invite selection (pure; used by OgmaraClient.findPendingInvite) ---

/** A usable invite found among the wallet's `channel_invite` notifications. */
export interface PendingInvite extends DecodedChannelInvite {
  /** Raw invite envelope bytes, exactly as signed — attach to `joinChannel`/`federateChannel`. */
  invite: Uint8Array;
}

/** Upper bound on notifications scanned by {@link selectPendingInvite} (input cap, not a result cap). */
const MAX_NOTIFICATIONS_SCANNED = 500;

/**
 * Pick the best usable invite for `channelId` aimed at `wallet` from a list
 * of notifications. Skips (never throws on): non-invite notifications,
 * notifications without an `invite_envelope` (older nodes, or `null` on the
 * wire), undecodable/oversized envelopes, invites for another channel or
 * another wallet, invites whose signed timestamp is too far in the future,
 * and invites expired by the client margin (`now >= expiresAt - 5 min`,
 * {@link INVITE_EXPIRY_MARGIN_MS}). When several qualify, the NEWEST (highest
 * signed timestamp) wins; ties go to the later expiry.
 *
 * UNVERIFIED — the node is the authority. Pure function (inject `now` in tests).
 */
export function selectPendingInvite(
  notifications: readonly Notification[],
  opts: { channelId: number; wallet: string; now?: number },
): PendingInvite | null {
  const now = opts.now ?? Date.now();
  let best: PendingInvite | null = null;
  const list = Array.isArray(notifications) ? notifications.slice(0, MAX_NOTIFICATIONS_SCANNED) : [];
  for (const n of list) {
    if (!n || n.type !== 'channel_invite') continue;
    const b64 = n.invite_envelope;
    if (typeof b64 !== 'string' || b64.length === 0 || b64.length > MAX_INVITE_B64_LEN) continue;
    const bytes = decodeBase64Strict(b64);
    if (!bytes || bytes.length === 0 || bytes.length > MAX_INVITE_ENVELOPE_BYTES) continue;
    const inv = decodeChannelInvite(bytes);
    if (!inv) continue;
    if (inv.channelId !== opts.channelId || inv.targetUser !== opts.wallet) continue;
    if (inv.timestamp > now + INVITE_FUTURE_TOLERANCE_MS) continue;
    if (now >= inv.expiresAt - INVITE_EXPIRY_MARGIN_MS) continue;
    if (
      !best ||
      inv.timestamp > best.timestamp ||
      (inv.timestamp === best.timestamp && inv.expiresAt > best.expiresAt)
    ) {
      best = { ...inv, invite: bytes };
    }
  }
  return best;
}

// --- Personal invite link ---

/**
 * Build a personal invite link for a Private channel:
 * `{base}/#/join/{channelId}?node={encodeURIComponent(hostUrl)}&inv={base64url invite}`.
 *
 * The third argument is either the host node URL (spec 05 §8.4 form) or an
 * options object `{ hostNodeUrl?, baseUrl? }`.
 *
 * The link is only useful to the wallet the invite is bound to — it is NOT a
 * bearer link (those are not supported for Private channels). Throws if the
 * invite does not decode as a `ChannelInvite` for `channelId`, or if
 * `channelId` is not a positive safe integer. The host URL is included only
 * when it is an `http(s)://` URL; `baseUrl` defaults to
 * {@link DEFAULT_INVITE_LINK_BASE}.
 */
export function buildPrivateChannelInviteUrl(
  channelId: number,
  inviteEnvelope: Uint8Array,
  hostUrlOrOptions?: string | { hostNodeUrl?: string; baseUrl?: string },
): string {
  const opts = typeof hostUrlOrOptions === 'string' ? { hostNodeUrl: hostUrlOrOptions } : (hostUrlOrOptions ?? {});
  if (!Number.isSafeInteger(channelId) || channelId <= 0) throw new RangeError('channelId must be a positive integer');
  assertInviteBytes(inviteEnvelope);
  const inv = decodeChannelInvite(inviteEnvelope);
  if (!inv) throw new Error('not a valid ChannelInvite envelope');
  if (inv.channelId !== channelId) throw new Error('invite is for a different channel');
  const base = (opts.baseUrl ?? DEFAULT_INVITE_LINK_BASE).replace(/\/+$/, '');
  if (!/^https?:\/\//.test(base)) throw new Error('baseUrl must be an http(s) URL');
  const params: string[] = [];
  if (opts.hostNodeUrl && /^https?:\/\//.test(opts.hostNodeUrl)) {
    params.push(`node=${encodeURIComponent(opts.hostNodeUrl)}`);
  }
  params.push(`inv=${encodeInviteForUrl(inviteEnvelope)}`);
  return `${base}/#/join/${channelId}?${params.join('&')}`;
}
