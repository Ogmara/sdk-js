/**
 * Direct Message E2E encryption (P1, protocol §8.2). A DM conversation is a
 * **two-member group**: a random 32-byte `conv_key` per epoch, delivered to each
 * participant device via `ChannelKeyEnvelope` (0x61, ECIES-wrapped, §8.1), and used
 * to XChaCha20-Poly1305-encrypt each message's content. Mirrors sdk-rust `dm.rs`.
 *
 * The node relays/stores opaque ciphertext + wrapped keys it cannot decrypt.
 */
import { encode, decode } from '@msgpack/msgpack';
import { aeadEncrypt, aeadDecrypt, wrapKey, unwrapKey, KEY_LEN, type WrappedKey } from './crypto';
import { buildEnvelope, computeConversationId, computeChannelScope } from './envelope';
import { MessageType } from './types';
import { mediaToWire, mediaFromWire, mediaToWireAttachment, type MediaDescriptor } from './media';
import type { WalletSigner } from './auth';

/** Scope discriminant for a {@link ChannelKeyEnvelopeParams} (matches node `key_scope_kind`). */
export const KeyScopeKind = { DM: 0, Channel: 1 } as const;

function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

function requireCsprng(): Crypto {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available');
  }
  return crypto;
}

/**
 * AEAD associated data binding DM content to its conversation + epoch:
 * `conversation_id(32) || epoch_be8` (spec §8.2.2). Identical in sdk-rust.
 */
export function dmContentAad(conversationId: Uint8Array, epoch: number): Uint8Array {
  const aad = new Uint8Array(conversationId.length + 8);
  aad.set(conversationId, 0);
  aad.set(u64be(epoch), conversationId.length);
  return aad;
}

/** Generate a random 32-byte conversation key. Throws if no CSPRNG is available. */
export function randomConvKey(): Uint8Array {
  return requireCsprng().getRandomValues(new Uint8Array(KEY_LEN));
}

/** Decrypted DM body. `replyTo` + `media` ride inside the ciphertext (not leaked to the node). */
export interface DmPlaintext {
  text: string;
  /** 32-byte parent msg_id, if this is a reply. */
  replyTo?: Uint8Array;
  /** Encrypted-media descriptors (P5 / spec 04 §9.2) — per-file keys live here. */
  media?: MediaDescriptor[];
}

/** Encrypted DM content for the `DirectMessage` payload. */
export interface EncryptedDmContent {
  /** XChaCha20-Poly1305 ciphertext (`ct || tag`). */
  content: Uint8Array;
  /** 24-byte AEAD nonce. */
  nonce: Uint8Array;
}

/**
 * Encrypt a DM body under `convKey`. The wire plaintext is
 * `msgpack({ text, reply_to? })`, AEAD-sealed with `aad = conversation_id || epoch`.
 */
export function encryptDmContent(
  convKey: Uint8Array,
  conversationId: Uint8Array,
  epoch: number,
  pt: DmPlaintext,
): EncryptedDmContent {
  const nonce = requireCsprng().getRandomValues(new Uint8Array(24));
  const blob = encode({
    text: pt.text,
    reply_to: pt.replyTo ?? null,
    media: pt.media && pt.media.length ? pt.media.map(mediaToWire) : null,
  });
  const content = aeadEncrypt(convKey, nonce, blob, dmContentAad(conversationId, epoch));
  return { content, nonce };
}

/** Decrypt a DM body produced by {@link encryptDmContent}. Throws on auth failure. */
export function decryptDmContent(
  convKey: Uint8Array,
  conversationId: Uint8Array,
  epoch: number,
  content: Uint8Array,
  nonce: Uint8Array,
): DmPlaintext {
  const blob = aeadDecrypt(convKey, nonce, content, dmContentAad(conversationId, epoch));
  const obj = decode(blob) as {
    text: string;
    reply_to?: Uint8Array | null;
    media?: Array<Record<string, unknown>> | null;
  };
  return {
    text: obj.text,
    replyTo: obj.reply_to ?? undefined,
    media: obj.media && obj.media.length ? obj.media.map(mediaFromWire) : undefined,
  };
}

/** Wrap a `conv_key` to a recipient device enc pubkey (ECIES). DM salt = conversation_id. */
export function wrapConvKey(
  convKey: Uint8Array,
  recipientEncPub: Uint8Array,
  conversationId: Uint8Array,
): WrappedKey {
  return wrapKey(convKey, recipientEncPub, conversationId);
}

/** Unwrap a `conv_key` with this device's enc privkey. DM salt = conversation_id. */
export function unwrapConvKey(
  wrapped: WrappedKey,
  deviceEncPriv: Uint8Array,
  conversationId: Uint8Array,
): Uint8Array {
  return unwrapKey(wrapped, deviceEncPriv, conversationId);
}

/** Parameters for a per-device {@link buildChannelKeyEnvelope}. */
export interface ChannelKeyEnvelopeParams {
  /** 32-byte key scope — `conversation_id` for DMs. */
  keyScope: Uint8Array;
  /** 0 = DM, 1 = channel (see {@link KeyScopeKind}). */
  scopeKind: number;
  /** Epoch this key belongs to. */
  epoch: number;
  /** Recipient wallet (`klv1…`) this key is wrapped for. */
  target: string;
  /** Recipient device id — hex of the device Ed25519 signing pubkey. */
  deviceId: string;
  /** DM only: the other participant (for the node's participant-binding check). */
  peer?: string;
  /** Channel only: the channel id. */
  channelId?: number;
  /** The ECIES-wrapped key from {@link wrapConvKey}. */
  wrapped: WrappedKey;
}

/**
 * Build a signed `ChannelKeyEnvelope` (0x61) delivering one wrapped key to one
 * device. Publish via the generic message endpoint (`POST /api/v1/messages`).
 */
export async function buildChannelKeyEnvelope(
  signer: WalletSigner,
  p: ChannelKeyEnvelopeParams,
): Promise<Uint8Array> {
  const payload = {
    key_scope: p.keyScope,
    scope_kind: p.scopeKind,
    epoch: p.epoch,
    target: p.target,
    device_id: p.deviceId.toLowerCase(),
    peer: p.peer ?? null,
    channel_id: p.channelId ?? null,
    eph_pub: p.wrapped.ephPub,
    nonce: p.wrapped.nonce,
    wrapped: p.wrapped.wrapped,
  };
  return buildEnvelope(signer, MessageType.ChannelKeyEnvelope, payload);
}

/** Parameters for {@link buildEncryptedDirectMessage}. */
export interface EncryptedDmParams {
  recipient: string;
  /** The conversation key for `epoch` (established + cached by the caller). */
  convKey: Uint8Array;
  epoch: number;
  text: string;
  /** Hex msg_id of the parent message — encrypted inside the body, not leaked. */
  replyTo?: string;
  /**
   * Encrypted-media descriptors (P5). Each file must already be encrypted +
   * uploaded ({@link encryptFile} → `uploadMedia(..., { encrypted: true })`); the
   * per-file keys ride inside the ciphertext and a stripped `{ cid, size }` goes
   * on the wire (spec 04 §9).
   */
  media?: MediaDescriptor[];
}

/**
 * Build a signed, encrypted `DirectMessage` (0x05). `reply_to` rides inside the
 * ciphertext (spec §8.2.2); the plaintext payload field is left null so the node
 * learns nothing beyond conversation + timing.
 */
export async function buildEncryptedDirectMessage(
  signer: WalletSigner,
  p: EncryptedDmParams,
): Promise<Uint8Array> {
  const senderWallet = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderWallet, p.recipient);
  const replyToBytes = p.replyTo ? hexToBytes32(p.replyTo) : undefined;
  const { content, nonce } = encryptDmContent(p.convKey, conversationId, p.epoch, {
    text: p.text,
    replyTo: replyToBytes,
    media: p.media,
  });
  const payload = {
    recipient: p.recipient,
    conversation_id: conversationId,
    content,
    nonce,
    key_epoch: p.epoch,
    reply_to: null,
    // Stripped on-wire attachments (spec 04 §9.3) — node lifecycle only; the real
    // descriptors (mime/filename/keys) live encrypted inside `content`.
    attachments: (p.media ?? []).map(mediaToWireAttachment),
  };
  return buildEnvelope(signer, MessageType.DirectMessage, payload);
}

/** Parameters for {@link buildEncryptedDmEdit}. */
export interface EncryptedDmEditParams {
  recipient: string;
  /** Hex msg_id (32-byte) of the original DM being edited. */
  msgId: string;
  /** The conversation key for `epoch` (same key the original body uses). */
  convKey: Uint8Array;
  epoch: number;
  /** The new plaintext content. */
  content: string;
}

/**
 * Build a signed, encrypted `DirectMessageEdit` (0x06). The new content is sealed
 * under `conv_key` exactly like a DM body (`aad = conversation_id || epoch`) and
 * carried in `enc_content`/`enc_nonce`; the node projects it onto the original DM
 * so the edited message decrypts identically to a never-edited one. The legacy
 * plaintext `content` String is sent empty — DM edits never leak content to the node.
 */
export async function buildEncryptedDmEdit(
  signer: WalletSigner,
  p: EncryptedDmEditParams,
): Promise<Uint8Array> {
  if (p.epoch < 1) throw new Error('DM edit requires key_epoch >= 1 (epoch 0 is legacy plaintext)');
  const senderWallet = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderWallet, p.recipient);
  const { content, nonce } = encryptDmContent(p.convKey, conversationId, p.epoch, {
    text: p.content,
  });
  const payload = {
    target_id: hexToBytes32(p.msgId),
    recipient: p.recipient, // lets the node route the edit to the recipient's DM topic
    channel_id: null,
    content: '', // unused plaintext placeholder for DM edits
    edited_at: Date.now(),
    enc_content: content,
    enc_nonce: nonce,
    key_epoch: p.epoch,
  };
  return buildEnvelope(signer, MessageType.DirectMessageEdit, payload);
}

function hexToBytes32(h: string): Uint8Array {
  const clean = h.toLowerCase();
  if (clean.length !== 64 || !/^[0-9a-f]+$/.test(clean)) throw new Error('reply_to must be 32-byte hex');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const CHANNEL_CONTENT_RATING: Record<string, number> = {
  general: 0, teen: 1, mature: 2, explicit: 3,
};

/** Parameters for {@link buildEncryptedChannelMessage}. */
export interface EncryptedChannelMessageParams {
  channelId: number;
  /** The channel epoch key (established + cached by the caller). */
  convKey: Uint8Array;
  epoch: number;
  text: string;
  /** Hex msg_id of the parent — stays PLAINTEXT (the node's thread index needs it). */
  replyTo?: string;
  /** Mentioned addresses — stay PLAINTEXT (the node generates notifications). */
  mentions?: string[];
  contentRating?: 'general' | 'teen' | 'mature' | 'explicit';
  /**
   * Encrypted-media descriptors (P5 / spec 04 §9). Each file is encrypted with its
   * own key BEFORE upload ({@link encryptFile} → `uploadMedia(..., { encrypted: true })`);
   * the keys ride inside `enc_content` and only a stripped `{ cid, size }` reaches the
   * wire. Used for BOTH private and public encrypted channels — public media is
   * encrypted too (anti-bulk-readout; spec 04 §9). Preferred over `attachments`.
   */
  media?: MediaDescriptor[];
  /**
   * Legacy PLAINTEXT attachment metadata (IPFS CID, mime, size) — retained for
   * callers that intentionally attach unencrypted media to an encrypted channel.
   * New code should use {@link media} so the file bytes are encrypted too.
   */
  attachments?: Array<{
    cid: string;
    mime_type: string;
    size_bytes: number;
    filename?: string;
    thumbnail_cid?: string;
  }>;
}

/**
 * Build a signed, encrypted `ChatMessage` (0x04) for a private channel. Only the
 * TEXT is sealed — under the channel epoch key with `aad = channel_scope || epoch`
 * (same scheme as a DM body) — and carried in `enc_content`/`enc_nonce`/`key_epoch`;
 * the plaintext `content` is empty. Per spec §3.3 `mentions`/`reply_to`/
 * `content_rating` stay plaintext so the node keeps doing notifications, threading,
 * and rating filters.
 */
export async function buildEncryptedChannelMessage(
  signer: WalletSigner,
  p: EncryptedChannelMessageParams,
): Promise<Uint8Array> {
  if (p.epoch < 1) throw new Error('channel message requires key_epoch >= 1');
  const scope = computeChannelScope(p.channelId);
  const { content, nonce } = encryptDmContent(p.convKey, scope, p.epoch, {
    text: p.text,
    media: p.media,
  });
  // Wire attachments: stripped entries for encrypted media (spec 04 §9.3) plus any
  // intentionally-plaintext legacy attachments. Encrypted-media keys/mime/filename
  // are NOT here — they ride inside enc_content.
  const wireAttachments = [
    ...(p.media ?? []).map(mediaToWireAttachment).map((a) => ({
      cid: a.cid,
      mime_type: a.mime_type,
      size_bytes: a.size_bytes,
      filename: null,
      thumbnail_cid: null,
    })),
    ...(p.attachments ?? []).map((a) => ({
      cid: a.cid,
      mime_type: a.mime_type,
      size_bytes: a.size_bytes,
      filename: a.filename ?? null,
      thumbnail_cid: a.thumbnail_cid ?? null,
    })),
  ];
  const payload = {
    channel_id: p.channelId,
    content: '', // text rides in enc_content
    content_rating: CHANNEL_CONTENT_RATING[p.contentRating ?? 'general'] ?? 0,
    reply_to: p.replyTo ? hexToBytes32(p.replyTo) : null,
    mentions: p.mentions ?? [],
    attachments: wireAttachments,
    enc_content: content,
    enc_nonce: nonce,
    key_epoch: p.epoch,
  };
  return buildEnvelope(signer, MessageType.ChatMessage, payload);
}
