/**
 * Envelope builder — constructs signed MessagePack-serialized envelopes
 * for the Ogmara L2 node protocol.
 *
 * The L2 node expects all write endpoints to receive raw MessagePack bytes
 * of a signed Envelope struct. This module handles:
 * 1. Payload serialization (typed payload → MessagePack bytes)
 * 2. msg_id computation (Keccak-256)
 * 3. Ed25519 signing (Ogmara protocol format)
 * 4. Full envelope serialization (MessagePack bytes)
 *
 * Per protocol spec section 3.1.
 */

import { encode } from '@msgpack/msgpack';
import type { WalletSigner } from './auth';
import {
  MessageType,
  type Attachment,
  type ContentRating,
  type ChatMessageData,
  type NewsPostData,
  type ProfileUpdateData,
  type ReactionPayload,
  type NewsRepostPayload,
} from './types';

// --- Content rating / visibility numeric mappings ---

const CONTENT_RATING_MAP: Record<ContentRating, number> = {
  general: 0,
  teen: 1,
  mature: 2,
  explicit: 3,
};

const VISIBILITY_PUBLIC = 0;

// --- Hex helpers ---

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`Invalid hex string: ${hex.slice(0, 20)}`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// --- Payload serializers ---
// Each returns a plain object matching the Rust struct field names exactly.
// The object is then MessagePack-encoded by buildEnvelope().

function chatMessagePayload(data: ChatMessageData): Record<string, unknown> {
  return {
    channel_id: data.channelId,
    content: data.content,
    content_rating: CONTENT_RATING_MAP[data.contentRating ?? 'general'],
    reply_to: data.replyTo ? hexToBytes(data.replyTo) : null,
    mentions: data.mentions ?? [],
    attachments: (data.attachments ?? []).map(serializeAttachment),
  };
}

function newsPostPayload(data: NewsPostData): Record<string, unknown> {
  return {
    title: data.title,
    content: data.content,
    content_rating: CONTENT_RATING_MAP[data.contentRating ?? 'general'],
    tags: data.tags ?? [],
    attachments: (data.attachments ?? []).map(serializeAttachment),
    visibility: VISIBILITY_PUBLIC,
  };
}

function profileUpdatePayload(data: ProfileUpdateData): Record<string, unknown> {
  return {
    display_name: data.display_name ?? null,
    avatar_cid: data.avatar_cid ?? null,
    bio: data.bio ?? null,
  };
}

function followPayload(target: string): Record<string, unknown> {
  return { target };
}

function reactionPayload(data: ReactionPayload): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.target_id),
    channel_id: data.channel_id ?? null,
    emoji: data.emoji,
    remove: data.remove,
  };
}

function repostPayload(data: NewsRepostPayload): Record<string, unknown> {
  return {
    original_id: hexToBytes(data.original_id),
    original_author: data.original_author,
    comment: data.comment ?? null,
  };
}

function serializeAttachment(a: Attachment): Record<string, unknown> {
  return {
    cid: a.cid,
    mime_type: a.mime_type,
    size_bytes: a.size_bytes,
    filename: a.filename ?? null,
    thumbnail_cid: a.thumbnail_cid ?? null,
  };
}

// --- Channel admin payload serializers ---

function channelJoinPayload(channelId: number): Record<string, unknown> {
  return { channel_id: channelId };
}

function channelLeavePayload(channelId: number): Record<string, unknown> {
  return { channel_id: channelId };
}

interface AddModeratorData {
  channelId: number;
  targetUser: string;
  permissions: {
    can_mute: boolean;
    can_kick: boolean;
    can_ban: boolean;
    can_pin: boolean;
    can_edit_info: boolean;
    can_delete_msgs: boolean;
  };
}

function addModeratorPayload(data: AddModeratorData): Record<string, unknown> {
  return {
    channel_id: data.channelId,
    target_user: data.targetUser,
    permissions: data.permissions,
  };
}

function removeModeratorPayload(channelId: number, targetUser: string): Record<string, unknown> {
  return { channel_id: channelId, target_user: targetUser };
}

function kickPayload(channelId: number, targetUser: string, reason?: string): Record<string, unknown> {
  return { channel_id: channelId, target_user: targetUser, reason: reason ?? null };
}

function banPayload(channelId: number, targetUser: string, reason?: string, durationSecs = 0): Record<string, unknown> {
  return { channel_id: channelId, target_user: targetUser, reason: reason ?? null, duration_secs: durationSecs };
}

function unbanPayload(channelId: number, targetUser: string): Record<string, unknown> {
  return { channel_id: channelId, target_user: targetUser };
}

function pinPayload(channelId: number, msgId: string): Record<string, unknown> {
  return { channel_id: channelId, msg_id: hexToBytes(msgId) };
}

function invitePayload(channelId: number, targetUser: string): Record<string, unknown> {
  return { channel_id: channelId, target_user: targetUser };
}

// --- Core envelope builder ---

/**
 * Build a signed, MessagePack-serialized envelope ready to send to the L2 node.
 *
 * @param signer - WalletSigner with private key
 * @param msgType - MessageType value (u8)
 * @param payloadObj - Plain JS object matching the Rust payload struct field names
 * @param lamportTs - Lamport clock value (0 if not tracking)
 * @returns MessagePack-serialized envelope bytes
 */
export async function buildEnvelope(
  signer: WalletSigner,
  msgType: number,
  payloadObj: Record<string, unknown>,
  lamportTs = 0,
): Promise<Uint8Array> {
  // 1. Serialize payload to MessagePack
  const payloadBytes = encode(payloadObj);

  // 2. Compute timestamp and msg_id
  const timestamp = Date.now();
  const msgId = signer.computeMsgId(new Uint8Array(payloadBytes), timestamp);

  // 3. Sign the envelope
  const signature = await signer.signEnvelope(
    1, // protocol version
    msgType,
    msgId,
    timestamp,
    new Uint8Array(payloadBytes),
  );

  // 4. Build the full envelope object with binary fields
  const envelope = {
    version: 1,
    msg_type: msgType,
    msg_id: msgId,
    author: signer.address,
    timestamp,
    lamport_ts: lamportTs,
    payload: new Uint8Array(payloadBytes),
    signature,
    relay_path: [],
  };

  // 5. Serialize the entire envelope to MessagePack
  return new Uint8Array(encode(envelope));
}

// --- High-level builders (one per SDK write method) ---

export async function buildChatMessage(signer: WalletSigner, data: ChatMessageData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChatMessage, chatMessagePayload(data));
}

export async function buildNewsPost(signer: WalletSigner, data: NewsPostData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsPost, newsPostPayload(data));
}

export async function buildProfileUpdate(signer: WalletSigner, data: ProfileUpdateData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ProfileUpdate, profileUpdatePayload(data));
}

export async function buildFollow(signer: WalletSigner, target: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.Follow, followPayload(target));
}

export async function buildUnfollow(signer: WalletSigner, target: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.Unfollow, followPayload(target));
}

export async function buildReaction(signer: WalletSigner, data: ReactionPayload): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsReaction, reactionPayload(data));
}

export async function buildRepost(signer: WalletSigner, data: NewsRepostPayload): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsRepost, repostPayload(data));
}

// Channel admin builders

export async function buildChannelJoin(signer: WalletSigner, channelId: number): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelJoin, channelJoinPayload(channelId));
}

export async function buildChannelLeave(signer: WalletSigner, channelId: number): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelLeave, channelLeavePayload(channelId));
}

export async function buildAddModerator(signer: WalletSigner, data: AddModeratorData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelAddModerator, addModeratorPayload(data));
}

export async function buildRemoveModerator(signer: WalletSigner, channelId: number, target: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelRemoveModerator, removeModeratorPayload(channelId, target));
}

export async function buildKick(signer: WalletSigner, channelId: number, target: string, reason?: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelKick, kickPayload(channelId, target, reason));
}

export async function buildBan(signer: WalletSigner, channelId: number, target: string, reason?: string, durationSecs?: number): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelBan, banPayload(channelId, target, reason, durationSecs));
}

export async function buildUnban(signer: WalletSigner, channelId: number, target: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelUnban, unbanPayload(channelId, target));
}

export async function buildPin(signer: WalletSigner, channelId: number, msgId: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelPinMessage, pinPayload(channelId, msgId));
}

export async function buildUnpin(signer: WalletSigner, channelId: number, msgId: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelUnpinMessage, pinPayload(channelId, msgId));
}

export async function buildInvite(signer: WalletSigner, channelId: number, target: string): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelInvite, invitePayload(channelId, target));
}
