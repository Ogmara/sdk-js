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
import { keccak_256 } from '@noble/hashes/sha3';
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
  type NewsCommentData,
  type DirectMessageData,
  type ChannelCreateData,
  type ChannelUpdateData,
  type ChannelMuteData,
  type ChatEditData,
  type ChatDeleteData,
  type ChatReactionData,
  type DirectMessageEditData,
  type DirectMessageDeleteData,
  type DirectMessageReactionData,
  type NewsEditData,
  type NewsDeleteData,
  type SettingsSyncData,
  type ReportData,
  type CounterVoteData,
} from './types';

/**
 * Map numeric MessageType to Rust enum variant name string.
 *
 * rmp-serde deserializes C-like enums from their variant NAME (string),
 * not their discriminant value (integer). If we send the integer 0x20,
 * rmp-serde interprets it as variant INDEX 32 (= Report), not
 * discriminant 0x20 (= NewsPost). So we must encode msg_type as a string.
 */
const MSG_TYPE_NAME: Record<number, string> = {
  [MessageType.ChatMessage]: 'ChatMessage',
  [MessageType.ChatEdit]: 'ChatEdit',
  [MessageType.ChatDelete]: 'ChatDelete',
  [MessageType.ChatReaction]: 'ChatReaction',
  [MessageType.DirectMessage]: 'DirectMessage',
  [MessageType.DirectMessageEdit]: 'DirectMessageEdit',
  [MessageType.DirectMessageDelete]: 'DirectMessageDelete',
  [MessageType.DirectMessageReaction]: 'DirectMessageReaction',
  [MessageType.ChannelCreate]: 'ChannelCreate',
  [MessageType.ChannelUpdate]: 'ChannelUpdate',
  [MessageType.ChannelJoin]: 'ChannelJoin',
  [MessageType.ChannelLeave]: 'ChannelLeave',
  [MessageType.ChannelAddModerator]: 'ChannelAddModerator',
  [MessageType.ChannelRemoveModerator]: 'ChannelRemoveModerator',
  [MessageType.ChannelKick]: 'ChannelKick',
  [MessageType.ChannelBan]: 'ChannelBan',
  [MessageType.ChannelUnban]: 'ChannelUnban',
  [MessageType.ChannelPinMessage]: 'ChannelPinMessage',
  [MessageType.ChannelUnpinMessage]: 'ChannelUnpinMessage',
  [MessageType.ChannelInvite]: 'ChannelInvite',
  [MessageType.NewsPost]: 'NewsPost',
  [MessageType.NewsEdit]: 'NewsEdit',
  [MessageType.NewsDelete]: 'NewsDelete',
  [MessageType.NewsComment]: 'NewsComment',
  [MessageType.NewsReaction]: 'NewsReaction',
  [MessageType.NewsRepost]: 'NewsRepost',
  [MessageType.ProfileUpdate]: 'ProfileUpdate',
  [MessageType.DeviceDelegation]: 'DeviceDelegation',
  [MessageType.DeviceRevocation]: 'DeviceRevocation',
  [MessageType.SettingsSync]: 'SettingsSync',
  [MessageType.Follow]: 'Follow',
  [MessageType.Unfollow]: 'Unfollow',
  [MessageType.DeviceEncBinding]: 'DeviceEncBinding',
  [MessageType.DeviceEncRevoke]: 'DeviceEncRevoke',
  [MessageType.Report]: 'Report',
  [MessageType.CounterVote]: 'CounterVote',
  [MessageType.ChannelMute]: 'ChannelMute',
  [MessageType.DeletionRequest]: 'DeletionRequest',
};

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

// --- Conversation ID ---

/**
 * Compute a deterministic DM conversation ID from two Klever addresses.
 *
 * Sorts the addresses lexicographically and hashes with Keccak-256.
 * Produces identical output to the Rust `compute_conversation_id`.
 */
export function computeConversationId(addrA: string, addrB: string): Uint8Array {
  const [first, second] = addrA <= addrB ? [addrA, addrB] : [addrB, addrA];
  return keccak_256(new TextEncoder().encode(first + second));
}

// --- Payload serializers ---
// Each returns a plain object matching the Rust struct field names exactly.
// The object is then MessagePack-encoded by buildEnvelope().

/** Extract @klv1... addresses from text content (auto-mention detection). */
function extractMentions(content: string): string[] {
  const matches = content.match(/@(klv1[a-z0-9]{58})/g);
  if (!matches) return [];
  return [...new Set(matches.map((m) => m.slice(1)))];
}

function chatMessagePayload(data: ChatMessageData): Record<string, unknown> {
  // Auto-extract @klv1... mentions from content if not explicitly provided
  const mentions = data.mentions ?? extractMentions(data.content);
  return {
    channel_id: data.channelId,
    content: data.content,
    content_rating: CONTENT_RATING_MAP[data.contentRating ?? 'general'],
    reply_to: data.replyTo ? hexToBytes(data.replyTo) : null,
    mentions,
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

function newsCommentPayload(data: NewsCommentData): Record<string, unknown> {
  const mentions = data.mentions ?? extractMentions(data.content);
  return {
    post_id: hexToBytes(data.postId),
    content: data.content,
    reply_to: data.replyTo ? hexToBytes(data.replyTo) : null,
    mentions,
    attachments: (data.attachments ?? []).map(serializeAttachment),
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

function directMessagePayload(
  data: DirectMessageData,
  signer: WalletSigner,
): Record<string, unknown> {
  const senderAddress = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderAddress, data.recipient);
  // MVP: plaintext content, no encryption. Random nonce for future E2E readiness.
  const nonce = typeof crypto !== 'undefined' && crypto.getRandomValues
    ? crypto.getRandomValues(new Uint8Array(12))
    : new Uint8Array(12);
  return {
    recipient: data.recipient,
    conversation_id: conversationId,
    content: new TextEncoder().encode(data.content),
    nonce,
    key_epoch: 0,
    reply_to: data.replyTo ? hexToBytes(data.replyTo) : null,
    attachments: (data.attachments ?? []).map(serializeAttachment),
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

function channelCreatePayload(data: ChannelCreateData): Record<string, unknown> {
  return {
    channel_id: data.channelId,
    slug: data.slug,
    channel_type: data.channelType ?? 0,
    display_name: data.displayName ?? null,
    description: data.description ?? null,
    content_rating: 0,
    moderation: {
      admins: [],
      rules: data.rules ?? null,
    },
  };
}

function channelUpdatePayload(data: ChannelUpdateData): Record<string, unknown> {
  return {
    channel_id: data.channelId,
    display_name: data.displayName ?? null,
    description: data.description ?? null,
    content_rating: null,
    moderation: data.rules !== undefined ? { admins: [], rules: data.rules } : null,
    logo_cid: data.logoCid ?? null,
    banner_cid: data.bannerCid ?? null,
    website_url: data.websiteUrl ?? null,
    tags: data.tags ?? null,
    channel_type: data.channelType ?? null,
    threads_enabled: data.threadsEnabled ?? null,
  };
}

function channelMutePayload(data: ChannelMuteData): Record<string, unknown> {
  return {
    channel_id: data.channelId,
    target_user: data.targetUser,
    duration_secs: data.durationSecs ?? 0,
    reason: data.reason ?? null,
  };
}

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

  // 4. Build the full envelope object with binary fields.
  // msg_type must be the Rust variant NAME string (not the numeric discriminant)
  // because rmp-serde deserializes C-like enums from variant names.
  const msgTypeName = MSG_TYPE_NAME[msgType];
  if (!msgTypeName) throw new Error(`Unknown message type: ${msgType}`);

  const envelope = {
    version: 1,
    msg_type: msgTypeName,
    msg_id: msgId,
    author: signer.signingAddress,
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

export async function buildNewsComment(signer: WalletSigner, data: NewsCommentData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsComment, newsCommentPayload(data));
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

export async function buildDirectMessage(signer: WalletSigner, data: DirectMessageData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.DirectMessage, directMessagePayload(data, signer));
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

export async function buildChannelCreate(signer: WalletSigner, data: ChannelCreateData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelCreate, channelCreatePayload(data));
}

export async function buildChannelUpdate(signer: WalletSigner, data: ChannelUpdateData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelUpdate, channelUpdatePayload(data));
}

export async function buildChannelMute(signer: WalletSigner, data: ChannelMuteData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChannelMute, channelMutePayload(data));
}

// --- v0.11.0 message action builders ---

function chatEditPayload(data: ChatEditData): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.msgId),
    channel_id: data.channelId,
    content: data.content,
    edited_at: Date.now(),
  };
}

function chatDeletePayload(data: ChatDeleteData): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.msgId),
    channel_id: data.channelId,
  };
}

function chatReactionPayload(data: ChatReactionData): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.msgId),
    channel_id: data.channelId,
    emoji: data.emoji,
    remove: data.remove,
  };
}

function dmEditPayload(data: DirectMessageEditData, signer: WalletSigner): Record<string, unknown> {
  const senderAddress = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderAddress, data.recipient);
  const nonce = typeof crypto !== 'undefined' && crypto.getRandomValues
    ? crypto.getRandomValues(new Uint8Array(12))
    : new Uint8Array(12);
  return {
    target_id: hexToBytes(data.msgId),
    recipient: data.recipient,
    conversation_id: conversationId,
    content: new TextEncoder().encode(data.content),
    edited_at: Date.now(),
    nonce,
    key_epoch: 0,
  };
}

function dmDeletePayload(data: DirectMessageDeleteData, signer: WalletSigner): Record<string, unknown> {
  const senderAddress = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderAddress, data.recipient);
  return {
    target_id: hexToBytes(data.msgId),
    recipient: data.recipient,
    conversation_id: conversationId,
  };
}

function dmReactionPayload(data: DirectMessageReactionData, signer: WalletSigner): Record<string, unknown> {
  const senderAddress = signer.walletAddress ?? signer.address;
  const conversationId = computeConversationId(senderAddress, data.recipient);
  return {
    target_id: hexToBytes(data.msgId),
    recipient: data.recipient,
    conversation_id: conversationId,
    emoji: data.emoji,
    remove: data.remove,
  };
}

function newsEditPayload(data: NewsEditData): Record<string, unknown> {
  // Per L2 protocol §3.7 (v0.37+): every field override is OPTIONAL and
  // preserved on the original payload when absent. Emitting `null` or
  // `[]` for an omitted field would, under the v0.37 read-time projection,
  // be treated as `Some(...)` → wholesale replace → wipe the original.
  // So `title`, `tags`, and `attachments` are all gated on `!== undefined`
  // identically; only the always-applied fields are unconditional.
  const out: Record<string, unknown> = {
    target_id: hexToBytes(data.msgId),
    content: data.content,
    edited_at: Date.now(),
  };
  if (data.title !== undefined) {
    out.title = data.title;
  }
  if (data.tags !== undefined) {
    out.tags = data.tags;
  }
  if (data.attachments !== undefined) {
    out.attachments = data.attachments.map(serializeAttachment);
  }
  return out;
}

function newsDeletePayload(data: NewsDeleteData): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.msgId),
  };
}

function settingsSyncPayload(data: SettingsSyncData): Record<string, unknown> {
  return {
    encrypted_settings: data.encrypted_settings,
    nonce: data.nonce,
    key_epoch: data.key_epoch,
  };
}

/** Map SDK category strings to Rust ReportReason enum variant names. */
const REPORT_REASON_MAP: Record<string, string> = {
  spam: 'Spam',
  scam: 'Scam',
  harassment: 'Harassment',
  illegal: 'IllegalContent',
  impersonation: 'Impersonation',
  misrated: 'MisratedContent',
  other: 'Other',
};

function reportPayload(data: ReportData): Record<string, unknown> {
  return {
    target_type: 'Message', // ReportTarget enum variant
    target_id: hexToBytes(data.targetId),
    reason: REPORT_REASON_MAP[data.category] || 'Other',
    details: data.details?.slice(0, 256) || null,
  };
}

function counterVotePayload(data: CounterVoteData): Record<string, unknown> {
  return {
    target_id: hexToBytes(data.reportId),
  };
}

export async function buildChatEdit(signer: WalletSigner, data: ChatEditData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChatEdit, chatEditPayload(data));
}

export async function buildChatDelete(signer: WalletSigner, data: ChatDeleteData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChatDelete, chatDeletePayload(data));
}

export async function buildChatReaction(signer: WalletSigner, data: ChatReactionData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.ChatReaction, chatReactionPayload(data));
}

export async function buildDmEdit(signer: WalletSigner, data: DirectMessageEditData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.DirectMessageEdit, dmEditPayload(data, signer));
}

export async function buildDmDelete(signer: WalletSigner, data: DirectMessageDeleteData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.DirectMessageDelete, dmDeletePayload(data, signer));
}

export async function buildDmReaction(signer: WalletSigner, data: DirectMessageReactionData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.DirectMessageReaction, dmReactionPayload(data, signer));
}

export async function buildNewsEdit(signer: WalletSigner, data: NewsEditData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsEdit, newsEditPayload(data));
}

export async function buildNewsDelete(signer: WalletSigner, data: NewsDeleteData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.NewsDelete, newsDeletePayload(data));
}

export async function buildSettingsSync(signer: WalletSigner, data: SettingsSyncData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.SettingsSync, settingsSyncPayload(data));
}

export async function buildReport(signer: WalletSigner, data: ReportData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.Report, reportPayload(data));
}

export async function buildCounterVote(signer: WalletSigner, data: CounterVoteData): Promise<Uint8Array> {
  return buildEnvelope(signer, MessageType.CounterVote, counterVotePayload(data));
}
