/**
 * Shared types for the Ogmara SDK.
 *
 * These types mirror the L2 node API responses and protocol spec definitions.
 */

/** A registered Ogmara user. */
export interface User {
  address: string;
  public_key: string;
  registered_at: number;
  display_name?: string;
  avatar_cid?: string;
  bio?: string;
}

/** A channel in the Ogmara network. */
export interface Channel {
  channel_id: number;
  slug: string;
  creator: string;
  channel_type: number;
  created_at: number;
  display_name?: string;
  description?: string;
  member_count?: number;
}

/** A message envelope as returned by the API. */
export interface Envelope {
  version: number;
  msg_type: number;
  msg_id: string;
  author: string;
  timestamp: number;
  lamport_ts: number;
  payload: string; // base64 encoded
  signature: string; // base64 encoded
  relay_path: string[];
}

/** Media attachment reference. */
export interface Attachment {
  cid: string;
  mime_type: string;
  size_bytes: number;
  filename?: string;
  thumbnail_cid?: string;
}

/** Voluntary content rating. */
export type ContentRating = 'general' | 'teen' | 'mature' | 'explicit';

/** Chat message data for sending. */
export interface ChatMessageData {
  channelId: number;
  content: string;
  contentRating?: ContentRating;
  replyTo?: string;
  mentions?: string[];
  attachments?: Attachment[];
}

/** News post data for sending. */
export interface NewsPostData {
  title: string;
  content: string;
  contentRating?: ContentRating;
  tags?: string[];
  attachments?: Attachment[];
}

/** News comment data for sending (reply to a news post). */
export interface NewsCommentData {
  postId: string;       // hex msg_id of parent NewsPost
  content: string;
  replyTo?: string;     // hex msg_id of parent comment (for threading)
  mentions?: string[];
  attachments?: Attachment[];
}

/** Direct message data for sending. */
export interface DirectMessageData {
  /** Recipient's klv1... wallet address. */
  recipient: string;
  /** Message content (plaintext for MVP). */
  content: string;
  /** Hex msg_id of parent message (for replies). */
  replyTo?: string;
}

/** DM conversation summary. */
export interface DmConversation {
  conversation_id: string;
  peer: string;
  last_message_at: number;
  last_message_preview: string;
  unread_count: number;
}

/** Health check response. */
export interface Health {
  status: string;
  version: string;
  peers: number;
}

/** Anchor verification status for a network node. */
export interface AnchorStatus {
  verified: boolean;
  level: 'active' | 'verified' | 'none';
  last_anchor_age_seconds?: number;
  anchoring_since?: number;
}

/** Self anchor status reported by a node in /network/stats. */
export interface SelfAnchorStatus {
  is_anchorer: boolean;
  last_anchor_height?: number;
  last_anchor_age_seconds?: number;
  total_anchors: number;
  anchoring_since?: number;
}

/** Network stats response. */
export interface NetworkStats {
  node_id: string;
  peers: number;
  total_messages: number;
  total_channels: number;
  total_users: number;
  uptime_seconds: number;
  protocol_version: number;
  anchor_status?: SelfAnchorStatus;
}

/** Channels list response. */
export interface ChannelsResponse {
  channels: Channel[];
  total: number;
  page: number;
}

/** Messages response with pagination cursor. */
export interface MessagesResponse {
  messages: Envelope[];
  has_more: boolean;
}

/** News list response. */
export interface NewsResponse {
  posts: Envelope[];
  total: number;
  page: number;
}

/** Media upload response. */
export interface UploadResult {
  cid: string;
  size: number;
  thumbnail_cid?: string;
}

/** Network node info for failover. */
export interface NodeInfo {
  node_id: string;
  api_endpoint?: string;
  channels?: number[];
  user_count?: number;
  last_seen?: number;
  anchor_status?: AnchorStatus;
}

/** WebSocket event types from the server. */
export type WsEvent =
  | { type: 'message'; envelope: Envelope }
  | { type: 'dm'; envelope: Envelope }
  | { type: 'notification'; mention: Record<string, unknown> }
  | { type: 'presence'; channel_id: string; online: string[] }
  | { type: 'error'; code: number; message: string };

/** SDK client configuration. */
export interface ClientConfig {
  /** Primary node URL (e.g., "https://node1.ogmara.org:41721"). */
  nodeUrl: string;
  /** Request timeout in milliseconds (default: 30000). */
  timeout?: number;
}

/** Message type identifiers (protocol spec 3.2). */
export const MessageType = {
  ChatMessage: 0x01,
  ChatEdit: 0x02,
  ChatDelete: 0x03,
  ChatReaction: 0x04,
  DirectMessage: 0x05,
  DirectMessageEdit: 0x06,
  DirectMessageDelete: 0x07,
  DirectMessageReaction: 0x08,
  ChannelCreate: 0x10,
  ChannelUpdate: 0x11,
  ChannelJoin: 0x12,
  ChannelLeave: 0x13,
  NewsPost: 0x20,
  NewsEdit: 0x21,
  NewsDelete: 0x22,
  NewsComment: 0x23,
  ProfileUpdate: 0x30,
  DeviceDelegation: 0x31,
  DeviceRevocation: 0x32,
  SettingsSync: 0x33,
  Report: 0x40,
  CounterVote: 0x41,
  ChannelMute: 0x42,
  Follow: 0x34,
  Unfollow: 0x35,
  DeletionRequest: 0x50,
  // Channel Administration
  ChannelAddModerator: 0x14,
  ChannelRemoveModerator: 0x15,
  ChannelKick: 0x16,
  ChannelBan: 0x17,
  ChannelUnban: 0x18,
  ChannelPinMessage: 0x19,
  ChannelUnpinMessage: 0x1a,
  ChannelInvite: 0x1b,
  // News Engagement
  NewsReaction: 0x24,
  NewsRepost: 0x25,
} as const;

/** Follow payload. */
export interface FollowPayload {
  target: string;
}

/** Unfollow payload. */
export interface UnfollowPayload {
  target: string;
}

/** Follower/following list response. */
export interface FollowerListResponse {
  followers?: string[];
  following?: string[];
  total: number;
  page: number;
}

/** Personal feed response. */
export interface FeedResponse {
  posts: Envelope[];
  total: number;
  page: number;
}

/** Pagination options. */
export interface PaginationOptions {
  page?: number;
  limit?: number;
}

/** News post detail response (GET /api/v1/news/:msg_id). */
export interface NewsPostResponse {
  post: Envelope;
  comments: Envelope[];
}

/** Profile update data for PUT /api/v1/profile. */
export interface ProfileUpdateData {
  display_name?: string;
  avatar_cid?: string;
  bio?: string;
}

/** DM conversations list response. */
export interface DmConversationsResponse {
  conversations: DmConversation[];
  total: number;
}

/** DM messages response. */
export interface DmMessagesResponse {
  messages: Envelope[];
  has_more: boolean;
}

/** Notification from the L2 node. */
export interface Notification {
  type: 'mention' | 'dm' | 'follow' | 'reply';
  msg_id?: string;
  channel_id?: string;
  from: string;
  timestamp: number;
  preview?: string;
}

/** Notifications list response. */
export interface NotificationsResponse {
  notifications: Notification[];
}

/** Channel creation data for POST /api/v1/channels. */
export interface ChannelCreateData {
  /** SC-assigned sequential channel ID. */
  channelId: number;
  /** Unique slug (matches SC), max 64 chars. */
  slug: string;
  /** Channel type: 0 = Public, 1 = ReadPublic, 2 = Private. */
  channelType?: number;
  /** Human-readable name, max 64 chars. */
  displayName?: string;
  /** Channel description, max 256 chars. */
  description?: string;
  /** Human-readable moderation rules. */
  rules?: string;
}

/** Channel update data for modifying channel info. */
export interface ChannelUpdateData {
  channelId: number;
  displayName?: string;
  description?: string;
  logoCid?: string;
  bannerCid?: string;
  websiteUrl?: string;
  tags?: string[];
  rules?: string;
}

/** Channel mute data for muting a user. */
export interface ChannelMuteData {
  channelId: number;
  targetUser: string;
  /** Duration in seconds (0 = permanent). */
  durationSecs?: number;
  reason?: string;
}

/** Channel creation response. */
export interface ChannelCreateResponse {
  channel_id: number;
}

/** User profile response (GET /api/v1/users/:address). */
export interface UserProfileResponse {
  user: User;
  post_count: number;
  channel_count: number;
  follower_count: number;
  following_count: number;
}

/** User posts response (GET /api/v1/users/:address/posts). */
export interface UserPostsResponse {
  posts: Envelope[];
  total: number;
  page: number;
}

/** Moderation reports response (GET /api/v1/moderation/reports). */
export interface ModerationReportsResponse {
  reports: Envelope[];
  counter_votes: Envelope[];
  current_score: number;
  auto_flags: string[];
}

/** Moderation user trust response (GET /api/v1/moderation/user/:address). */
export interface ModerationUserResponse {
  reports_against: number;
  reports_confirmed: number;
  counter_votes_received: number;
  reporter_reputation: number;
  overall_trust_score: number;
}

/** Account export response. */
export interface AccountExportResponse {
  profile: User;
  messages: Envelope[];
  posts: Envelope[];
  dms: Envelope[];
  channels: number[];
}

// --- News Engagement types ---

/** Reaction info for a specific emoji. */
export interface ReactionInfo {
  count: number;
  user_reacted?: boolean;
}

/** News reactions response. */
export interface NewsReactionsResponse {
  reactions: Record<string, ReactionInfo>;
}

/** Reaction payload for sending. */
export interface ReactionPayload {
  target_id: string;
  channel_id?: number;
  emoji: string;
  remove: boolean;
}

/** News repost payload for sending. */
export interface NewsRepostPayload {
  original_id: string;
  original_author: string;
  comment?: string;
}

/** Reposts list response. */
export interface RepostsResponse {
  reposters: string[];
  total: number;
}

/** Bookmarks list response. */
export interface BookmarksResponse {
  bookmarks: Envelope[];
  total: number;
}

// --- Channel Administration types ---

/** Moderator permissions. */
export interface ModeratorPermissions {
  can_mute: boolean;
  can_kick: boolean;
  can_ban: boolean;
  can_pin: boolean;
  can_edit_info: boolean;
  can_delete_msgs: boolean;
}

/** Channel member info. */
export interface ChannelMember {
  address: string;
  role: 'creator' | 'moderator' | 'member';
  joined_at: number;
  permissions?: ModeratorPermissions;
}

/** Channel members response. */
export interface ChannelMembersResponse {
  members: ChannelMember[];
  total: number;
}

/** Channel pins response. */
export interface ChannelPinsResponse {
  pinned_messages: Envelope[];
}

/** Channel bans response. */
export interface ChannelBansResponse {
  bans: {
    address: string;
    reason?: string;
    duration_secs?: number;
    banned_at?: number;
    banned_by?: string;
  }[];
}

// --- Device Identity ---

/** Request body for device registration. */
export interface RegisterDeviceRequest {
  device_pubkey_hex: string;
  wallet_address: string;
  wallet_signature: string;
  timestamp: number;
}

/** Response from device registration. */
export interface RegisterDeviceResponse {
  ok: boolean;
  device_address: string;
  wallet_address: string;
}

/** A registered device in the list response. */
export interface DeviceInfo {
  device_address: string;
  device_pubkey_hex: string;
  registered_at: number;
}

/** Response from listing devices. */
export interface ListDevicesResponse {
  wallet_address: string;
  devices: DeviceInfo[];
  total: number;
}

/** Response from device revocation. */
export interface RevokeDeviceResponse {
  ok: boolean;
  device_address: string;
}

// --- v0.11.0 Message Action types ---

/** Chat message edit data. */
export interface ChatEditData {
  channelId: number;
  msgId: string;   // hex msg_id of original message
  content: string; // new content
}

/** Chat message delete data. */
export interface ChatDeleteData {
  channelId: number;
  msgId: string; // hex msg_id of message to delete
}

/** Chat message reaction data. */
export interface ChatReactionData {
  channelId: number;
  msgId: string; // hex msg_id of target message
  emoji: string;
  remove: boolean;
}

/** DM edit data. */
export interface DirectMessageEditData {
  recipient: string;
  msgId: string;
  content: string;
}

/** DM delete data. */
export interface DirectMessageDeleteData {
  recipient: string;
  msgId: string;
}

/** DM reaction data. */
export interface DirectMessageReactionData {
  recipient: string;
  msgId: string;
  emoji: string;
  remove: boolean;
}

/** News edit data. */
export interface NewsEditData {
  msgId: string;
  title?: string;
  content: string;
  tags?: string[];
}

/** News delete data. */
export interface NewsDeleteData {
  msgId: string;
}

/** Settings sync data for cross-device settings. */
export interface SettingsSyncData {
  /** AES-256-GCM encrypted settings blob (hex). */
  encrypted_blob: string;
  /** IV used for encryption (hex). */
  iv: string;
}

/** Report data for moderation. */
export interface ReportData {
  targetId: string;
  reason: string;
  category: 'spam' | 'harassment' | 'illegal' | 'other';
}

/** Counter-vote data against a moderation report. */
export interface CounterVoteData {
  reportId: string;
  reason?: string;
}

/** Settings sync response (GET). */
export interface SettingsSyncResponse {
  encrypted_blob: string;
  iv: string;
  updated_at: number;
}

/** Extended channel detail response (with admin data). */
export interface ChannelDetailResponse {
  channel: Channel & {
    logo_cid?: string;
    banner_cid?: string;
    website_url?: string;
    tags?: string[];
    moderator_count?: number;
  };
  moderators?: string[];
  pinned_messages?: Envelope[];
  message_count?: number;
}
