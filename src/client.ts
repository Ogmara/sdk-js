/**
 * Ogmara API client — HTTP client for all L2 node REST endpoints.
 *
 * Supports both public (no auth) and authenticated (Klever wallet signature)
 * endpoints. Handles node failover via discovered node lists.
 *
 * @example
 * ```ts
 * import { OgmaraClient } from '@ogmara/sdk';
 *
 * const client = new OgmaraClient({ nodeUrl: 'http://localhost:41721' });
 * const health = await client.health();
 * console.log(`Node v${health.version}, ${health.peers} peers`);
 *
 * const channels = await client.listChannels();
 * channels.channels.forEach(ch => console.log(`#${ch.channel_id} ${ch.slug}`));
 * ```
 */

import type { WalletSigner } from './auth';
import type { PowChallenge } from './pow';
import { solveChallengeAsync } from './pow';
import {
  buildChatMessage,
  buildNewsPost,
  buildNewsComment,
  buildProfileUpdate,
  buildFollow,
  buildUnfollow,
  buildReaction,
  buildRepost,
  buildAddModerator,
  buildRemoveModerator,
  buildKick,
  buildBan,
  buildUnban,
  buildPin,
  buildUnpin,
  buildInvite,
  buildChannelCreate,
  buildChannelUpdate,
  buildChannelJoin,
  buildChannelLeave,
  buildChannelMute,
  buildChatEdit,
  buildChatDelete,
  buildChatReaction,
  buildDmEdit,
  buildDmDelete,
  buildDmReaction,
  buildNewsEdit,
  buildNewsDelete,
  buildSettingsSync,
  buildReport,
  buildCounterVote,
} from './envelope';
import type {
  Health,
  NetworkStats,
  Channel,
  NewsCommentData,
  ChannelsResponse,
  MessagesResponse,
  NewsResponse,
  ClientConfig,
  NodeInfo,
  FollowerListResponse,
  FeedResponse,
  PaginationOptions,
  NewsPostResponse,
  UploadResult,
  ProfileUpdateData,
  ChatMessageData,
  NewsPostData,
  Attachment,
  DmConversationsResponse,
  DmMessagesResponse,
  NotificationsResponse,
  ChannelCreateResponse,
  UserProfileResponse,
  UserPostsResponse,
  AccountExportResponse,
  ModerationReportsResponse,
  ModerationUserResponse,
  NewsReactionsResponse,
  RepostsResponse,
  BookmarksResponse,
  ChannelMembersResponse,
  ChannelPinsResponse,
  ChannelBansResponse,
  ChannelDetailResponse,
  ModeratorPermissions,
  ChannelCreateData,
  ChannelUpdateData,
  ChannelMuteData,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  RevokeDeviceResponse,
  ListDevicesResponse,
  ChatEditData,
  ChatDeleteData,
  ChatReactionData,
  DirectMessageEditData,
  DirectMessageDeleteData,
  DirectMessageReactionData,
  NewsEditData,
  NewsDeleteData,
  SettingsSyncData,
  SettingsSyncResponse,
  ReportData,
  CounterVoteData,
} from './types';

/** Ogmara SDK client for the L2 node REST API. */
export class OgmaraClient {
  private nodeUrl: string;
  private timeout: number;
  private signer?: WalletSigner;
  private knownNodes: string[] = [];

  /** Whether this client's wallet has been verified (PoW solved or on-chain registered). */
  private powVerified = false;

  /** Optional callback invoked during PoW solving with progress (hashes computed). */
  onPowProgress?: (hashes: number) => void;

  /** Optional callback invoked when PoW solving starts (for UI loading indicators). */
  onPowStart?: () => void;

  /** Optional callback invoked when PoW solving completes. */
  onPowComplete?: (elapsed_ms: number) => void;

  constructor(config: ClientConfig) {
    this.nodeUrl = config.nodeUrl.replace(/\/$/, ''); // strip trailing slash
    this.timeout = config.timeout ?? 30000;
  }

  /** Set the wallet signer for authenticated endpoints. */
  withSigner(signer: WalletSigner): this {
    this.signer = signer;
    return this;
  }

  /** Get the signer's address (if configured). */
  get address(): string | undefined {
    return this.signer?.address;
  }

  // --- Public endpoints ---

  /** GET /api/v1/health */
  async health(): Promise<Health> {
    return this.get('/api/v1/health');
  }

  /** GET /api/v1/network/stats */
  async networkStats(): Promise<NetworkStats> {
    return this.get('/api/v1/network/stats');
  }

  /** GET /api/v1/channels */
  async listChannels(page = 1, limit = 20, sort?: 'recent' | 'popular'): Promise<ChannelsResponse> {
    let path = `/api/v1/channels?page=${page}&limit=${limit}`;
    if (sort) path += `&sort=${sort}`;
    return this.get(path);
  }

  /** GET /api/v1/channels/:channelId */
  async getChannel(channelId: number): Promise<{ channel: Channel; member_count: number; message_count: number }> {
    return this.get(`/api/v1/channels/${channelId}`);
  }

  /** GET /api/v1/channels/:channelId/messages
   *  `after` returns messages newer than the given msg_id (incremental fetch).
   *  `before` and `after` are mutually exclusive; `after` takes precedence.
   */
  async getChannelMessages(
    channelId: number,
    limit = 50,
    before?: string,
    after?: string,
  ): Promise<MessagesResponse> {
    let path = `/api/v1/channels/${channelId}/messages?limit=${limit}`;
    if (after) path += `&after=${encodeURIComponent(after)}`;
    else if (before) path += `&before=${encodeURIComponent(before)}`;
    return this.get(path);
  }

  /** POST /api/v1/channels/:channelId/read — mark channel as read. */
  async markChannelRead(channelId: number): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    await this.postJson(`/api/v1/channels/${channelId}/read`, {});
  }

  /** GET /api/v1/channels/unread — get unread counts per channel. */
  async getUnreadCounts(): Promise<{ unread: Record<string, number> }> {
    if (!this.signer) throw new Error('Signer required');
    return this.getAuthenticated('/api/v1/channels/unread');
  }

  /** GET /api/v1/news */
  async listNews(page = 1, limit = 20, tag?: string): Promise<NewsResponse> {
    let path = `/api/v1/news?page=${page}&limit=${limit}`;
    if (tag) path += `&tag=${encodeURIComponent(tag)}`;
    return this.get(path);
  }

  /** GET /api/v1/network/nodes */
  async listNodes(page = 1, limit = 20): Promise<{ nodes: NodeInfo[]; total: number }> {
    return this.get(`/api/v1/network/nodes?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/news/:msgId — single news post with comments. */
  async getNewsPost(msgId: string): Promise<NewsPostResponse> {
    return this.get(`/api/v1/news/${encodeURIComponent(msgId)}`);
  }

  /** GET /api/v1/users/:address — full user profile with counts. */
  async getUserProfile(address: string): Promise<UserProfileResponse> {
    return this.get(`/api/v1/users/${encodeURIComponent(address)}`);
  }

  /** GET /api/v1/users/:address/posts */
  async getUserPosts(address: string, options?: PaginationOptions): Promise<UserPostsResponse> {
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    return this.get(`/api/v1/users/${encodeURIComponent(address)}/posts?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/moderation/reports — get reports for a target message/user. */
  async getModerationReports(target: string): Promise<ModerationReportsResponse> {
    return this.get(`/api/v1/moderation/reports?target=${encodeURIComponent(target)}`);
  }

  /** GET /api/v1/moderation/user/:address — get moderation trust info for a user. */
  async getModerationUser(address: string): Promise<ModerationUserResponse> {
    return this.get(`/api/v1/moderation/user/${encodeURIComponent(address)}`);
  }

  /** Build the URL for fetching media by IPFS CID (GET /api/v1/media/:cid). */
  getMediaUrl(cid: string): string {
    return `${this.nodeUrl}/api/v1/media/${encodeURIComponent(cid)}`;
  }

  /** GET /api/v1/users/:address/followers */
  async getFollowers(address: string, options?: PaginationOptions): Promise<FollowerListResponse> {
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 50;
    return this.get(`/api/v1/users/${encodeURIComponent(address)}/followers?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/users/:address/following */
  async getFollowing(address: string, options?: PaginationOptions): Promise<FollowerListResponse> {
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 50;
    return this.get(`/api/v1/users/${encodeURIComponent(address)}/following?page=${page}&limit=${limit}`);
  }

  // --- News Engagement (public) ---

  /** GET /api/v1/news/:msgId/reactions */
  async getNewsReactions(msgId: string): Promise<NewsReactionsResponse> {
    return this.get(`/api/v1/news/${encodeURIComponent(msgId)}/reactions`);
  }

  /** GET /api/v1/news/:msgId/reposts */
  async getNewsReposts(msgId: string, options?: PaginationOptions): Promise<RepostsResponse> {
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    return this.get(`/api/v1/news/${encodeURIComponent(msgId)}/reposts?page=${page}&limit=${limit}`);
  }

  // --- Channel Administration (public) ---

  /** GET /api/v1/channels/:channelId (extended with admin data) */
  async getChannelDetail(channelId: number): Promise<ChannelDetailResponse> {
    return this.get(`/api/v1/channels/${channelId}`);
  }

  /** GET /api/v1/channels/:channelId/members */
  async getChannelMembers(channelId: number, options?: PaginationOptions): Promise<ChannelMembersResponse> {
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 50;
    return this.get(`/api/v1/channels/${channelId}/members?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/channels/:channelId/pins */
  async getChannelPins(channelId: number): Promise<ChannelPinsResponse> {
    return this.get(`/api/v1/channels/${channelId}/pins`);
  }

  /** GET /api/v1/channels/:channelId/bans */
  async getChannelBans(channelId: number): Promise<ChannelBansResponse> {
    return this.get(`/api/v1/channels/${channelId}/bans`);
  }

  // --- Authenticated endpoints ---

  /** POST /api/v1/messages — send a signed chat message envelope. */
  async sendMessage(
    channelId: number,
    content: string,
    options?: { replyTo?: string; mentions?: string[]; attachments?: Attachment[] },
  ): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required for authenticated endpoints');
    const data: ChatMessageData = {
      channelId,
      content,
      replyTo: options?.replyTo,
      mentions: options?.mentions,
      attachments: options?.attachments,
    };
    const envelope = await buildChatMessage(this.signer, data);
    return this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/dm/:address — send an encrypted DM.
   *  Note: DM encryption is handled by the caller. The encryptedPayload
   *  is the pre-built envelope bytes (MessagePack). */
  async sendDm(recipient: string, envelopeBytes: Uint8Array): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required for authenticated endpoints');
    return this.postEnvelope(
      `/api/v1/dm/${encodeURIComponent(recipient)}`,
      envelopeBytes,
    );
  }

  /** POST /api/v1/users/:address/follow — follow a user. */
  async follow(target: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildFollow(this.signer, target);
    await this.postEnvelope(`/api/v1/users/${encodeURIComponent(target)}/follow`, envelope);
  }

  /** DELETE /api/v1/users/:address/follow — unfollow a user. */
  async unfollow(target: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildUnfollow(this.signer, target);
    await this.deleteEnvelope(`/api/v1/users/${encodeURIComponent(target)}/follow`, envelope);
  }

  /** GET /api/v1/feed — personal news feed (posts from followed users). */
  async getFeed(options?: PaginationOptions & { before?: number }): Promise<FeedResponse> {
    if (!this.signer) throw new Error('Signer required');
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    let path = `/api/v1/feed?page=${page}&limit=${limit}`;
    if (options?.before !== undefined) path += `&before=${options.before}`;
    return this.getAuthenticated(path);
  }

  /** POST /api/v1/channels — create a new channel.
   *  Requires an on-chain SC call first to get the channel_id. */
  async createChannel(data: ChannelCreateData): Promise<ChannelCreateResponse> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChannelCreate(this.signer, data);
    return this.postEnvelope('/api/v1/channels', envelope);
  }

  /** POST /api/v1/messages — update channel info (owner/moderator with can_edit_info). */
  async updateChannel(data: ChannelUpdateData): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChannelUpdate(this.signer, data);
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — join a channel. */
  async joinChannel(channelId: number): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChannelJoin(this.signer, channelId);
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — leave a channel. */
  async leaveChannel(channelId: number): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChannelLeave(this.signer, channelId);
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — mute a user in a channel (moderator action). */
  async muteUser(data: ChannelMuteData): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChannelMute(this.signer, data);
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** DELETE /api/v1/channels/:channelId — delete a channel (creator only). */
  async deleteChannel(channelId: number): Promise<{ ok: boolean }> {
    if (!this.signer) throw new Error('Signer required');
    return this.deleteAuthenticated(`/api/v1/channels/${channelId}`);
  }

  /** POST /api/v1/media/upload — upload media to IPFS via the node. */
  async uploadMedia(file: Blob, filename?: string): Promise<UploadResult> {
    if (!this.signer) throw new Error('Signer required');

    const formData = new FormData();
    formData.append('file', file, filename);

    const headers = await this.signer.signRequest('POST', '/api/v1/media/upload');
    const url = `${this.nodeUrl}/api/v1/media/upload`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { ...headers }, // no content-type — FormData sets it with boundary
        body: formData,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** PUT /api/v1/profile — update the authenticated user's profile. */
  async updateProfile(data: ProfileUpdateData): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildProfileUpdate(this.signer, data);
    await this.putEnvelope('/api/v1/profile', envelope);
  }

  /** GET /api/v1/dm/conversations — list DM conversations. */
  async getDmConversations(options?: PaginationOptions): Promise<DmConversationsResponse> {
    if (!this.signer) throw new Error('Signer required');
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    return this.getAuthenticated(`/api/v1/dm/conversations?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/dm/:address/messages — retrieve DM messages with a user. */
  async getDmMessages(address: string, limit = 50, before?: string, after?: string): Promise<DmMessagesResponse> {
    if (!this.signer) throw new Error('Signer required');
    let path = `/api/v1/dm/${encodeURIComponent(address)}/messages?limit=${limit}`;
    if (after) path += `&after=${encodeURIComponent(after)}`;
    else if (before) path += `&before=${encodeURIComponent(before)}`;
    return this.getAuthenticated(path);
  }

  /** POST /api/v1/dm/:address/read — mark DM conversation as read. */
  async markDmRead(address: string): Promise<{ ok: boolean }> {
    if (!this.signer) throw new Error('Signer required');
    return this.postJson(`/api/v1/dm/${encodeURIComponent(address)}/read`, {});
  }

  /** GET /api/v1/dm/unread — get unread counts per DM conversation. */
  async getDmUnread(): Promise<{ unread: Record<string, number> }> {
    if (!this.signer) throw new Error('Signer required');
    return this.getAuthenticated('/api/v1/dm/unread');
  }

  /** GET /api/v1/notifications — fetch notifications for the authenticated user. */
  async getNotifications(since?: number, limit = 50): Promise<NotificationsResponse> {
    if (!this.signer) throw new Error('Signer required');
    let path = `/api/v1/notifications?limit=${limit}`;
    if (since !== undefined) path += `&since=${since}`;
    return this.getAuthenticated(path);
  }

  /** POST /api/v1/messages — post a news article (signed envelope). */
  async postNews(
    title: string,
    content: string,
    options?: { tags?: string[]; attachments?: Attachment[] },
  ): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required');
    const data: NewsPostData = {
      title,
      content,
      tags: options?.tags,
      attachments: options?.attachments,
    };
    const envelope = await buildNewsPost(this.signer, data);
    return this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — post a comment on a news article (signed envelope). */
  async postComment(
    postId: string,
    content: string,
    options?: { replyTo?: string; mentions?: string[]; attachments?: Attachment[] },
  ): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required');
    const data: NewsCommentData = {
      postId,
      content,
      replyTo: options?.replyTo,
      mentions: options?.mentions,
      attachments: options?.attachments,
    };
    const envelope = await buildNewsComment(this.signer, data);
    return this.postEnvelope('/api/v1/messages', envelope);
  }

  /** GET /api/v1/account/export — export all user data. */
  async exportAccount(): Promise<AccountExportResponse> {
    if (!this.signer) throw new Error('Signer required');
    return this.getAuthenticated('/api/v1/account/export');
  }

  // --- News Engagement (authenticated) ---

  /** POST /api/v1/news/:msgId/react — react to a news post. */
  async reactToNews(msgId: string, emoji: string, remove = false): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildReaction(this.signer, { target_id: msgId, emoji, remove });
    await this.postEnvelope(`/api/v1/news/${encodeURIComponent(msgId)}/react`, envelope);
  }

  /** POST /api/v1/news/:msgId/repost — repost a news post. */
  async repostNews(msgId: string, originalAuthor: string, comment?: string): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildRepost(this.signer, { original_id: msgId, original_author: originalAuthor, comment });
    return this.postEnvelope(`/api/v1/news/${encodeURIComponent(msgId)}/repost`, envelope);
  }

  // --- Bookmarks (authenticated) ---

  /** GET /api/v1/bookmarks — list saved posts. */
  async listBookmarks(options?: PaginationOptions): Promise<BookmarksResponse> {
    if (!this.signer) throw new Error('Signer required');
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    return this.getAuthenticated(`/api/v1/bookmarks?page=${page}&limit=${limit}`);
  }

  /** POST /api/v1/bookmarks/:msgId — save a post (no envelope needed). */
  async saveBookmark(msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const path = `/api/v1/bookmarks/${encodeURIComponent(msgId)}`;
    const headers = await this.signer.signRequest('POST', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { ...headers },
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** DELETE /api/v1/bookmarks/:msgId — unsave a post. */
  async removeBookmark(msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('DELETE', `/api/v1/bookmarks/${encodeURIComponent(msgId)}`);
    const url = `${this.nodeUrl}/api/v1/bookmarks/${encodeURIComponent(msgId)}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const resp = await fetch(url, {
        method: 'DELETE',
        headers: { ...headers },
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // --- Channel Administration (authenticated) ---

  /** POST /api/v1/channels/:channelId/moderators — add moderator. */
  async addModerator(channelId: number, targetUser: string, permissions: ModeratorPermissions): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildAddModerator(this.signer, { channelId, targetUser, permissions });
    await this.postEnvelope(`/api/v1/channels/${channelId}/moderators`, envelope);
  }

  /** DELETE /api/v1/channels/:channelId/moderators/:address — remove moderator. */
  async removeModerator(channelId: number, address: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildRemoveModerator(this.signer, channelId, address);
    await this.deleteEnvelope(`/api/v1/channels/${channelId}/moderators/${encodeURIComponent(address)}`, envelope);
  }

  /** POST /api/v1/channels/:channelId/kick/:address — kick user. */
  async kickUser(channelId: number, address: string, reason?: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildKick(this.signer, channelId, address, reason);
    await this.postEnvelope(`/api/v1/channels/${channelId}/kick/${encodeURIComponent(address)}`, envelope);
  }

  /** POST /api/v1/channels/:channelId/ban/:address — ban user. */
  async banUser(channelId: number, address: string, reason?: string, durationSecs?: number): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildBan(this.signer, channelId, address, reason, durationSecs);
    await this.postEnvelope(`/api/v1/channels/${channelId}/ban/${encodeURIComponent(address)}`, envelope);
  }

  /** DELETE /api/v1/channels/:channelId/ban/:address — unban user. */
  async unbanUser(channelId: number, address: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildUnban(this.signer, channelId, address);
    await this.deleteEnvelope(`/api/v1/channels/${channelId}/ban/${encodeURIComponent(address)}`, envelope);
  }

  /** POST /api/v1/channels/:channelId/pin/:msgId — pin message. */
  async pinMessage(channelId: number, msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildPin(this.signer, channelId, msgId);
    await this.postEnvelope(`/api/v1/channels/${channelId}/pin/${encodeURIComponent(msgId)}`, envelope);
  }

  /** DELETE /api/v1/channels/:channelId/pin/:msgId — unpin message. */
  async unpinMessage(channelId: number, msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildUnpin(this.signer, channelId, msgId);
    await this.deleteEnvelope(`/api/v1/channels/${channelId}/pin/${encodeURIComponent(msgId)}`, envelope);
  }

  /** POST /api/v1/channels/:channelId/invite/:address — invite user to private channel. */
  async inviteUser(channelId: number, address: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildInvite(this.signer, channelId, address);
    await this.postEnvelope(`/api/v1/channels/${channelId}/invite/${encodeURIComponent(address)}`, envelope);
  }

  // --- v0.11.0 Message Actions ---

  /** POST /api/v1/messages — edit a chat message (own, within 30 min). */
  async editMessage(channelId: number, msgId: string, content: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChatEdit(this.signer, { channelId, msgId, content });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — delete a chat message (own). */
  async deleteMessage(channelId: number, msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChatDelete(this.signer, { channelId, msgId });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — react to a chat message. */
  async reactToMessage(channelId: number, msgId: string, emoji: string, remove = false): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildChatReaction(this.signer, { channelId, msgId, emoji, remove });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — edit a DM (own). */
  async editDm(recipient: string, msgId: string, content: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildDmEdit(this.signer, { recipient, msgId, content });
    await this.postEnvelope(`/api/v1/dm/${encodeURIComponent(recipient)}`, envelope);
  }

  /** POST /api/v1/messages — delete a DM (own). */
  async deleteDm(recipient: string, msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildDmDelete(this.signer, { recipient, msgId });
    await this.postEnvelope(`/api/v1/dm/${encodeURIComponent(recipient)}`, envelope);
  }

  /** POST /api/v1/messages — react to a DM. */
  async reactToDm(recipient: string, msgId: string, emoji: string, remove = false): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildDmReaction(this.signer, { recipient, msgId, emoji, remove });
    await this.postEnvelope(`/api/v1/dm/${encodeURIComponent(recipient)}`, envelope);
  }

  /** POST /api/v1/messages — edit a news post (own, within 30 min, registered). */
  async editNews(msgId: string, content: string, options?: { title?: string; tags?: string[] }): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildNewsEdit(this.signer, {
      msgId,
      content,
      title: options?.title,
      tags: options?.tags,
    });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — delete a news post (own). */
  async deleteNews(msgId: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildNewsDelete(this.signer, { msgId });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — sync encrypted settings to L2 node. */
  async syncSettings(data: SettingsSyncData): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildSettingsSync(this.signer, data);
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** GET /api/v1/settings — retrieve synced settings. */
  async getSettings(): Promise<SettingsSyncResponse | null> {
    if (!this.signer) throw new Error('Signer required');
    try {
      return await this.getAuthenticated<SettingsSyncResponse>('/api/v1/settings');
    } catch {
      return null;
    }
  }

  /** POST /api/v1/messages — report content for moderation. */
  async reportMessage(targetId: string, details: string, category: ReportData['category']): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildReport(this.signer, { targetId, details, category });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  /** POST /api/v1/messages — counter-vote against a moderation report. */
  async counterVote(reportId: string, reason?: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildCounterVote(this.signer, { reportId, reason });
    await this.postEnvelope('/api/v1/messages', envelope);
  }

  // --- Device Identity Management ---

  /**
   * Register a device key under a wallet.
   *
   * Submits a wallet-signed claim that binds the device key to the wallet.
   * The claim must be signed by the wallet (via extension or K5).
   *
   * @param walletSignatureHex - Hex-encoded wallet signature over the claim string
   * @param walletAddress - The wallet's klv1... address
   * @param timestamp - The timestamp used in the claim string
   */
  async registerDevice(
    walletSignatureHex: string,
    walletAddress: string,
    timestamp: number,
  ): Promise<RegisterDeviceResponse> {
    if (!this.signer) throw new Error('Signer required');
    const result = await this.postJson<RegisterDeviceResponse>('/api/v1/devices/register', {
      device_pubkey_hex: this.signer.publicKeyHex,
      wallet_address: walletAddress,
      wallet_signature: walletSignatureHex,
      timestamp,
    } satisfies RegisterDeviceRequest);
    // Auto-set walletAddress on the signer after successful registration
    if (result.ok) {
      this.signer.walletAddress = walletAddress;
    }
    return result;
  }

  /** Revoke a device registration. Only the owning wallet can revoke. */
  async revokeDevice(deviceAddress: string): Promise<RevokeDeviceResponse> {
    return this.deleteAuthenticated<RevokeDeviceResponse>(
      `/api/v1/devices/${encodeURIComponent(deviceAddress)}`,
    );
  }

  /** List all devices registered to the authenticated wallet. */
  async listDevices(): Promise<ListDevicesResponse> {
    return this.getAuthenticated<ListDevicesResponse>('/api/v1/devices');
  }

  /** Discover nodes from the current home node for failover. */
  async discoverNodes(): Promise<void> {
    const resp = await this.listNodes();
    this.knownNodes = resp.nodes
      .map((n) => n.api_endpoint)
      .filter((url): url is string => !!url && url.length > 0);
  }

  // --- Internal helpers ---

  private async getAuthenticated<T>(path: string): Promise<T> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('GET', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, { headers: { ...headers }, signal: controller.signal });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async get<T>(path: string): Promise<T> {
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // Send auth headers when available (for optional-auth endpoints like channels list)
      const headers = this.signer
        ? { ...await this.signer.signRequest('GET', path) }
        : {} as Record<string, string>;
      const resp = await fetch(url, { headers, signal: controller.signal });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** POST with envelope bytes (MessagePack binary body). */
  private async postEnvelope<T>(path: string, envelopeBytes: Uint8Array): Promise<T> {
    if (!this.signer) throw new Error('Signer required');

    const headers = await this.signer.signRequest('POST', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          ...headers,
          'content-type': 'application/octet-stream',
        },
        body: envelopeBytes.buffer.slice(envelopeBytes.byteOffset, envelopeBytes.byteOffset + envelopeBytes.byteLength) as ArrayBuffer,
        signal: controller.signal,
      });

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const body = await resp.json().catch(() => null);
        if (body?.error === 'pow_required' && body?.challenge) {
          await this.solvePow(body.challenge as PowChallenge);
          // Retry the original request with fresh auth headers
          return this.postEnvelope(path, envelopeBytes);
        }
      }

      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** PUT with envelope bytes (MessagePack binary body). */
  private async putEnvelope(path: string, envelopeBytes: Uint8Array): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('PUT', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'PUT',
        headers: { ...headers, 'content-type': 'application/octet-stream' },
        body: envelopeBytes.buffer.slice(envelopeBytes.byteOffset, envelopeBytes.byteOffset + envelopeBytes.byteLength) as ArrayBuffer,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** DELETE with envelope bytes (MessagePack binary body). */
  private async deleteEnvelope(path: string, envelopeBytes: Uint8Array): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('DELETE', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'DELETE',
        headers: { ...headers, 'content-type': 'application/octet-stream' },
        body: envelopeBytes.buffer.slice(envelopeBytes.byteOffset, envelopeBytes.byteOffset + envelopeBytes.byteLength) as ArrayBuffer,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** POST with JSON body (for non-envelope endpoints like device registration). */
  private async postJson<T>(path: string, body: Record<string, unknown>): Promise<T> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('POST', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { ...headers, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const respBody = await resp.json().catch(() => null);
        if (respBody?.error === 'pow_required' && respBody?.challenge) {
          await this.solvePow(respBody.challenge as PowChallenge);
          return this.postJson(path, body);
        }
      }

      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** DELETE with auth headers (no body). */
  private async deleteAuthenticated<T>(path: string): Promise<T> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('DELETE', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'DELETE',
        headers: { ...headers },
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Solve a PoW challenge and submit the solution to the node.
   *
   * Called automatically when a 429 pow_required response is received.
   * After successful verification, sets `powVerified = true` so subsequent
   * requests don't trigger PoW again.
   */
  private async solvePow(challenge: PowChallenge): Promise<void> {
    if (!this.signer) throw new Error('Signer required');

    this.onPowStart?.();

    const result = await solveChallengeAsync(challenge, this.onPowProgress);

    this.onPowComplete?.(result.elapsed_ms);

    // Submit solution to node
    const solution = {
      challenge_id: challenge.challenge_id,
      address: this.signer.signingAddress,
      nonce: result.nonce,
    };

    const url = `${this.nodeUrl}/api/v1/pow/verify`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(solution),
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      throw new Error(`PoW verification failed (${resp.status}): ${text.slice(0, 200)}`);
    }

    const body = await resp.json();
    if (!body.ok) {
      throw new Error(`PoW verification rejected: ${body.error ?? 'unknown'}`);
    }

    this.powVerified = true;
  }
}
