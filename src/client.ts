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
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  RevokeDeviceResponse,
  ListDevicesResponse,
} from './types';

/** Ogmara SDK client for the L2 node REST API. */
export class OgmaraClient {
  private nodeUrl: string;
  private timeout: number;
  private signer?: WalletSigner;
  private knownNodes: string[] = [];

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

  /** GET /api/v1/channels/:channelId/messages */
  async getChannelMessages(
    channelId: number,
    limit = 50,
    before?: string,
  ): Promise<MessagesResponse> {
    let path = `/api/v1/channels/${channelId}/messages?limit=${limit}`;
    if (before) path += `&before=${encodeURIComponent(before)}`;
    return this.get(path);
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
   *  Note: Channel creation requires an on-chain SC call first to get the channel_id.
   *  The envelope is built by the caller with the assigned channel_id. */
  async createChannel(envelopeBytes: Uint8Array): Promise<ChannelCreateResponse> {
    if (!this.signer) throw new Error('Signer required');
    return this.postEnvelope('/api/v1/channels', envelopeBytes);
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

    console.log('[SDK] uploadMedia:', url, 'file:', filename, 'size:', file.size);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { ...headers }, // no content-type — FormData sets it with boundary
        body: formData,
        signal: controller.signal,
      });
      console.log('[SDK] uploadMedia response:', resp.status, resp.statusText);
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        console.error('[SDK] uploadMedia error body:', text);
        throw new Error(`API error (${resp.status}): ${text.slice(0, 200)}`);
      }
      const result = await resp.json();
      console.log('[SDK] uploadMedia result:', result);
      return result;
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
  async getDmMessages(address: string, limit = 50, before?: string): Promise<DmMessagesResponse> {
    if (!this.signer) throw new Error('Signer required');
    let path = `/api/v1/dm/${encodeURIComponent(address)}/messages?limit=${limit}`;
    if (before) path += `&before=${encodeURIComponent(before)}`;
    return this.getAuthenticated(path);
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
      const resp = await fetch(url, { signal: controller.signal });
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
}
