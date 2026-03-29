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
import type {
  Health,
  NetworkStats,
  Channel,
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
  DmConversationsResponse,
  DmMessagesResponse,
  NotificationsResponse,
  ChannelCreateData,
  ChannelCreateResponse,
  UserProfileResponse,
  UserPostsResponse,
  AccountExportResponse,
  ModerationReportsResponse,
  ModerationUserResponse,
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

  // --- Authenticated endpoints ---

  /** POST /api/v1/messages — send a signed message envelope. */
  async sendMessage(channelId: number, content: string): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required for authenticated endpoints');
    // Build and sign the envelope
    const payload = JSON.stringify({
      channel_id: channelId,
      content,
      content_rating: 0,
      mentions: [],
      attachments: [],
    });
    return this.postAuthenticated('/api/v1/messages', payload);
  }

  /** POST /api/v1/dm/:address — send an encrypted DM. */
  async sendDm(recipient: string, encryptedPayload: string): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required for authenticated endpoints');
    return this.postAuthenticated(
      `/api/v1/dm/${encodeURIComponent(recipient)}`,
      encryptedPayload,
    );
  }

  /** POST /api/v1/users/:address/follow — follow a user. */
  async follow(target: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    await this.postAuthenticated(
      `/api/v1/users/${encodeURIComponent(target)}/follow`,
      JSON.stringify({ target }),
    );
  }

  /** DELETE /api/v1/users/:address/follow — unfollow a user. */
  async unfollow(target: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('DELETE', `/api/v1/users/${encodeURIComponent(target)}/follow`);
    const url = `${this.nodeUrl}/api/v1/users/${encodeURIComponent(target)}/follow`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const resp = await fetch(url, {
        method: 'DELETE',
        headers: { ...headers, 'content-type': 'application/octet-stream' },
        body: JSON.stringify({ target }),
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
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

  /** POST /api/v1/channels — create a new channel. */
  async createChannel(data: ChannelCreateData): Promise<ChannelCreateResponse> {
    if (!this.signer) throw new Error('Signer required');
    return this.postAuthenticated('/api/v1/channels', JSON.stringify(data));
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
        throw new Error(`API error (${resp.status}): ${text}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** PUT /api/v1/profile — update the authenticated user's profile. */
  async updateProfile(data: ProfileUpdateData): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    await this.putAuthenticated('/api/v1/profile', JSON.stringify(data));
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

  /** POST /api/v1/messages — post a news article. */
  async postNews(channelId: number, title: string, content: string, tags?: string[]): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required');
    const payload = JSON.stringify({
      channel_id: channelId,
      title,
      content,
      content_rating: 0,
      tags: tags ?? [],
      mentions: [],
      attachments: [],
    });
    return this.postAuthenticated('/api/v1/messages', payload);
  }

  /** GET /api/v1/account/export — export all user data. */
  async exportAccount(): Promise<AccountExportResponse> {
    if (!this.signer) throw new Error('Signer required');
    return this.getAuthenticated('/api/v1/account/export');
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
        throw new Error(`API error (${resp.status}): ${text}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async putAuthenticated(path: string, body: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.signer.signRequest('PUT', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method: 'PUT',
        headers: { ...headers, 'content-type': 'application/octet-stream' },
        body,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text}`);
      }
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
        throw new Error(`API error (${resp.status}): ${text}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async postAuthenticated<T>(path: string, body: string): Promise<T> {
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
        body,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`API error (${resp.status}): ${text}`);
      }
      return resp.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
