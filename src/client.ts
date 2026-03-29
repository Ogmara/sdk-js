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
  ChannelsResponse,
  MessagesResponse,
  NewsResponse,
  ClientConfig,
  NodeInfo,
  FollowerListResponse,
  FeedResponse,
  PaginationOptions,
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
  async listChannels(page = 1, limit = 20): Promise<ChannelsResponse> {
    return this.get(`/api/v1/channels?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/channels/:channelId */
  async getChannel(channelId: number): Promise<Record<string, unknown>> {
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

  /** GET /api/v1/users/:address */
  async getUser(address: string): Promise<Record<string, unknown>> {
    return this.get(`/api/v1/users/${encodeURIComponent(address)}`);
  }

  /** GET /api/v1/news */
  async listNews(page = 1, limit = 20): Promise<NewsResponse> {
    return this.get(`/api/v1/news?page=${page}&limit=${limit}`);
  }

  /** GET /api/v1/network/nodes */
  async listNodes(): Promise<{ nodes: NodeInfo[] }> {
    return this.get('/api/v1/network/nodes');
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
  async getFeed(options?: PaginationOptions): Promise<FeedResponse> {
    if (!this.signer) throw new Error('Signer required');
    const page = options?.page ?? 1;
    const limit = options?.limit ?? 20;
    const path = `/api/v1/feed?page=${page}&limit=${limit}`;
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

  /** Discover nodes from the current home node for failover. */
  async discoverNodes(): Promise<void> {
    const resp = await this.listNodes();
    this.knownNodes = resp.nodes
      .map((n) => n.api_endpoint)
      .filter((url): url is string => !!url && url.length > 0);
  }

  // --- Internal helpers ---

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
