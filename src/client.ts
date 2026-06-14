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

import type { WalletSigner, AuthHeaders, NodeBinding } from './auth';
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
  UserSearchResponse,
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
  EncKeysResponse,
  KeyEnvelopeResponse,
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
  NetworkIdentity,
  PresenceRecord,
  PresenceResponse,
  KnownNode,
} from './types';

/**
 * Spec 5 §1.1 trust score derivation (locked in spec 13 §10.8 /
 * planning doc §4.2). Returns an integer in [0, 100].
 *
 * Contributions:
 *  - +50 if `attestation` includes "on-chain" (i.e., `on-chain` or `both`)
 *  - +30 if the node anchored within the last 7 days (`anchoring === true`)
 *  - +10 if `attestation === "both"` (cross-source consistency bonus)
 *  - +10 if `reachable_probe_at` is set and within the last 24 hours
 *
 * The function is pure and exported separately so callers can
 * re-score nodes after an external reachability probe lands
 * without re-fetching the whole list.
 */
export function computeTrustScore(node: KnownNode): number {
  let s = 0;
  if (node.attestation === 'on-chain' || node.attestation === 'both') s += 50;
  if (node.anchoring) s += 30;
  if (node.attestation === 'both') s += 10;
  if (
    typeof node.reachable_probe_at === 'number' &&
    Date.now() - node.reachable_probe_at < 86_400_000
  ) {
    s += 10;
  }
  return Math.min(100, s);
}

/** Ogmara SDK client for the L2 node REST API. */
export class OgmaraClient {
  private nodeUrl: string;
  private timeout: number;
  private signer?: WalletSigner;
  private knownNodes: string[] = [];

  /**
   * Cached node identity (network + node_id) the auth signatures bind to
   * (audit 2026-06-07 host-binding). Fetched lazily from `/api/v1/health`
   * the first time an authenticated request is signed, then reused.
   */
  private nodeBinding?: NodeBinding;

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

  /** GET /api/v1/channels/by-slug/:slug — resolve a channel by slug.
   *  Returns the channel metadata (incl. `channel_id`), or null if the node
   *  doesn't know it yet (404). Lets the web learn a freshly-created channel's
   *  SC-assigned id by polling the node — no direct Klever RPC call (CORS). */
  async getChannelBySlug(slug: string): Promise<{ channel_id: number } & Record<string, unknown> | null> {
    try {
      return await this.get(`/api/v1/channels/by-slug/${encodeURIComponent(slug)}`);
    } catch (e: any) {
      if (typeof e?.message === 'string' && e.message.includes('404')) return null;
      throw e;
    }
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

  /**
   * GET /api/v1/channels/unread — get unread counts per channel.
   *
   * `unread[channelId]` is the count of unread messages (excluding own).
   * `mentions[channelId]` is the subset of those that @-mention the viewer
   * (resolved through device delegation). The `mentions` field is optional —
   * older nodes that don't set it return `undefined`, in which case clients
   * should treat it as "no mention info available" rather than zero.
   */
  async getUnreadCounts(): Promise<{
    unread: Record<string, number>;
    mentions?: Record<string, number>;
  }> {
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

  /**
   * GET /api/v1/network/identity (l2-node 0.48.0+, spec 03 §4.1).
   *
   * Lightweight self-description used by the Reachable probe in consumer
   * UIs (spec 13 §10.9). Optionally targets a different node via
   * `url` — useful when verifying that a presence-gossip claim's
   * `public_url` actually resolves to the claimed PeerId. Without
   * `url`, queries the configured home node.
   */
  async getNetworkIdentity(url?: string): Promise<NetworkIdentity> {
    if (url) {
      const stripped = url.replace(/\/+$/, '');
      return this.getAbsolute<NetworkIdentity>(`${stripped}/api/v1/network/identity`);
    }
    return this.get<NetworkIdentity>('/api/v1/network/identity');
  }

  /**
   * GET /api/v1/network/presence (l2-node 0.48.0+, spec 13 §10.6).
   *
   * Returns the home node's cached presence-gossip records. Each row
   * is enriched server-side with `verified_on_chain` / `anchored` /
   * `last_anchor_at`. Returns an empty `records` array when the node
   * has presence disabled.
   */
  async getPresenceRecords(): Promise<PresenceResponse> {
    return this.get<PresenceResponse>('/api/v1/network/presence');
  }

  /**
   * GET /api/v1/network/presence/:peer_id (l2-node 0.48.0+).
   *
   * Returns the single cached record for `peerId`, or `null` if the
   * node hasn't cached one (TTL-evicted, never received, or presence
   * disabled).
   */
  async getPresenceRecord(peerId: string): Promise<PresenceRecord | null> {
    try {
      return await this.get<PresenceRecord>(
        `/api/v1/network/presence/${encodeURIComponent(peerId)}`,
      );
    } catch (e) {
      if (e instanceof Error && /\b404\b/.test(e.message)) return null;
      throw e;
    }
  }

  /**
   * Spec 5 §1.1 — merged client-side view of all known nodes.
   *
   * Joins the SC-derived `/network/nodes` response with the off-chain
   * `/network/presence` cache by libp2p PeerId. Each result carries:
   *  - `attestation`     — `on-chain` / `gossip` / `both` (spec 13 §10.8).
   *  - `anchoring`       — true if the node anchored within the last 7 days.
   *  - `trust_score`     — 0..100, computed via {@link computeTrustScore}.
   *
   * Results are sorted by `trust_score` desc as a sensible default for
   * failover selection. Apps building their own UI may resort by
   * latency, version, or any other field.
   *
   * @param probeCache Optional map of `peerId -> unix ms of last
   *   successful reachability probe`. Apps that maintain their own
   *   probe state pass it here so the +10 reachability contribution
   *   lands in `trust_score`. Without it, scores top out at 90.
   */
  async getKnownNodes(
    probeCache?: Record<string, number>,
  ): Promise<KnownNode[]> {
    const scResp = await this.listNodes(1, 256).catch(() => ({
      nodes: [] as NodeInfo[],
      total: 0,
    }));
    const presenceResp = await this.getPresenceRecords().catch<PresenceResponse>(() => ({
      self_peer_id: '',
      broadcasting: false,
      cache_size: 0,
      cache_cap: 4096,
      records: [],
    }));

    const merged = new Map<string, KnownNode>();

    // Seed with SC view first — SC is the trust root, so its URL wins
    // on conflict (matches the website's spec 9 §3.2.2 merge rule).
    for (const n of scResp.nodes) {
      if (!n.node_id) continue;
      const anchoring =
        n.anchor_status?.level === 'active' ||
        n.anchor_status?.level === 'verified';
      const age = n.anchor_status?.last_anchor_age_seconds;
      merged.set(n.node_id, {
        peer_id: n.node_id,
        url: n.api_endpoint ?? null,
        attestation: 'on-chain',
        anchoring,
        anchor_age_seconds: typeof age === 'number' ? age : undefined,
        reachable_probe_at: probeCache?.[n.node_id],
        trust_score: 0, // computed below
      });
    }

    // Layer presence records on top.
    for (const rec of presenceResp.records) {
      if (!rec.peer_id) continue;
      const existing = merged.get(rec.peer_id);
      if (existing) {
        existing.attestation = 'both';
        existing.presence_timestamp_ms = rec.timestamp * 1000;
        // SC URL wins on conflict, but if SC had no URL, fall back to
        // the presence URL so callers see something.
        if (!existing.url && rec.public_url) existing.url = rec.public_url;
      } else {
        merged.set(rec.peer_id, {
          peer_id: rec.peer_id,
          url: rec.public_url,
          attestation: 'gossip',
          anchoring: rec.anchored,
          anchor_age_seconds:
            rec.last_anchor_at != null
              ? Math.max(0, Math.floor(Date.now() / 1000) - rec.last_anchor_at)
              : undefined,
          presence_timestamp_ms: rec.timestamp * 1000,
          reachable_probe_at: probeCache?.[rec.peer_id],
          trust_score: 0,
        });
      }
    }

    // Compute scores and sort desc.
    const out: KnownNode[] = [];
    for (const node of merged.values()) {
      node.trust_score = computeTrustScore(node);
      out.push(node);
    }
    out.sort((a, b) => b.trust_score - a.trust_score);
    return out;
  }

  /** GET /api/v1/news/:msgId — single news post with comments. */
  async getNewsPost(msgId: string): Promise<NewsPostResponse> {
    return this.get(`/api/v1/news/${encodeURIComponent(msgId)}`);
  }

  /** GET /api/v1/users/:address — full user profile with counts. */
  async getUserProfile(address: string): Promise<UserProfileResponse> {
    return this.get(`/api/v1/users/${encodeURIComponent(address)}`);
  }

  /**
   * GET /api/v1/users/search — `@`-mention autocomplete.
   *
   * Case-insensitive prefix search on `display_name`. When `q` looks like
   * a `klv1...` prefix the L2 node also matches addresses, so users can
   * complete `@klv1abc` even if no display name is set.
   *
   * `limit` is clamped server-side to 1..=50 (default 20). `q` is required
   * and capped at 64 chars after trim — empty/whitespace returns 400.
   *
   * No authentication required (display names are public profile data).
   * Pairs with `l2-node` v0.32.0+; older nodes return 404.
   */
  async searchUsers(q: string, limit = 20): Promise<UserSearchResponse> {
    const params = new URLSearchParams({ q, limit: String(limit) });
    return this.get(`/api/v1/users/search?${params.toString()}`);
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

  /**
   * POST /api/v1/messages — send a pre-built message envelope (e.g. an encrypted
   * private-channel ChatMessage from `buildEncryptedChannelMessage`). The caller
   * is responsible for constructing + signing the envelope.
   */
  async sendMessageEnvelope(envelope: Uint8Array): Promise<{ msg_id: string }> {
    if (!this.signer) throw new Error('Signer required for authenticated endpoints');
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

  /**
   * POST /api/v1/channels/:id/federate — replicate a PRIVATE channel hosted on
   * another node to THIS (the caller's home) node. The node fetches the channel
   * record from `hostUrl`, records the caller's membership, and subscribes to the
   * channel's gossip topic, so the channel's encrypted messages + keys flow here
   * live without the member switching nodes. `hostUrl` comes from the invite link.
   * Authenticated.
   */
  async federateChannel(channelId: number, hostUrl: string): Promise<{ federated: boolean; channel_id: number }> {
    if (!this.signer) throw new Error('Signer required');
    return this.postJson(
      `/api/v1/channels/${channelId}/federate`,
      { host_url: hostUrl },
    );
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

    const headers = await this.authHeaders('POST', '/api/v1/media/upload');
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
    const headers = await this.authHeaders('POST', path);
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
    const headers = await this.authHeaders('DELETE', `/api/v1/bookmarks/${encodeURIComponent(msgId)}`);
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

  /**
   * POST /api/v1/channels/:channelId/moderators — add moderator.
   *
   * `permissions` defaults to the standard full moderator set when omitted
   * (audit 2026-06-07 B4.1 — the "promote to moderator" UI has no per-permission
   * picker); pass an explicit set to grant a narrower role.
   */
  async addModerator(
    channelId: number,
    targetUser: string,
    permissions?: ModeratorPermissions,
  ): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const perms: ModeratorPermissions = permissions ?? {
      can_mute: true,
      can_kick: true,
      can_ban: true,
      can_pin: true,
      can_edit_info: true,
      can_delete_msgs: true,
    };
    const envelope = await buildAddModerator(this.signer, { channelId, targetUser, permissions: perms });
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

  /**
   * POST /api/v1/messages — edit a DM (own).
   * @deprecated Sends plaintext content, which l2-node 0.70.0+ rejects. Build an
   * encrypted edit with `buildEncryptedDmEdit` (needs the conv_key) and POST it
   * via `sendDm`, as the web/desktop clients do.
   */
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

  /**
   * POST /api/v1/messages — edit a news post (own, within 30 min, registered).
   *
   * `attachments` MUST be supplied with the full list the post should
   * keep after the edit — the server overwrites the stored payload with
   * the edit envelope, so omitting it drops every attachment.
   */
  async editNews(
    msgId: string,
    content: string,
    options?: { title?: string; tags?: string[]; attachments?: Attachment[] },
  ): Promise<void> {
    if (!this.signer) throw new Error('Signer required');
    const envelope = await buildNewsEdit(this.signer, {
      msgId,
      content,
      title: options?.title,
      tags: options?.tags,
      attachments: options?.attachments,
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
   * The device key automatically co-signs the SAME claim string as a
   * **proof-of-possession** (P-0 dual-signed delegation, node 0.49.0+). With
   * both signatures the node can gossip a delegation that every peer verifies
   * itself (the wallet authorizes the binding; the device proves it holds the
   * key), so the device→wallet mapping reaches all nodes for **free** — no
   * on-chain transaction — and is unforgeable: impersonating a wallet needs
   * the wallet key, hijacking a device needs the device key.
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

    // Reconstruct the EXACT canonical claim the wallet signed (lowercase
    // device pubkey — see buildDeviceClaim) and co-sign it with the device key.
    const devicePubkeyHex = this.signer.publicKeyHex.toLowerCase();
    const claimString = `ogmara-device-claim:${devicePubkeyHex}:${walletAddress}:${timestamp}`;
    const deviceSigBytes = await this.signer.signKleverMessage(
      new TextEncoder().encode(claimString),
    );
    const deviceSignatureHex = Array.from(deviceSigBytes, (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('');

    const result = await this.postJson<RegisterDeviceResponse>('/api/v1/devices/register', {
      device_pubkey_hex: this.signer.publicKeyHex,
      wallet_address: walletAddress,
      wallet_signature: walletSignatureHex,
      timestamp,
      device_signature: deviceSignatureHex,
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

  /**
   * Fetch a wallet's active device encryption keys (E2E P0, protocol §2.4).
   * Public X25519 key material — used by a sender to wrap message keys to each
   * of a recipient's devices.
   */
  async getEncKeys(address: string): Promise<EncKeysResponse> {
    return this.getAuthenticated<EncKeysResponse>(
      `/api/v1/users/${encodeURIComponent(address)}/enc-keys`,
    );
  }

  /**
   * Publish a wallet-authored `DeviceEncBinding`/`DeviceEncRevoke` envelope
   * (build it with `buildDeviceEncBinding` / `buildDeviceEncRevoke`). The
   * envelope's wallet signature is the authority; the HTTP request is
   * device-authenticated like any other.
   */
  async publishEncKeyEnvelope(walletAddress: string, envelopeBytes: Uint8Array): Promise<unknown> {
    return this.postEnvelope(
      `/api/v1/users/${encodeURIComponent(walletAddress)}/enc-keys`,
      envelopeBytes,
    );
  }

  /**
   * Publish a signed `ChannelKeyEnvelope` (0x61) — a per-device wrapped epoch key
   * for a DM or channel (build it with `buildChannelKeyEnvelope`). Routed through
   * the generic message-ingestion path.
   */
  async publishKeyEnvelope(envelopeBytes: Uint8Array): Promise<unknown> {
    return this.postEnvelope('/api/v1/messages', envelopeBytes);
  }

  /**
   * Fetch THIS wallet's per-device wrapped key envelope for a `keyScope` (a DM
   * `conversation_id` hex, or a channel scope). Returns the latest epoch unless one
   * is given. `deviceId` is the caller's device id (hex). The node only ever serves
   * envelopes wrapped for the authenticated wallet, and the blob is ECIES-sealed to
   * a device enc key the caller must hold to unwrap.
   */
  async getKeyEnvelope(
    keyScopeHex: string,
    deviceId: string,
    author?: string,
    epoch?: number,
  ): Promise<KeyEnvelopeResponse> {
    const params = new URLSearchParams({ device_id: deviceId });
    if (author !== undefined) params.set('author', author);
    if (epoch !== undefined) params.set('epoch', String(epoch));
    return this.getAuthenticated<KeyEnvelopeResponse>(
      `/api/v1/keys/${encodeURIComponent(keyScopeHex)}?${params.toString()}`,
    );
  }

  /** Discover nodes from the current home node for failover. */
  async discoverNodes(): Promise<void> {
    const resp = await this.listNodes();
    this.knownNodes = resp.nodes
      .map((n) => n.api_endpoint)
      .filter((url): url is string => !!url && url.length > 0);
  }

  // --- Internal helpers ---

  /**
   * Resolve (and cache) the node identity that auth signatures bind to.
   * Fetched unauthenticated from `/api/v1/health` — it must NOT route
   * through the auth path, which itself depends on this binding.
   */
  private async getNodeBinding(): Promise<NodeBinding> {
    if (this.nodeBinding) return this.nodeBinding;
    const health = await this.getAbsolute<Health>(`${this.nodeUrl}/api/v1/health`);
    if (!health.node_id || !health.network) {
      throw new Error(
        'node /health did not return node_id/network — node too old for host-bound auth',
      );
    }
    this.nodeBinding = { network: health.network, nodeId: health.node_id };
    return this.nodeBinding;
  }

  /**
   * Sign auth headers for `method path`, binding to this node's identity
   * (audit 2026-06-07 host-binding). Public so callers that must issue the
   * request themselves — e.g. a Tauri/native fetch for large bodies, or a
   * multipart upload — can obtain correctly host-bound, nonce'd headers
   * without reaching into the signer. The `path` should be the request path
   * (query string is stripped before signing, matching the node verifier).
   */
  async authHeaders(method: string, path: string): Promise<AuthHeaders> {
    if (!this.signer) throw new Error('Signer required');
    const binding = await this.getNodeBinding();
    return this.signer.signRequest(method, path, binding);
  }

  private async getAuthenticated<T>(path: string): Promise<T> {
    if (!this.signer) throw new Error('Signer required');
    const headers = await this.authHeaders('GET', path);
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, { headers: { ...headers }, signal: controller.signal });

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const body = await resp.json().catch(() => null);
        if (body?.error === 'pow_required' && body?.challenge) {
          await this.solvePow(body.challenge as PowChallenge, body.address);
          return this.getAuthenticated(path);
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

  private async get<T>(path: string): Promise<T> {
    const url = `${this.nodeUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // Send auth headers when available (for optional-auth endpoints like
      // channels list). This is best-effort: if the node binding can't be
      // fetched (e.g. an old node without node_id in /health), proceed
      // unauthenticated rather than failing the public read.
      let headers: Record<string, string> = {};
      if (this.signer) {
        try {
          headers = { ...await this.authHeaders('GET', path) };
        } catch {
          headers = {};
        }
      }
      const resp = await fetch(url, { headers, signal: controller.signal });

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const body = await resp.json().catch(() => null);
        if (body?.error === 'pow_required' && body?.challenge) {
          await this.solvePow(body.challenge as PowChallenge, body.address);
          return this.get(path);
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

  /**
   * Like `get`, but takes a fully-qualified URL instead of a path so
   * the caller can target a node other than `this.nodeUrl`. Used by
   * `getNetworkIdentity(url?)` for the consumer-side reachability
   * probe in spec 13 §10.9.
   *
   * No auth headers, no PoW retry — probes are public read-only and
   * shouldn't burn the caller's PoW budget on a target node.
   */
  private async getAbsolute<T>(url: string): Promise<T> {
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

    const headers = await this.authHeaders('POST', path);
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
          await this.solvePow(body.challenge as PowChallenge, body.address);
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
    const headers = await this.authHeaders('PUT', path);
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

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const body = await resp.json().catch(() => null);
        if (body?.error === 'pow_required' && body?.challenge) {
          await this.solvePow(body.challenge as PowChallenge, body.address);
          return this.putEnvelope(path, envelopeBytes);
        }
      }

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
    const headers = await this.authHeaders('DELETE', path);
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

      // Handle PoW challenge: auto-solve and retry once
      if (resp.status === 429 && !this.powVerified) {
        const body = await resp.json().catch(() => null);
        if (body?.error === 'pow_required' && body?.challenge) {
          await this.solvePow(body.challenge as PowChallenge, body.address);
          return this.deleteEnvelope(path, envelopeBytes);
        }
      }

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
    const headers = await this.authHeaders('POST', path);
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
          await this.solvePow(respBody.challenge as PowChallenge, respBody.address);
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
    const headers = await this.authHeaders('DELETE', path);
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
  private async solvePow(challenge: PowChallenge, resolvedAddress?: string): Promise<void> {
    if (!this.signer) throw new Error('Signer required');

    this.onPowStart?.();

    const result = await solveChallengeAsync(challenge, this.onPowProgress);

    this.onPowComplete?.(result.elapsed_ms);

    // Use the address from the server's 429 response if provided — it's the
    // exact resolved_author the node used when issuing the challenge. This
    // avoids mismatch when device registration hasn't completed yet (node
    // resolves to ogd1... but client would guess klv1...).
    const solution = {
      challenge_id: challenge.challenge_id,
      address: resolvedAddress || this.signer.walletAddress || this.signer.address,
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
