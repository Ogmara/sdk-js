# Changelog

All notable changes to the Ogmara JS/TS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-03-30

### Added

- `AnchorStatus` interface — anchor verification level for network nodes
- `SelfAnchorStatus` interface — self-reported anchor status from `/network/stats`
- `anchor_status` field on `NodeInfo` and `NetworkStats` interfaces
- `anchorStatus` field on `NodeWithPing` — propagated from node discovery
- Failover sort now prefers verified/active anchoring nodes (same latency tier)

## [0.4.0] - 2026-03-30

### Added
- **Message Formatting & URL Detection**
  - `parseMessageContent()` — parses text into segments with URLs, bold, italic, underline, code, strikethrough
  - `applyFormatting()` — wraps selected text range with Markdown markers for compose inputs
  - `TextSegment` type for rendering parsed content
- **Node Discovery & Selection**
  - `pingNode()` — measure latency to any node URL
  - `discoverAndPingNodes()` — discover all nodes, ping in parallel, return sorted by latency
  - `NodeWithPing` type for node selection UI
  - `DEFAULT_NODE_URL` constant (`https://node.ogmara.org`)

## [0.3.0] - 2026-03-30

### Added
- 10 new MessageType entries: channel admin (0x14-0x1B) and news engagement (0x24-0x25)
- News engagement methods: reactToNews(), repostNews(), getNewsReactions(), getNewsReposts()
- Bookmark methods: listBookmarks(), saveBookmark(), removeBookmark()
- Channel admin methods: addModerator(), removeModerator(), kickUser(), banUser(), unbanUser(), pinMessage(), unpinMessage(), inviteUser()
- Channel query methods: getChannelDetail(), getChannelMembers(), getChannelPins(), getChannelBans()
- New types: ReactionInfo, NewsReactionsResponse, ReactionPayload, NewsRepostPayload, RepostsResponse, BookmarksResponse, ModeratorPermissions, ChannelMember, ChannelMembersResponse, ChannelPinsResponse, ChannelBansResponse, ChannelDetailResponse

## [0.2.0] - 2026-03-29

### Added
- Full spec endpoint coverage (25+ client methods):
  - `getNewsPost()` — single news post with comments
  - `getUserProfile()` — typed user profile with counts
  - `getUserPosts()` — paginated user posts
  - `createChannel()` — channel creation
  - `uploadMedia()` — media upload to IPFS via node
  - `updateProfile()` — profile editing
  - `getDmConversations()` — DM conversation list
  - `getDmMessages()` — DM message history
  - `getNotifications()` — notification center
  - `postNews()` — news article posting
  - `exportAccount()` — full user data export
  - `getModerationReports()` — moderation reports for a target
  - `getModerationUser()` — user moderation trust info
  - `getMediaUrl()` — build media fetch URL by CID
- Missing spec query parameters:
  - `listChannels()` — `sort` parameter (recent/popular)
  - `listNews()` — `tag` filter parameter
  - `getFeed()` — `before` timestamp parameter
  - `listNodes()` — `page`/`limit` pagination and `total` in response
- New response types: `NewsPostResponse`, `ProfileUpdateData`,
  `DmConversationsResponse`, `DmMessagesResponse`, `NotificationsResponse`,
  `ChannelCreateData/Response`, `UserProfileResponse`, `UserPostsResponse`,
  `AccountExportResponse`, `ModerationReportsResponse`, `ModerationUserResponse`
- Exponential backoff with jitter for WebSocket reconnection
  (base * 2^attempts, capped at maxReconnectDelay, ±25% jitter)
- `maxReconnectDelay` option for WsSubscription (default: 30s)

### Changed
- `getChannel()` now returns typed `{ channel: Channel; member_count; message_count }`
  instead of `Record<string, unknown>`
- `putAuthenticated` helper no longer calls `resp.json()` on empty bodies
  (prevents crash on 204 No Content)
- Default `reconnectDelay` changed from 3000ms to 1000ms (first retry is faster)

### Removed
- `getUser()` — replaced by typed `getUserProfile()`

### Fixed
- `getNotifications(since=0)` no longer skipped due to falsy check
- `ChannelCreateResponse.channel_id` type changed from `string` to `number`
  to match `Channel.channel_id`

## [0.1.0] - 2026-03-29

### Added
- OgmaraClient HTTP client for all L2 node REST endpoints
  - Public: health, stats, channels, messages, users, news, nodes,
    followers, following
  - Authenticated: send message, send DM, follow, unfollow, personal feed
- WalletSigner for Klever wallet signing (Ed25519 + Keccak-256)
  - Klever message format signing for auth headers
  - Ogmara protocol format signing for envelope construction
  - Key creation from private key, hex, or random generation
  - bech32 address encoding (klv1... format)
- WebSocket subscription client with auto-reconnect
  - Authenticated and public (read-only) modes
  - Channel subscribe/unsubscribe, DM subscription
  - State change callbacks
- Embeddable feed widget for third-party websites
  - Self-contained HTML/CSS/JS rendering
  - Dark/light/auto theme support
  - Live updates via public WebSocket
  - XSS-safe rendering (textContent, not innerHTML)
- Hashtag extraction utility (extractHashtags)
  - Parses #hashtags from content
  - Lowercase, deduplicate, max 10 tags
- Full TypeScript type definitions
  - Envelope, Channel, User, ChatMessage, NewsPost, WsEvent
  - MessageType constants (27+ entries)
  - FollowPayload, UnfollowPayload, FollowerListResponse, FeedResponse
- Zero framework dependencies (works in browsers and Node.js)
- Crypto: @noble/ed25519 + @noble/hashes (no native deps)
