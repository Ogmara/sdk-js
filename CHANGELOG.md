# Changelog

All notable changes to the Ogmara JS/TS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.15.0] - 2026-05-06

### Added
- **`searchUsers(q, limit)` method** — wraps `GET /api/v1/users/search`
  for `@`-mention autocomplete. Case-insensitive prefix search on
  `display_name`; when `q` starts with `klv1...` the L2 node also
  matches addresses. Returns `{ users: UserSearchHit[] }` with
  `address`, `display_name` (or `null`), `avatar_cid` (or `null`),
  and `verified` (`true` for on-chain registered users). No auth.
  Pairs with `l2-node` v0.32.0+; older nodes return 404.
- **`UserSearchHit` and `UserSearchResponse` types** exported from
  `@ogmara/sdk` for clients building mention popovers.

### Notes
- Server clamps `limit` to 1..=50 (default 20) and rejects empty `q`
  with 400. Clients should still validate locally before calling for
  the best UX.

## [0.14.0] - 2026-05-05

### Added
- **Read-only / broadcast channel support (paired with `l2-node` v0.31.0).**
  `ChannelUpdateData` gained two optional fields:
  - `channelType?: number` — flip the runtime channel type. The L2 node
    accepts `Public` (0) ⇄ `ReadPublic` (1) only; `Private` (2) is rejected
    at validation. Omit to leave unchanged.
  - `threadsEnabled?: boolean` — toggle threaded posting mode (rendering
    hint; actual thread indexing lands in Phase 3).
- **`canPost(channel, address, isModerator)` helper** in `utils` — returns
  whether the address may post `ChatMessage` / `ChatEdit` / `ChatDelete`
  under the channel's runtime posting policy. Returns `true` for non-
  ReadPublic channels and for the creator/moderators of ReadPublic
  channels. Use this to gate composer UI in clients.
- **Channel type constants exported:** `CHANNEL_TYPE_PUBLIC` (0),
  `CHANNEL_TYPE_READ_PUBLIC` (1), `CHANNEL_TYPE_PRIVATE` (2).
- **`Channel.threads_enabled?: boolean`** added to the `Channel` interface
  so consumers can read the runtime flag from API responses without `any`.

### Notes
- Wire format: the SDK encodes `ChannelUpdate` payloads as a msgpack **map**
  (string keys), not a positional array, so adding optional fields is
  generally backwards-compatible. The L2 node's struct decoder (rmp-serde
  on a serde-derived struct without `deny_unknown_fields`) silently ignores
  unknown keys. However, until `l2-node` v0.31.0 ships, nodes won't honor
  `channel_type` / `threads_enabled` even if they accept them — coordinate
  node deploy before relying on the new fields client-side.
- The `Channel.channel_type` doc-comment now clarifies it reflects the
  runtime (L2-mutable) value, not the on-chain immutable type.

## [0.13.5] - 2026-05-02

### Security
- **Bumped `postcss` to ≥ 8.5.10 via overrides** — addresses CVE-2026-41305
  (XSS via unescaped `</style>` in CSS stringify output). Transitive dev
  dependency only (via `tsup` and `vitest`); not shipped in the published
  SDK bundle. Fixed for completeness so Dependabot stops flagging.
- **`npm audit fix` for transitive Vite vulns** — three high-severity
  advisories on Vite 7.0.0–7.3.1 (path traversal in optimized deps, fs.deny
  bypass, dev-server WebSocket arbitrary file read). Dev-only via vitest;
  no runtime impact on consumers.

## [0.13.4] - 2026-04-11

### Fixed
- **PoW address mismatch when device registration pending** — the server now
  includes the resolved address in the 429 challenge response. The SDK uses
  this address directly instead of guessing, eliminating mismatches between
  `ogd1...` (device) and `klv1...` (wallet) when the device mapping hasn't
  been established yet.

## [0.13.3] - 2026-04-11

### Fixed
- **PoW solution uses wrong address for extension wallets** — `solvePow()`
  submitted the device signing address (`ogd1...`) but the challenge is
  issued to the resolved wallet address (`klv1...`). Now uses
  `walletAddress` when available, matching the node's `resolved_author`.

## [0.13.2] - 2026-04-11

### Fixed
- **PoW challenge not handled on PUT, DELETE, and GET requests** — only
  `postEnvelope` and `postJson` had auto-solve logic for 429 `pow_required`
  responses. Added PoW handling to `putEnvelope`, `deleteEnvelope`, `get`,
  and `getAuthenticated`. This caused profile updates, message deletions,
  and authenticated reads to fail with raw 429 errors instead of
  auto-solving the challenge and retrying.

## [0.13.1] - 2026-04-11

### Fixed
- **`DEFAULT_NODE_URL` pointed to website instead of node** — changed from
  `https://ogmara.org` (the main website) to `https://node.ogmara.org`
  (the actual L2 node endpoint). This caused the node selector to show
  the website URL as a node option.

## [0.13.0] - 2026-04-10

### Added
- **Proof-of-Work solver** — new `pow.ts` module with `solveChallenge()` and
  `solveChallengeAsync()` functions for solving SHA-256 hash puzzles.
- **Automatic PoW handling in client** — `OgmaraClient` now detects 429
  `pow_required` responses, auto-solves the challenge, submits the solution,
  and retries the original request transparently.
- **PoW lifecycle callbacks** — `onPowStart`, `onPowProgress`, and
  `onPowComplete` callbacks on `OgmaraClient` for UI loading indicators.
- Exports: `solveChallenge`, `solveChallengeAsync`, `PowChallenge`,
  `PowSolution`, `PowResult` types.

## [0.12.0] - 2026-04-05

### Added
- **Device address prefix (`ogd1...`)** — `WalletSigner` now exposes a
  `deviceAddress` getter that encodes the public key with `ogd` bech32 prefix,
  distinguishing device keys from wallet addresses (`klv1...`)
- `signingAddress` getter on `WalletSigner` — returns `ogd1...` when
  `walletAddress` is set (delegated device mode), or `klv1...` for built-in
  wallet mode
- `DEVICE_HRP` and `WALLET_HRP` constants for bech32 encoding

### Changed
- Auth headers (`signRequest`) now use `signingAddress` — device keys send
  `ogd1...` in `X-Ogmara-Address`, wallet keys send `klv1...`

## [0.11.7] - 2026-04-05

### Added
- `last_read_ts` field on `MessagesResponse` — the authenticated user's read
  cursor timestamp, enabling clients to show an unread messages divider

## [0.11.6] - 2026-04-05

### Added
- `after` parameter on `getChannelMessages` and `getDmMessages` — enables
  incremental fetching of only new messages since a known msg_id cursor

## [0.11.5] - 2026-04-04

### Added
- Auto-extract `@klv1...` mentions from message content — `buildChatMessage`
  and `buildNewsComment` now parse the content text for `@klv1` addresses
  when `mentions` is not explicitly provided, ensuring the L2 node's
  notification engine can detect and deliver mention notifications

## [0.11.4] - 2026-04-04

### Added

- `DirectMessageData` now supports `attachments?: Attachment[]` — DM envelope builder serializes them instead of hardcoding empty array

## [0.11.3] - 2026-04-04

### Changed

- `SettingsSyncResponse` type updated to match L2 node's new GET /api/v1/settings response format (`encrypted_settings`/`nonce`/`key_epoch` as number arrays)

## [0.11.1] - 2026-04-04

### Fixed

- All message action envelope payloads (edit, delete, reaction) now use `target_id` field instead of `msg_id`, matching L2 node's `EditPayload`, `DeletePayload`, and `ReactionPayload` structs
- Edit payloads now include required `edited_at` timestamp field
- Affects all variants: chat, DM, and news edit/delete/reaction
- Report payload: added missing `target_type` field, renamed `reason`→`details` and `category`→`reason` (mapped to Rust `ReportReason` enum variant names)
- CounterVote payload: renamed `report_id`→`target_id` to match `CounterVotePayload` struct
- Settings sync payload: renamed `encrypted_blob`/`iv` to `encrypted_settings`/`nonce`/`key_epoch` to match `SettingsSyncPayload` struct

## [0.11.0] - 2026-04-02

### Added

- 11 new data types: `ChatEditData`, `ChatDeleteData`, `ChatReactionData`, `DirectMessageEditData`, `DirectMessageDeleteData`, `DirectMessageReactionData`, `NewsEditData`, `NewsDeleteData`, `SettingsSyncData`, `ReportData`, `CounterVoteData`
- `SettingsSyncResponse` type for GET /api/v1/settings
- 11 new envelope builders: `buildChatEdit`, `buildChatDelete`, `buildChatReaction`, `buildDmEdit`, `buildDmDelete`, `buildDmReaction`, `buildNewsEdit`, `buildNewsDelete`, `buildSettingsSync`, `buildReport`, `buildCounterVote`
- 12 new client methods: `editMessage()`, `deleteMessage()`, `reactToMessage()`, `editDm()`, `deleteDm()`, `reactToDm()`, `editNews()`, `deleteNews()`, `syncSettings()`, `getSettings()`, `reportMessage()`, `counterVote()`

## [0.10.2] - 2026-04-02

### Fixed
- **Private channels invisible to owners** — `get()` method now sends auth
  headers when a signer is available. Previously, `listChannels` always made
  unauthenticated requests, so the server's optional auth middleware never
  identified the caller and filtered out all private channels.

## [0.9.0] - 2026-04-01

### Added
- **Direct Messaging support:**
  - `computeConversationId(addrA, addrB)` — deterministic conversation ID from
    two Klever addresses using Keccak-256. Matches Rust implementation.
  - `buildDirectMessage(signer, data)` — builds signed DM envelope with
    conversation_id computation. MVP uses plaintext content (no encryption).
  - `DirectMessageData` type with `recipient`, `content`, `replyTo` fields.
  - `client.markDmRead(address)` — mark DM conversation as read.
  - `client.getDmUnread()` — get unread counts per DM conversation.
- `DmConversation.last_message_preview` field added to type definition.

## [0.8.0] - 2026-04-01

### Added
- **Device-to-wallet identity mapping** — multi-device support:
  - `WalletSigner.walletAddress` optional field for device-wallet binding
  - `buildDeviceClaim(devicePubkeyHex, walletAddress, timestamp?)` helper
    for constructing claim strings to be signed by the wallet
  - `client.registerDevice(walletSignatureHex, walletAddress, timestamp)`
    submits wallet-signed claim to register a device key under a wallet
  - `client.revokeDevice(deviceAddress)` revokes a device registration
  - `client.listDevices()` lists all devices for the authenticated wallet
- Types: `RegisterDeviceRequest`, `RegisterDeviceResponse`, `DeviceInfo`,
  `ListDevicesResponse`, `RevokeDeviceResponse`

## [0.7.0] - 2026-03-31

### Added
- `buildNewsComment` envelope builder for reply/comment on news posts
- `postComment(postId, content, options?)` method on OgmaraClient
- `NewsCommentData` type with `postId`, `content`, `replyTo`, `mentions`, `attachments`

## [0.6.1] - 2026-03-31

### Fixed
- Signature verification failed on L2 node — `msg_type` was sent as numeric
  discriminant (e.g., `0x20`), but `rmp-serde` interprets integers as variant
  INDEX (32nd variant = `Report`), not discriminant. Node then computed
  `msg_type as u8 = 0x40` for signing, while SDK signed with `0x20`. Now
  sends variant NAME string (e.g., `"NewsPost"`) matching Rust serde format.

## [0.6.0] - 2026-03-31

### Added
- **Envelope builder** (`envelope.ts`) — constructs signed MessagePack-serialized
  envelopes per protocol spec 3.1. Builds proper Envelope with version, msg_type,
  msg_id (Keccak-256), Ed25519 signature, and MessagePack-serialized payload.
- `@msgpack/msgpack` dependency for MessagePack serialization
- High-level builders: `buildChatMessage`, `buildNewsPost`, `buildProfileUpdate`,
  `buildFollow`, `buildUnfollow`, `buildReaction`, `buildRepost`, and all
  channel admin builders (kick, ban, pin, invite, etc.)
- `postEnvelope`, `putEnvelope`, `deleteEnvelope` internal helpers for binary body
- `postNews` now accepts optional `attachments` array for media

### Changed
- **BREAKING**: All write methods now send MessagePack-serialized Envelope bytes
  instead of JSON strings. This matches what the L2 node actually expects.
- `postNews(title, content, options?)` — removed `channelId` parameter (news posts
  are not channel-scoped per protocol spec)
- `sendMessage(channelId, content, options?)` — added optional `replyTo`,
  `mentions`, `attachments` parameters
- `createChannel` now accepts pre-built envelope bytes
- `addModerator`, `kickUser`, `banUser`, `pinMessage`, `unpinMessage`, `inviteUser`
  now accept typed parameters instead of raw JSON body strings
- `sendDm` now accepts `Uint8Array` envelope bytes instead of JSON string

### Fixed
- "deserialization failed: expected struct Envelope" error — root cause was SDK
  sending JSON while L2 node expected MessagePack binary

## [0.5.1] - 2026-03-31

### Fixed
- `pingNode` now validates response body (must have `version` field) —
  prevents false positives from web servers that return 200 on any path
- `discoverAndPingNodes` no longer filters out unreachable nodes — they
  are sorted to the bottom so the UI can show them as offline

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
