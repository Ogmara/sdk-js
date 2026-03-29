# Changelog

All notable changes to the Ogmara JS/TS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
