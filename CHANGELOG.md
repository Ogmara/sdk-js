# Changelog

All notable changes to the Ogmara JS/TS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.32.0] - 2026-06-14

P2b — SDK surface for end-to-end-encrypted PRIVATE channels (OECK).

### Added

- **`computeChannelScope(channelId)`** — `keccak256("ogmara-channel-scope-v1" ||
  channel_id_be8)`, the deterministic 32-byte channel key scope (mirrors the Rust
  `compute_channel_scope`, cross-impl KAT). Domain-separated from DM scopes.
- **`buildEncryptedChannelMessage`** (dm.ts) — builds an encrypted `ChatMessage`
  (0x04) for a private channel: only the TEXT is sealed under the channel epoch key
  (`aad = channel_scope || epoch`, same scheme as a DM body) and carried in
  `enc_content`/`enc_nonce`/`key_epoch`; `content` is empty. `mentions`/`reply_to`/
  `content_rating` stay PLAINTEXT (spec §3.3) so the node keeps doing notifications,
  threading, and filtering. New `EncryptedChannelMessageParams` type. Round-trip +
  channel-scope KAT tests.
- **`Client.sendMessageEnvelope(envelope)`** — POST a pre-built (e.g. encrypted)
  message envelope to `/api/v1/messages`.

## [0.31.1] - 2026-06-14
## [0.31.1] - 2026-06-14

### Fixed

- **`buildEncryptedDmEdit` now includes `recipient` in the payload.** The node
  needs it to route a DM edit to the recipient's gossip topic (l2-node 0.71.0); it
  is an unused field for `EditPayload` decoding otherwise. Without it, edits never
  reached the recipient cross-node.

## [0.31.0] - 2026-06-14

### Added

- **`buildEncryptedDmEdit`** (dm.ts) — builds a signed, E2E-encrypted
  `DirectMessageEdit` (0x06). The new content is sealed under the conversation's
  `conv_key` exactly like a DM body (`aad = conversation_id || epoch`) and carried
  in `enc_content`/`enc_nonce`/`key_epoch`; the plaintext `content` String is sent
  empty so the node never sees the edited text. Requires `key_epoch ≥ 1`. New
  `EncryptedDmEditParams` type; both exported from the package root. Round-trip
  unit test added.

### Deprecated

- **`buildDmEdit` (envelope.ts) and `Client.editDm`** — these send a plaintext DM
  edit, which l2-node 0.70.0+ rejects (DM edits must be E2E-encrypted). Use
  `buildEncryptedDmEdit` with the conv_key and POST via `sendDm`.

## [0.30.0] - 2026-06-13

### Changed

- **`DEFAULT_NODE_URL` is now an empty string** — no hardcoded default node. Node
  discovery is dynamic (the connected node's `/network/nodes` derived from the SC
  `getActiveNodes` registry + libp2p gossip, plus a same-origin bootstrap list and
  user-added URLs). The old `node.ogmara.org` seed was decommissioned; consumers
  already treat empty as "unset" (`push.ts` fallback, node picker). Do NOT
  reintroduce a hardcoded host.

## [0.29.1] - 2026-06-13

### Security

- Cleared all `npm audit` findings (dev/build toolchain only — not shipped in the
  published package): pinned `esbuild >=0.28.1` via `overrides` (GHSA-gv7w-rqvm-qjhr,
  the affected range ends at 0.28.0) and bumped `vitest` to `^3.2.6`
  (GHSA-5xrq-8626-4rwp, Vitest UI server arbitrary file read/execute). `npm audit`
  now reports 0 vulnerabilities. No runtime/API change.

## [0.29.0] - 2026-06-12

### Changed

- `getKeyEnvelope(keyScope, deviceId, author?, epoch?)` — added the `author` param
  for per-sender DM keys (fetch a specific sender's key). Defaults to the caller's
  own wallet server-side. (Pairs with l2-node 0.65.0.)

## [0.28.0] - 2026-06-11

E2E encryption P1 — encrypted Direct Messages on top of the crypto core.

### Added

- **`dm` module** (protocol §8.2): `encryptDmContent` / `decryptDmContent`
  (XChaCha20-Poly1305 under a per-conversation `conv_key`, `aad = conversation_id ||
  epoch`; `reply_to` rides inside the ciphertext, not leaked to the node);
  `wrapConvKey` / `unwrapConvKey` (ECIES, salt = conversation_id); `randomConvKey`;
  `buildChannelKeyEnvelope` (0x61 per-device key delivery) and
  `buildEncryptedDirectMessage` (0x05 with encrypted content). `KeyScopeKind`.
- **Client methods**: `getKeyEnvelope(keyScope, deviceId, epoch?)` (per-device key
  retrieval), `publishKeyEnvelope(envelope)` (publish a 0x61 via the generic path).
- `MessageType.ChannelKeyEnvelope` (0x61); `KeyEnvelopeRecord` / `KeyEnvelopeResponse`.

### Changed

- The legacy plaintext `buildDirectMessage` now emits a **24-byte** nonce (matches
  the node's XChaCha20 wire format) and throws if no CSPRNG is present. It is
  **deprecated** — use `buildEncryptedDirectMessage`.

### Notes

- sdk-rust DM mirror is intentionally deferred (no Rust DM consumer yet). When
  added, the inner `{text, reply_to}` blob needs a cross-impl KAT — `@msgpack`
  encodes a `Uint8Array` as `bin` while `rmp_serde` encodes `[u8;32]` as a seq, so a
  present `reply_to` is not byte-identical across impls until reconciled.

## [0.27.0] - 2026-06-11

E2E encryption P1 — shared crypto core (matches sdk-rust `crypto.rs` byte-for-byte).

### Added

- **`crypto` module** — the symmetric content-encryption + key-wrapping core for
  E2E (protocol §8). Audited primitives wrapped behind Ogmara-native names:
  - `aeadEncrypt` / `aeadDecrypt` — XChaCha20-Poly1305 (24-byte nonce); `aad`
    binds ciphertext to its envelope.
  - `hkdfSha256` — HKDF-SHA256 (RFC 5869).
  - `x25519Dh` / `x25519Public` — X25519 DH; DH rejects all-zero (low-order) output.
  - `wrapKey` / `wrapKeyWith` / `unwrapKey` + `WrappedKey` — ECIES key wrap to a
    recipient device enc pubkey: `wk = HKDF(X25519(eph, R_pub), salt=context,
    info="ogmara-keywrap-v1")`, `wrapped = AEAD(wk, nonce, K, aad=ephPub)`.
  - Constants `KEY_LEN` (32), `AEAD_NONCE_LEN` (24), `AEAD_TAG_LEN` (16).
- **Cross-impl test vectors** asserted identically in sdk-rust: RFC 5869 HKDF
  case 1, draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD KAT, and an Ogmara wrap KAT.
- `wrapKey` draws a fresh 24-byte CSPRNG nonce and **throws** if no CSPRNG is
  present — never the all-zero-nonce fallback (audit N1).

### Dependencies

- Added `@noble/ciphers ^2.1.1` (XChaCha20-Poly1305), matching mobile's range.
  Imported via the `.js` subpath (`@noble/ciphers/chacha.js`) its `exports` map
  requires. **Consumers must add it as a direct dependency** (web/desktop/mobile),
  same as `@noble/hashes` — a transitive-only `@noble` dep is not reliably present
  in a `file:`-linked consumer's node_modules.

## [0.26.3] - 2026-06-11

### Fixed

- **All authenticated calls failing with 401 "invalid signature" until reconnect
  (device-link bug).** `WalletSigner.fromPrivateKey` stored the caller's
  private-key `Uint8Array` *by reference*. Callers that zero their key buffer
  right after constructing a signer (e.g. the web's `deviceVaultGenerate`,
  best-effort key hygiene) thereby wiped the signer's key in place — it then
  signed with all-zeros while still advertising the real public key/`ogd1`
  address, so the node rejected every request as "invalid signature". A freshly
  generated device key stayed broken until reloaded from storage on the next
  session, which is why it only worked *after a disconnect+reconnect*. The
  signer now keeps a defensive copy (`privateKey.slice()`), immune to caller
  mutation. Added a regression test.

### Removed

- The temporary opt-in `[auth-debug]` diagnostic from 0.26.2 (no longer needed).

## [0.26.2] - 2026-06-11

### Added

- **Gated auth diagnostic** for the device-link 401 investigation. Disabled by
  default; enable in the browser console with `localStorage.ogmara_auth_debug = '1'`,
  then reproduce. `signRequest` self-verifies its own signature (Klever-hash →
  ed25519 verify against the signer's public key) and logs the authString,
  signing address, pubkey, nonce/timestamp, signature, and `selfVerify` result.
  Temporary — to be removed once the 401 is root-caused.

## [0.26.1] - 2026-06-09

### Fixed

- **WebSocket reconnect storm.** The reconnect backoff was reset on socket
  *open*, but a socket that opens then closes almost immediately (auth rejected,
  or — before l2-node 0.63.2 — a node whose gossip hadn't meshed) turned that
  into a tight ~1s reconnect loop that hammered the node. The backoff now resets
  only after the connection stays open ~3s (proven stable), so persistent
  failures back off properly. Also surfaces the previously-swallowed WS auth
  error (`[ogmara-ws] WS auth failed`) instead of silently looping.

## [0.26.0] - 2026-06-08

Correctness + transport hardening (audit 2026-06-07 fix-plan Batch 4).

### Security

- **`validateNodeUrl` SSRF hardening (B4.2).** Replaced the bypassable
  string-blocklist with structured checks on the WHATWG-canonicalized hostname
  (catches decimal/hex/octal IPv4, IPv4-mapped IPv6, CGNAT, etc., shared with
  the SC-discovery dial path), and now **requires https in web mode** (no
  plaintext downgrade). `allowPrivateHosts: true` (desktop/mobile) still permits
  LAN/loopback + http.
- **WebSocket TLS enforcement (B4.3 W2).** The WS client refuses cleartext
  `ws://` to a non-loopback host (the first frame is the auth credential) — use
  `wss://`. New `WsOptions.onError` surfaces the refusal. Loopback ws:// still
  allowed for dev.
- **WS robustness (B4.3 W1/W3).** Reconnects fully tear down the prior socket
  (no stale-handler / double-timer races); inbound frames over ~1 MiB are
  dropped before `JSON.parse`.

### Added

- `OgmaraClient.authHeaders(method, path)` was added in 0.25.0; `Envelope` now
  carries the node's enriched read fields (`channel_id`, `target_msg_id`,
  `emoji`, `remove`, `reactions`, `reaction_counts`, `deleted`, `edited`);
  `NetworkStats.network`, `Channel.logo_cid`, `ChannelDetailResponse.member_count`
  added (B4.1 — aligns the `.d.ts` with the node's output, clearing 30 web/
  desktop tsc errors).

### Changed

- `WalletSigner` `addModerator`'s `permissions` arg (via `OgmaraClient`) is now
  **optional**, defaulting to the full standard moderator set (B4.1 — fixes the
  2-arg call sites in web/desktop). Exported `randomNonceHex`, `resolveWsUrl`,
  `isPrivateIpv4/Ipv6/DnsName`.

## [0.25.0] - 2026-06-08

### Security

- **X25519 crypto hardening (audit C2/W4, fix-plan B2.1 — E2E prerequisite).**
  The vendored X25519 Montgomery ladder now uses a BRANCHLESS constant-time
  conditional swap (removing the secret-dependent `if (swap===1n)` timing leak);
  `getSharedSecret` validates the 32-byte key lengths and rejects an all-zero /
  low-order shared secret (RFC 7748 §6.1) so a malicious peer key can't force an
  attacker-predictable secret. `hexToBytes` in `auth.ts` and `encryption.ts` now
  validate the hex charset + even length and throw, instead of `parseInt`
  silently coercing bad input to a *different* key/signature. (BigInt limb math
  remains variable-time — documented residual; not in the client threat model.)
- **Auth host-binding (audit C1, fix-plan B1.3).** `WalletSigner.signRequest`
  now binds each auth signature to the target node's `{network, nodeId}` plus a
  fresh single-use `nonce`, signing
  `ogmara-auth:{network}:{nodeId}:{nonce}:{timestamp}:{method}:{path}` and
  emitting a new `x-ogmara-nonce` header. A captured header can no longer be
  replayed against another node/network or reused on the same node. The
  `OgmaraClient` lazily fetches and caches the node identity from
  `GET /api/v1/health` (now returns `node_id`/`network`); the WS client does the
  same and includes the nonce in its auth frame. Requires l2-node ≥0.61.0.

### Added

- `OgmaraClient.authHeaders(method, path)` (public) — returns host-bound,
  nonce'd auth headers for callers that must issue the request themselves
  (native/Tauri fetch for large bodies, multipart uploads) instead of reaching
  into the signer.
- `WalletSigner.signPushClaim(action, gatewayHost, token)` — signs a
  push-gateway registration/unregistration claim bound to the gateway host + a
  single-use nonce + the exact token (audit C1/C2/C3). Returns the auth headers
  plus the address to send in the request body.

### Changed

- **BREAKING:** `WalletSigner.signRequest(method, path)` →
  `signRequest(method, path, binding)` where `binding: NodeBinding` is
  `{ network, nodeId }`. `AuthHeaders` gains `x-ogmara-nonce`. New exports:
  `NodeBinding`, `randomNonceHex`. Most consumers use the higher-level
  `OgmaraClient`/`subscribe` and need no changes.

## [0.24.1] - 2026-06-07

### Fixed

- **Build portability.** Replaced the `@noble/curves` dependency with a vendored,
  dependency-free X25519 (RFC 7748, verified against the spec's official test
  vectors). `@noble/curves/ed25519` is a package `exports` subpath whose types fail
  to resolve under older TypeScript (DTS build error TS2307), and as a transitive
  dep of this `file:`-linked package it wasn't present in consumer node_modules —
  both broke the production web/SDK build. The vendored module resolves everywhere
  and needs no consumer changes.

## [0.24.0] - 2026-06-07

### Added

- **Device encryption keys (E2E P0, protocol §2.4)** — new `encryption` module:
  - `generateDeviceEncKeypair()` / `encPublicKeyHex()` — per-device X25519 keypair
    (distinct from the Ed25519 signing key); the private key stays on the device.
  - `buildDeviceEncBinding()` / `buildDeviceEncRevoke()` — build the **wallet-authored**
    `DeviceEncBinding` (0x36) / `DeviceEncRevoke` (0x37) envelopes (author = wallet,
    `msg_id` keyed to the wallet pubkey, signature = wallet `signMessage` over the
    canonical claim). `encBindClaim()` / `encRevokeClaim()` expose the exact claim.
  - `OgmaraClient.getEncKeys(address)` (GET) and `publishEncKeyEnvelope(wallet, bytes)`
    (POST `/api/v1/users/{address}/enc-keys`).
- **`normalizeWalletSig()`** — canonicalizes a wallet `signMessage` return (Klever
  Extension hex / K5 base64-of-hex / raw bytes) into the 64 raw Ed25519 signature
  bytes. Fixes a latent bug where K5's base64-of-hex failed the `/^[0-9a-f]{128}$/`
  check in clients. Required so signature-derived values reproduce across wallets.
- New dependency `@noble/curves` (X25519).

## [0.23.0] - 2026-06-06

### Added

- `client.getChannelBySlug(slug)` — resolve a channel by slug via the node's
  `GET /api/v1/channels/by-slug/:slug` (returns the channel metadata incl.
  `channel_id`, or `null` on 404). Lets clients learn a freshly-created
  channel's id by polling the node instead of querying Klever's SC RPC directly
  (CORS-blocked in browsers).

## [0.22.0] - 2026-06-05

### Added

- **`registerDevice` now co-signs the device claim (P-0 dual-signed
  delegation, node 0.49.0+).** In addition to the wallet's claim signature,
  the device key automatically signs the SAME canonical claim string as a
  proof-of-possession and sends it as `device_signature`. This lets the node
  gossip a free, unforgeable device→wallet delegation to all peers (no
  on-chain transaction) — so the mapping follows the user to any node. No
  caller change: the device signature is derived from the signer the client
  already holds. `RegisterDeviceRequest` gained the optional `device_signature`
  field.

## [0.21.0] - 2026-06-04

### Added

- On-chain node discovery: `discoverNodesViaSc(network)` and
  `discoverNodeUrlsViaSc(network)` enumerate registered Ogmara nodes
  directly from the KApp on Klever (`getActiveNodes` → `getNodeMetadata`
  → derived HTTPS endpoint) with **no hardcoded seed node**. Plus
  `SC_NETWORKS` (mainnet/testnet RPC + SC addresses) and the
  `ScNetwork` / `ScNetworkConfig` / `ScDiscoveredNode` /
  `ScDiscoveryOptions` types. This is the decentralized replacement for
  the `DEFAULT_NODE_URL` seed — a single point of failure when
  `node.ogmara.org` is down. Ported (behaviourally identical) from the
  website's proven `sc_bootstrap.js`; includes the SSRF guard that
  strips loopback / RFC1918 / CGNAT / link-local / `.local` hosts from
  on-chain multiaddrs. Validated against live testnet (discovers the
  registered fleet) and covered by unit tests.

### Deprecated

- `DEFAULT_NODE_URL` (`https://node.ogmara.org`) is retained for
  backward compatibility but should no longer be relied on as a seed —
  prefer SC discovery. `node.ogmara.org` is not currently a live node.

## [0.20.0] - 2026-06-04

### Added

- `Health.media_uploads?: boolean` — the node's live media capability
  (IPFS configured AND the Kubo daemon reachable), reported by
  `/api/v1/health` on l2-node 0.48.7+. A node can be configured-but-
  offline (text-only deployment), so this is a live signal, not a static
  flag. Optional: older nodes omit it (`undefined`), which clients should
  treat as "unknown → assume available" to preserve prior behavior.
  Clients use it to disable the upload UI and render a friendly
  "hosted on another node" placeholder instead of failing on upload or
  showing broken images.

## [0.19.0] - 2026-06-01

Presence-gossip consumer surface — spec 13 §10 + spec 5 §1.1. Lands
alongside l2-node v0.48.0 which started serving the
`/api/v1/network/presence*` and `/api/v1/network/identity` endpoints.

### Added

- **`OgmaraClient.getKnownNodes(probeCache?)` — high-level merged
  view of all network nodes.** Joins `/network/nodes` (SC view) with
  `/network/presence` (off-chain gossip cache) by libp2p PeerId,
  returns `KnownNode[]` sorted by `trust_score` desc. Each row
  exposes:
  - `peer_id` (libp2p PeerId)
  - `url` (SC-preferred on conflict; falls back to presence URL)
  - `attestation: 'on-chain' | 'gossip' | 'both'` (spec 13 §10.8)
  - `anchoring` boolean
  - `anchor_age_seconds`, `presence_timestamp_ms` for diagnostics
  - `reachable_probe_at` (apps that probe reachability themselves
    pass a `{ peer_id: unix_ms }` map as `probeCache` so the +10
    reachability contribution lands)
  - `trust_score: 0..100` (computed via the exported
    `computeTrustScore`; locked formula per planning §4.2)
- **`OgmaraClient.getNetworkIdentity(url?)`** — wraps
  `GET /api/v1/network/identity` for the Reachable probe. Optionally
  targets a different node via `url` so apps can verify that a
  gossip-claimed `public_url` resolves to the same PeerId before
  trusting it for failover.
- **`OgmaraClient.getPresenceRecords()`** — wraps
  `GET /api/v1/network/presence`. Returns the home node's cached
  presence records with `verified_on_chain` enrichment. Empty
  `records: []` and `broadcasting: false` on nodes that haven't
  opted in to presence — no special-casing needed at the call
  site.
- **`OgmaraClient.getPresenceRecord(peerId)`** — single-record
  lookup. Returns `null` on 404 (cache miss / TTL-evicted / not
  yet received).
- **New types:** `NetworkIdentity`, `PresenceRecord`,
  `PresenceResponse`, `KnownNode`, `Attestation`.
- **`computeTrustScore(node: KnownNode): number`** — pure
  re-scoring helper for apps that update reachability state out
  of band and want to resort without re-fetching.

### References

- Spec 13 §10: <https://github.com/Ogmara/ogmara/blob/main/docs/specs/13-node-discovery.md#10-presence-gossip-layer>
- Spec 5 §1.1: <https://github.com/Ogmara/ogmara/blob/main/docs/specs/05-clients.md#11-node-failover--auto-discovery>
- Planning: `docs/planning/presence-gossip-plan.md` (Ogmara hub)

## [0.18.0] - 2026-05-17

Adds an opt-in flag to permit LAN / loopback / Tailscale hosts in
`validateNodeUrl` and the helpers built on it. Required by desktop
and native mobile clients so users can connect to their own L2 node
on the same network — previously the SDK's SSRF guard silently
rejected every private IP / DNS name and the calling client had no
way to tell why.

### Added
- **`ValidateNodeUrlOptions` type and `allowPrivateHosts` flag.**
  `validateNodeUrl(url, options?)`, `pingNode(url, timeout?,
  options?)`, and `discoverAndPingNodes(primary, options?)` all
  accept `{ allowPrivateHosts?: boolean }`. Default stays `false`
  so the web client keeps the SSRF/DNS-rebinding protection it
  needs; desktop/mobile shells should pass `true` because the
  Tauri / React Native host process IS the trust boundary, not
  the URL host filter.

### Pairs with
- desktop v1.22.0 — uses `allowPrivateHosts: true` from
  `NodeSelector` and `getAvailableNodes` so users can finally add
  Odroid / RPi / Tailscale node URLs in the picker.

## [0.17.0] - 2026-05-15

### Added
- **`editNews()` and the news-edit envelope now carry title, tags, and
  attachments — all as truly optional overrides.** Aligns with L2
  protocol §3.7 (v0.37+) read-time projection semantics: a field that
  is *absent* from the envelope means "preserve the original", while a
  field that is *present* (even as `null` / `[]`) means "replace
  wholesale". `NewsEditData` now accepts `title?: string`,
  `tags?: string[]`, and `attachments?: Attachment[]`; the encoder
  gates each behind a `!== undefined` check so legacy callers
  (`editNews(id, content)`) do not silently wipe the original title,
  tag list, or attachments.

### Changed
- **All three override fields are now omitted from the envelope when
  not passed.** Earlier in this release cycle only `attachments` was
  conditional, while `title` defaulted to `null` and `tags` to `[]` —
  which against an L2 v0.37 node would have wiped the original title
  and cleared the tag list on every `editNews(id, content)` call,
  exactly the bug the spec extension was meant to fix. All three
  fields now follow the same "absent = preserve" pattern.
- **Bumped minor.** Adding new optional fields to the news edit
  payload is forward-compatible on the wire (older nodes ignore
  unrecognized fields), but the SDK ↔ node contract for edit
  preservation is a meaningful behaviour change — MINOR rather than
  PATCH per Keep a Changelog.

### Pairs with
- L2 node **v0.37.0**: server-side projection now applies these
  override fields on top of the original payload instead of
  collapsing the response to a content string.
- Desktop **v1.19.0+**: ComposeView pre-loads and resubmits all three
  fields so they survive end-to-end.
- Web **v0.33.0**: same pre-load + resubmit pattern.

## [0.16.0] - 2026-05-12

### Changed
- **`getUnreadCounts()` return type widened to include `mentions`.**
  The response shape is now `{ unread: Record<string, number>; mentions?: Record<string, number> }`.
  `mentions[channelId]` is the count of unread messages that @-mention
  the viewer in that channel (paired with l2-node ≥ v0.33.0). The
  field is marked optional so older nodes that don't set it remain
  fully compatible — callers should treat `undefined` as "no mention
  info available" rather than zero. No code change required for
  callers that don't read mentions yet.

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
