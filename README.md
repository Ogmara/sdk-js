# @ogmara/sdk

JavaScript/TypeScript SDK for the [Ogmara](https://ogmara.org) decentralized chat and news platform on [Klever](https://klever.org) blockchain.

## Features

- REST API client for all L2 node endpoints (public + authenticated)
- WebSocket client with auto-reconnect for real-time subscriptions
- Klever wallet signing (Ed25519 + Keccak-256)
- Embeddable feed widget for third-party websites
- Full TypeScript type definitions
- Zero framework dependencies (works with any JS environment)

## Install

```bash
npm install @ogmara/sdk
```

## Quick Start

```ts
import { OgmaraClient, WalletSigner } from '@ogmara/sdk';

// Read-only client (no auth)
const client = new OgmaraClient({ nodeUrl: 'http://localhost:41721' });
const health = await client.health();
console.log(`Node v${health.version}, ${health.peers} peers`);

// List channels
const channels = await client.listChannels();
channels.channels.forEach(ch => console.log(`#${ch.channel_id} ${ch.slug}`));

// Authenticated client
const signer = await WalletSigner.fromHex('your_hex_private_key');
client.withSigner(signer);
await client.sendMessage(1, 'Hello Ogmara!');
```

## WebSocket Subscriptions

```ts
import { subscribe } from '@ogmara/sdk';

const sub = subscribe({
  nodeUrl: 'http://localhost:41721',
  channels: ['1', '2'],
  onEvent: (event) => {
    if (event.type === 'message') {
      console.log('New message:', event.envelope);
    }
  },
  onStateChange: (connected) => {
    console.log(connected ? 'Connected' : 'Disconnected');
  },
});

// Subscribe to more channels
sub.subscribe(['3']);

// Clean up
sub.close();
```

## Embeddable Widget

For embedding Ogmara feeds on any website:

```html
<div id="ogmara-feed"></div>
<script src="https://cdn.ogmara.org/widget.js"></script>
<script>
  Ogmara.feed({
    element: '#ogmara-feed',
    node: 'https://node1.ogmara.org',
    channel: '1',
    theme: 'auto',  // 'light', 'dark', or 'auto'
    maxMessages: 50
  });
</script>
```

Build the widget:
```bash
npm run build:widget
# Output: dist/widget.global.js
```

## Modules

| Module | What |
|--------|------|
| `client` | HTTP API client with all REST endpoints |
| `auth` | Klever wallet signing, envelope construction, bech32 encoding |
| `ws` | WebSocket subscription client with auto-reconnect |
| `widget` | Embeddable feed widget (IIFE build for CDN) |
| `types` | Full TypeScript type definitions |
| `channelKeyCommit` | Channel key commitments + arbitration rank, typed key-envelope errors (l2-node 0.143.0+) |
| `epochKey` | `establishEpochKey` — the shared channel key-epoch protocol — and `verifyChannelKeyWrap` |

### Channel key epochs (l2-node 0.143.0+)

Encrypted channels rotate their key per epoch, and the node keeps exactly one
winning key per epoch: the lowest `(key_ts, key_commitment)` pair, final 120 s
after the node recorded it. Use `establishEpochKey(deps)` instead of writing
your own rotation logic — it reuses one key across retries, publishes to your
own device first, adopts another member's winning key only from a wrap it has
verified (`verifyChannelKeyWrap`), and escalates to the next epoch when the
winner never reaches you. Refuse to use it on nodes whose `/health` `features`
lack `key_commitment_v1`.

You must pass `highestEpochSeen` and `epochKnownToExist`, both from
AUTHENTICATED evidence only: an epoch whose channel message you decrypted,
whose wrap verified, or a commitment read from another node — never a bare
`key_epoch` number from a message (any member can write any number there; the
SDK cannot tell, so this contract is the protection). When your node has no
state for an epoch the channel already uses, the result is `node_lagging` and
no key is created there — rotate to its `recoveryEpoch` (gated by
`EscalationGate`, once per channel per 10 min); with `unrecoverableHere: true`
that epoch is beyond what this node accepts (its highest + 256), so switch
nodes or surface it instead. If the node's highest epoch
cannot be read the call fails closed (`failed`, retryable).
`key_epoch_too_far` comes back as `failed` with `epochTooHigh`: surface it,
never retry at another epoch. `established.uncovered` / `rejected` describe
your home node only.

A network partition during a rotation can split an epoch across nodes, and no
node-to-node sync repairs it (this is an open residual). Two mitigations:
pass `peerCommitments` — query other nodes' `getKeyCommitment` with
`Promise.allSettled`, return the answers you got, throw only if none answered
(a 404 from a node where you are not a member is "no answer") — and you get
`split` before anything is confirmed (`peerQuorum`, default 1, sets how many
peers must agree; with 1 a single hostile peer can force a gated rotation;
with more, a dissent below the quorum is never confirmed over, so a hostile
peer can still DELAY confirmation, about 75-90 min per epoch, before
`unconfirmed_exhausted`). With peers known but none reachable, nothing is
ever confirmed — return `[]` only when you truly have no peer nodes;
and treat a channel message at your confirmed epoch that your key cannot
decrypt as the signal to rotate (gated — anyone can send garbage ciphertext,
the gate is the rate limit). After `maxUnconfirmedCalls` (5) calls in a row
end unconfirmed for an epoch you get `unconfirmed_exhausted`. Always pass a
`guard` that throws on account switch, and make every injected dep time out;
one call per channel and epoch runs at a time (`waiting` / `in_flight`; a lock
older than `maxTotalMs` + 60 s is taken over), and a call whose pending key is
cleared mid-way stops (`waiting` / `pending_lost`).

By default a key is returned only once the node reports its winner **final**
(≤ ~2 min after a rotation). Clients that cannot wait may pass
`onUnconfirmed` to receive the key as soon as it is the node's (not yet final)
winner and send under it — at the risk that a better-ranked key still
supersedes it, orphaning those messages for every other member. The SDK's
simulator measures that risk (`npm test` prints `provisionalOrphaned`).

### Channel keyring (0.68.0+)

`ChannelKeyring` is the one store of channel epoch keys for web, desktop and
mobile, and its mapping to the key vault's `chan` map. Keep one per account
and `clear()` it on sign-out / account switch.

```ts
const ring = new ChannelKeyring({ generation: () => accountGeneration });
ring.importFromVault(openKeyVault(bk, blob).chan, gen);
// node-served key: check the epoch binding first; it stays untrusted
if (acceptFetchedEnvelope(epoch, env.key_epoch)) ring.put(scopeHex, epoch, key, { source: 'fetch', pair, generation: gen });
// a wrap whose author verifyChannelKeyWrap verified, pair checked against the node
ring.put(scopeHex, epoch, key, { source: 'wrap', pair, verified: true, final, generation: gen });
ring.keysAt(scopeHex, epoch);                                  // decrypt, primary first (copies: compare bytes)
ring.bestForSend(scopeHex, { maxEpoch: nodeHighest + 256 });   // trusted (or own provisional) only
ring.latestVerified(scopeHex, { maxEpoch: nodeHighest + 256 })?.epoch ?? 0; // highestEpochSeen / rotation base
// backup: re-open and import the REMOTE vault first (never overwrite another device's keys)
ring.importFromVault(openKeyVault(bk, await fetchRemoteVault()).chan, gen);
const { chan, commitToken } = ring.prepareExport(gen);   // no side effect
await publishVault(sealKeyVault(bk, { conv, chan }));
ring.commitExport(commitToken, gen);                      // only after a successful publish
```

Three different checks — never confuse them:

- **pair-consistent** (`verified`): the `(keyTs, commitment)` pair re-hashes
  to the key. A hostile node can make that true for any key of its own.
- **author-verified** (`source: 'establish' | 'wrap'`): our own key, or a wrap
  whose author and membership `verifyChannelKeyWrap` verified. `fetch`,
  `legacy` and `vault` keys are not; `markVerified` on them returns
  `'needs_author_proof'` — verify the wrap, then re-`put` with `source: 'wrap'`.
- **final** (`final`): the node reported the pair as the epoch's final winner.

A key is **trusted** when it is author-verified and pair-consistent and not
provisional; only trusted keys are sent under (`bestForSend`) or count as
evidence (`latestVerified`; `finalOnly` for final ones).

Rules (each is a tested invariant, see `src/channelKeyring.property.test.ts`):

- **Never lose a key of yours.** A different key at a held epoch is kept as
  an alternate; keys are stored by copy. The keyring itself only refuses or
  evicts node-served keys (never vouched for by an author — they can be
  served again) and refuses other members' wraps beyond the member caps;
  a commitment-less node-served key is not kept at an occupied epoch. Keys
  leave a backup only as node-served keys beyond a quarter of the budget, or
  through a `pruneUnverified` the user confirmed.
- **Primary order:** trusted+final > trusted > provisional > own / vault >
  node-served. A strictly better key is promoted; among equals the first seen
  key stays (a second trusted key wins only when it is final and the first is
  not).
- **Provisional keys** are finalised only by an author source (`establish` /
  `wrap`) with `provisional: false` or `verified` + `final`; a fetch or vault
  copy of the same bytes never finalises them, even claiming `final` (a vault
  copy makes them exportable).
- **Your responsibility:** `source: 'wrap'` only after `verifyChannelKeyWrap`
  verified the author; `final` only for the node's final winner. Residual: a
  malicious member's verified wrap that a hostile node calls final outranks
  your own non-final key (yours stays held); between two final keys the first
  seen stays.
- **Caps:** 4 alternates per epoch (the newest unprotected key is shed, so a
  flood cannot push out the first key seen); 512 untrusted epochs per scope
  ABOVE its highest trusted epoch (restored vault epochs count there and are
  never evicted, so a hostile node cannot grow your backup across sessions;
  restored history at or below it does not count, new node-served history
  there is limited to 64 epochs per scope per session); 4096 epochs per
  scope absolute for new node-served epochs. Protected keys are never
  refused.
- **Node-served keys are never protected**, not even once backed up: they are
  written as `S:E#ns<n>`, come back node-served, and are the first to go at
  every cap. Re-`put` one as `wrap` after `verifyChannelKeyWrap` to keep it.
- **Vault byte budget:** the export stays within 1.5 MiB (estimated; the node
  takes 2 MiB sealed). Node-served keys only fill up to a quarter of it, so
  they can never crowd out your keys; if your protected keys alone exceed
  the budget the export throws `ChannelKeyringError('vault_too_large')` —
  show it and offer `pruneUnverified({dryRun: true})` first, then with the
  user's confirmation. Default: node-served keys only (zero risk);
  `classes: ['restoredAlternates', 'memberWraps']` and `scopes: [hostile]` on
  request (warn when `byClass.ownAlternatesAtRisk.count > 0` — those may be
  your own outranked keys); restored primary-name keys only with
  `includeRestoredPrimaries`, the last resort. Pruned keys are not
  re-imported this session, so the next backup drops them.
- **`ownSlot: true` is REQUIRED for every wrap taken from your OWN enc-key
  slot whose verified author is your own wallet** (keys you established,
  re-verified after a restart). Without it the key counts as another
  member's: once the member cap of that channel is full such a put is
  `'refused'` (that epoch cannot be decrypted until re-put with `ownSlot`),
  and a `classes: ['memberWraps']` prune would remove it. After a restart,
  re-verify the latest OWN epoch (with `ownSlot`) BEFORE processing other
  members' wraps.
- **Pass `maxEpoch` (node highest + 256) to every `put` of a key that is not
  yours** and to `importFromVault(chan, gen, {maxEpoch})`: keys of others
  above it are refused at put time; restored keys of unknown provenance above
  it are classed `memberWraps`, so a restored member flood can be pruned
  without touching history below it. A FINAL (node-arbitrated) member wrap
  is exempt from the member caps (only the absolute 4096-epoch cap bounds
  it), so a flood can never stop the channel's real key from arriving.
- `memberWraps` reaches member keys still sourced `wrap` in this session and
  restored keys above the import ceiling; other restored keys are
  `restoredPrimaries` / `restoredAlternates`.
- **Malicious members** (refuse-only, never evicting): above the latest final
  epoch at most 512 epochs per channel that may be another member's (restored
  unknown keys count after a restart, but are never removed for it); below
  it at most 64 new member epochs per session; at most 4 member keys per
  epoch. Re-put your own key with `ownSlot: true` (author is your wallet) —
  it is never capped. A hostile member can make further member wraps be
  refused, never delete yours.
- **Legacy channels:** `bestForSendLegacy(scope, {isLegacyEpoch, maxEpoch})`
  returns a key only when the channel holds nothing but commitment-less keys
  a node served this session; derive `isLegacyEpoch` from data the node
  cannot forge, never assume it after a restart.
- **Downgrades** ("this pair lost") are client state; the keyring never
  lowers a key.
- **Backups never shrink silently.** `exportForVault()` holds every
  exportable key of yours or restored, node-served keys within their quarter
  of the budget, and every vault entry the keyring could not interpret,
  collision-free, in canonical order per slot: `S:E`, `S:E#pri` (a copy of the
  primary, for each scope's 16 highest epochs while the record is within half
  the budget), `S:E#alt<n>` ascending from 5 (up to 64), `S:E#ovf<n>`;
  unknown entries last. Older clients keep 4 alternates and rewrite `S:E` and
  `#alt1..#alt4`: with room they renumber ours; with their own slot full they
  keep ours verbatim under names they never rewrite, and `#pri` backs up the
  `S:E` they overwrite. A node-served key never gets the primary name `S:E`.
  Old mobile keeps at most 1024 unknown entries. More than 8192
  unreadable entries make the export throw `ChannelKeyringError(
  'opaque_overflow')` instead of dropping them; an outdated `generation`
  throws `'stale'`.
- **Hostile epochs.** Check node-served envelopes with
  `acceptFetchedEnvelope(requestedEpoch, envelopeEpoch)` and pass `maxEpoch`.
- **`allowUnverified`** is ONLY for scopes you know are pre-arbitration (no
  commitments anywhere). Its fallback never returns a key a node served this
  session (unless an author source re-put it) or one restored from an alias
  name.
- **Malicious members** can author verified wraps at any epoch: pass
  `maxEpoch` to `latestVerified` as well as to `bestForSend`.

After a restart every key comes back as `vault` (the vault records no
provenance), so nothing is trusted — `latestVerified` is null and the
rotation floor 0 — until you re-verify your own slot's wrap and re-put the key
as `wrap`. Do that before sending; never use `allowUnverified` to bridge it.

The vault format is unchanged (same `chan` map, same primary names), so older
clients read a 0.68.0 backup and vice versa; names they do not parse they keep
verbatim. `sealKeyVault` / `openKeyVault` also rename an own `__proto__`
entry name (which the msgpack decoder rejects) to `%proto_NN`, keeping its
bytes, and repair a vault sealed earlier with such a name.

## Crypto Dependencies

- `@noble/ed25519` -- Ed25519 signing (same algorithm as Klever)
- `@noble/hashes` -- Keccak-256 hashing (Klever ecosystem)

No native dependencies. Works in browsers and Node.js.

## License

MIT
