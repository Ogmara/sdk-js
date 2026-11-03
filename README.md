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

## Crypto Dependencies

- `@noble/ed25519` -- Ed25519 signing (same algorithm as Klever)
- `@noble/hashes` -- Keccak-256 hashing (Klever ecosystem)

No native dependencies. Works in browsers and Node.js.

## License

MIT
