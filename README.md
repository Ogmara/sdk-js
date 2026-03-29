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

## Crypto Dependencies

- `@noble/ed25519` -- Ed25519 signing (same algorithm as Klever)
- `@noble/hashes` -- Keccak-256 hashing (Klever ecosystem)

No native dependencies. Works in browsers and Node.js.

## License

MIT
