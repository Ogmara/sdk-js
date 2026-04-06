# Building the Ogmara JS/TS SDK

## Prerequisites

- **Node.js** 22+ (via [nodesource](https://github.com/nodesource/distributions))
- npm 10+

## Build

```bash
git clone https://github.com/Ogmara/sdk-js.git
cd sdk-js
npm install
npm run build
```

Output in `dist/`:
- `index.js` — CommonJS
- `index.mjs` — ES modules
- `index.d.ts` — TypeScript declarations

## Test

```bash
npm test
```

All tests are unit tests (no network access required).

## Usage

```bash
npm install @ogmara/sdk
```

Or link locally for development:

```bash
cd sdk-js && npm link
cd ../your-project && npm link @ogmara/sdk
```

```typescript
import { OgmaraClient, WalletSigner } from '@ogmara/sdk';

const client = new OgmaraClient({ nodeUrl: 'https://ogmara.org' });
const health = await client.getHealth();
const channels = await client.getChannels();

// Authenticated operations
const signer = WalletSigner.fromPrivateKey('hex-private-key');
client.setSigner(signer);
await client.postChatMessage(signer, { channelId: 1, content: 'Hello!' });
```

## Known build notes

- `@noble/ed25519` DTS warnings about `getPublicKeyAsync`/`signAsync` are
  non-blocking — the JS build succeeds, only TypeScript type declarations
  show errors. The runtime functions work correctly.
