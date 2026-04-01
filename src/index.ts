/**
 * @ogmara/sdk — Client library for the Ogmara decentralized platform.
 *
 * @example
 * ```ts
 * import { OgmaraClient, WalletSigner, subscribe } from '@ogmara/sdk';
 *
 * // Read-only client
 * const client = new OgmaraClient({ nodeUrl: 'http://localhost:41721' });
 * const health = await client.health();
 *
 * // Authenticated client
 * const signer = await WalletSigner.fromHex('your_hex_private_key');
 * client.withSigner(signer);
 * await client.sendMessage(1, 'Hello Ogmara!');
 *
 * // Real-time subscriptions
 * const sub = subscribe({
 *   nodeUrl: 'http://localhost:41721',
 *   channels: ['1', '2'],
 *   onEvent: (event) => console.log(event),
 * });
 * ```
 *
 * @packageDocumentation
 */

export { OgmaraClient } from './client';
export { WalletSigner, buildDeviceClaim } from './auth';
export type { ExternalSigner, AuthHeaders } from './auth';
export { WsSubscription, subscribe } from './ws';
export type { WsOptions } from './ws';
export { buildEnvelope, buildChatMessage, buildNewsPost, buildNewsComment, buildProfileUpdate, buildFollow, buildUnfollow, buildReaction, buildRepost, buildDirectMessage, computeConversationId } from './envelope';
export * from './types';
export {
  extractHashtags,
  parseMessageContent,
  applyFormatting,
  pingNode,
  discoverAndPingNodes,
  validateNodeUrl,
  DEFAULT_NODE_URL,
} from './utils';
export type { TextSegment, NodeWithPing } from './utils';
