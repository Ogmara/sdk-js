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
export { WalletSigner, buildDeviceClaim, randomNonceHex } from './auth';
export type { ExternalSigner, AuthHeaders, NodeBinding } from './auth';
export {
  generateDeviceEncKeypair,
  encPublicKeyHex,
  normalizeWalletSig,
  addressToPubkey,
  encBindClaim,
  encRevokeClaim,
  buildDeviceEncBinding,
  buildDeviceEncRevoke,
} from './encryption';
export type {
  DeviceEncKeypair,
  WalletSignFn,
  DeviceEncBindingParams,
  DeviceEncRevokeParams,
} from './encryption';
export {
  aeadEncrypt,
  aeadDecrypt,
  hkdfSha256,
  x25519Dh,
  x25519Public,
  wrapKey,
  wrapKeyWith,
  unwrapKey,
  AEAD_NONCE_LEN,
  AEAD_TAG_LEN,
  KEY_LEN,
} from './crypto';
export type { WrappedKey } from './crypto';
export {
  KeyScopeKind,
  dmContentAad,
  randomConvKey,
  encryptDmContent,
  decryptDmContent,
  wrapConvKey,
  unwrapConvKey,
  buildChannelKeyEnvelope,
  buildEncryptedDirectMessage,
  buildEncryptedDmEdit,
  buildEncryptedChannelMessage,
} from './dm';
export type {
  DmPlaintext,
  EncryptedDmContent,
  ChannelKeyEnvelopeParams,
  EncryptedDmParams,
  EncryptedDmEditParams,
  EncryptedChannelMessageParams,
} from './dm';
export { solveChallenge, solveChallengeAsync } from './pow';
export type { PowChallenge, PowSolution, PowResult } from './pow';
export { WsSubscription, subscribe } from './ws';
export type { WsOptions } from './ws';
export {
  buildEnvelope, buildChatMessage, buildNewsPost, buildNewsComment, buildProfileUpdate,
  buildFollow, buildUnfollow, buildReaction, buildRepost, buildDirectMessage,
  computeConversationId, computeChannelScope, buildChannelCreate, buildChannelUpdate, buildChannelJoin,
  buildChannelLeave, buildChannelMute,
  buildChatEdit, buildChatDelete, buildChatReaction,
  buildDmEdit, buildDmDelete, buildDmReaction,
  buildNewsEdit, buildNewsDelete,
  buildSettingsSync, buildReport, buildCounterVote,
} from './envelope';
export * from './types';
export {
  extractHashtags,
  parseMessageContent,
  applyFormatting,
  pingNode,
  discoverAndPingNodes,
  validateNodeUrl,
  DEFAULT_NODE_URL,
  canPost,
  CHANNEL_TYPE_PUBLIC,
  CHANNEL_TYPE_READ_PUBLIC,
  CHANNEL_TYPE_PRIVATE,
} from './utils';
export type { TextSegment, NodeWithPing } from './utils';
export {
  discoverNodesViaSc,
  discoverNodeUrlsViaSc,
  SC_NETWORKS,
} from './sc_discovery';
export type {
  ScNetwork,
  ScNetworkConfig,
  ScDiscoveredNode,
  ScDiscoveryOptions,
} from './sc_discovery';
