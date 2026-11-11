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
export {
  WalletSigner,
  buildDeviceClaim,
  buildDmSyncAuthClaim,
  buildPrivateChannelSyncAuthClaim,
  randomNonceHex,
} from './auth';
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
  buildChannelEpochKeyEnvelope,
  buildEncryptedDirectMessage,
  buildEncryptedDmEdit,
  buildEncryptedChannelMessage,
  buildEncryptedChannelEdit,
} from './dm';
export type {
  DmPlaintext,
  EncryptedDmContent,
  ChannelKeyEnvelopeParams,
  DmKeyEnvelopeParams,
  ChannelScopeKeyEnvelopeParams,
  ChannelEpochKeyEnvelopeParams,
  EncryptedDmParams,
  EncryptedDmEditParams,
  EncryptedChannelMessageParams,
  EncryptedChannelEditParams,
} from './dm';
export {
  MEDIA_AAD,
  randomFileKey,
  encryptFile,
  encryptThumbnail,
  decryptMedia,
  mediaToWire,
  mediaFromWire,
  mediaToWireAttachment,
} from './media';
export type { MediaDescriptor, EncryptedFile } from './media';
export { solveChallenge, solveChallengeAsync } from './pow';
export { derivePrivateChannelId } from './channelId';
// Private-channel "verify before cover" (sdk-js 0.66.0, l2-node 0.142.0+):
// client-side verification of member-proofs evidence before wrapping a
// channel key to a member, plus device-claim and enc-key-binding verifiers.
export {
  verifyEnvelopeBytes,
  verifyDeviceClaim,
  verifyDeviceClaimObject,
  deviceClaimCovers,
  verifyEncKeyBinding,
  verifyPrivateMemberProof,
  memberProofBundle,
  filterVerifiedMembers,
  legacyJoinActivationMs,
  MemberProofCache,
  MemberProofsError,
  TESTNET_LEGACY_JOIN_ACTIVATION_MS,
  MAX_TIMESTAMP_DRIFT_MS,
  MAX_EVIDENCE_BYTES,
  MAX_MEMBER_PROOF_ADDRESSES,
  MAX_MEMBER_PROOFS_RESPONSE_BYTES,
  MAX_VERIFICATIONS_PER_RESPONSE,
} from './privateChannelProof';
export type {
  VerifiedEnvelope,
  EnvelopeVerification,
  VerifyEnvelopeOptions,
  VerifiedDeviceClaim,
  DeviceClaimObjectVerification,
  EncKeyBindingVerdict,
  PrivateMemberProofBundle,
  PrivateMemberProofContext,
  PrivateMemberProofResult,
  CreatorSource,
  SeenRemovals,
  FilterVerifiedMembersOptions,
  FilterVerifiedMembersResult,
} from './privateChannelProof';
export type { PrivateChannelIdDerivation } from './channelId';
// Node-arbitrated key epochs (sdk-js 0.67.0, l2-node 0.143.0+ `key_commitment_v1`):
// key commitments + rank, typed publish errors, and the ONE shared epoch
// establishment protocol every client uses.
export {
  KEY_COMMITMENT_DOMAIN,
  KEY_COMMITMENT_LEN,
  KEY_COMMIT_FINALITY_MS,
  KEY_TS_MAX_AGE_MS,
  PENDING_KEY_MAX_AGE_MS,
  KEY_ENVELOPE_RATE_LIMIT,
  KEY_ENVELOPE_SCOPE_RATE_LIMIT,
  KEY_SCOPE_ROW_CAP,
  FEATURE_KEY_COMMITMENT_V1,
  DEFAULT_KEY_ENVELOPE_RETRY_MS,
  MAX_KEY_ENVELOPE_RETRY_MS,
  computeKeyCommitment,
  compareRank,
  sameCandidate,
  isValidKeyCommitment,
  keyCommitmentsEqual,
  keyCommitmentFromHex,
  keyCommitmentToHex,
  parseKeyCommitmentInfo,
  parseKeyCommitmentWinner,
  classifyKeyEnvelopeResponse,
  KeyCommitmentConflictError,
  KeyEnvelopeRateLimitedError,
  KeyEnvelopeRejectedError,
  KeyEnvelopeTransientError,
} from './channelKeyCommit';
export type { KeyRank } from './channelKeyCommit';
export {
  verifyChannelKeyWrap,
  establishEpochKey,
  makeOwnWrapFetcher,
  compareTargets,
  TokenBucket,
  EscalationGate,
  PendingEpochKeyStore,
  DEFAULT_ESTABLISH_OPTIONS,
  validateEstablishOptions,
} from './epochKey';
export type {
  VerifiedChannelKeyWrap,
  VerifyChannelKeyWrapContext,
  ChannelKeyWrapVerification,
  EpochKeyTarget,
  PendingEpochKey,
  EstablishEpochKeyOptions,
  EstablishEpochKeyDeps,
  EstablishEpochKeyOutcome,
  UnconfirmedEpochKey,
} from './epochKey';

// Bot command parsing (protocol §3.3, §3.11). `parseCommand` is the bot
// author's half of the contract — see its doc comment for why a bot must fall
// through silently on a command it does not implement.
export { parseCommand } from './commands';
export type { ParsedCommand, CommandMessage } from './commands';
export { validateBotDescriptor, validateButtons } from './envelope';
export type { PowChallenge, PowSolution, PowResult } from './pow';
export { WsSubscription, subscribe } from './ws';
export type { WsOptions } from './ws';
export {
  buildEnvelope, buildChatMessage, buildNewsPost, buildNewsComment, buildProfileUpdate,
  buildFollow, buildUnfollow, buildReaction, buildRepost, buildDirectMessage,
  computeConversationId, computeChannelScope, buildChannelCreate, buildChannelUpdate, buildChannelJoin,
  buildChannelLeave, buildChannelDelete, buildChannelMute, buildChannelUnmute,
  buildChatEdit, buildChatDelete, buildChatReaction,
  buildDmEdit, buildDmDelete, buildDmReaction,
  buildNewsEdit, buildNewsDelete,
  buildSettingsSync, buildKeyVaultSync, buildReport, buildCounterVote, buildDeviceRevocation,
  buildDeletionRequest, buildInvite,
} from './envelope';
// Private-channel join gate (l2-node 0.140.0+): invite decoding (UNVERIFIED,
// UI only), pending-invite selection, personal invite links, size/TTL limits.
export {
  DEFAULT_INVITE_TTL_MS,
  MAX_INVITE_TTL_MS,
  MIN_INVITE_TTL_MS,
  MAX_INVITE_ENVELOPE_BYTES,
  MAX_INVITER_GRANT_BYTES,
  INVITE_EXPIRY_MARGIN_MS,
  INVITE_FUTURE_TOLERANCE_MS,
  DEFAULT_INVITE_LINK_BASE,
  decodeChannelInvite,
  selectPendingInvite,
  encodeInviteForUrl,
  decodeInviteFromUrl,
  buildPrivateChannelInviteUrl,
  bytesToBase64,
  base64ToBytes,
} from './invite';
export type { DecodedChannelInvite, PendingInvite } from './invite';
export {
  VAULT_SIGN_CLAIM,
  VAULT_FORMAT_VERSION,
  deriveVaultBackupKey,
  sealKeyVault,
  openKeyVault,
  emptyKeyring,
  renameProtoKey,
  renameProtoKeysInVaultPlaintext,
} from './keyVault';
export type { VaultKeyring } from './keyVault';
export {
  ChannelKeyring,
  ChannelKeyringError,
  acceptFetchedEnvelope,
  MAX_ALTS_PER_EPOCH,
  MAX_UNTRUSTED_EPOCHS_PER_SCOPE,
  MAX_EPOCHS_PER_SCOPE,
  FIRST_WRITTEN_ALT_INDEX,
  MAX_SESSION_HISTORY_EPOCHS_PER_SCOPE,
  VAULT_CHAN_SOFT_LIMIT_BYTES,
  PRI_COPIES_PER_SCOPE,
  MAX_PRI_COPIES,
  estimateVaultChanBytes,
  NODE_SERVED_VAULT_SHARE,
  MAX_MEMBER_EPOCHS_PER_SCOPE,
  MAX_OPAQUE_VAULT_ENTRIES,
  MAX_ALT_INDEX,
} from './channelKeyring';
export type {
  ChannelKeySource,
  ChannelKeyPair,
  ChannelKeyPutOptions,
  ChannelKeyMarkOptions,
  ChannelKeyImportOptions,
  ChannelKeyQuery,
  ChannelKeyPruneOptions,
  ChannelKeyPruneResult,
  ChannelKeyPruneClass,
  ChannelKeyPruneClassName,
  ChannelKeyExportToken,
  ChannelKeyPreparedExport,
  ChannelKeyLegacyQuery,
  ChannelKeyPutResult,
  ChannelKeyMarkResult,
  ChannelKeyInfo,
  ChannelKeyHeld,
  ChannelKeyringOptions,
  ChannelKeyringErrorCode,
} from './channelKeyring';
export * from './types';
export {
  extractHashtags,
  normalizeHashtag,
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
  getActiveNodeCount,
  SC_NETWORKS,
} from './sc_discovery';
export type {
  ScNetwork,
  ScNetworkConfig,
  ScDiscoveredNode,
  ScDiscoveryOptions,
} from './sc_discovery';
export {
  getUserRegisteredAt,
  getRegistrationFee,
  getNodeFeeShareBps,
  getNodeEarnings,
  getTotalUnclaimedNodeEarnings,
  getChannelInfo,
  getEscalatedCanonical,
} from './sc_queries';
export type { ScQueryOptions, ScChannelInfo } from './sc_queries';
