/**
 * Encrypted media (P5 / D6, protocol §8 + spec 04 §9).
 *
 * Files attached to encrypted DMs and channels are sealed with a fresh per-file
 * XChaCha20-Poly1305 key BEFORE they touch IPFS. The per-file key never gets its
 * own envelope: it rides inside the message's already-encrypted content blob
 * (a {@link MediaDescriptor} in `content.media`), which is itself sealed under the
 * channel epoch key / DM conv key. The members who can read the message can
 * therefore recover every file key for free — and the node, holding no key, serves
 * the ciphertext blindly.
 *
 * Mirrors the same `aad = "ogmara-media-v1"` domain tag in sdk-rust so a blob
 * encrypted by one impl decrypts in the other.
 */
import { aeadEncrypt, aeadDecrypt, KEY_LEN, AEAD_NONCE_LEN } from './crypto';

/** AEAD associated data binding every encrypted media blob to its purpose. */
export const MEDIA_AAD = new TextEncoder().encode('ogmara-media-v1');

/**
 * A decrypted attachment, carried INSIDE the message ciphertext (spec 04 §9.2).
 * Everything here is hidden from the node — including the real MIME type and
 * filename. The on-wire `Attachment` keeps only `{ cid, size_bytes }` + a generic
 * `application/octet-stream` MIME (spec 04 §9.3).
 */
export interface MediaDescriptor {
  /** CID of the ENCRYPTED blob on IPFS. */
  cid: string;
  /** Plaintext byte size (UI hint; the blob on IPFS is ~16 bytes larger). */
  size: number;
  /** Real MIME type (e.g. `image/png`) — hidden from the node. */
  mime: string;
  /** Original filename — hidden from the node. */
  name?: string;
  /** 32-byte per-file key. */
  key: Uint8Array;
  /** 24-byte nonce for the file content. */
  nonce: Uint8Array;
  /** CID of the encrypted thumbnail blob, if any. */
  tcid?: string;
  /** 24-byte nonce for the thumbnail (reuses {@link MediaDescriptor.key}). */
  tnonce?: Uint8Array;
}

/** Output of {@link encryptFile}: upload `cipher`, keep `key`/`nonce` for the descriptor. */
export interface EncryptedFile {
  /** Ciphertext (`ct || tag`) — upload this opaque blob via `uploadMedia(..., { encrypted: true })`. */
  cipher: Uint8Array;
  /** 32-byte per-file key (goes into the {@link MediaDescriptor}). */
  key: Uint8Array;
  /** 24-byte file nonce. */
  nonce: Uint8Array;
}

function requireCsprng(): Crypto {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available for media encryption');
  }
  return crypto;
}

/** Generate a fresh 32-byte per-file key. Throws if no CSPRNG is available. */
export function randomFileKey(): Uint8Array {
  return requireCsprng().getRandomValues(new Uint8Array(KEY_LEN));
}

function randomNonce(): Uint8Array {
  return requireCsprng().getRandomValues(new Uint8Array(AEAD_NONCE_LEN));
}

/**
 * Encrypt file bytes with a fresh per-file key (spec 04 §9.1). The returned
 * `cipher` is uploaded as an opaque blob; `key`/`nonce` go into the
 * {@link MediaDescriptor} that rides inside the sealed message content.
 */
export function encryptFile(plaintext: Uint8Array): EncryptedFile {
  const key = randomFileKey();
  const nonce = randomNonce();
  const cipher = aeadEncrypt(key, nonce, plaintext, MEDIA_AAD);
  return { cipher, key, nonce };
}

/**
 * Encrypt a thumbnail under an existing file key (distinct nonce — never reuse a
 * `(key, nonce)` pair). Returns the ciphertext to upload and the nonce to record
 * in {@link MediaDescriptor.tnonce}.
 */
export function encryptThumbnail(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
): { cipher: Uint8Array; nonce: Uint8Array } {
  const nonce = randomNonce();
  const cipher = aeadEncrypt(fileKey, nonce, plaintext, MEDIA_AAD);
  return { cipher, nonce };
}

/** Decrypt an encrypted media (or thumbnail) blob. Throws on auth failure. */
export function decryptMedia(
  cipher: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  return aeadDecrypt(key, nonce, cipher, MEDIA_AAD);
}

/**
 * Serialize a {@link MediaDescriptor} for inclusion in the (about-to-be-encrypted)
 * message content blob. Short keys keep the sealed payload compact. Inverse:
 * {@link mediaFromWire}.
 */
export function mediaToWire(m: MediaDescriptor): Record<string, unknown> {
  return {
    cid: m.cid,
    size: m.size,
    mime: m.mime,
    name: m.name ?? null,
    key: m.key,
    nonce: m.nonce,
    tcid: m.tcid ?? null,
    tnonce: m.tnonce ?? null,
  };
}

/** Parse a {@link MediaDescriptor} decoded from the message content blob. */
export function mediaFromWire(o: Record<string, unknown>): MediaDescriptor {
  return {
    cid: String(o.cid),
    size: Number(o.size ?? 0),
    mime: String(o.mime ?? 'application/octet-stream'),
    name: (o.name as string) ?? undefined,
    key: o.key as Uint8Array,
    nonce: o.nonce as Uint8Array,
    tcid: (o.tcid as string) ?? undefined,
    tnonce: (o.tnonce as Uint8Array) ?? undefined,
  };
}

/**
 * Strip a {@link MediaDescriptor} down to the non-identifying on-wire `Attachment`
 * (spec 04 §9.3): the CID is already public on IPFS, the size is approximate, and
 * the MIME is generic. No filename, no thumbnail CID — those stay in the ciphertext.
 */
export function mediaToWireAttachment(m: MediaDescriptor): {
  cid: string;
  mime_type: string;
  size_bytes: number;
} {
  return { cid: m.cid, mime_type: 'application/octet-stream', size_bytes: m.size };
}
