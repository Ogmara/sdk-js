/**
 * E2E key-recovery vault (P3, protocol §2.5 / E2E plan D4).
 *
 * The vault is the persistence layer for a user's *symmetric content keys* — DM
 * `conv_key`s and channel epoch `channel_key`s — so a fresh install or a new device
 * can restore full message history. It is sealed under a **backup key** derived
 * deterministically from the wallet's `signMessage("ogmara-keyvault-v1")`:
 *
 *   bk     = HKDF-SHA256(ikm = normalizeWalletSig(sig), salt, info, 32)
 *   vault  = XChaCha20-Poly1305(bk, nonce, msgpack(keyring), aad)
 *
 * Because Klever Extension + K5 both `signMessage` byte-identically to our SDK
 * (validated 2026-06-07; see e2e plan §14), `bk` reproduces on any device without
 * ever exposing the wallet private key. The node stores the blob opaquely (it never
 * holds `bk`) and cannot decrypt it.
 *
 * The device X25519 enc *private* key is deliberately NOT in the vault — each device
 * keeps its own; the vault carries the content keys, which is what makes history
 * recoverable independent of device. Mirrors how SettingsSync syncs per-user state,
 * but with the new XChaCha20-Poly1305 primitive (not the legacy AES-256-GCM/12B).
 */
import { encode, decode } from '@msgpack/msgpack';
import { aeadEncrypt, aeadDecrypt, hkdfSha256, KEY_LEN, AEAD_NONCE_LEN } from './crypto';
import { normalizeWalletSig } from './encryption';
import type { KeyVaultSyncData, KeyVaultResponse } from './types';

/** The fixed string the wallet signs to derive the vault backup key. NEVER change
 *  this — it would orphan every existing vault. */
export const VAULT_SIGN_CLAIM = 'ogmara-keyvault-v1';

/** Current vault payload format version. */
export const VAULT_FORMAT_VERSION = 1;

const VAULT_KDF_SALT = new TextEncoder().encode('ogmara-keyvault-salt-v1');
const VAULT_KDF_INFO = new TextEncoder().encode('xchacha20poly1305');
const VAULT_AAD_BASE = new TextEncoder().encode('ogmara-keyvault-v1');

/** AEAD AAD: the primitive label with the `format_version` appended, so a blob
 *  sealed under one format can't be opened (or downgraded) under another. */
function vaultAad(formatVersion: number): Uint8Array {
  const aad = new Uint8Array(VAULT_AAD_BASE.length + 1);
  aad.set(VAULT_AAD_BASE);
  aad[VAULT_AAD_BASE.length] = formatVersion & 0xff;
  return aad;
}

/**
 * The decrypted keyring carried by the vault. Keys are 32-byte symmetric content
 * keys; the composite string keys mirror the in-memory client caches verbatim:
 * - `conv`: DM conv keys keyed by `${convIdHex}:${epoch}:${author}`
 * - `chan`: channel epoch keys keyed by `${channelScopeHex}:${epoch}`
 */
export interface VaultKeyring {
  conv: Record<string, Uint8Array>;
  chan: Record<string, Uint8Array>;
}

/** An empty keyring (starting point before merging in cached keys). */
export function emptyKeyring(): VaultKeyring {
  return { conv: {}, chan: {} };
}

/**
 * Derive the 32-byte vault backup key from a wallet `signMessage(VAULT_SIGN_CLAIM)`
 * return. Accepts hex / base64-of-hex / raw bytes (see {@link normalizeWalletSig}),
 * so it is identical across Extension, K5, and local signers. Derive ONCE per session
 * and cache in memory — never call the wallet per vault operation (each `signMessage`
 * shows a popup and takes seconds).
 */
export function deriveVaultBackupKey(walletSig: string | Uint8Array): Uint8Array {
  const ikm = normalizeWalletSig(walletSig);
  return hkdfSha256(ikm, VAULT_KDF_SALT, VAULT_KDF_INFO, KEY_LEN);
}

/**
 * Seal a keyring into a {@link KeyVaultSyncData} ready to publish. `nonce` is fresh
 * random (24 bytes) — the caller must NOT reuse a nonce under the same `bk`.
 */
export function sealKeyVault(bk: Uint8Array, keyring: VaultKeyring): KeyVaultSyncData {
  if (bk.length !== KEY_LEN) throw new Error(`vault backup key must be ${KEY_LEN} bytes`);
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available for vault nonce');
  }
  const nonce = crypto.getRandomValues(new Uint8Array(AEAD_NONCE_LEN));
  const plaintext = new Uint8Array(encode({ conv: keyring.conv, chan: keyring.chan }));
  const encrypted_vault = aeadEncrypt(bk, nonce, plaintext, vaultAad(VAULT_FORMAT_VERSION));
  return { encrypted_vault, nonce, format_version: VAULT_FORMAT_VERSION };
}

/**
 * Open a vault fetched from the node back into a keyring. `data` may be the raw GET
 * response ({@link KeyVaultResponse}, number[] arrays) or already-typed bytes. Throws
 * on any authentication failure (wrong wallet/key, tampering) or unknown format.
 */
export function openKeyVault(
  bk: Uint8Array,
  data: KeyVaultSyncData | KeyVaultResponse,
): VaultKeyring {
  if (bk.length !== KEY_LEN) throw new Error(`vault backup key must be ${KEY_LEN} bytes`);
  const fmt = data.format_version;
  if (fmt !== VAULT_FORMAT_VERSION) {
    throw new Error(`unsupported key-vault format_version ${fmt}`);
  }
  const ct = data.encrypted_vault instanceof Uint8Array
    ? data.encrypted_vault
    : Uint8Array.from(data.encrypted_vault as number[]);
  const nonce = data.nonce instanceof Uint8Array
    ? data.nonce
    : Uint8Array.from(data.nonce as number[]);
  if (nonce.length !== AEAD_NONCE_LEN) throw new Error('key-vault nonce wrong length');
  const plaintext = aeadDecrypt(bk, nonce, ct, vaultAad(fmt));
  const obj = decode(plaintext) as { conv?: unknown; chan?: unknown };
  return {
    conv: coerceKeyMap(obj.conv),
    chan: coerceKeyMap(obj.chan),
  };
}

/** Coerce a decoded msgpack map into `Record<string, Uint8Array>`, dropping any
 *  entry whose value is not a 32-byte key (defensive against a corrupt/forged blob). */
function coerceKeyMap(v: unknown): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  if (v && typeof v === 'object') {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (val instanceof Uint8Array && val.length === KEY_LEN) out[k] = val;
    }
  }
  return out;
}
