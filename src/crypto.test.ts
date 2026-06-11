import { describe, it, expect } from 'vitest';
import {
  aeadEncrypt,
  aeadDecrypt,
  hkdfSha256,
  wrapKey,
  wrapKeyWith,
  unwrapKey,
  x25519Public,
  AEAD_NONCE_LEN,
  AEAD_TAG_LEN,
  KEY_LEN,
} from './crypto';

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const range = (start: number, end: number): Uint8Array =>
  Uint8Array.from({ length: end - start + 1 }, (_, i) => start + i);

describe('crypto core — cross-impl with sdk-rust crypto.rs', () => {
  // --- HKDF-SHA256: RFC 5869 Test Case 1 (externally verifiable KAT) ----------
  it('HKDF-SHA256 matches RFC 5869 case 1', () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = range(0x00, 0x0c); // 00..0c (13 bytes)
    const info = range(0xf0, 0xf9); // f0..f9 (10 bytes)
    const okm = hkdfSha256(ikm, salt, info, 42);
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  // --- AEAD XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1 KAT ----------
  it('XChaCha20-Poly1305 matches draft A.3.1 KAT', () => {
    const key = range(0x80, 0x9f); // 80..9f (32 bytes)
    const nonce = range(0x40, 0x57); // 40..57 (24 bytes)
    const aad = Uint8Array.from([
      0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ]);
    const pt = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const ct = aeadEncrypt(key, nonce, pt, aad);
    expect(toHex(ct)).toBe(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
        '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
        '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
        '21f9664c97637da9768812f615c68b13b52e' +
        'c0875924c1c7987947deafd8780acf49',
    );
    // Roundtrip + AAD binding.
    expect(aeadDecrypt(key, nonce, ct, aad)).toEqual(pt);
    expect(() => aeadDecrypt(key, nonce, ct, new TextEncoder().encode('wrong aad'))).toThrow();
  });

  // --- ECIES key wrap: roundtrip + deterministic Ogmara KAT (cross-impl) ------
  it('wrap/unwrap roundtrips and rejects wrong context', () => {
    const k = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 7) & 0xff);
    const recipPriv = range(0x01, 0x20);
    const recipPub = x25519Public(recipPriv);
    const ctx = new TextEncoder().encode('ctx');
    const w = wrapKey(k, recipPub, ctx);
    expect(w.wrapped.length).toBe(KEY_LEN + AEAD_TAG_LEN);
    expect(w.nonce.length).toBe(AEAD_NONCE_LEN);
    expect(unwrapKey(w, recipPriv, ctx)).toEqual(k);
    expect(() => unwrapKey(w, recipPriv, new TextEncoder().encode('other'))).toThrow();
  });

  // Deterministic wrap KAT — identical literals asserted in sdk-rust crypto.rs
  // (`wrap_cross_impl_vector`). recipient priv = 0x01..0x20, ephemeral priv =
  // 0x21..0x40, nonce = 0xa0..0xb7, key = 0xff..0xe0 (descending),
  // context = "ogmara-test-context".
  it('wrap KAT is byte-identical to sdk-rust', () => {
    const k = Uint8Array.from({ length: 32 }, (_, i) => 0xff - i);
    const recipPriv = range(0x01, 0x20);
    const recipPub = x25519Public(recipPriv);
    const ephPriv = range(0x21, 0x40);
    const nonce = range(0xa0, 0xb7);
    const ctx = new TextEncoder().encode('ogmara-test-context');

    const w = wrapKeyWith(k, recipPub, ctx, ephPriv, nonce);
    expect(toHex(w.ephPub)).toBe(
      '5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b',
    );
    expect(toHex(w.wrapped)).toBe(
      '68697ad63cd9360b1fcbcd26fa499292df75de990f0467a6034617eeeb88eabe2002135f9016a8d20a157d7fcaf4ae6f',
    );
    expect(unwrapKey(w, recipPriv, ctx)).toEqual(k);
  });
});
