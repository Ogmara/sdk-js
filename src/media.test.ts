import { describe, it, expect } from 'vitest';
import {
  encryptFile,
  encryptThumbnail,
  decryptMedia,
  randomFileKey,
  mediaToWire,
  mediaFromWire,
  mediaToWireAttachment,
  MEDIA_AAD,
  type MediaDescriptor,
} from './media';
import { aeadEncrypt, aeadDecrypt } from './crypto';
import { encryptDmContent, decryptDmContent } from './dm';
import { computeConversationId } from './envelope';

const range = (start: number, end: number): Uint8Array =>
  Uint8Array.from({ length: end - start + 1 }, (_, i) => start + i);

describe('Encrypted media (P5)', () => {
  it('encryptFile → decryptMedia roundtrips', () => {
    const plain = range(0, 199);
    const { cipher, key, nonce } = encryptFile(plain);
    expect(key.length).toBe(32);
    expect(nonce.length).toBe(24);
    expect(cipher.length).toBe(plain.length + 16); // + Poly1305 tag
    const out = decryptMedia(cipher, key, nonce);
    expect(out).toEqual(plain);
  });

  it('thumbnail reuses the file key with a distinct nonce', () => {
    const { key, nonce } = encryptFile(range(1, 50));
    const thumb = range(60, 90);
    const t = encryptThumbnail(thumb, key);
    expect(t.nonce).not.toEqual(nonce); // fresh nonce, never reused
    expect(decryptMedia(t.cipher, key, t.nonce)).toEqual(thumb);
  });

  it('wrong key fails authentication', () => {
    const { cipher, nonce } = encryptFile(range(1, 32));
    expect(() => decryptMedia(cipher, randomFileKey(), nonce)).toThrow();
  });

  it('descriptor survives wire round-trip (keys + optional fields)', () => {
    const m: MediaDescriptor = {
      cid: 'bafyTEST',
      size: 1234,
      mime: 'image/png',
      name: 'secret.png',
      key: range(1, 32),
      nonce: range(33, 56),
      tcid: 'bafyTHUMB',
      tnonce: range(57, 80),
    };
    const back = mediaFromWire(mediaToWire(m));
    expect(back).toEqual(m);
  });

  it('wire attachment is stripped to non-identifying fields', () => {
    const m: MediaDescriptor = {
      cid: 'bafyX',
      size: 999,
      mime: 'image/png',
      name: 'private.png',
      key: range(1, 32),
      nonce: range(1, 24),
    };
    const a = mediaToWireAttachment(m);
    expect(a).toEqual({ cid: 'bafyX', mime_type: 'application/octet-stream', size_bytes: 999 });
    expect(JSON.stringify(a)).not.toContain('private.png'); // no filename leak
    expect(JSON.stringify(a)).not.toContain('image/png'); // no real-mime leak
  });

  it('media descriptors ride inside the sealed DM content (hidden from node)', () => {
    const convKey = range(1, 32);
    const convId = computeConversationId('klv1aaa', 'klv1bbb');
    const file = encryptFile(range(0, 99));
    const media: MediaDescriptor[] = [
      { cid: 'bafyimg', size: 100, mime: 'image/jpeg', name: 'cat.jpg', key: file.key, nonce: file.nonce },
    ];
    const enc = encryptDmContent(convKey, convId, 3, { text: 'look', media });
    // The sealed ciphertext must not expose the filename or per-file key.
    expect(new TextDecoder('utf-8', { fatal: false }).decode(enc.content)).not.toContain('cat.jpg');
    const out = decryptDmContent(convKey, convId, 3, enc.content, enc.nonce);
    expect(out.text).toBe('look');
    expect(out.media).toHaveLength(1);
    expect(out.media![0].cid).toBe('bafyimg');
    expect(out.media![0].key).toEqual(file.key);
  });

  it('cross-impl KAT: fixed key/nonce/plaintext → fixed ciphertext (mirror sdk-rust)', () => {
    // Deterministic vector so sdk-rust asserts the identical bytes. file_key = 1..32,
    // nonce = 1..24, plaintext = "ogmara", aad = MEDIA_AAD ("ogmara-media-v1").
    const key = range(1, 32);
    const nonce = range(1, 24);
    const plaintext = new TextEncoder().encode('ogmara');
    const cipher = aeadEncrypt(key, nonce, plaintext, MEDIA_AAD);
    const hex = Buffer.from(cipher).toString('hex');
    // Fixed KAT — sdk-rust `media`/`crypto` must reproduce it byte-for-byte. Do NOT
    // bless a new value with `-u`: a change here means the AEAD or AAD drifted.
    expect(hex).toBe('dabfaaef612395d76fade0ec7c7780daeee008e5d398');
    // Sanity: decrypt path agrees.
    expect(aeadDecrypt(key, nonce, cipher, MEDIA_AAD)).toEqual(plaintext);
  });
});
