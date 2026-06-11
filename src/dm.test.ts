import { describe, it, expect } from 'vitest';
import {
  randomConvKey,
  encryptDmContent,
  decryptDmContent,
  wrapConvKey,
  unwrapConvKey,
  dmContentAad,
} from './dm';
import { x25519Public } from './crypto';
import { computeConversationId } from './envelope';

const range = (start: number, end: number): Uint8Array =>
  Uint8Array.from({ length: end - start + 1 }, (_, i) => start + i);

describe('DM E2E (P1)', () => {
  it('encrypt → decrypt roundtrips and binds conversation + epoch', () => {
    const convKey = range(1, 32);
    const convId = computeConversationId('klv1aaa', 'klv1bbb');
    const enc = encryptDmContent(convKey, convId, 1, { text: 'hello 🔐' });
    expect(enc.nonce.length).toBe(24);
    const out = decryptDmContent(convKey, convId, 1, enc.content, enc.nonce);
    expect(out.text).toBe('hello 🔐');
    expect(out.replyTo).toBeUndefined();

    // Wrong epoch → AAD mismatch → auth failure.
    expect(() => decryptDmContent(convKey, convId, 2, enc.content, enc.nonce)).toThrow();
    // Wrong conversation → AAD mismatch.
    const other = computeConversationId('klv1aaa', 'klv1ccc');
    expect(() => decryptDmContent(convKey, other, 1, enc.content, enc.nonce)).toThrow();
  });

  it('carries reply_to inside the ciphertext', () => {
    const convKey = randomConvKey();
    const convId = computeConversationId('klv1aaa', 'klv1bbb');
    const replyTo = range(100, 131); // 32 bytes
    const enc = encryptDmContent(convKey, convId, 3, { text: 're', replyTo });
    const out = decryptDmContent(convKey, convId, 3, enc.content, enc.nonce);
    expect(out.replyTo && Array.from(out.replyTo)).toEqual(Array.from(replyTo));
  });

  it('wraps conv_key to a recipient device and unwraps it back', () => {
    const convKey = randomConvKey();
    const recipPriv = range(1, 32);
    const recipPub = x25519Public(recipPriv);
    const convId = computeConversationId('klv1aaa', 'klv1bbb');
    const w = wrapConvKey(convKey, recipPub, convId);
    expect(unwrapConvKey(w, recipPriv, convId)).toEqual(convKey);
    // Wrong conversation context → unwrap fails (domain separation).
    const other = computeConversationId('klv1aaa', 'klv1ccc');
    expect(() => unwrapConvKey(w, recipPriv, other)).toThrow();
  });

  it('dmContentAad = conversation_id || epoch_be8', () => {
    const convId = new Uint8Array(32).fill(7);
    const aad = dmContentAad(convId, 0x01020304); // safe integer
    expect(aad.length).toBe(40);
    expect(Array.from(aad.slice(32))).toEqual([0, 0, 0, 0, 1, 2, 3, 4]);
  });
});
