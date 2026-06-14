import { describe, it, expect } from 'vitest';
import { decode } from '@msgpack/msgpack';
import {
  randomConvKey,
  encryptDmContent,
  decryptDmContent,
  wrapConvKey,
  unwrapConvKey,
  dmContentAad,
  buildEncryptedDmEdit,
} from './dm';
import { x25519Public } from './crypto';
import { computeConversationId, computeChannelScope } from './envelope';
import { keccak_256 } from '@noble/hashes/sha3';
import { buildEncryptedChannelMessage } from './dm';
import { WalletSigner } from './auth';

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

  it('builds an encrypted DM edit whose enc_content decrypts to the new text', async () => {
    const signer = await WalletSigner.generate();
    const recipient = 'klv1bbb';
    const convKey = randomConvKey();
    const msgId = 'ab'.repeat(32); // 32-byte hex
    const envBytes = await buildEncryptedDmEdit(signer, {
      recipient,
      msgId,
      convKey,
      epoch: 2,
      content: 'corrected text 🔁',
    });

    // Decode envelope → inner edit payload.
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      content: string;
      enc_content: Uint8Array;
      enc_nonce: Uint8Array;
      key_epoch: number;
      target_id: Uint8Array;
    };

    // The plaintext String is an empty placeholder; content never leaks.
    expect(payload.content).toBe('');
    expect(payload.key_epoch).toBe(2);
    expect(payload.enc_nonce.length).toBe(24);
    expect(payload.target_id.length).toBe(32);

    // The node projects enc_content/enc_nonce/key_epoch onto the DM body, so the
    // recipient decrypts exactly like a fresh DM at that epoch.
    const convId = computeConversationId(signer.address, recipient);
    const out = decryptDmContent(convKey, convId, 2, payload.enc_content, payload.enc_nonce);
    expect(out.text).toBe('corrected text 🔁');
  });

  it('computeChannelScope matches the Rust KAT and is domain-separated', () => {
    // keccak256("ogmara-channel-scope-v1" || 1u64_be) — locked cross-impl with Rust.
    const tag = new TextEncoder().encode('ogmara-channel-scope-v1');
    const buf = new Uint8Array(tag.length + 8);
    buf.set(tag, 0);
    new DataView(buf.buffer).setBigUint64(tag.length, 1n);
    expect(Array.from(computeChannelScope(1))).toEqual(Array.from(keccak_256(buf)));
    // Disjoint from a DM scope.
    const dm = computeConversationId('klv1aaaa', 'klv1bbbb');
    expect(Array.from(computeChannelScope(0))).not.toEqual(Array.from(dm));
  });

  it('builds an encrypted channel message: text in enc_content, metadata plaintext', async () => {
    const signer = await WalletSigner.generate();
    const convKey = randomConvKey();
    const envBytes = await buildEncryptedChannelMessage(signer, {
      channelId: 12,
      convKey,
      epoch: 3,
      text: 'secret channel msg 🛡️',
      mentions: ['klv1mentioned'],
      replyTo: 'cd'.repeat(32),
    });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      channel_id: number; content: string; mentions: string[];
      reply_to: Uint8Array; enc_content: Uint8Array; enc_nonce: Uint8Array; key_epoch: number;
    };
    expect(payload.channel_id).toBe(12);
    expect(payload.content).toBe('');           // text never leaks plaintext
    expect(payload.mentions).toEqual(['klv1mentioned']); // metadata stays plaintext
    expect(payload.reply_to.length).toBe(32);
    expect(payload.key_epoch).toBe(3);
    // The text decrypts under the channel scope.
    const scope = computeChannelScope(12);
    const out = decryptDmContent(convKey, scope, 3, payload.enc_content, payload.enc_nonce);
    expect(out.text).toBe('secret channel msg 🛡️');
  });
});
