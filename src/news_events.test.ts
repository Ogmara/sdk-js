import { describe, it, expect } from 'vitest';
import { isNewsEnvelope, NEWS_MSG_TYPES, MessageType } from './types';

// `msg_type` reaches clients in two different shapes: the signed wire envelope
// carries the numeric discriminant, while the node's enriched read/WS JSON
// serializes the Rust enum by variant NAME. A check that handles only one of
// them fails closed and silently — the live news update simply never fires,
// which is exactly how news went un-live on every client before l2-node 0.119.0.
describe('isNewsEnvelope', () => {
  it('accepts numeric msg_type for every news type', () => {
    for (const code of NEWS_MSG_TYPES) {
      expect(isNewsEnvelope({ msg_type: code })).toBe(true);
    }
  });

  it('accepts the Rust variant-name string form', () => {
    for (const name of [
      'NewsPost',
      'NewsEdit',
      'NewsDelete',
      'NewsComment',
      'NewsReaction',
      'NewsRepost',
    ]) {
      expect(isNewsEnvelope({ msg_type: name })).toBe(true);
    }
  });

  it('rejects non-news types in both forms', () => {
    expect(isNewsEnvelope({ msg_type: MessageType.ChatMessage })).toBe(false);
    expect(isNewsEnvelope({ msg_type: 'ChatMessage' })).toBe(false);
    expect(isNewsEnvelope({ msg_type: MessageType.DirectMessage })).toBe(false);
    expect(isNewsEnvelope({ msg_type: 'DirectMessage' })).toBe(false);
  });

  it('rejects malformed input rather than throwing', () => {
    expect(isNewsEnvelope(undefined)).toBe(false);
    expect(isNewsEnvelope(null)).toBe(false);
    expect(isNewsEnvelope({})).toBe(false);
    expect(isNewsEnvelope({ msg_type: 'NotARealType' })).toBe(false);
    expect(isNewsEnvelope({ msg_type: 0xff })).toBe(false);
    expect(isNewsEnvelope('NewsPost')).toBe(false);
  });

  it('covers exactly the 0x20-0x25 news range', () => {
    expect([...NEWS_MSG_TYPES].sort((a, b) => a - b)).toEqual([
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    ]);
  });
});
