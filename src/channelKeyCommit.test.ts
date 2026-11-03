/**
 * Key commitment KAT + rank + wire parsing (sdk-js 0.67.0, protocol §8.1).
 *
 * KAT inputs (also pinned in spec 01 §8.1 and the l2-node tests):
 *   channel_id = 4294967297 (2^32 + 1, a private-range id)
 *   channel_scope = keccak256("ogmara-channel-scope-v1" || u64be(channel_id))
 *                 = 7085627c18f35c684cf3c70bf45ace585fea2da90932c1a52da8992cc9bdc952
 *   epoch = 7, key_ts = 1790000000000, channel_key = 0x00 0x01 … 0x1f
 *   key_commitment = keccak256("ogmara-chankey-commit-v1" || scope || u64be(7)
 *                              || u64be(key_ts) || key)
 *                  = 8016166a572c3b83cf9547a51877d8f7bd66ee26ac19d2ca74c74fe55268a5d4
 * Second vector: scope = 32×0x00, epoch = 1, key_ts = 1, key = 32×0x00
 *                  = bcd39e590bd58ecaf69b25e13032a70829f47e98c1f33d20d976dd2ed9208d32
 * Both were cross-checked against an independent pure-Python Keccak-256.
 */
import { describe, expect, it } from 'vitest';
import {
  classifyKeyEnvelopeResponse,
  compareRank,
  computeKeyCommitment,
  sameCandidate,
  isValidKeyCommitment,
  keyCommitmentFromHex,
  keyCommitmentToHex,
  parseKeyCommitmentInfo,
  KeyCommitmentConflictError,
  KeyEnvelopeRateLimitedError,
  KeyEnvelopeRejectedError,
  KeyEnvelopeTransientError,
  MAX_KEY_ENVELOPE_RETRY_MS,
} from './channelKeyCommit';
import { computeChannelScope } from './envelope';

const hex = (b: Uint8Array) => keyCommitmentToHex(b);

describe('computeKeyCommitment KAT', () => {
  it('channel scope of 2^32+1', () => {
    expect(hex(computeChannelScope(4294967297))).toBe('7085627c18f35c684cf3c70bf45ace585fea2da90932c1a52da8992cc9bdc952');
  });
  it('vector 1', () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(hex(computeKeyCommitment(computeChannelScope(4294967297), 7, 1790000000000, key))).toBe(
      '8016166a572c3b83cf9547a51877d8f7bd66ee26ac19d2ca74c74fe55268a5d4',
    );
    // input not mutated
    expect(key[31]).toBe(31);
  });
  it('vector 2 (all zero inputs)', () => {
    expect(hex(computeKeyCommitment(new Uint8Array(32), 1, 1, new Uint8Array(32)))).toBe(
      'bcd39e590bd58ecaf69b25e13032a70829f47e98c1f33d20d976dd2ed9208d32',
    );
  });
  it('binds scope, epoch, key_ts and key', () => {
    const s = computeChannelScope(4294967297);
    const k = new Uint8Array(32).fill(9);
    const a = hex(computeKeyCommitment(s, 1, 100, k));
    expect(hex(computeKeyCommitment(s, 2, 100, k))).not.toBe(a);
    expect(hex(computeKeyCommitment(s, 1, 99, k))).not.toBe(a);
    expect(hex(computeKeyCommitment(computeChannelScope(4294967298), 1, 100, k))).not.toBe(a);
    expect(hex(computeKeyCommitment(s, 1, 100, new Uint8Array(32).fill(8)))).not.toBe(a);
  });
  it('rejects bad inputs', () => {
    expect(() => computeKeyCommitment(new Uint8Array(31), 1, 1, new Uint8Array(32))).toThrow();
    expect(() => computeKeyCommitment(new Uint8Array(32), 1, 1, new Uint8Array(33))).toThrow();
    expect(() => computeKeyCommitment(new Uint8Array(32), -1, 1, new Uint8Array(32))).toThrow();
    expect(() => computeKeyCommitment(new Uint8Array(32), 1.5, 1, new Uint8Array(32))).toThrow();
    expect(() => computeKeyCommitment(new Uint8Array(32), 1, -1, new Uint8Array(32))).toThrow();
    expect(() => computeKeyCommitment(new Uint8Array(32), 1, 2 ** 60, new Uint8Array(32))).toThrow();
  });
});

describe('sameCandidate', () => {
  it('compares the PAIR', () => {
    const c = new Uint8Array(32).fill(1);
    expect(sameCandidate({ keyTs: 1, keyCommitment: c }, { keyTs: 1, keyCommitment: c.slice() })).toBe(true);
    expect(sameCandidate({ keyTs: 1, keyCommitment: c }, { keyTs: 2, keyCommitment: c })).toBe(false);
  });
});

describe('compareRank', () => {
  const c = (b: number) => new Uint8Array(32).fill(b);
  it('lower key_ts wins regardless of commitment', () => {
    expect(compareRank({ keyTs: 1, keyCommitment: c(0xff) }, { keyTs: 2, keyCommitment: c(1) })).toBeLessThan(0);
    expect(compareRank({ keyTs: 3, keyCommitment: c(1) }, { keyTs: 2, keyCommitment: c(0xff) })).toBeGreaterThan(0);
  });
  it('ties on key_ts broken by unsigned bytes', () => {
    const a = c(1);
    const b = c(1);
    b[31] = 2;
    expect(compareRank({ keyTs: 5, keyCommitment: a }, { keyTs: 5, keyCommitment: b })).toBeLessThan(0);
    expect(compareRank({ keyTs: 5, keyCommitment: c(0x80) }, { keyTs: 5, keyCommitment: c(0x7f) })).toBeGreaterThan(0);
    expect(compareRank({ keyTs: 5, keyCommitment: a }, { keyTs: 5, keyCommitment: c(1) })).toBe(0);
  });
});

describe('validation + parsing', () => {
  it('isValidKeyCommitment', () => {
    expect(isValidKeyCommitment(new Uint8Array(32))).toBe(false);
    expect(isValidKeyCommitment(new Uint8Array(31).fill(1))).toBe(false);
    expect(isValidKeyCommitment(new Uint8Array(32).fill(1))).toBe(true);
    expect(isValidKeyCommitment('00')).toBe(false);
  });
  it('hex round trip', () => {
    const c = new Uint8Array(32).fill(0xab);
    expect(keyCommitmentFromHex(hex(c).toUpperCase())).toEqual(c);
    expect(keyCommitmentFromHex('ab')).toBeNull();
  });
  const good = {
    channel_id: 5, epoch: 3, state: 'arbitrated', key_commitment: 'aa'.repeat(32), key_ts: 1000,
    author: 'klv1x', msg_id: 'BB'.repeat(32), recorded_at: 2000, final: false, finality_ms: 120000,
  };
  it('parseKeyCommitmentInfo accepts a valid arbitrated body', () => {
    const i = parseKeyCommitmentInfo(good)!;
    expect(i.state).toBe('arbitrated');
    expect(i.msg_id).toBe('bb'.repeat(32));
    expect(i.final).toBe(false);
  });
  it('parseKeyCommitmentInfo fails closed on unsafe numbers / bad commitments / unknown state', () => {
    expect(parseKeyCommitmentInfo({ ...good, epoch: 2 ** 60 })).toBeNull();
    expect(parseKeyCommitmentInfo({ ...good, epoch: -1 })).toBeNull();
    expect(parseKeyCommitmentInfo({ ...good, key_commitment: '00'.repeat(32) })).toBeNull();
    expect(parseKeyCommitmentInfo({ ...good, key_ts: 0 })).toBeNull();
    expect(parseKeyCommitmentInfo({ ...good, key_ts: 1.5 })).toBeNull();
    expect(parseKeyCommitmentInfo({ ...good, state: 'weird' })).toBeNull();
    expect(parseKeyCommitmentInfo(null)).toBeNull();
    expect(parseKeyCommitmentInfo({ channel_id: 5, epoch: 0, state: 'none', final: false, finality_ms: 120000 })?.state).toBe('none');
  });
});

describe('classifyKeyEnvelopeResponse', () => {
  it('plain-text 409 duplicate is success', () => {
    expect(classifyKeyEnvelopeResponse(409, 'message already exists')).toBe('duplicate');
  });
  it('JSON 409 conflict carries the winner', () => {
    const r = classifyKeyEnvelopeResponse(409, JSON.stringify({
      error: 'key_commitment_conflict', channel_id: 5, epoch: 2, state: 'arbitrated',
      winner: { key_commitment: 'cd'.repeat(32), key_ts: 77, author: 'klv1a', msg_id: 'ee'.repeat(32), final: true },
    }));
    expect(r).toBeInstanceOf(KeyCommitmentConflictError);
    const e = r as KeyCommitmentConflictError;
    expect(e.winner?.key_ts).toBe(77);
    expect(e.winner?.final).toBe(true);
    expect(e.epoch).toBe(2);
  });
  it('other 409 bodies are rejections, never duplicates', () => {
    expect(classifyKeyEnvelopeResponse(409, '{"error":"something"}')).toBeInstanceOf(KeyEnvelopeRejectedError);
    expect(classifyKeyEnvelopeResponse(409, 'conflict')).toBeInstanceOf(KeyEnvelopeRejectedError);
  });
  it('429 retry_after_ms (clamped) and default', () => {
    const a = classifyKeyEnvelopeResponse(429, '{"error":"rate_limited","retry_after_ms":1234}') as KeyEnvelopeRateLimitedError;
    expect(a.retryAfterMs).toBe(1234);
    expect(a.fromServer).toBe(true);
    const b = classifyKeyEnvelopeResponse(429, '{"error":"rate_limited","retry_after_ms":99999999}') as KeyEnvelopeRateLimitedError;
    expect(b.retryAfterMs).toBe(MAX_KEY_ENVELOPE_RETRY_MS);
    const c = classifyKeyEnvelopeResponse(429, 'rate limited') as KeyEnvelopeRateLimitedError;
    expect(c.fromServer).toBe(false);
  });
  it('400 codes and 5xx', () => {
    for (const code of ['key_commitment_required', 'key_commitment_invalid', 'key_ts_stale', 'key_epoch_below_floor', 'key_epoch_evicted', 'key_scope_full']) {
      const r = classifyKeyEnvelopeResponse(400, JSON.stringify({ error: code })) as KeyEnvelopeRejectedError;
      expect(r).toBeInstanceOf(KeyEnvelopeRejectedError);
      expect(r.code).toBe(code);
    }
    expect((classifyKeyEnvelopeResponse(400, 'epoch below floor') as KeyEnvelopeRejectedError).code).toBe('epoch below floor');
    expect(classifyKeyEnvelopeResponse(503, 'busy')).toBeInstanceOf(KeyEnvelopeTransientError);
  });
});
