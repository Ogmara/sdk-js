import { describe, it, expect } from 'vitest';
import { derivePrivateChannelId } from './channelId';

describe('derivePrivateChannelId', () => {
  it('matches the Rust l2-node KAT (cross-impl lock)', () => {
    // Fixed vector, independently computed and pinned on BOTH sides
    // (l2-node's `validation.rs` channel_create_private_id_derivation_tests
    // module has the identical hardcoded expectation). If this ever
    // fails, the two implementations have drifted — DO NOT "fix" by
    // just updating one side's expected value without first
    // understanding why they disagree; a silent drift here means
    // Phase 3 enforcement bricks private-channel creation network-wide.
    const addr = 'klv1testvector0000000000000000000000000000000000000000000000';
    const slug = 'cross-impl-lock';
    const ts = 1700000000000;
    const { channelId, idDerivationTs } = derivePrivateChannelId(addr, slug, ts);
    expect(idDerivationTs).toBe(ts); // no re-roll needed for this vector
    expect(channelId).toBe(1746962510838664);
  });

  it('re-rolls id_derivation_ts when the raw result lands at or below the floor', () => {
    // Can't easily force a below-floor hash by construction, but we CAN
    // confirm the loop's invariant holds for a broad sample: every
    // returned channelId must clear the floor, and idDerivationTs must
    // never decrease from the input.
    for (let i = 0; i < 50; i++) {
      const ts = 1700000000000 + i;
      const { channelId, idDerivationTs } = derivePrivateChannelId('klv1sample', `slug-${i}`, ts);
      expect(channelId).toBeGreaterThan(2 ** 32);
      expect(idDerivationTs).toBeGreaterThanOrEqual(ts);
    }
  });

  it('defaults ts to Date.now() when omitted', () => {
    const before = Date.now();
    const { idDerivationTs } = derivePrivateChannelId('klv1sample', 'no-ts-given');
    const after = Date.now();
    // idDerivationTs may have been re-rolled upward, but never below `before`.
    expect(idDerivationTs).toBeGreaterThanOrEqual(before);
    expect(idDerivationTs).toBeLessThanOrEqual(after + 1000); // generous ceiling
  });

  it('a different wallet address produces a different channel_id for the same (slug, ts)', () => {
    const a = derivePrivateChannelId('klv1aaaa', 'same-slug', 1_700_000_000_000);
    const b = derivePrivateChannelId('klv1bbbb', 'same-slug', 1_700_000_000_000);
    expect(a.channelId).not.toBe(b.channelId);
  });

  it('a different slug produces a different channel_id for the same (address, ts)', () => {
    const a = derivePrivateChannelId('klv1sameaddr', 'slug-one', 1_700_000_000_000);
    const b = derivePrivateChannelId('klv1sameaddr', 'slug-two', 1_700_000_000_000);
    expect(a.channelId).not.toBe(b.channelId);
  });
});
