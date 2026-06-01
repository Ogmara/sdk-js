import { describe, it, expect } from 'vitest';
import { computeTrustScore } from './client';
import type { KnownNode, Attestation } from './types';

function node(attestation: Attestation, anchoring: boolean): KnownNode {
  return {
    peer_id: '12D3KooWTest',
    url: 'https://node.example.org',
    attestation,
    anchoring,
    trust_score: 0,
  };
}

describe('computeTrustScore (spec 5 §1.1 / spec 13 §10.8 locked formula)', () => {
  it('gossip-only with no probe scores 0', () => {
    expect(computeTrustScore(node('gossip', false))).toBe(0);
  });

  it('on-chain without anchoring scores 50', () => {
    expect(computeTrustScore(node('on-chain', false))).toBe(50);
  });

  it('on-chain + anchoring scores 80', () => {
    expect(computeTrustScore(node('on-chain', true))).toBe(80);
  });

  it('both + anchoring scores 90 (cross-source +10)', () => {
    expect(computeTrustScore(node('both', true))).toBe(90);
  });

  it('both + anchoring + fresh probe caps at 100', () => {
    const n = node('both', true);
    n.reachable_probe_at = Date.now();
    expect(computeTrustScore(n)).toBe(100);
  });

  it('stale probe (>24h old) does NOT contribute the +10', () => {
    const n = node('both', true);
    n.reachable_probe_at = Date.now() - 25 * 3600 * 1000;
    expect(computeTrustScore(n)).toBe(90);
  });

  it('score never exceeds 100', () => {
    const n = node('both', true);
    n.reachable_probe_at = Date.now();
    expect(computeTrustScore(n)).toBeLessThanOrEqual(100);
  });

  it('gossip + fresh probe scores 10', () => {
    const n = node('gossip', false);
    n.reachable_probe_at = Date.now();
    expect(computeTrustScore(n)).toBe(10);
  });
});
