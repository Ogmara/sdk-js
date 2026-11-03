/**
 * Parity with the l2-node 0.143.0 key-epoch arbitration golden vectors
 * (`l2-node/tests/fixtures/epoch-arbitration/vectors.json`, copied to
 * `fixtures/epoch-arbitration-vectors.json`): commitment KATs, byte-exact
 * payload / msg_id / signature reproduction by `buildChannelKeyEnvelope`, the
 * node's exact 409 conflict body, and verification of the Rust-encoded
 * envelopes.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { decode } from '@msgpack/msgpack';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WalletSigner } from './auth';
import { buildChannelKeyEnvelope } from './dm';
import { buildEnvelope, computeChannelScope } from './envelope';
import { verifyEnvelopeBytes } from './privateChannelProof';
import {
  classifyKeyEnvelopeResponse,
  computeKeyCommitment,
  keyCommitmentToHex,
  KeyCommitmentConflictError,
  KeyEnvelopeRejectedError,
  KEY_COMMITMENT_DOMAIN,
  KEY_COMMIT_FINALITY_MS,
  KEY_TS_MAX_AGE_MS,
} from './channelKeyCommit';
import { MessageType } from './types';

const FIXTURE = resolve(__dirname, '../fixtures/epoch-arbitration-vectors.json');
const SIBLING = resolve(__dirname, '../../l2-node/tests/fixtures/epoch-arbitration/vectors.json');
const V = JSON.parse(readFileSync(FIXTURE, 'utf8'));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

afterEach(() => vi.useRealTimers());

async function at<T>(ts: number, f: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(ts);
  try {
    return await f();
  } finally {
    vi.useRealTimers();
  }
}

describe('epoch-arbitration golden vectors (l2-node 0.143.0)', () => {
  it('fixture copy matches the sibling l2-node checkout when present', () => {
    expect(V.format).toBe('ogmara-epoch-arbitration-vectors/1');
    if (existsSync(SIBLING)) expect(readFileSync(FIXTURE, 'utf8')).toBe(readFileSync(SIBLING, 'utf8'));
  });

  it('constants agree', () => {
    expect(V.commitment.domain_utf8).toBe(KEY_COMMITMENT_DOMAIN);
    expect(V.rank.finality_ms).toBe(KEY_COMMIT_FINALITY_MS);
    expect(V.rank.key_ts_max_age_ms).toBe(KEY_TS_MAX_AGE_MS);
  });

  for (const k of V.commitment.kat) {
    it(`commitment KAT channel ${k.channel_id} epoch ${k.epoch} key_ts ${k.key_ts}`, () => {
      const scope = computeChannelScope(k.channel_id);
      expect(toHex(scope)).toBe(k.key_scope_hex);
      expect(keyCommitmentToHex(computeKeyCommitment(scope, k.epoch, k.key_ts, fromHex(k.channel_key_hex)))).toBe(k.key_commitment_hex);
      // Preimage layout: domain || scope || epoch_be8 || key_ts_be8 || key.
      const be8 = (n: number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return toHex(b); };
      expect(Buffer.from(KEY_COMMITMENT_DOMAIN).toString('hex') + k.key_scope_hex + be8(k.epoch) + be8(k.key_ts) + k.channel_key_hex).toBe(k.preimage_hex);
    });
  }

  for (const e of V.envelopes) {
    it(`envelope ${e.name}: SDK reproduces payload, msg_id and signature byte for byte`, async () => {
      const s = await WalletSigner.fromHex(e.signer_seed_hex);
      s.network = V.network;
      expect(s.address).toBe(e.author);
      const f = e.payload_fields;
      const wrapped = { ephPub: fromHex(f.eph_pub_hex), nonce: fromHex(f.nonce_hex), wrapped: fromHex(f.wrapped_hex) };
      const bytes = await at(e.timestamp, () =>
        f.key_commitment_hex
          ? buildChannelKeyEnvelope(s, {
              keyScope: fromHex(f.key_scope_hex), scopeKind: f.scope_kind, epoch: f.epoch, target: f.target,
              deviceId: f.device_id, channelId: f.channel_id, wrapped,
              keyCommitment: fromHex(f.key_commitment_hex), keyTs: f.key_ts,
            })
          : // The builder refuses commitment-less channel envelopes (STRICT); reproduce the raw form.
            buildEnvelope(s, MessageType.ChannelKeyEnvelope, {
              key_scope: fromHex(f.key_scope_hex), scope_kind: f.scope_kind, epoch: f.epoch, target: f.target,
              device_id: f.device_id, peer: null, channel_id: f.channel_id,
              eph_pub: wrapped.ephPub, nonce: wrapped.nonce, wrapped: wrapped.wrapped,
            }),
      );
      const env = decode(bytes) as any;
      expect(toHex(env.payload)).toBe(e.payload_msgpack_hex);
      expect(toHex(env.msg_id)).toBe(e.msg_id_hex);
      expect(toHex(env.signature)).toBe(e.signature_hex);
      // The node's own (Rust-encoded) envelope verifies with the SDK verifier.
      const v = await verifyEnvelopeBytes(fromHex(e.envelope_msgpack_hex), V.network, { expectedType: MessageType.ChannelKeyEnvelope });
      expect(v.ok).toBe(true);
    });
  }

  it('the node 409 body classifies as a conflict with its winner; 400 code maps to a rejection', () => {
    const rival = V.envelopes.find((e: any) => e.name === 'rival_epoch2_worse_rank');
    const r = classifyKeyEnvelopeResponse(409, JSON.stringify(rival.expected.http_409));
    expect(r).toBeInstanceOf(KeyCommitmentConflictError);
    const w = (r as KeyCommitmentConflictError).winner!;
    expect(w.key_commitment).toBe(rival.expected.http_409.winner.key_commitment);
    expect(w.key_ts).toBe(rival.expected.http_409.winner.key_ts);
    expect(w.final).toBe(false);
    const less = V.envelopes.find((e: any) => e.name === 'commitment_less_new_epoch');
    const rej = classifyKeyEnvelopeResponse(400, JSON.stringify({ error: less.expected.http_400_error }));
    expect(rej).toBeInstanceOf(KeyEnvelopeRejectedError);
    expect((rej as KeyEnvelopeRejectedError).code).toBe('key_commitment_required');
  });
});
