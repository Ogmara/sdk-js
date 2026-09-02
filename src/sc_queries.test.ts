import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  getUserRegisteredAt,
  getChannelInfo,
  getEscalatedCanonical,
  getRegistrationFee,
  getNodeFeeShareBps,
  getNodeEarnings,
  getTotalUnclaimedNodeEarnings,
} from './sc_queries';
import { getActiveNodeCount } from './sc_discovery';

// ── Helpers to build a fake Klever `/vm/query` response (mirrors
//    sc_discovery.test.ts so both files stay behaviorally consistent) ────

function b64(bytes: number[] | Uint8Array): string {
  return Buffer.from(bytes as any).toString('base64');
}

function vmOk(returnData: string[]) {
  return {
    ok: true,
    json: async () => ({ data: { data: { returnCode: 'Ok', returnData } } }),
  } as unknown as Response;
}

function vmRequireFail(message: string) {
  return {
    ok: true,
    json: async () => ({ data: { data: { returnCode: 'UserError', returnMessage: message } } }),
  } as unknown as Response;
}

function tsBytes(v: number): number[] {
  if (v === 0) return [];
  const out: number[] = [];
  let n = v;
  while (n > 0) {
    out.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return out;
}

function utf8(s: string): number[] {
  return Array.from(Buffer.from(s, 'utf8'));
}

const TEST_ADDRESS = 'klv10x64vt50ue20jsrckyfw32vt57gplpf6u62ma4lquwgshtgyjejq9d4x8v';
const TEST_ROOT = 'a'.repeat(64);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getUserRegisteredAt', () => {
  it('decodes a nonzero timestamp', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64(tsBytes(1780000000))]));
    expect(await getUserRegisteredAt('testnet', TEST_ADDRESS)).toBe(1780000000);
  });

  it('returns 0 on a require! failure (not registered)', async () => {
    vi.stubGlobal('fetch', async () => vmRequireFail('Not registered'));
    expect(await getUserRegisteredAt('testnet', TEST_ADDRESS)).toBe(0);
  });

  it('returns 0 for the zero-encoding (empty bytes)', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([])]));
    expect(await getUserRegisteredAt('testnet', TEST_ADDRESS)).toBe(0);
  });

  it('rejects a malformed address instead of sending garbage bytes on-chain', async () => {
    // No fetch stub: addressToPubkey must throw BEFORE any network call is
    // attempted — it now verifies the bech32 checksum and decoded length
    // itself (see encryption.test.ts for dedicated checksum/length cases).
    await expect(getUserRegisteredAt('testnet', 'klv1')).rejects.toThrow(/not a bech32 address/);
    await expect(
      getUserRegisteredAt('testnet', 'klv1' + 'a'.repeat(80)),
    ).rejects.toThrow(/checksum/);
  });
});

describe('getChannelInfo', () => {
  it('decodes channel_type + created_at', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([1]), b64(tsBytes(1700000000))]));
    const info = await getChannelInfo('testnet', 42);
    expect(info).toEqual({ channelType: 1, createdAt: 1700000000 });
  });

  it('decodes the zero-value convention (both empty)', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([]), b64([])]));
    const info = await getChannelInfo('testnet', 1);
    expect(info).toEqual({ channelType: 0, createdAt: 0 });
  });

  it('returns null on a require! failure (channel not found)', async () => {
    vi.stubGlobal('fetch', async () => vmRequireFail('Channel not found'));
    expect(await getChannelInfo('testnet', 999)).toBeNull();
  });

  it('rejects an unexpected item count', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([1])]));
    await expect(getChannelInfo('testnet', 1)).rejects.toThrow(/unexpected item count/);
  });

  it('rejects an oversized channel_type byte array', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([1, 2]), b64([])]));
    await expect(getChannelInfo('testnet', 1)).rejects.toThrow(/unexpected length/);
  });

  it('rejects a negative or non-integer channelId before any network call', async () => {
    await expect(getChannelInfo('testnet', -1)).rejects.toThrow(/non-negative integer/);
    await expect(getChannelInfo('testnet', 1.5)).rejects.toThrow(/non-negative integer/);
  });
});

describe('getEscalatedCanonical', () => {
  it('decodes a materialized 64-char root', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64(utf8(TEST_ROOT))]));
    expect(await getEscalatedCanonical('testnet', 50)).toBe(TEST_ROOT);
  });

  it('returns null when not yet materialized (empty payload) — the provisional/final distinction', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64([])]));
    expect(await getEscalatedCanonical('testnet', 50)).toBeNull();
  });

  it('returns null on a require! failure', async () => {
    vi.stubGlobal('fetch', async () => vmRequireFail('some failure'));
    expect(await getEscalatedCanonical('testnet', 50)).toBeNull();
  });

  it('rejects a malformed (wrong-length) root', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64(utf8('short'))]));
    await expect(getEscalatedCanonical('testnet', 50)).rejects.toThrow(/malformed root/);
  });

  it('rejects a 64-char payload that is not hex', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64(utf8('z'.repeat(64)))]));
    await expect(getEscalatedCanonical('testnet', 50)).rejects.toThrow(/malformed root/);
  });

  it('rejects a negative or non-integer blockHeight before any network call', async () => {
    await expect(getEscalatedCanonical('testnet', -1)).rejects.toThrow(/non-negative integer/);
    await expect(getEscalatedCanonical('testnet', 1.5)).rejects.toThrow(/non-negative integer/);
    await expect(getEscalatedCanonical('testnet', NaN)).rejects.toThrow(/non-negative integer/);
  });
});

describe('getActiveNodeCount', () => {
  it('decodes a nonzero count', async () => {
    vi.stubGlobal('fetch', async () => vmOk([b64(tsBytes(7))]));
    expect(await getActiveNodeCount('testnet')).toBe(7);
  });

  it('returns 0 on a require! failure (empty SC state)', async () => {
    vi.stubGlobal('fetch', async () => vmRequireFail('nothing registered'));
    expect(await getActiveNodeCount('testnet')).toBe(0);
  });
});

// ── Registration fee + node revenue sharing (smart-contract 0.10.0) ────

describe('registration fee views', () => {
  afterEach(() => vi.restoreAllMocks());

  it('decodes the fee as an exact bigint, not a lossy number', async () => {
    // 100 KLV in raw units = 100_000_000 = 0x05F5E100.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64([0x05, 0xf5, 0xe1, 0x00])]));
    await expect(getRegistrationFee('testnet')).resolves.toBe(100_000_000n);
  });

  it('keeps full precision past 2^53, where a number would silently round', async () => {
    // 2^64 - 1: exactly representable as a bigint, NOT as a JS number.
    const bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64(bytes)]));
    const v = await getRegistrationFee('testnet');
    expect(v).toBe(18_446_744_073_709_551_615n);
    // The precision the bigint buys us: Number() cannot represent this.
    expect(v).not.toBe(BigInt(Number(v)));
  });

  it('reports a free/unset fee as 0n', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64([])]));
    await expect(getRegistrationFee('testnet')).resolves.toBe(0n);
  });

  it('treats a contract without the view (pre-0.10.0) as free', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmRequireFail('invalid function'));
    await expect(getRegistrationFee('testnet')).resolves.toBe(0n);
  });

  it('decodes the fee share as a plain number', async () => {
    // 5000 bps = 0x1388.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64([0x13, 0x88])]));
    const bps = await getNodeFeeShareBps('testnet');
    expect(bps).toBe(5000);
    expect(typeof bps).toBe('number');
  });

  it('reads a node balance as a bigint', async () => {
    // 50 KLV = 50_000_000 = 0x02FAF080.
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64([0x02, 0xfa, 0xf0, 0x80])]));
    await expect(
      getNodeEarnings('testnet', 'klv1heatuswg9u9u356snvj20fn9jvcgva8fea5v54uhqadchhaz6pgq26t8jh'),
    ).resolves.toBe(50_000_000n);
  });

  it('rejects a malformed address client-side rather than returning a false zero', async () => {
    const spy = vi.spyOn(globalThis, 'fetch');
    await expect(getNodeEarnings('testnet', 'klv1notavalidaddress')).rejects.toThrow();
    // Must fail before any RPC round-trip.
    expect(spy).not.toHaveBeenCalled();
  });

  it('reads the network-wide unclaimed total as a bigint', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(vmOk([b64([0x01, 0x00])]));
    await expect(getTotalUnclaimedNodeEarnings('testnet')).resolves.toBe(256n);
  });
});
