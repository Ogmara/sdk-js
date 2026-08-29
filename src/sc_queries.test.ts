import { describe, it, expect, afterEach, vi } from 'vitest';
import { getUserRegisteredAt, getChannelInfo, getEscalatedCanonical } from './sc_queries';
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
