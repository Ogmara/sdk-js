import { describe, it, expect, vi, afterEach } from 'vitest';
import { decode } from '@msgpack/msgpack';
import { WalletSigner } from './auth';
import { buildChatMessage, buildChatEdit, validateButtons } from './envelope';
import { OgmaraClient } from './client';
import { BUTTON_LIMITS, type ButtonRow } from './types';

const row = (buttons: { label: string; command: string }[]): ButtonRow => ({ buttons });

function mockPostEnvelope(): { bodies: Uint8Array[] } {
  const bodies: Uint8Array[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.body) bodies.push(new Uint8Array(init.body as ArrayBuffer));
      const isHealth = String(url).includes('/api/v1/health');
      const body = isHealth
        ? { status: 'ok', version: '0', peers: 0, node_id: 'node1', network: 'testnet' }
        : { msg_id: 'x' };
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => body,
        text: async () => JSON.stringify(body),
      } as unknown as Response;
    }),
  );
  return { bodies };
}

describe('validateButtons', () => {
  it('accepts a well-formed row', () => {
    expect(() =>
      validateButtons([row([{ label: '15m', command: '/c BTC 15m' }])]),
    ).not.toThrow();
  });

  it('accepts an empty array (no buttons)', () => {
    expect(() => validateButtons([])).not.toThrow();
  });

  it('rejects an empty row', () => {
    expect(() => validateButtons([row([])])).toThrow(/must not be empty/);
  });

  it('rejects too many rows', () => {
    const rows = Array.from({ length: BUTTON_LIMITS.MAX_ROWS + 1 }, () =>
      row([{ label: 'x', command: '/x' }]),
    );
    expect(() => validateButtons(rows)).toThrow(/too many button rows/);
  });

  it('accepts exactly the max row count', () => {
    const rows = Array.from({ length: BUTTON_LIMITS.MAX_ROWS }, () =>
      row([{ label: 'x', command: '/x' }]),
    );
    expect(() => validateButtons(rows)).not.toThrow();
  });

  it('rejects too many buttons in a single row', () => {
    const buttons = Array.from({ length: BUTTON_LIMITS.MAX_PER_ROW + 1 }, () => ({
      label: 'x',
      command: '/x',
    }));
    expect(() => validateButtons([row(buttons)])).toThrow(/too many buttons in a row/);
  });

  it('rejects more than MAX_TOTAL even within row/per-row caps (the binding constraint)', () => {
    // MAX_ROWS * MAX_PER_ROW (10 * 8 = 80) exceeds MAX_TOTAL (40) — a message
    // using the max of BOTH individual caps must still be rejected on the
    // combined total.
    expect(BUTTON_LIMITS.MAX_ROWS * BUTTON_LIMITS.MAX_PER_ROW).toBeGreaterThan(
      BUTTON_LIMITS.MAX_TOTAL,
    );
    const buttons = Array.from({ length: BUTTON_LIMITS.MAX_PER_ROW }, () => ({
      label: 'x',
      command: '/x',
    }));
    const rows = Array.from({ length: BUTTON_LIMITS.MAX_ROWS }, () => row(buttons));
    // Anchored so a regression that fires the (also-true) per-row error
    // instead of the total-count error is caught, not silently passed.
    expect(() => validateButtons(rows)).toThrow(/^too many buttons \(max/);
  });

  it('accepts the true worst case at every cap simultaneously', () => {
    const perRow = BUTTON_LIMITS.MAX_PER_ROW;
    const rows = Math.min(BUTTON_LIMITS.MAX_ROWS, Math.floor(BUTTON_LIMITS.MAX_TOTAL / perRow));
    expect(rows * perRow).toBe(BUTTON_LIMITS.MAX_TOTAL);
    const bigLabel = 'x'.repeat(BUTTON_LIMITS.MAX_LABEL);
    const bigCommand = '/' + 'y'.repeat(BUTTON_LIMITS.MAX_COMMAND - 1);
    const buttons = Array.from({ length: perRow }, () => ({ label: bigLabel, command: bigCommand }));
    const allRows = Array.from({ length: rows }, () => row(buttons));
    expect(() => validateButtons(allRows)).not.toThrow();
  });

  it('rejects an oversize label (measured in UTF-8 bytes, not UTF-16 units)', () => {
    // '描' is 3 UTF-8 bytes — 8 repeats = 24 bytes, exactly at the cap.
    const cjkLabel = '描'.repeat(BUTTON_LIMITS.MAX_LABEL / 3);
    expect(() => validateButtons([row([{ label: cjkLabel, command: '/x' }])])).not.toThrow();
    // One more character pushes it to 27 bytes — over the cap despite being
    // only 9 UTF-16 code units, the exact 0.57.1-class bug this mirrors.
    const cjkTooLong = '描'.repeat(BUTTON_LIMITS.MAX_LABEL / 3 + 1);
    expect(() => validateButtons([row([{ label: cjkTooLong, command: '/x' }])])).toThrow(
      /button label must be/,
    );
    const tooLong = 'x'.repeat(BUTTON_LIMITS.MAX_LABEL + 1);
    expect(() => validateButtons([row([{ label: tooLong, command: '/x' }])])).toThrow(
      /button label must be/,
    );
  });

  it('rejects an empty label or command', () => {
    expect(() => validateButtons([row([{ label: '', command: '/x' }])])).toThrow(
      /button label must be/,
    );
    expect(() => validateButtons([row([{ label: 'x', command: '' }])])).toThrow(
      /button command must be/,
    );
  });

  it('rejects an oversize command', () => {
    const tooLong = '/' + 'y'.repeat(BUTTON_LIMITS.MAX_COMMAND);
    expect(() => validateButtons([row([{ label: 'x', command: tooLong }])])).toThrow(
      /button command must be/,
    );
  });

  it('rejects control and bidi codepoints in label and command', () => {
    expect(() =>
      validateButtons([row([{ label: '15m‮', command: '/c BTC 15m' }])]),
    ).toThrow(/control or bidirectional/);
    expect(() =>
      validateButtons([row([{ label: '15m', command: '/c​BTC' }])]),
    ).toThrow(/control or bidirectional/);
  });

  it('accepts full Unicode labels and commands (never an ASCII allowlist)', () => {
    expect(() =>
      validateButtons([row([{ label: '查看图表', command: '/图表 BTC' }])]),
    ).not.toThrow();
  });

  it('accepts ZWJ emoji sequences and Persian ZWNJ (the deliberate carve-out)', () => {
    // U+200D ZWJ / U+200C ZWNJ sit inside the U+200B..U+200F block a naive
    // range would sweep up — a real risk for button labels specifically,
    // since a single ZWJ family emoji can be close to the 24-byte cap.
    expect(() =>
      validateButtons([row([{ label: '👨‍👩‍👧', command: '/family' }])]),
    ).not.toThrow();
    expect(() =>
      validateButtons([
        row([{ label: 'می‌خواهم', command: '/x' }]),
      ]),
    ).not.toThrow();
  });
});

describe('buildChatMessage — buttons wire format', () => {
  it('encodes buttons and via_button when provided', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildChatMessage(signer, {
      channelId: 1,
      content: 'price card',
      buttons: [row([{ label: '1h', command: '/c BTC 1h' }])],
    });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      buttons: { buttons: { label: string; command: string }[] }[];
      via_button: boolean;
    };

    expect(payload.buttons).toHaveLength(1);
    expect(payload.buttons[0].buttons[0]).toEqual({ label: '1h', command: '/c BTC 1h' });
    expect(payload.via_button).toBe(false);
  });

  it('defaults buttons to [] and via_button to false when omitted', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildChatMessage(signer, { channelId: 1, content: 'hi' });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as { buttons: unknown[]; via_button: boolean };

    expect(payload.buttons).toEqual([]);
    expect(payload.via_button).toBe(false);
  });

  it('throws locally on an invalid button rather than letting the node reject it', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    await expect(
      buildChatMessage(signer, {
        channelId: 1,
        content: 'hi',
        buttons: [row([{ label: '', command: '/x' }])],
      }),
    ).rejects.toThrow(/button label must be/);
  });
});

describe('buildChatEdit — buttons absent-vs-empty semantics (protocol §3.7)', () => {
  it('omits the buttons key entirely when not provided — UNCHANGED on the node', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildChatEdit(signer, {
      channelId: 1,
      msgId: '11'.repeat(16),
      content: 'edited text',
    });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as Record<string, unknown>;

    expect('buttons' in payload).toBe(false);
  });

  it('throws locally on an invalid button rather than letting the node reject it', async () => {
    // The edit path is the PRIMARY button lifecycle path (swap/clear a row on
    // press) — a regression that dropped local validation here would still
    // pass every buildChatMessage test.
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    await expect(
      buildChatEdit(signer, {
        channelId: 1,
        msgId: '11'.repeat(16),
        content: 'edited text',
        buttons: [row([{ label: '', command: '/x' }])],
      }),
    ).rejects.toThrow(/button label must be/);
  });

  it('sends an explicit empty array to CLEAR the button row', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildChatEdit(signer, {
      channelId: 1,
      msgId: '11'.repeat(16),
      content: 'edited text',
      buttons: [],
    });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as { buttons: unknown[] };

    expect(payload.buttons).toEqual([]);
  });

  it('sends a non-empty array to REPLACE the button row wholesale', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildChatEdit(signer, {
      channelId: 1,
      msgId: '11'.repeat(16),
      content: 'edited text',
      buttons: [row([{ label: '4h', command: '/c BTC 4h' }])],
    });
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      buttons: { buttons: { label: string; command: string }[] }[];
    };

    expect(payload.buttons[0].buttons[0]).toEqual({ label: '4h', command: '/c BTC 4h' });
  });
});

describe('OgmaraClient.sendMessage / editMessage — buttons client-level wiring', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sendMessage forwards options.buttons onto the wire', async () => {
    const { bodies } = mockPostEnvelope();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://test-node.example' }).withSigner(signer);

    await client.sendMessage(7, 'price card', {
      buttons: [row([{ label: '1h', command: '/c BTC 1h' }])],
    });

    const env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      buttons: { buttons: { label: string; command: string }[] }[];
    };
    expect(payload.buttons[0].buttons[0]).toEqual({ label: '1h', command: '/c BTC 1h' });
  });

  it('editMessage forwards options.buttons onto the wire, and omits the key when not passed', async () => {
    const { bodies } = mockPostEnvelope();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://test-node.example' }).withSigner(signer);
    const msgId = 'ab'.repeat(32);

    await client.editMessage(7, msgId, 'edited', {
      buttons: [row([{ label: '4h', command: '/c BTC 4h' }])],
    });
    let env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    let payload = decode(env.payload) as {
      buttons: { buttons: { label: string; command: string }[] }[];
    };
    expect(payload.buttons[0].buttons[0]).toEqual({ label: '4h', command: '/c BTC 4h' });

    await client.editMessage(7, msgId, 'edited again');
    env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    const noButtonsPayload = decode(env.payload) as Record<string, unknown>;
    expect('buttons' in noButtonsPayload).toBe(false);
  });
});

describe('OgmaraClient.pressButton', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends content=command, mentions=[origin.author], reply_to=origin.msgId, via_button=true', async () => {
    const { bodies } = mockPostEnvelope();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://test-node.example' }).withSigner(signer);
    const originMsgId = 'ab'.repeat(32);

    await client.pressButton(
      { channelId: 42, msgId: originMsgId, author: 'klv1bot' },
      '/c BTC 1h',
    );

    const env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      channel_id: number;
      content: string;
      mentions: string[];
      reply_to: Uint8Array;
      via_button: boolean;
    };

    expect(payload.channel_id).toBe(42);
    expect(payload.content).toBe('/c BTC 1h');
    expect(payload.mentions).toEqual(['klv1bot']);
    expect(Buffer.from(payload.reply_to).toString('hex')).toBe(originMsgId);
    expect(payload.via_button).toBe(true);
  });

  it('rejects without a signer, like every other authenticated endpoint', async () => {
    const client = new OgmaraClient({ nodeUrl: 'https://test-node.example' });
    await expect(
      client.pressButton({ channelId: 1, msgId: 'ab'.repeat(32), author: 'klv1bot' }, '/x'),
    ).rejects.toThrow(/Signer required/);
  });
});
