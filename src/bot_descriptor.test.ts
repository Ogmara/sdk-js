import { describe, it, expect, vi } from 'vitest';
import { validateBotDescriptor } from './envelope';
import { OgmaraClient } from './client';
import type { BotDescriptor } from './types';

const cmd = (description: string) => [{ name: 'c', description }];

describe('validateBotDescriptor', () => {
  it('measures caps in UTF-8 BYTES, not UTF-16 units (0.57.1 regression)', () => {
    // SHIPPED BROKEN IN 0.57.0: `.length` is UTF-16 code units, so 128 CJK
    // characters measured 128 locally and 384 bytes at the node. The check
    // passed and the node then rejected it — undercutting the entire point of
    // validating locally, for exactly the non-ASCII authors the
    // "not an ASCII allowlist" rule exists to protect.
    const cjk128 = '\u63cf'.repeat(128); // 128 UTF-16 units, 384 UTF-8 bytes
    expect(() => validateBotDescriptor({ is_bot: true, commands: cmd(cjk128) })).toThrow(
      /UTF-8 bytes/,
    );
    // 42 CJK chars = 126 bytes, comfortably under the 128-byte cap.
    expect(() =>
      validateBotDescriptor({ is_bot: true, commands: cmd('\u63cf'.repeat(42)) }),
    ).not.toThrow();
  });

  it('rejects control and bidi codepoints locally, like the node does', () => {
    const bad = [
      'a\u202eb',    // right-to-left override
      'a\u0007b',    // C0 control
      'a\u200bb',    // zero-width space
      'a\ufeffb',    // BOM
      'a\u{e0041}b', // tag character
    ];
    for (const s of bad) {
      expect(() => validateBotDescriptor({ is_bot: true, commands: cmd(s) })).toThrow(
        /control or bidirectional/,
      );
    }
  });

  it('still accepts emoji ZWJ sequences and Persian ZWNJ', () => {
    // These sit inside the U+200B..U+200F block a naive range sweeps up.
    const ok = [
      'Run \u{1f469}\u200d\u{1f4bb}', // ZWJ emoji sequence
      '\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645', // Persian ZWNJ
      '\u56fe\u8868\u67e5\u8be2', // CJK
    ];
    for (const s of ok) {
      expect(() => validateBotDescriptor({ is_bot: true, commands: cmd(s) })).not.toThrow();
    }
  });

  it('rejects a non-lowercase command name', () => {
    expect(() =>
      validateBotDescriptor({ is_bot: true, commands: [{ name: 'Dom', description: 'd' }] }),
    ).toThrow(/lowercase/);
  });
});

describe('setBotCommands', () => {
  it('cannot be tricked into clearing the descriptor (0.57.1 regression)', async () => {
    // SHIPPED BROKEN IN 0.57.0: the implementation was
    // `{ is_bot: true, ...descriptor }` — spread LAST, so a caller-supplied
    // `is_bot: false` won, and on the node that is the explicit CLEAR branch.
    // `Omit<BotDescriptor,'is_bot'>` gave no runtime protection, because
    // TypeScript's excess-property check only fires on fresh object literals.
    // So calling the method named "set commands" could wipe the bot outright.
    const client = new OgmaraClient({ nodeUrl: 'https://example.invalid' });
    const spy = vi
      .spyOn(client, 'updateProfile')
      .mockResolvedValue(undefined as unknown as void);

    const hostile = { is_bot: false, handle: 'x', commands: cmd('d') } as BotDescriptor;
    await client.setBotCommands(hostile as Omit<BotDescriptor, 'is_bot'>);

    expect(spy).toHaveBeenCalledTimes(1);
    const sent = spy.mock.calls[0][0];
    expect(sent.bot?.is_bot).toBe(true);
    expect(sent.bot?.handle).toBe('x');
  });
});
