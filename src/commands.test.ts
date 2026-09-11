import { describe, it, expect } from 'vitest';
import { parseCommand } from './commands';

const ME = 'klv1me';
const OTHER = 'klv1other';

describe('parseCommand', () => {
  it('returns null for anything that is not a command', () => {
    expect(parseCommand({ content: 'hello' }, ME)).toBeNull();
    expect(parseCommand({ content: '' }, ME)).toBeNull();
    expect(parseCommand({ content: null }, ME)).toBeNull();
    expect(parseCommand({}, ME)).toBeNull();
    // A mid-message slash is a path, a date or an and/or — not a command.
    expect(parseCommand({ content: 'see and/or this' }, ME)).toBeNull();
  });

  it('lowercases the command token but NEVER the arguments', () => {
    // THE trap. Mobile keyboards autocapitalise an empty composer, so `/C KLV`
    // is what users really send — but lowercasing the whole message turns the
    // ticker into `klv` and the bot looks up a different asset. A test suite
    // written with `/c btc` passes either way, which is why this is easy to
    // ship broken.
    const parsed = parseCommand({ content: '/C KLV' }, ME);
    expect(parsed?.name).toBe('c');
    expect(parsed?.args).toEqual(['KLV']);

    const mixed = parseCommand({ content: '/Chart BTC-USD Weekly' }, ME);
    expect(mixed?.name).toBe('chart');
    expect(mixed?.args).toEqual(['BTC-USD', 'Weekly']);
  });

  it('parses arguments and preserves the raw rest', () => {
    const p = parseCommand({ content: '/ask  what is  Klever?' }, ME);
    expect(p?.name).toBe('ask');
    expect(p?.args).toEqual(['what', 'is', 'Klever?']);
    // `rest` starts at the first argument character — the whitespace separating
    // it from the command token is consumed — but INNER spacing is preserved,
    // which matters for a bot that wants the raw prompt rather than `args`.
    expect(p?.rest).toBe('what is  Klever?');
  });

  it('rejects a malformed command name rather than guessing', () => {
    expect(parseCommand({ content: '/Fo-o' }, ME)).toBeNull();
    expect(parseCommand({ content: '/über' }, ME)).toBeNull();
    expect(parseCommand({ content: '/' }, ME)).toBeNull();
  });

  it('treats a mention of me as addressed', () => {
    const p = parseCommand({ content: '/c KLV', mentions: [ME] }, ME);
    expect(p?.addressed).toBe(true);
  });

  it('treats a mention of another bot as NOT addressed to me', () => {
    const p = parseCommand({ content: '/c KLV', mentions: [OTHER] }, ME);
    expect(p?.addressed).toBe(false);
  });

  it('matches my handle case-insensitively', () => {
    expect(parseCommand({ content: '/c@CoinTrendz KLV' }, ME, 'cointrendz')?.addressed).toBe(true);
    expect(parseCommand({ content: '/c@cointrendz KLV' }, ME, 'CoinTrendz')?.addressed).toBe(true);
    expect(parseCommand({ content: '/c@cointrendz' }, ME, 'CoinTrendz')?.handle).toBe('cointrendz');
  });

  it('a handle naming another bot is decisive, even with no mentions', () => {
    // Without this, the "nobody was named" arm would wrongly claim the message.
    const p = parseCommand({ content: '/c@SomeoneElse KLV' }, ME, 'cointrendz');
    expect(p?.addressed).toBe(false);
  });

  it('a bare command with no handle and no mentions is addressed to EVERY bot', () => {
    // Deliberate: no bot can tell it was meant for another. This is why a bot
    // must fall through SILENTLY on a command it does not implement — replying
    // "unknown command" makes a three-bot channel answer every typo three times.
    const p = parseCommand({ content: '/help' }, ME);
    expect(p?.addressed).toBe(true);
    expect(p?.handle).toBeNull();
  });

  it('a handle naming another bot beats mentions[] (0.57.1 regression)', () => {
    // SHIPPED BROKEN IN 0.57.0: `mentionedMe` short-circuited ahead of the
    // handle check, so a message explicitly addressed to another bot still made
    // this one answer if its address appeared in mentions[]. mentions[] is
    // plaintext and set by the sender — so one crafted message naming bot B by
    // handle while listing every bot's address made ALL of them reply, each
    // spending its own wallet and rate budget.
    const p = parseCommand(
      { content: '/c@otherbot KLV', mentions: [ME, 'klv1otherbot'] },
      ME,
      'mybothandle',
    );
    expect(p?.handle).toBe('otherbot');
    expect(p?.addressed).toBe(false);
  });

  it('my own handle still wins even when someone else is mentioned', () => {
    const p = parseCommand({ content: '/c@mine KLV', mentions: [OTHER] }, ME, 'MINE');
    expect(p?.addressed).toBe(true);
  });

  it('rejects a handle containing @ rather than parsing it oddly', () => {
    expect(parseCommand({ content: '/a@@b' }, ME)).toBeNull();
    expect(parseCommand({ content: '/a@b@c' }, ME)).toBeNull();
  });

  it('handles a command with no arguments', () => {
    const p = parseCommand({ content: '/about' }, ME);
    expect(p?.name).toBe('about');
    expect(p?.args).toEqual([]);
    expect(p?.rest).toBe('');
  });

  it('works on decrypted content from an encrypted channel', () => {
    // In an encrypted channel `content` arrives empty and the text is in
    // `enc_content`; the bot decrypts first. `mentions` stays plaintext, which
    // is how it knew to look at all.
    const p = parseCommand({ content: '/c KLV', mentions: [ME] }, ME);
    expect(p?.addressed).toBe(true);
    expect(p?.args).toEqual(['KLV']);
  });
});
