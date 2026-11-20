import { describe, it, expect } from 'vitest';
import { buildPermalink, parsePermalink, normalizeMsgId, PERMALINK_BASE, type PermalinkTarget } from './permalink';

const A = 'ab'.repeat(32);
const B = 'cd'.repeat(32);
const A_UP = A.toUpperCase();
/** Largest id a private channel can get (derivation modulus is 2^53-1). */
const BIG = Number.MAX_SAFE_INTEGER - 1;

describe('buildPermalink', () => {
  it('builds the frozen canonical forms', () => {
    expect(buildPermalink({ kind: 'chat', channelId: 9, msgId: A })).toBe(`https://ogmara.org/app/#/chat/9?msg=${A}`);
    expect(buildPermalink({ kind: 'news', msgId: A })).toBe(`https://ogmara.org/app/#/news/${A}`);
    expect(buildPermalink({ kind: 'news', msgId: A, commentId: B })).toBe(`https://ogmara.org/app/#/news/${A}?c=${B}`);
    expect(buildPermalink({ kind: 'join', channelId: 9 })).toBe('https://ogmara.org/app/#/join/9');
    expect(buildPermalink({ kind: 'join', channelId: 9, node: 'https://n.example:8443/x', inv: 'AbC-_9' })).toBe(
      'https://ogmara.org/app/#/join/9?node=https%3A%2F%2Fn.example%3A8443%2Fx&inv=AbC-_9',
    );
  });

  it('lower-cases ids', () => {
    expect(buildPermalink({ kind: 'chat', channelId: 1, msgId: A_UP })).toBe(`${PERMALINK_BASE}/#/chat/1?msg=${A}`);
  });

  it('emits the native form', () => {
    expect(buildPermalink({ kind: 'chat', channelId: 9, msgId: A }, { native: true })).toBe(`ogmara://chat/9?msg=${A}`);
    expect(buildPermalink({ kind: 'news', msgId: A, commentId: B }, { native: true })).toBe(`ogmara://news/${A}?c=${B}`);
  });

  it('honours a self-hosted base and strips trailing slashes', () => {
    expect(buildPermalink({ kind: 'news', msgId: A }, { base: 'https://chat.example.org/app/' })).toBe(
      `https://chat.example.org/app/#/news/${A}`,
    );
    expect(() => buildPermalink({ kind: 'news', msgId: A }, { base: 'javascript:alert(1)' })).toThrow(TypeError);
    expect(() => buildPermalink({ kind: 'news', msgId: A }, { base: 'https://x.org/app?q=1' })).toThrow(TypeError);
  });

  it('keeps private channel ids ≥ 2^32 exact', () => {
    const url = buildPermalink({ kind: 'chat', channelId: BIG, msgId: A })!;
    expect(url).toContain(`/chat/${String(BIG)}?`);
    expect(url).toContain('9007199254740990');
  });

  it.each<[string, unknown]>([
    ['zero channel', { kind: 'chat', channelId: 0, msgId: A }],
    ['negative channel', { kind: 'chat', channelId: -1, msgId: A }],
    ['fractional channel', { kind: 'chat', channelId: 1.5, msgId: A }],
    ['unsafe channel', { kind: 'chat', channelId: 2 ** 53, msgId: A }],
    ['string channel', { kind: 'chat', channelId: '9', msgId: A }],
    ['short msg', { kind: 'chat', channelId: 9, msgId: A.slice(1) }],
    ['non-hex msg', { kind: 'chat', channelId: 9, msgId: 'z'.repeat(64) }],
    ['bad comment', { kind: 'news', msgId: A, commentId: 'x' }],
    ['ftp node', { kind: 'join', channelId: 9, node: 'ftp://x' }],
    ['node with space', { kind: 'join', channelId: 9, node: 'https://x y' }],
    ['bad inv', { kind: 'join', channelId: 9, inv: 'a+b/' }],
    ['IDN homograph node', { kind: 'join', channelId: 9, node: 'https://\u043egmara.org' }],
    ['bidi override node', { kind: 'join', channelId: 9, node: 'https://evil\u202egro.aramgo' }],
    ['userinfo node', { kind: 'join', channelId: 9, node: 'https://ogmara.org@evil.com' }],
    ['lone surrogate node', { kind: 'join', channelId: 9, node: 'https://a\ud800b.org' }],
    ['dm kind', { kind: 'dm', msgId: A }],
    ['null', null],
  ])('returns null (never throws) for %s', (_n, t) => {
    expect(() => buildPermalink(t as PermalinkTarget)).not.toThrow();
    expect(buildPermalink(t as PermalinkTarget)).toBeNull();
  });
});

describe('parsePermalink', () => {
  const targets: PermalinkTarget[] = [
    { kind: 'chat', channelId: 9, msgId: A },
    { kind: 'chat', channelId: BIG, msgId: A },
    { kind: 'chat', channelId: 2 ** 32 + 1, msgId: B },
    { kind: 'news', msgId: A },
    { kind: 'news', msgId: A, commentId: B },
    { kind: 'join', channelId: 9 },
    { kind: 'join', channelId: BIG, node: 'https://node.example:41721/', inv: 'AbC-_9xyz' },
  ];

  it.each(targets)('round-trips %o (https and native)', (t) => {
    expect(parsePermalink(buildPermalink(t)!)).toEqual(t);
    expect(parsePermalink(buildPermalink(t, { native: true })!)).toEqual(t);
  });

  it('returns safe-integer channel ids without precision loss', () => {
    const r = parsePermalink(`https://ogmara.org/app/#/chat/9007199254740990?msg=${A}`);
    expect(r).toEqual({ kind: 'chat', channelId: 9007199254740990, msgId: A });
  });

  it('rejects channel ids that do not fit a safe integer', () => {
    // 2^53 and 2^53+1 (the latter would silently round to 2^53).
    expect(parsePermalink(`https://ogmara.org/app/#/chat/9007199254740992?msg=${A}`)).toBeNull();
    expect(parsePermalink(`https://ogmara.org/app/#/chat/9007199254740993?msg=${A}`)).toBeNull();
    expect(parsePermalink(`https://ogmara.org/app/#/chat/18446744073709551615?msg=${A}`)).toBeNull();
  });

  it('tolerates the documented variants', () => {
    const want = { kind: 'chat', channelId: 9, msgId: A };
    expect(parsePermalink(`https://ogmara.org/app#/chat/9?msg=${A}`)).toEqual(want);
    expect(parsePermalink(`https://ogmara.org/app/#/chat/9/?msg=${A}`)).toEqual(want);
    expect(parsePermalink(`HTTPS://OGMARA.ORG/app/#/chat/9?msg=${A_UP}`)).toEqual(want);
    expect(parsePermalink(`  https://ogmara.org/app/#/chat/9?msg=${A}\n`)).toEqual(want);
    expect(parsePermalink(`https://ogmara.org/app/?fbclid=x&y=1#/chat/9?msg=${A}`)).toEqual(want);
    expect(parsePermalink(`https://ogmara.org/app/#/chat/9?msg=${A}&t=${B}`)).toEqual(want); // reserved thread key ignored
    expect(parsePermalink(`ogmara:///chat/9?msg=${A}`)).toEqual(want);
    expect(parsePermalink(`OGMARA://chat/9?msg=${A}`)).toEqual(want);
  });

  it('decodes percent-encoded ids and params', () => {
    const encA = A.replace(/a/g, '%61');
    expect(parsePermalink(`https://ogmara.org/app/#/chat/%39?msg=${encA}`)).toEqual({ kind: 'chat', channelId: 9, msgId: A });
    expect(parsePermalink(`https://ogmara.org/app/#/news/${encA}?%63=${B}`)).toEqual({ kind: 'news', msgId: A, commentId: B });
  });

  it('does not let an encoded slash forge a path segment', () => {
    expect(parsePermalink(`https://ogmara.org/app/#/chat%2F9?msg=${A}`)).toBeNull();
    expect(parsePermalink(`https://ogmara.org/app/#/chat/9%2Fx?msg=${A}`)).toBeNull();
  });

  it.each([
    ['look-alike suffix host', `https://ogmara.org.evil.tld/app/#/chat/9?msg=${A}`],
    ['look-alike prefix host', `https://notogmara.org/app/#/chat/9?msg=${A}`],
    ['subdomain', `https://www.ogmara.org/app/#/chat/9?msg=${A}`],
    ['userinfo', `https://evil@ogmara.org/app/#/chat/9?msg=${A}`],
    ['userinfo spoof', `https://ogmara.org@evil.tld/app/#/chat/9?msg=${A}`],
    ['non-default port', `https://ogmara.org:8443/app/#/chat/9?msg=${A}`],
    ['plain http', `http://ogmara.org/app/#/chat/9?msg=${A}`],
    ['backslash', `https://ogmara.org\\evil.tld/app/#/chat/9?msg=${A}`],
    ['other path', `https://ogmara.org/application#/chat/9?msg=${A}`],
    ['landing page root', `https://ogmara.org/#/chat/9?msg=${A}`],
    ['javascript scheme', `javascript:alert(1)//https://ogmara.org/app/#/chat/9?msg=${A}`],
    ['query instead of fragment', `https://ogmara.org/app/?route=/chat/9&msg=${A}`],
  ])('rejects %s', (_n, url) => {
    expect(parsePermalink(url)).toBeNull();
  });

  it.each([
    ['missing msg', 'https://ogmara.org/app/#/chat/9'],
    ['short msg', `https://ogmara.org/app/#/chat/9?msg=${A.slice(2)}`],
    ['long msg', `https://ogmara.org/app/#/chat/9?msg=${A}00`],
    ['selector injection', `https://ogmara.org/app/#/chat/9?msg=${A.slice(4)}"],*`],
    ['duplicate msg', `https://ogmara.org/app/#/chat/9?msg=${A}&msg=${B}`],
    ['leading-zero channel', `https://ogmara.org/app/#/chat/09?msg=${A}`],
    ['zero channel', `https://ogmara.org/app/#/chat/0?msg=${A}`],
    ['negative channel', `https://ogmara.org/app/#/chat/-9?msg=${A}`],
    ['hex channel', `https://ogmara.org/app/#/chat/0x9?msg=${A}`],
    ['exponent channel', `https://ogmara.org/app/#/chat/1e3?msg=${A}`],
    ['extra segment', `https://ogmara.org/app/#/chat/9/settings?msg=${A}`],
    ['second fragment', `https://ogmara.org/app/#/chat/9?msg=${A}#x`],
    ['bad percent', `https://ogmara.org/app/#/chat/9?msg=%E0%A4%A`],
    ['bad comment', `https://ogmara.org/app/#/news/${A}?c=nope`],
    ['dm route', `https://ogmara.org/app/#/dm/klv1abc?msg=${A}`],
    ['unknown kind', `https://ogmara.org/app/#/user/${A}`],
    ['node not http', 'https://ogmara.org/app/#/join/9?node=javascript%3Aalert(1)'],
    ['node with newline', 'https://ogmara.org/app/#/join/9?node=https%3A%2F%2Fa%0Ab'],
    ['inv not base64url', 'https://ogmara.org/app/#/join/9?inv=a%2Bb'],
    ['IDN homograph node', 'https://ogmara.org/app/#/join/9?node=https%3A%2F%2F%D0%BEgmara.org'],
    ['bidi override node', 'https://ogmara.org/app/#/join/9?node=https%3A%2F%2Fevil%E2%80%AEgro.aramgo'],
    ['userinfo node', 'https://ogmara.org/app/#/join/9?node=https%3A%2F%2Fogmara.org%40evil.com'],
    ['lone surrogate node', 'https://ogmara.org/app/#/join/9?node=https%3A%2F%2Fa%ED%A0%80b.org'],
    ['inner whitespace', `https://ogmara.org/app/#/chat/9?msg= ${A}`],
    ['empty', ''],
  ])('rejects malformed input: %s', (_n, url) => {
    expect(parsePermalink(url)).toBeNull();
  });

  it('never throws on non-string or oversized input', () => {
    expect(parsePermalink(undefined as unknown as string)).toBeNull();
    expect(parsePermalink(42 as unknown as string)).toBeNull();
    expect(parsePermalink(`https://ogmara.org/app/#/join/9?inv=${'A'.repeat(9000)}`)).toBeNull();
  });

  it('can refuse the native form', () => {
    expect(parsePermalink(`ogmara://chat/9?msg=${A}`, { allowNative: false })).toBeNull();
  });

  it('accepts extra bases only when explicitly given, matched exactly', () => {
    const url = `https://chat.example.org/app/#/news/${A}`;
    expect(parsePermalink(url)).toBeNull();
    expect(parsePermalink(url, { extraBases: ['https://chat.example.org/app'] })).toEqual({ kind: 'news', msgId: A });
    expect(parsePermalink(`https://chat.example.org.evil/app/#/news/${A}`, { extraBases: ['https://chat.example.org/app'] })).toBeNull();
    // Canonical stays accepted alongside extras.
    expect(parsePermalink(`https://ogmara.org/app/#/news/${A}`, { extraBases: ['https://chat.example.org/app'] })).not.toBeNull();
    expect(() => parsePermalink(url, { extraBases: ['not a url'] })).toThrow(TypeError);
  });
});

describe('normalizeMsgId', () => {
  it('accepts 64-hex in any case and lower-cases it', () => {
    expect(normalizeMsgId(A_UP)).toBe(A);
    expect(normalizeMsgId(A.slice(1))).toBeNull();
    expect(normalizeMsgId(123)).toBeNull();
  });
});
