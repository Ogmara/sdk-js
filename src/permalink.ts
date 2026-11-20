/**
 * Share links ("permalinks") — one build/parse pair for every client
 * (docs/planning/message-permalinks-plan.md §4.5, §5.5, §8.7).
 *
 * Canonical forms (frozen — links already in the wild must keep resolving):
 *
 * | Target       | Canonical                                              | Native                                   |
 * |--------------|--------------------------------------------------------|------------------------------------------|
 * | Chat message | `https://ogmara.org/app/#/chat/<channel_id>?msg=<hex>` | `ogmara://chat/<channel_id>?msg=<hex>`   |
 * | News post    | `https://ogmara.org/app/#/news/<hex>`                  | `ogmara://news/<hex>`                    |
 * | News comment | `https://ogmara.org/app/#/news/<hex>?c=<hex>`          | `ogmara://news/<hex>?c=<hex>`            |
 * | Invite       | `https://ogmara.org/app/#/join/<channel_id>[?node=…][&inv=…]` | `ogmara://join/<channel_id>[?…]`  |
 *
 * PRIVACY: the target always lives AFTER the `#`. User agents and link-preview
 * crawlers never transmit the fragment, so a pasted link produces exactly one
 * server request (`GET /app/`) that names no channel and no message. Never
 * add a form that moves the identifier into the path or query (plan §8.1).
 * DMs deliberately have no permalink (plan §7.5).
 *
 * The parser is fed hostile strings (pasted text, OS-supplied deep links).
 * It is pure string processing — no `URL` dependency, so it behaves the same
 * under React Native — and matches the base by exact prefix: scheme and host
 * compared case-insensitively, then the path literally, then only `/`, an
 * optional outer `?query` and the `#`. `https://ogmara.org.evil.tld/app/#…`,
 * `https://evil@ogmara.org/…`, `https://ogmara.org:8443/app/#…` and
 * `http://ogmara.org/app/#…` all fail.
 */

/** Canonical public base for share links. */
export const PERMALINK_BASE = 'https://ogmara.org/app';

/** Native deep-link scheme prefix. */
export const PERMALINK_NATIVE_PREFIX = 'ogmara://';

/** Longest input {@link parsePermalink} looks at (an `inv=` is ≤ 2731 chars). */
const MAX_PERMALINK_LEN = 8192;
/** Longest `node=` URL accepted/emitted. */
const MAX_NODE_URL_LEN = 2048;
/**
 * Longest `inv=` param: unpadded base64url of a maximal invite envelope.
 * 2048 = `MAX_INVITE_ENVELOPE_BYTES` (invite.ts), inlined because invite.ts
 * imports {@link isPermalinkNodeUrl} from here; a test pins the two equal.
 */
export const MAX_PERMALINK_INV_LEN = Math.ceil((2048 * 4) / 3);

const HEX64 = /^[0-9a-fA-F]{64}$/;
/** Canonical decimal: no sign, no leading zero, ≤ 16 digits (2^53 has 16). */
const CHANNEL_ID_DEC = /^[1-9][0-9]{0,15}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** http(s) base: scheme://host[:port][/path], path without query/fragment. */
const BASE_URL = /^(https?:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?)(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$/;
// eslint-disable-next-line no-control-regex
const WHITESPACE_OR_CONTROL = /[\u0000-\u0020\u007f-\u009f\u2028\u2029]/;

/** What a share link points at. `msgId` / `commentId` are lower-case 64-hex. */
export type PermalinkTarget =
  | { kind: 'chat'; channelId: number; msgId: string }
  | { kind: 'news'; msgId: string; commentId?: string }
  | {
      kind: 'join';
      channelId: number;
      /**
       * Host node hint (http(s) URL, shape-checked by {@link isPermalinkNodeUrl}).
       * UNTRUSTED: pass it through `validateNodeUrl()` before any fetch;
       * display `new URL(node).host`, never the raw string; never auto-switch
       * nodes — ask the user first.
       */
      node?: string;
      /**
       * Personal Private-channel invite, raw base64url as in the link. Only
       * shape-checked here; decode with `decodeInviteFromUrl` and verify with
       * `decodeChannelInvite`. Build real invite links with
       * `buildPrivateChannelInviteUrl`, which validates the envelope.
       */
      inv?: string;
    };

/** Options for {@link buildPermalink}. */
export interface BuildPermalinkOptions {
  /** Emit the `ogmara://…` native form instead of an https link. */
  native?: boolean;
  /**
   * Override the https base (self-hosters), e.g. `https://chat.example.org/app`.
   * Must be an http(s) URL without query or fragment; throws otherwise.
   * Default {@link PERMALINK_BASE}. Ignored when `native` is set.
   */
  base?: string;
}

/** Options for {@link parsePermalink}. */
export interface ParsePermalinkOptions {
  /**
   * Additional bases to accept, matched EXACTLY like the canonical one
   * (which is always accepted). Never derive these from the link itself.
   * Throws if one is not a valid http(s) base.
   */
  extraBases?: readonly string[];
  /** Accept the `ogmara://` native form. Default `true`. */
  allowNative?: boolean;
}

/** Lower-cased msg_id if `s` is exactly 64 hex chars, else null. */
export function normalizeMsgId(s: unknown): string | null {
  return typeof s === 'string' && HEX64.test(s) ? s.toLowerCase() : null;
}

function validChannelId(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0;
}

/**
 * Shape check for a `node=` host hint, shared by {@link buildPermalink},
 * {@link parsePermalink} and `buildPrivateChannelInviteUrl` so a builder can
 * never emit a value the parser rejects: `http(s)://` + non-empty authority,
 * printable ASCII only (no IDN homographs, bidi overrides, whitespace or lone
 * surrogates — the last would make `encodeURIComponent` throw), no `@` in the
 * authority (no userinfo spoofing like `https://ogmara.org@evil.com`), at most
 * 2048 chars. This is NOT a safety check for fetching: callers must still run
 * `validateNodeUrl()` before any request.
 */
export function isPermalinkNodeUrl(s: unknown): s is string {
  if (typeof s !== 'string' || s.length > MAX_NODE_URL_LEN || !/^[\x21-\x7e]+$/.test(s)) return false;
  const m = /^https?:\/\/([^/?#]+)/.exec(s);
  return m !== null && !m[1]!.includes('@');
}

function validInv(s: unknown): s is string {
  return typeof s === 'string' && s.length > 0 && s.length <= MAX_PERMALINK_INV_LEN && BASE64URL.test(s);
}

/** Validate + split an http(s) base into origin and path (no trailing `/`). */
function splitBase(base: string): { origin: string; path: string } {
  const m = typeof base === 'string' ? BASE_URL.exec(base.replace(/\/+$/, '')) : null;
  if (!m) throw new TypeError(`invalid permalink base: ${String(base)}`);
  return { origin: m[1]!.toLowerCase(), path: m[2] ?? '' };
}

/** Route part (`chat/1?msg=…`), no leading slash; null if the target is invalid. */
function buildRoute(t: PermalinkTarget): string | null {
  if (!t || typeof t !== 'object') return null;
  switch (t.kind) {
    case 'chat': {
      const id = normalizeMsgId(t.msgId);
      if (!validChannelId(t.channelId) || !id) return null;
      return `chat/${t.channelId}?msg=${id}`;
    }
    case 'news': {
      const id = normalizeMsgId(t.msgId);
      if (!id) return null;
      if (t.commentId === undefined) return `news/${id}`;
      const c = normalizeMsgId(t.commentId);
      return c ? `news/${id}?c=${c}` : null;
    }
    case 'join': {
      if (!validChannelId(t.channelId)) return null;
      const params: string[] = [];
      if (t.node !== undefined) {
        if (!isPermalinkNodeUrl(t.node)) return null;
        params.push(`node=${encodeURIComponent(t.node)}`);
      }
      if (t.inv !== undefined) {
        if (!validInv(t.inv)) return null;
        params.push(`inv=${t.inv}`);
      }
      return `join/${t.channelId}${params.length ? `?${params.join('&')}` : ''}`;
    }
    default:
      return null;
  }
}

/**
 * Build a share link. Returns `null` when the target is invalid (channel id
 * not a positive safe integer, msg/comment id not 64-hex, malformed `node` /
 * `inv`). Ids are emitted lower-case. Throws only on an invalid `options.base`.
 */
export function buildPermalink(target: PermalinkTarget, options: BuildPermalinkOptions = {}): string | null {
  const route = buildRoute(target);
  if (route === null) return null;
  if (options.native) return `${PERMALINK_NATIVE_PREFIX}${route}`;
  const { origin, path } = splitBase(options.base ?? PERMALINK_BASE);
  return `${origin}${path}/#/${route}`;
}

/** Strict `k=v&k=v` parse; null on a duplicate key or undecodable value. */
function parseQuery(q: string): Map<string, string> | null {
  const out = new Map<string, string>();
  if (q === '') return out;
  for (const part of q.split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const rawKey = eq < 0 ? part : part.slice(0, eq);
    const rawVal = eq < 0 ? '' : part.slice(eq + 1);
    let key: string;
    let val: string;
    try {
      key = decodeURIComponent(rawKey);
      val = decodeURIComponent(rawVal);
    } catch {
      return null;
    }
    // A repeated key is ambiguous (first-wins vs last-wins differs between
    // parsers) — reject rather than pick one.
    if (out.has(key)) return null;
    out.set(key, val);
  }
  return out;
}

function decodeSegment(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

function parseChannelId(seg: string): number | null {
  const s = decodeSegment(seg);
  if (s === null || !CHANNEL_ID_DEC.test(s)) return null;
  const n = Number(s);
  // Rejects ≥ 2^53: a digit string that does not survive the round trip
  // would silently name a different channel.
  return Number.isSafeInteger(n) && String(n) === s ? n : null;
}

/** Parse the route after `#/` or `ogmara://`: `kind/<id>[/][?query]`. */
function parseRoute(route: string): PermalinkTarget | null {
  if (route.includes('#')) return null;
  const qi = route.indexOf('?');
  const pathPart = qi < 0 ? route : route.slice(0, qi);
  const query = parseQuery(qi < 0 ? '' : route.slice(qi + 1));
  if (!query) return null;
  // Split BEFORE decoding so an encoded `%2F` cannot forge a segment.
  const segs = pathPart.replace(/\/$/, '').split('/');
  if (segs.length !== 2) return null;
  const [kind, idSeg] = segs as [string, string];
  switch (kind) {
    case 'chat': {
      const channelId = parseChannelId(idSeg);
      const msgId = normalizeMsgId(query.get('msg'));
      if (channelId === null || !msgId) return null;
      return { kind: 'chat', channelId, msgId };
    }
    case 'news': {
      const msgId = normalizeMsgId(decodeSegment(idSeg));
      if (!msgId) return null;
      if (!query.has('c')) return { kind: 'news', msgId };
      const commentId = normalizeMsgId(query.get('c'));
      return commentId ? { kind: 'news', msgId, commentId } : null;
    }
    case 'join': {
      const channelId = parseChannelId(idSeg);
      if (channelId === null) return null;
      const t: Extract<PermalinkTarget, { kind: 'join' }> = { kind: 'join', channelId };
      if (query.has('node')) {
        const node = query.get('node');
        if (!isPermalinkNodeUrl(node)) return null;
        t.node = node;
      }
      if (query.has('inv')) {
        const inv = query.get('inv');
        if (!validInv(inv)) return null;
        t.inv = inv;
      }
      return t;
    }
    default:
      return null;
  }
}

/**
 * Parse a share link into its target, or `null` for anything that is not a
 * well-formed Ogmara permalink on an accepted base. Never throws on input
 * (throws only on an invalid `options.extraBases` entry).
 *
 * Accepts the canonical `https://ogmara.org/app/#/…` form (an optional `/`
 * before the `#` and an outer `?query` such as a tracker param are
 * tolerated), any `extraBases` given, and — unless `allowNative: false` —
 * `ogmara://…`. Unknown query keys are ignored (e.g. the reserved thread
 * `t=`); a repeated key, a bad id, a bad `c`/`node`/`inv`, or an extra path
 * segment rejects the whole link. Bare channel links (`#/chat/<id>` without
 * `?msg=`) are not permalinks and return `null`.
 */
export function parsePermalink(input: string, options: ParsePermalinkOptions = {}): PermalinkTarget | null {
  const bases = [PERMALINK_BASE, ...(options.extraBases ?? [])].map(splitBase);
  if (typeof input !== 'string' || input.length > MAX_PERMALINK_LEN) return null;
  const s = input.trim();
  if (s === '' || WHITESPACE_OR_CONTROL.test(s)) return null;

  if (options.allowNative !== false && s.slice(0, PERMALINK_NATIVE_PREFIX.length).toLowerCase() === PERMALINK_NATIVE_PREFIX) {
    // Some link handlers hand over `ogmara:///chat/…`; tolerate one extra slash.
    return parseRoute(s.slice(PERMALINK_NATIVE_PREFIX.length).replace(/^\//, ''));
  }

  for (const { origin, path } of bases) {
    if (s.slice(0, origin.length).toLowerCase() !== origin) continue;
    if (s.slice(origin.length, origin.length + path.length) !== path) continue;
    // After the base: optional `/`, optional outer `?query` (no `#` in it), then `#/`.
    const m = /^\/?(?:\?[^#]*)?#\/(.*)$/.exec(s.slice(origin.length + path.length));
    if (m) return parseRoute(m[1]!);
  }
  return null;
}
