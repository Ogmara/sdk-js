/**
 * Utility functions for the Ogmara SDK.
 *
 * Text formatting, URL detection, hashtag extraction.
 */

import type { AnchorStatus, Channel } from './types';
import { isPrivateIpv4, isPrivateIpv6, isPrivateDnsName } from './sc_discovery';

/** Default production node. */
export const DEFAULT_NODE_URL = 'https://node.ogmara.org';

/**
 * Extract hashtags from text content.
 *
 * Rules (from protocol spec):
 * - Match `#word` patterns (alphanumeric + underscores)
 * - Lowercase all tags
 * - Deduplicate
 * - Maximum 10 tags
 */
export function extractHashtags(text: string): string[] {
  const regex = /#([a-zA-Z0-9_]+)/g;
  const tags = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (tags.size >= 10) break;
    tags.add(match[1].toLowerCase());
  }

  return Array.from(tags);
}

// --- URL Detection ---

/** Regex for detecting URLs in plain text. */
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;

/** A segment of formatted text — either plain text, a URL, or formatted span. */
export type TextSegment =
  | { type: 'text'; content: string }
  | { type: 'url'; url: string; display: string }
  | { type: 'bold'; content: string }
  | { type: 'italic'; content: string }
  | { type: 'underline'; content: string }
  | { type: 'code'; content: string }
  | { type: 'strikethrough'; content: string };

/**
 * Parse a message string into segments with URLs and formatting.
 *
 * Supported formatting (Markdown subset for chat):
 * - `**bold**`
 * - `*italic*`
 * - `__underline__`
 * - `` `code` ``
 * - `~~strikethrough~~`
 *
 * URLs are auto-detected and split into separate segments.
 */
export function parseMessageContent(text: string): TextSegment[] {
  // First pass: extract URLs
  const urlSegments = splitByUrls(text);

  // Second pass: parse formatting in text segments
  const result: TextSegment[] = [];
  for (const seg of urlSegments) {
    if (seg.type === 'url') {
      result.push(seg);
    } else {
      result.push(...parseFormatting(seg.content));
    }
  }

  return result;
}

/** Split text into plain-text and URL segments. */
function splitByUrls(text: string): TextSegment[] {
  const segments: TextSegment[] = [];
  let lastIndex = 0;

  for (const match of text.matchAll(URL_REGEX)) {
    const start = match.index!;
    if (start > lastIndex) {
      segments.push({ type: 'text', content: text.slice(lastIndex, start) });
    }
    // Cap URL length to prevent memory abuse
    let url = match[0];
    if (url.length > 2048) {
      segments.push({ type: 'text', content: url });
      lastIndex = start + match[0].length;
      continue;
    }
    const trailingPunct = /[.,;:!?)]+$/.exec(url);
    let trailing = '';
    if (trailingPunct) {
      trailing = trailingPunct[0];
      url = url.slice(0, -trailing.length);
    }
    // Display URL without protocol for cleanliness
    const display = url.replace(/^https?:\/\//, '');
    segments.push({ type: 'url', url, display });
    if (trailing) {
      segments.push({ type: 'text', content: trailing });
    }
    lastIndex = start + match[0].length;
  }

  if (lastIndex < text.length) {
    segments.push({ type: 'text', content: text.slice(lastIndex) });
  }

  return segments;
}

/** Parse inline formatting from a plain-text segment. */
function parseFormatting(text: string): TextSegment[] {
  // Order matters: code first (prevents inner parsing), then multi-char markers
  const patterns: { regex: RegExp; type: TextSegment['type'] }[] = [
    { regex: /`([^`]+)`/g, type: 'code' },
    { regex: /\*\*(.+?)\*\*/g, type: 'bold' },
    { regex: /~~(.+?)~~/g, type: 'strikethrough' },
    { regex: /__(.+?)__/g, type: 'underline' },
    { regex: /\*(.+?)\*/g, type: 'italic' },
  ];

  let segments: TextSegment[] = [{ type: 'text', content: text }];

  for (const { regex, type } of patterns) {
    const next: TextSegment[] = [];
    for (const seg of segments) {
      if (seg.type !== 'text') {
        next.push(seg);
        continue;
      }
      let lastIdx = 0;
      const source = seg.content;
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(source)) !== null) {
        if (m.index > lastIdx) {
          next.push({ type: 'text', content: source.slice(lastIdx, m.index) });
        }
        next.push({ type, content: m[1] } as TextSegment);
        lastIdx = m.index + m[0].length;
      }
      if (lastIdx < source.length) {
        next.push({ type: 'text', content: source.slice(lastIdx) });
      }
    }
    segments = next;
  }

  return segments;
}

// --- Formatting helpers for composing ---

/** Wrap selected text with formatting markers. */
export function applyFormatting(
  text: string,
  selectionStart: number,
  selectionEnd: number,
  format: 'bold' | 'italic' | 'underline' | 'code' | 'strikethrough',
): { text: string; cursorPos: number } {
  const markers: Record<string, [string, string]> = {
    bold: ['**', '**'],
    italic: ['*', '*'],
    underline: ['__', '__'],
    code: ['`', '`'],
    strikethrough: ['~~', '~~'],
  };
  const [open, close] = markers[format];
  const before = text.slice(0, selectionStart);
  const selected = text.slice(selectionStart, selectionEnd);
  const after = text.slice(selectionEnd);
  const newText = before + open + selected + close + after;
  // When no text is selected, place cursor between markers so user can type
  const cursorPos = selectionStart === selectionEnd
    ? selectionStart + open.length
    : selectionEnd + open.length + close.length;
  return { text: newText, cursorPos };
}

// --- Node discovery helpers ---

/** Private/reserved IP ranges that must be blocked to prevent SSRF. */
/** Options for {@link validateNodeUrl}. */
export interface ValidateNodeUrlOptions {
  /**
   * Allow private / LAN / loopback hostnames (e.g. `192.168.x.x`,
   * `localhost`, `10.x.x.x`).
   *
   * **Default `false`** — the SSRF block stays on for the web client,
   * where a hosted page making requests to the user's LAN is a real
   * attack surface (DNS rebinding, browser-side SSRF).
   *
   * **Set to `true` on desktop / mobile clients** — those apps are
   * already local code with full host access, so blocking LAN URLs
   * just prevents the user from connecting to their own L2 node on
   * the same network. The Tauri / React-Native shell IS the trust
   * boundary, not the URL host filter.
   */
  allowPrivateHosts?: boolean;
}

/**
 * Validate a node URL for safety (SSRF prevention).
 * Returns the validated URL or null if unsafe.
 *
 * Pass `{ allowPrivateHosts: true }` on local-trust clients (desktop
 * Tauri shell, native mobile) to permit LAN/loopback URLs — see
 * {@link ValidateNodeUrlOptions} for the security rationale.
 */
export function validateNodeUrl(
  url: string,
  options: ValidateNodeUrlOptions = {},
): string | null {
  try {
    // Reasonable length limit (before parse).
    if (url.length > 256) return null;
    const parsed = new URL(url);
    // Only allow http/https schemes.
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return null;
    }
    if (!options.allowPrivateHosts) {
      // Web / SSRF-sensitive mode (audit 2026-06-07 B4.2):
      //  1. Require https — no plaintext downgrade for a remote node.
      if (parsed.protocol !== 'https:') return null;
      //  2. Reject private / reserved hosts. `parsed.hostname` is already
      //     WHATWG-canonicalized, so decimal/hex/octal IPv4 (e.g.
      //     `http://2130706433`) and IPv4-mapped IPv6 are normalized to a
      //     form the structured checks below catch — defeating the
      //     string-blocklist bypasses the old regex set missed. The checks
      //     are shared with the SC-discovery dial path (`sc_discovery.ts`).
      let host = parsed.hostname.toLowerCase();
      if (host.startsWith('[') && host.endsWith(']')) {
        if (isPrivateIpv6(host.slice(1, -1))) return null;
      } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        if (isPrivateIpv4(host)) return null;
      } else if (isPrivateDnsName(host)) {
        return null;
      }
      // A public DNS name passes here; DNS-rebinding at fetch time is a
      // residual the browser/dialer must handle (documented).
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

/** Measure ping to a node URL (ms). Returns Infinity on failure.
 *  Validates the response is an actual L2 node health endpoint
 *  (must return JSON with `version` field) to avoid false positives
 *  from web servers that return 200 on any path.
 *
 *  Pass `{ allowPrivateHosts: true }` to permit LAN / loopback URLs
 *  (desktop and mobile clients should do this; web should not). */
export async function pingNode(
  nodeUrl: string,
  timeout = 5000,
  options: ValidateNodeUrlOptions = {},
): Promise<number> {
  const validated = validateNodeUrl(nodeUrl, options);
  if (!validated) return Infinity;

  const start = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${validated}/api/v1/health`, { signal: controller.signal });
    if (!resp.ok) return Infinity;
    // Validate this is actually an L2 node, not a random web server
    const body = await resp.json();
    if (!body || typeof body.version !== 'string') return Infinity;
    return Date.now() - start;
  } catch {
    return Infinity;
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Node with measured latency. */
export interface NodeWithPing {
  url: string;
  ping: number; // ms, Infinity if unreachable
  nodeId?: string;
  peers?: number;
  anchorStatus?: AnchorStatus;
}

/**
 * Discover and ping all available nodes.
 * Returns nodes sorted by latency (best first).
 *
 * Pass `{ allowPrivateHosts: true }` for desktop / mobile so the
 * primary node URL and any peer-advertised endpoints on the LAN
 * survive validation. Web should leave it off.
 */
export async function discoverAndPingNodes(
  primaryUrl: string,
  options: ValidateNodeUrlOptions = {},
): Promise<NodeWithPing[]> {
  const results: NodeWithPing[] = [];

  // Always include the primary/default node
  const primaryPing = await pingNode(primaryUrl, undefined, options);
  results.push({ url: primaryUrl, ping: primaryPing });

  // Try to discover more nodes from the primary
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(`${primaryUrl}/api/v1/network/nodes`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (resp.ok) {
      const data = await resp.json();
      const nodes: { api_endpoint?: string; node_id?: string; anchor_status?: AnchorStatus }[] = data.nodes ?? [];
      // Ping discovered nodes in parallel (max 10)
      const candidates = nodes
        .filter((n) => n.api_endpoint && n.api_endpoint !== primaryUrl && validateNodeUrl(n.api_endpoint, options))
        .slice(0, 10);
      const pings = await Promise.all(
        candidates.map(async (n) => {
          const p = await pingNode(n.api_endpoint!, undefined, options);
          return { url: n.api_endpoint!, ping: p, nodeId: n.node_id, anchorStatus: n.anchor_status };
        }),
      );
      results.push(...pings);
    }
  } catch {
    // Discovery failed — just use the primary
  }

  // Sort: online first (filtered), then latency (primary), anchor level (tiebreaker)
  const anchorRank = (n: NodeWithPing): number => {
    if (!n.anchorStatus) return 2;
    if (n.anchorStatus.level === 'active') return 0;
    if (n.anchorStatus.level === 'verified') return 1;
    return 2;
  };

  return results.sort((a, b) => {
    // Unreachable nodes go to the bottom
    if (a.ping === Infinity && b.ping !== Infinity) return 1;
    if (a.ping !== Infinity && b.ping === Infinity) return -1;
    if (a.ping === Infinity && b.ping === Infinity) return 0;
    // Primary sort: latency
    const pingDiff = a.ping - b.ping;
    // Within same latency tier (50ms tolerance), prefer verified nodes
    if (Math.abs(pingDiff) > 50) return pingDiff;
    const rankDiff = anchorRank(a) - anchorRank(b);
    if (rankDiff !== 0) return rankDiff;
    return pingDiff;
  });
}

/**
 * Channel type constants (mirrors `ChannelType` in the protocol spec §3.6).
 *
 * Stored on the channel record as a numeric value. `Public` and `ReadPublic`
 * are L2-mutable; `Private` is set at creation and cannot be flipped.
 */
export const CHANNEL_TYPE_PUBLIC = 0;
export const CHANNEL_TYPE_READ_PUBLIC = 1;
export const CHANNEL_TYPE_PRIVATE = 2;

/**
 * Whether a given address is permitted to post `ChatMessage` / `ChatEdit` /
 * `ChatDelete` to a channel under the channel's runtime posting policy.
 *
 * Posting rules (protocol spec §3.6):
 * - `Public` (0): any member with a valid signature can post.
 * - `ReadPublic` (1, broadcast): only the creator and moderators can post;
 *   members may still react.
 * - `Private` (2): same as `Public` for the membership-set; non-members are
 *   already filtered out at the membership layer.
 *
 * Pass the moderator-status flag the caller already knows from its UI state
 * (e.g. `myRole() === 'moderator'`). When `isModerator` is unknown, pass
 * `false` — this errs on the safe side and hides the composer.
 *
 * @param channel - the channel record from `getChannel()` / `listChannels()`
 * @param address - the wallet address (klv1...) that wants to post
 * @param isModerator - whether `address` is a moderator of `channel`
 * @returns `true` if posting is permitted under the read-only policy
 */
export function canPost(
  channel: Pick<Channel, 'channel_type' | 'creator'>,
  address: string,
  isModerator: boolean,
): boolean {
  if (channel.channel_type !== CHANNEL_TYPE_READ_PUBLIC) {
    // Public and Private channels: posting is gated elsewhere (membership,
    // bans, mutes). The read-only policy itself is permissive.
    return true;
  }
  // ReadPublic: creator + moderators only.
  return channel.creator === address || isModerator;
}
