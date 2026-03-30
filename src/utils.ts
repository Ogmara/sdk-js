/**
 * Utility functions for the Ogmara SDK.
 *
 * Text formatting, URL detection, hashtag extraction.
 */

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
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^\[::1\]/,
  /^\[fc/i,
  /^\[fd/i,
  /^\[fe80/i,
];

/**
 * Validate a node URL for safety (SSRF prevention).
 * Returns the validated URL or null if unsafe.
 */
export function validateNodeUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    // Only allow http/https schemes
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return null;
    }
    // Block private/reserved IPs
    const host = parsed.hostname;
    for (const pattern of BLOCKED_HOST_PATTERNS) {
      if (pattern.test(host)) {
        return null;
      }
    }
    // Reasonable length limit
    if (url.length > 256) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/** Measure ping to a node URL (ms). Returns Infinity on failure. */
export async function pingNode(nodeUrl: string, timeout = 5000): Promise<number> {
  const validated = validateNodeUrl(nodeUrl);
  if (!validated) return Infinity;

  const start = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${validated}/api/v1/health`, { signal: controller.signal });
    if (!resp.ok) return Infinity;
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
}

/**
 * Discover and ping all available nodes.
 * Returns nodes sorted by latency (best first).
 */
export async function discoverAndPingNodes(primaryUrl: string): Promise<NodeWithPing[]> {
  const results: NodeWithPing[] = [];

  // Always include the primary/default node
  const primaryPing = await pingNode(primaryUrl);
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
      const nodes: { api_endpoint?: string; node_id?: string }[] = data.nodes ?? [];
      // Ping discovered nodes in parallel (max 10)
      const candidates = nodes
        .filter((n) => n.api_endpoint && n.api_endpoint !== primaryUrl && validateNodeUrl(n.api_endpoint))
        .slice(0, 10);
      const pings = await Promise.all(
        candidates.map(async (n) => {
          const p = await pingNode(n.api_endpoint!);
          return { url: n.api_endpoint!, ping: p, nodeId: n.node_id };
        }),
      );
      results.push(...pings);
    }
  } catch {
    // Discovery failed — just use the primary
  }

  // Sort by ping (best first), filter out unreachable
  return results
    .filter((n) => n.ping < Infinity)
    .sort((a, b) => a.ping - b.ping);
}
