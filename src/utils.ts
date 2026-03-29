/**
 * Utility functions for the Ogmara SDK.
 */

/**
 * Extract hashtags from text content.
 *
 * Rules (from protocol spec):
 * - Match `#word` patterns (alphanumeric + underscores)
 * - Lowercase all tags
 * - Deduplicate
 * - Maximum 10 tags
 *
 * @example
 * ```ts
 * extractHashtags('Hello #World! Check out #crypto and #DeFi #crypto');
 * // Returns: ['world', 'crypto', 'defi']
 * ```
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
