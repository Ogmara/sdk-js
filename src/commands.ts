/**
 * Bot command parsing (protocol §3.3, §3.11).
 *
 * A slash command is an **ordinary chat message** whose content begins with
 * `/name` or `/name@handle`, with the bot's wallet in the envelope's
 * `mentions[]`. There is no command message type — which is what lets commands
 * reuse moderation, mute, rate limits and reports unchanged, and what makes
 * them indistinguishable from chat to a hostile relay.
 *
 * The consequence bot authors must understand: because a node cannot identify
 * command traffic, it cannot rate-limit invocations either. **Per-invoker
 * limiting is your job**, and it is also where it belongs — only your bot knows
 * what a given command costs it to answer.
 */

/**
 * The decoded chat payload a bot inspects.
 *
 * Deliberately NOT the raw `Envelope`: its `payload` is msgpack bytes, and in an
 * encrypted channel the text rides in `enc_content` and must be decrypted first.
 * A bot therefore always has a decoded object by the time it calls this.
 *
 * `mentions` stays PLAINTEXT even in encrypted channels (protocol §3.3), which
 * is how a bot learns it was addressed without reading the message text.
 */
export interface CommandMessage {
  /** Plaintext message content — post-decryption for an encrypted channel. */
  content?: string | null;
  /** Wallet addresses named in the envelope. Plaintext even when encrypted. */
  mentions?: string[] | null;
}

/** A parsed command invocation. */
export interface ParsedCommand {
  /** Command name, lowercased. Never includes the leading `/`. */
  name: string;
  /**
   * Arguments, split on whitespace, **with original casing preserved**.
   *
   * `/c KLV` yields `["KLV"]`. Lowercasing arguments would turn a ticker into
   * `klv` and send the bot looking up a different asset — see `parseCommand`.
   */
  args: string[];
  /** The `@handle` the user typed, lowercased, or `null` if they typed none. */
  handle: string | null;
  /** Whether this invocation is addressed to the calling bot. */
  addressed: boolean;
  /**
   * Everything after the command token, starting at the first argument
   * character. The whitespace separating it from the token is consumed; inner
   * spacing is preserved, so a bot wanting the raw prompt (`/ask what is  X`)
   * should use this rather than re-joining `args`.
   */
  rest: string;
}

/**
 * Parse a chat envelope as a bot command invocation.
 *
 * Returns `null` when the message is not a command at all.
 *
 * `addressed` is true when:
 *  - the typed `@handle` matches `myHandle` (case-insensitively) — this wins
 *    outright; or
 *  - NO `@handle` named a different bot, AND either `mentions[]` contains
 *    `myAddress` or the message named nobody at all.
 *
 * A handle naming another bot is decisive over `mentions[]` too, not just over
 * the fallback. `mentions[]` is plaintext and set by whoever sent the message,
 * so otherwise a crafted message could name one bot by handle while listing
 * every bot's address, and all of them would answer — each reply spending that
 * bot's own wallet and rate budget.
 *
 * **That last arm means a bare `/foo` is addressed to EVERY bot in the channel**
 * — none of them can tell it was meant for another. So a bot MUST fall through
 * silently on a command it does not implement. Never reply "unknown command", or
 * a channel with three bots answers every mistyped slash three times.
 */
export function parseCommand(
  message: CommandMessage,
  myAddress: string,
  myHandle?: string | null,
): ParsedCommand | null {
  const content = message.content;
  if (!content || !content.startsWith('/')) return null;

  // A command token is the first whitespace-delimited word. Everything after it
  // is arguments and is left alone.
  // Both the name and handle captures exclude `@`, so `/a@@b` and `/a@b@c` fail
  // to parse rather than yielding a handle that contains `@`.
  const match = /^\/([^\s@]+)(?:@([^\s@]+))?(?:\s+([\s\S]*))?$/.exec(content);
  if (!match) return null;

  const [, rawName, rawHandle, rest = ''] = match;

  // LOWERCASE THE COMMAND TOKEN ONLY — never the arguments.
  //
  // Mobile keyboards autocapitalise the first character of an empty composer, so
  // `/C KLV` is what users actually send and must resolve to `c`. But a naive
  // `content.toLowerCase()` also turns `KLV` into `klv`, and the bot then looks
  // up a different asset. A test suite written with `/c btc` passes either way,
  // which is exactly why this is easy to ship broken.
  const name = rawName.toLowerCase();
  if (!/^[a-z0-9_]+$/.test(name)) return null;

  const handle = rawHandle ? rawHandle.toLowerCase() : null;
  const mentions = Array.isArray(message.mentions) ? message.mentions : [];

  const mentionedMe = mentions.some((m) => m === myAddress);
  const handleIsMine =
    handle != null && myHandle != null && handle === myHandle.toLowerCase();
  const unaddressed = handle == null && mentions.length === 0;

  // A handle that names someone else is decisive: do not fall through to the
  // "nobody was named" arm.
  const namesAnotherBot = handle != null && !handleIsMine;

  return {
    name,
    args: rest.length > 0 ? rest.trim().split(/\s+/).filter(Boolean) : [],
    handle,
    // A handle naming another bot is decisive over EVERYTHING, including
    // `mentions[]`. `mentions[]` is plaintext and is set by whoever sent the
    // message — not only by the picker — so without this gate a crafted message
    // could name one bot by handle while listing every bot's address, and all of
    // them would answer. Each spurious reply spends the other bots' own wallets
    // and rate budgets. Fixed in 0.57.1.
    addressed: handleIsMine || (!namesAnotherBot && (mentionedMe || unaddressed)),
    rest,
  };
}
