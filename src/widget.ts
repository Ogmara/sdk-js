/**
 * Embeddable Ogmara feed widget.
 *
 * A lightweight, self-contained widget for embedding Ogmara channel feeds
 * on any website. Published to cdn.ogmara.org (spec 7.3).
 *
 * @example
 * ```html
 * <div id="ogmara-feed"></div>
 * <script src="https://cdn.ogmara.org/widget.js"></script>
 * <script>
 *   Ogmara.feed({
 *     element: '#ogmara-feed',
 *     node: 'https://node1.ogmara.org',
 *     channel: '1',
 *     theme: 'light',
 *     maxMessages: 50
 *   });
 * </script>
 * ```
 */

interface FeedOptions {
  /** CSS selector or DOM element to render into. */
  element: string | HTMLElement;
  /** Node URL to connect to. */
  node: string;
  /** Channel ID to display. */
  channel: string;
  /** Theme: 'light' or 'dark' or 'auto' (default: 'auto'). */
  theme?: 'light' | 'dark' | 'auto';
  /** Maximum messages to display (default: 50). */
  maxMessages?: number;
}

interface FeedMessage {
  msg_id: string;
  author: string;
  content: string;
  timestamp: number;
}

/** Create an embedded feed widget. */
export function feed(options: FeedOptions): void {
  const container =
    typeof options.element === 'string'
      ? document.querySelector(options.element)
      : options.element;

  if (!container) {
    console.error('[Ogmara] Element not found:', options.element);
    return;
  }

  const maxMessages = options.maxMessages ?? 50;
  const theme = options.theme ?? 'auto';
  const nodeUrl = options.node.replace(/\/$/, '');

  // Inject styles
  const style = document.createElement('style');
  style.textContent = getWidgetStyles(theme);
  container.appendChild(style);

  // Create message list
  const list = document.createElement('div');
  list.className = 'ogmara-feed';
  container.appendChild(list);

  // Loading indicator
  list.innerHTML = '<div class="ogmara-loading">Loading...</div>';

  // Fetch initial messages
  fetchMessages(nodeUrl, options.channel, maxMessages).then((messages) => {
    list.innerHTML = '';
    messages.forEach((msg) => {
      list.appendChild(renderMessage(msg));
    });

    if (messages.length === 0) {
      list.innerHTML = '<div class="ogmara-empty">No messages yet</div>';
    }
  }).catch((err) => {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'ogmara-error';
    errorDiv.textContent = `Failed to load: ${err.message}`;
    list.innerHTML = '';
    list.appendChild(errorDiv);
  });

  // Connect WebSocket for live updates
  const wsUrl = nodeUrl.replace(/^http/, 'ws') + '/api/v1/ws/public';
  connectWidget(wsUrl, options.channel, list, maxMessages);
}

async function fetchMessages(
  nodeUrl: string,
  channelId: string,
  limit: number,
): Promise<FeedMessage[]> {
  const resp = await fetch(
    `${nodeUrl}/api/v1/channels/${encodeURIComponent(channelId)}/messages?limit=${limit}`,
  );
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const data = await resp.json();
  return (data.messages || []).map(parseEnvelope);
}

function parseEnvelope(env: Record<string, unknown>): FeedMessage {
  return {
    msg_id: (env.msg_id as string) || '',
    author: (env.author as string) || 'unknown',
    content: '', // payload is binary — would need msgpack decode
    timestamp: (env.timestamp as number) || 0,
  };
}

function renderMessage(msg: FeedMessage): HTMLElement {
  const el = document.createElement('div');
  el.className = 'ogmara-msg';

  const author = document.createElement('span');
  author.className = 'ogmara-author';
  author.textContent = shortenAddress(msg.author);

  const time = document.createElement('span');
  time.className = 'ogmara-time';
  time.textContent = formatTime(msg.timestamp);

  const text = document.createElement('div');
  text.className = 'ogmara-text';
  text.textContent = msg.content || '[binary payload]';

  el.appendChild(author);
  el.appendChild(time);
  el.appendChild(text);
  return el;
}

function connectWidget(
  wsUrl: string,
  channelId: string,
  list: HTMLElement,
  maxMessages: number,
): void {
  try {
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'subscribe', channels: [channelId] }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'message' && data.envelope) {
          const msg = parseEnvelope(data.envelope);
          const el = renderMessage(msg);
          list.insertBefore(el, list.firstChild);

          // Trim old messages
          while (list.children.length > maxMessages) {
            list.removeChild(list.lastChild!);
          }
        }
      } catch {
        // Ignore parse errors
      }
    };

    ws.onclose = () => {
      // Reconnect after 5 seconds
      setTimeout(() => connectWidget(wsUrl, channelId, list, maxMessages), 5000);
    };
  } catch {
    // WebSocket not available
  }
}

function shortenAddress(addr: string): string {
  if (addr.length > 16) {
    return addr.slice(0, 8) + '...' + addr.slice(-4);
  }
  return addr;
}

function formatTime(timestampMs: number): string {
  if (!timestampMs) return '';
  const d = new Date(timestampMs);
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function getWidgetStyles(theme: string): string {
  const isDark = theme === 'dark' || (theme === 'auto' && window.matchMedia?.('(prefers-color-scheme: dark)').matches);
  const bg = isDark ? '#1a1a2e' : '#ffffff';
  const fg = isDark ? '#e0e0e0' : '#1a1a1a';
  const border = isDark ? '#2a2a4a' : '#e0e0e0';
  const authorColor = isDark ? '#a29bfe' : '#6c5ce7';

  return `
    .ogmara-feed { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: ${bg}; color: ${fg}; border: 1px solid ${border}; border-radius: 8px; max-height: 500px; overflow-y: auto; padding: 8px; }
    .ogmara-msg { padding: 8px; border-bottom: 1px solid ${border}; }
    .ogmara-msg:last-child { border-bottom: none; }
    .ogmara-author { font-weight: 600; color: ${authorColor}; margin-right: 8px; font-size: 0.85em; }
    .ogmara-time { font-size: 0.75em; opacity: 0.5; }
    .ogmara-text { margin-top: 4px; font-size: 0.9em; line-height: 1.4; }
    .ogmara-loading, .ogmara-empty, .ogmara-error { padding: 20px; text-align: center; opacity: 0.6; }
    .ogmara-error { color: #d63031; }
  `;
}
