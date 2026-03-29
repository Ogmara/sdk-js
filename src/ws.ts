/**
 * WebSocket client for real-time subscriptions.
 *
 * Connects to the node's WebSocket endpoints:
 * - /api/v1/ws — authenticated (full read/write)
 * - /api/v1/ws/public — no auth (read-only)
 */

import type { WalletSigner } from './auth';
import type { WsEvent } from './types';

/** Options for creating a WebSocket subscription. */
export interface WsOptions {
  /** Node URL (HTTP). Converted to ws:// or wss:// automatically. */
  nodeUrl: string;
  /** Channels to subscribe to initially. */
  channels?: string[];
  /** Whether to subscribe to DMs (requires auth). */
  subscribeDm?: boolean;
  /** Callback for incoming events. */
  onEvent: (event: WsEvent) => void;
  /** Callback for connection state changes. */
  onStateChange?: (connected: boolean) => void;
  /** Wallet signer for authenticated WS (omit for public WS). */
  signer?: WalletSigner;
  /** Auto-reconnect on disconnect (default: true). */
  autoReconnect?: boolean;
  /** Reconnect delay in ms (default: 3000). */
  reconnectDelay?: number;
}

/** A handle to an active WebSocket connection. */
export class WsSubscription {
  private ws: WebSocket | null = null;
  private options: WsOptions;
  private closed = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: WsOptions) {
    this.options = options;
    this.connect();
  }

  /** Subscribe to additional channels. */
  subscribe(channels: string[]): void {
    this.send({ type: 'subscribe', channels });
  }

  /** Unsubscribe from channels. */
  unsubscribe(channels: string[]): void {
    this.send({ type: 'unsubscribe', channels });
  }

  /** Close the connection permanently (no reconnect). */
  close(): void {
    this.closed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
  }

  private async connect(): Promise<void> {
    const isPublic = !this.options.signer;
    const wsPath = isPublic ? '/api/v1/ws/public' : '/api/v1/ws';
    const wsUrl = this.options.nodeUrl
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:')
      .replace(/\/$/, '') + wsPath;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = async () => {
        this.options.onStateChange?.(true);

        // Send auth message for authenticated WS
        if (this.options.signer) {
          const headers = await this.options.signer.signRequest('GET', '/api/v1/ws');
          this.send({
            address: headers['x-ogmara-address'],
            timestamp: parseInt(headers['x-ogmara-timestamp']),
            signature: headers['x-ogmara-auth'],
          });
        }

        // Subscribe to initial channels
        if (this.options.channels?.length) {
          this.send({ type: 'subscribe', channels: this.options.channels });
        }

        // Subscribe to DMs
        if (this.options.subscribeDm && this.options.signer) {
          this.send({ type: 'subscribe_dm' });
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WsEvent;
          this.options.onEvent(data);
        } catch {
          // Ignore unparseable messages
        }
      };

      this.ws.onclose = () => {
        this.options.onStateChange?.(false);
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        // onclose will fire after onerror
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.closed || this.options.autoReconnect === false) return;

    const delay = this.options.reconnectDelay ?? 3000;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private send(data: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }
}

/**
 * Create a WebSocket subscription.
 *
 * @example
 * ```ts
 * import { subscribe } from '@ogmara/sdk';
 *
 * const sub = subscribe({
 *   nodeUrl: 'http://localhost:41721',
 *   channels: ['1', '2'],
 *   onEvent: (event) => {
 *     if (event.type === 'message') {
 *       console.log('New message:', event.envelope);
 *     }
 *   },
 * });
 *
 * // Later: sub.close();
 * ```
 */
export function subscribe(options: WsOptions): WsSubscription {
  return new WsSubscription(options);
}
