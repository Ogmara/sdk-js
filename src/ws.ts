/**
 * WebSocket client for real-time subscriptions.
 *
 * Connects to the node's WebSocket endpoints:
 * - /api/v1/ws — authenticated (full read/write)
 * - /api/v1/ws/public — no auth (read-only)
 */

import type { WalletSigner, NodeBinding } from './auth';
import type { WsEvent } from './types';

/**
 * Max byte/char length of an inbound WS frame we will JSON.parse.
 * Browser WebSocket has no built-in frame cap, so a hostile node could stream
 * a huge frame → memory blowup. Reject oversize frames before parsing
 * (audit 2026-06-07, W3). 1 MiB is well above any legitimate event payload.
 */
const MAX_WS_FRAME_CHARS = 1024 * 1024;

/** Hostnames for which cleartext ws:// is permitted (local dev only). */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Derive the ws(s):// URL from the node URL and enforce TLS for non-loopback
 * hosts (audit 2026-06-07, W2). The first WS frame carries the auth credential
 * (address/timestamp/signature/nonce); over cleartext ws:// a MITM can read a
 * replayable credential. Allow ws:// only for localhost. Mirrors sdk-rust C2.
 * @throws if the resolved URL would send auth/data over cleartext to a remote host.
 */
export function resolveWsUrl(nodeUrl: string, wsPath: string): string {
  const wsUrl =
    nodeUrl
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:')
      .replace(/\/$/, '') + wsPath;

  if (wsUrl.startsWith('wss://')) return wsUrl;

  if (!wsUrl.startsWith('ws://')) {
    // Scheme-less or unexpected scheme: refuse rather than guess cleartext.
    throw new Error(
      `refusing to connect: node URL "${nodeUrl}" has no ws/wss scheme — use https:// (wss://) for remote nodes`,
    );
  }

  // ws:// — only safe for loopback.
  let host: string;
  try {
    host = new URL(wsUrl).hostname;
  } catch {
    throw new Error(`refusing to connect: invalid node URL "${nodeUrl}"`);
  }
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(
      `refusing to connect over cleartext ws:// to non-loopback host "${host}" — ` +
        `the WS auth credential would be exposed to a MITM; use https:// (wss://)`,
    );
  }
  return wsUrl;
}

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
  /**
   * Callback for fatal connection errors that prevent connecting at all, e.g.
   * refusing cleartext ws:// to a remote host (audit 2026-06-07, W2). When this
   * fires the subscription is permanently closed (no reconnect).
   */
  onError?: (error: Error) => void;
  /** Wallet signer for authenticated WS (omit for public WS). */
  signer?: WalletSigner;
  /** Auto-reconnect on disconnect (default: true). */
  autoReconnect?: boolean;
  /** Initial reconnect delay in ms (default: 1000). */
  reconnectDelay?: number;
  /** Maximum reconnect delay in ms (default: 30000). */
  maxReconnectDelay?: number;
}

/** A handle to an active WebSocket connection. */
export class WsSubscription {
  private ws: WebSocket | null = null;
  private options: WsOptions;
  private closed = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  /**
   * True between creating a socket and that socket reaching a terminal state.
   * Guards against double-scheduling reconnects: a stale onclose firing while a
   * fresh socket is already connecting must not queue another timer
   * (audit 2026-06-07, W1).
   */
  private connecting = false;
  /**
   * Fires a few seconds after a socket opens; only then do we treat the
   * connection as healthy and reset the backoff. A socket that opens but is
   * closed almost immediately (e.g. the node rejects the auth frame) must NOT
   * reset the backoff — otherwise a persistent auth failure becomes a tight
   * reconnect storm that hammers the node (audit 2026-06-07 follow-up).
   */
  private stableTimer: ReturnType<typeof setTimeout> | null = null;
  /** Cached node identity the WS auth signature binds to (host-binding). */
  private nodeBinding?: NodeBinding;

  constructor(options: WsOptions) {
    this.options = options;
    // connect() handles its own errors internally; void the promise.
    void this.connect();
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
    // Set closed first so any in-flight onclose sees it and skips reconnect
    // (audit 2026-06-07, W1: no race where a stale handler re-schedules).
    this.closed = true;
    this.connecting = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.teardownSocket();
  }

  /**
   * Detach all handlers from the current socket and close it, then drop the
   * reference. Detaching first ensures stale handler closures from a previous
   * socket can't fire after we've moved on (audit 2026-06-07, W1).
   */
  private teardownSocket(): void {
    if (this.stableTimer) {
      clearTimeout(this.stableTimer);
      this.stableTimer = null;
    }
    const ws = this.ws;
    if (!ws) return;
    this.ws = null;
    ws.onopen = null;
    ws.onmessage = null;
    ws.onclose = null;
    ws.onerror = null;
    try {
      ws.close();
    } catch {
      // ignore — already closing/closed
    }
  }

  /**
   * Resolve (and cache) the node identity the auth signature binds to,
   * from `GET /api/v1/health`. The WS URL is ws(s):// so we derive the
   * http(s):// origin to fetch health.
   */
  private async getNodeBinding(): Promise<NodeBinding> {
    if (this.nodeBinding) return this.nodeBinding;
    const httpBase = this.options.nodeUrl
      .replace(/^ws:/, 'http:')
      .replace(/^wss:/, 'https:')
      .replace(/\/$/, '');
    const resp = await fetch(`${httpBase}/api/v1/health`);
    if (!resp.ok) throw new Error(`health fetch failed: ${resp.status}`);
    const health = await resp.json() as { node_id?: string; network?: string };
    if (!health.node_id || !health.network) {
      throw new Error('node /health did not return node_id/network — node too old for host-bound auth');
    }
    this.nodeBinding = { network: health.network, nodeId: health.node_id };
    return this.nodeBinding;
  }

  private async connect(): Promise<void> {
    if (this.closed) return;

    // Detach + close any previous socket before opening a new one so its stale
    // handler closures can never fire against this fresh connection
    // (audit 2026-06-07, W1).
    this.teardownSocket();

    const isPublic = !this.options.signer;
    const wsPath = isPublic ? '/api/v1/ws/public' : '/api/v1/ws';

    let wsUrl: string;
    try {
      // Enforce TLS for non-loopback hosts before sending auth (audit 2026-06-07, W2).
      wsUrl = resolveWsUrl(this.options.nodeUrl, wsPath);
    } catch (err) {
      // Cleartext to a remote host (or bad URL): never connect. Surface as a
      // disconnected state and a permanent close — reconnecting would just
      // refuse again — so this misconfiguration is loud but not a crash.
      this.closed = true;
      this.options.onStateChange?.(false);
      this.options.onError?.(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    this.connecting = true;
    try {
      const ws = new WebSocket(wsUrl);
      this.ws = ws;

      ws.onopen = async () => {
        // Ignore events from a socket we've since replaced/torn down.
        if (this.ws !== ws) return;
        this.connecting = false;
        this.options.onStateChange?.(true);

        // Send auth message for authenticated WS. The signature is bound to
        // the node's {network, node_id} + a single-use nonce (host-binding,
        // audit 2026-06-07), mirroring the REST auth header. If the binding
        // fetch or signing fails (e.g. /health transiently errors, or an old
        // node lacks node_id), close the socket so it reconnects rather than
        // sitting open and silently unauthenticated.
        if (this.options.signer) {
          try {
            const binding = await this.getNodeBinding();
            const headers = await this.options.signer.signRequest('GET', '/api/v1/ws', binding);
            // The socket may have been replaced while awaiting the binding/sign.
            if (this.ws !== ws) return;
            this.send({
              address: headers['x-ogmara-address'],
              timestamp: parseInt(headers['x-ogmara-timestamp']),
              signature: headers['x-ogmara-auth'],
              nonce: headers['x-ogmara-nonce'],
            });
          } catch (err) {
            // Surface WHY auth failed instead of silently looping (this was the
            // blind spot behind the reconnect storm). The backoff is NOT reset
            // here, so repeated failures back off instead of hammering the node.
            console.warn('[ogmara-ws] WS auth failed; will reconnect with backoff:', err);
            ws.close(); // triggers onclose → scheduleReconnect
            return;
          }
        }

        // Subscribe to initial channels
        if (this.options.channels?.length) {
          this.send({ type: 'subscribe', channels: this.options.channels });
        }

        // Subscribe to DMs
        if (this.options.subscribeDm && this.options.signer) {
          this.send({ type: 'subscribe_dm' });
        }

        // Reset backoff ONLY once the connection has stayed open a few seconds.
        // If the node rejects auth and closes the socket before this fires, the
        // backoff is preserved and grows — preventing a tight reconnect storm
        // (audit 2026-06-07 follow-up; this storm was knocking other clients of
        // the same node offline).
        if (this.stableTimer) clearTimeout(this.stableTimer);
        this.stableTimer = setTimeout(() => {
          if (this.ws === ws) this.reconnectAttempts = 0;
        }, 3000);
      };

      ws.onmessage = (event) => {
        if (this.ws !== ws) return;
        // Reject oversize frames before parsing (audit 2026-06-07, W3).
        const raw = event.data;
        if (typeof raw === 'string' && raw.length > MAX_WS_FRAME_CHARS) {
          // Ignore — a legitimate event never approaches 1 MiB.
          return;
        }
        try {
          const data = JSON.parse(raw) as WsEvent;
          this.options.onEvent(data);
        } catch {
          // Ignore unparseable messages
        }
      };

      ws.onclose = () => {
        // Ignore terminal events from a socket we've already replaced/torn down
        // so a stale onclose can't double-schedule a reconnect (audit 2026-06-07, W1).
        if (this.ws !== ws) return;
        this.connecting = false;
        this.ws = null;
        this.options.onStateChange?.(false);
        this.scheduleReconnect();
      };

      ws.onerror = () => {
        // onclose will fire after onerror
      };
    } catch {
      this.connecting = false;
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.closed || this.options.autoReconnect === false) return;
    // Never queue a second timer; a reconnect is already pending or in flight
    // (audit 2026-06-07, W1).
    if (this.reconnectTimer !== null || this.connecting) return;

    const baseDelay = this.options.reconnectDelay ?? 1000;
    const maxDelay = this.options.maxReconnectDelay ?? 30000;
    // Exponential backoff: base * 2^attempts, capped at maxDelay
    const expDelay = Math.min(baseDelay * Math.pow(2, this.reconnectAttempts), maxDelay);
    // Add jitter: ±25% to prevent thundering herd
    const jitter = expDelay * 0.25 * (Math.random() * 2 - 1);
    const delay = Math.max(0, Math.round(expDelay + jitter));
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      // connect() handles its own errors internally; void the promise so a
      // rejection can't surface as an unhandled rejection (audit 2026-06-07, W1).
      void this.connect();
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
