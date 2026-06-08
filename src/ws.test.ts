import { describe, it, expect } from 'vitest';
import { resolveWsUrl } from './ws';

describe('resolveWsUrl (audit 2026-06-07, W2 — TLS enforcement)', () => {
  it('maps https:// node URL to wss://', () => {
    expect(resolveWsUrl('https://node.example.org', '/api/v1/ws')).toBe(
      'wss://node.example.org/api/v1/ws',
    );
  });

  it('maps https:// with port and trailing slash to wss://', () => {
    expect(resolveWsUrl('https://node.example.org:8443/', '/api/v1/ws/public')).toBe(
      'wss://node.example.org:8443/api/v1/ws/public',
    );
  });

  it('allows cleartext ws:// for localhost', () => {
    expect(resolveWsUrl('http://localhost:41721', '/api/v1/ws')).toBe(
      'ws://localhost:41721/api/v1/ws',
    );
  });

  it('allows cleartext ws:// for 127.0.0.1', () => {
    expect(resolveWsUrl('http://127.0.0.1:41721', '/api/v1/ws')).toBe(
      'ws://127.0.0.1:41721/api/v1/ws',
    );
  });

  it('allows cleartext ws:// for [::1]', () => {
    expect(resolveWsUrl('http://[::1]:41721', '/api/v1/ws')).toBe(
      'ws://[::1]:41721/api/v1/ws',
    );
  });

  it('refuses cleartext http:// (ws://) to a remote host', () => {
    expect(() => resolveWsUrl('http://node.example.org', '/api/v1/ws')).toThrow(
      /cleartext/i,
    );
  });

  it('refuses cleartext to a remote IP host', () => {
    expect(() => resolveWsUrl('http://203.0.113.7:41721', '/api/v1/ws')).toThrow(
      /cleartext/i,
    );
  });

  it('refuses a scheme-less node URL rather than guessing cleartext', () => {
    expect(() => resolveWsUrl('node.example.org', '/api/v1/ws')).toThrow(
      /no ws\/wss scheme/i,
    );
  });
});
