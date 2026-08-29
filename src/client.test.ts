import { describe, it, expect } from 'vitest';
import { boundedText, boundedJson, MAX_RESPONSE_BYTES } from './client';

describe('boundedText / boundedJson (finding 4 — response-size ceiling)', () => {
  it('parses a normal small JSON body via the streaming path', async () => {
    const resp = new Response(JSON.stringify({ ok: true, n: 42 }));
    expect(await boundedJson(resp)).toEqual({ ok: true, n: 42 });
  });

  it('boundedText decodes a normal small text body via the streaming path', async () => {
    const resp = new Response('hello world');
    expect(await boundedText(resp)).toBe('hello world');
  });

  it('rejects immediately on a Content-Length that already exceeds the cap', async () => {
    // The declared length alone must be enough to reject — no need to
    // actually send that many bytes for this check to fire.
    const resp = new Response('tiny body, lying header', {
      headers: { 'content-length': String(MAX_RESPONSE_BYTES + 1) },
    });
    await expect(boundedText(resp)).rejects.toThrow(/too large/);
  });

  it('allows a Content-Length exactly at the cap', async () => {
    const resp = new Response('ok', {
      headers: { 'content-length': String(MAX_RESPONSE_BYTES) },
    });
    expect(await boundedText(resp)).toBe('ok');
  });

  it('aborts a streamed body once cumulative bytes cross the cap, even with no Content-Length', async () => {
    // Two chunks: the first lands exactly on the cap (allowed), the second
    // pushes over it by one byte (must reject) — mirrors a chunked-transfer
    // response with no (or an understated) Content-Length header.
    const first = new Uint8Array(MAX_RESPONSE_BYTES);
    const second = new Uint8Array(1);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first);
        controller.enqueue(second);
        controller.close();
      },
    });
    const resp = new Response(stream);
    await expect(boundedText(resp)).rejects.toThrow(/exceeds/);
  }, 20_000);

  it('falls back to a post-hoc length check when the runtime exposes no streaming body', async () => {
    const oversized = 'x'.repeat(MAX_RESPONSE_BYTES + 1);
    const fakeResp = {
      headers: { get: () => null },
      body: null,
      text: async () => oversized,
    } as unknown as Response;
    await expect(boundedText(fakeResp)).rejects.toThrow(/too large/);
  }, 20_000);

  it('boundedJson returns undefined for an empty body', async () => {
    const resp = new Response('');
    expect(await boundedJson(resp)).toBeUndefined();
  });
});
