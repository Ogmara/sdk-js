import { describe, it, expect, vi, afterEach } from 'vitest';
import { decode } from '@msgpack/msgpack';
import { WalletSigner } from './auth';
import { buildInvite } from './envelope';
import { OgmaraClient } from './client';

describe('buildInvite', () => {
  it('carries anchor_node through the payload when given', async () => {
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildInvite(signer, 42, 'klv1target', 'https://host.example');
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as {
      channel_id: number;
      target_user: string;
      anchor_node: string | null;
    };

    expect(payload.channel_id).toBe(42);
    expect(payload.target_user).toBe('klv1target');
    expect(payload.anchor_node).toBe('https://host.example');
  });

  it('sends anchor_node as null, not absent, when omitted', async () => {
    // Matches the Rust side's `#[serde(default)]` + `Option<String>`, which
    // accepts either — but `null` is what this build has always produced
    // for "no value" fields elsewhere, so a stray `undefined` slipping onto
    // the wire (msgpack encodes it as nothing, not null) would be a
    // regression worth catching.
    const signer = await WalletSigner.generate();
    signer.network = 'testnet';

    const envBytes = await buildInvite(signer, 42, 'klv1target');
    const env = decode(envBytes) as { payload: Uint8Array };
    const payload = decode(env.payload) as Record<string, unknown>;

    expect(payload.anchor_node).toBeNull();
  });
});

describe('OgmaraClient.inviteUser — anchor_node population', () => {
  function mockPostEnvelope(): { bodies: Uint8Array[] } {
    const bodies: Uint8Array[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.body) bodies.push(new Uint8Array(init.body as ArrayBuffer));
        const isHealth = String(url).includes('/api/v1/health');
        const body = isHealth
          ? { status: 'ok', version: '0', peers: 0, node_id: 'node1', network: 'testnet' }
          : { msg_id: 'x' };
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          json: async () => body,
          text: async () => JSON.stringify(body),
        } as unknown as Response;
      }),
    );
    return { bodies };
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sets anchor_node to this node\'s own URL when it is https', async () => {
    const { bodies } = mockPostEnvelope();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'https://test-node.example' }).withSigner(signer);

    await client.inviteUser(42, 'klv1target');

    const env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    const payload = decode(env.payload) as { anchor_node: string | null };
    expect(payload.anchor_node).toBe('https://test-node.example');
  });

  it('omits anchor_node — never sends an unreachable http/local URL', async () => {
    // The receiving node's federate_channel SSRF guard requires https + a
    // publicly-routable host, so a local/dev node's URL would only ever
    // produce an unusable value. Confirmed with the SDK's own documented
    // dev example (`http://localhost:41721`).
    const { bodies } = mockPostEnvelope();
    const signer = await WalletSigner.generate();
    const client = new OgmaraClient({ nodeUrl: 'http://localhost:41721' }).withSigner(signer);

    await client.inviteUser(42, 'klv1target');

    const env = decode(bodies[bodies.length - 1]!) as { payload: Uint8Array };
    const payload = decode(env.payload) as { anchor_node: string | null };
    expect(payload.anchor_node).toBeNull();
  });
});
