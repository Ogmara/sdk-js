/**
 * SC bootstrap discovery — enumerate registered Ogmara nodes directly from
 * the on-chain KApp on Klever, with NO hardcoded seed node.
 *
 * Queries the smart contract via Klever RPC (`POST <rpc>/vm/query`) for
 * `getActiveNodes` (paged) then `getNodeMetadata` per node, and derives each
 * node's HTTP API base from its on-chain libp2p multiaddrs. This is the
 * decentralized replacement for the old `DEFAULT_NODE_URL` seed (which was a
 * single point of failure — when `node.ogmara.org` went down, fresh clients
 * had nothing to bootstrap from).
 *
 * Ported from the website's `js/sc_bootstrap.js` (kept behaviourally
 * identical), which itself mirrors `l2-node/src/chain/sc_views.rs`
 * (`vm_query_multi` + `getActiveNodes` + `getNodeMetadata`). Pure RPC +
 * decoding; no DOM, no node dependency.
 *
 * SSRF guard: a hostile registered node can publish loopback / RFC1918 /
 * CGNAT / link-local / `.local` hosts in its on-chain multiaddrs (including
 * IPv4-mapped / NAT64 / 6to4 IPv6 forms, and port-injected DNS names). Those
 * are stripped at parse time so a discovered endpoint is always a public
 * `https://<host>` on the implicit 443.
 *
 * Residual risk (accepted, same as the website): an operator-controlled DNS
 * name (`/dns4/evil.example.org`) can still resolve to a private/metadata IP
 * at fetch time (DNS rebinding) — parse-time filtering can't see the resolved
 * address. Consumers MUST NOT treat a discovered endpoint as trusted; the
 * desktop only attaches the wallet signer to a node the user explicitly
 * selects, and auth headers are short-lived signed requests, never the key.
 */

export type ScNetwork = 'mainnet' | 'testnet';

export interface ScNetworkConfig {
  key: ScNetwork;
  label: string;
  /** Klever RPC base (no trailing slash needed). */
  rpc: string;
  /** Ogmara KApp contract address (bech32 klv1...). */
  sc: string;
}

/** Mainnet/testnet RPC + KApp addresses (mirrors website `sc_bootstrap.js`). */
export const SC_NETWORKS: Record<ScNetwork, ScNetworkConfig> = {
  mainnet: {
    key: 'mainnet',
    label: 'Mainnet',
    rpc: 'https://node.mainnet.klever.org',
    sc: 'klv1qqqqqqqqqqqqqpgq8c9yag9vuc2pe64fwvqsq9e8ul8w5zuglf5qfgh7z3',
  },
  testnet: {
    key: 'testnet',
    label: 'Testnet',
    rpc: 'https://node.testnet.klever.org',
    sc: 'klv1qqqqqqqqqqqqqpgq0ja2j7xwz843ryfsk9vlz6xzsaak590h6pgq7nwr02',
  },
};

/** A node enumerated from the on-chain registry. */
export interface ScDiscoveredNode {
  /** bech32 wallet address (klv1...) — the node's identity. */
  walletAddress: string;
  /** 64-char hex of the raw 32-byte pubkey. */
  walletHex: string;
  /** Unix seconds of the node's last on-chain anchor (0 if never). */
  lastAnchorAt: number;
  /** Raw on-chain libp2p multiaddrs. */
  multiaddrs: string[];
  /** Derived HTTPS API base (`https://<host>`), or null if none usable. */
  endpoint: string | null;
  /** libp2p PeerId from a `/p2p/` segment, or null. */
  peerId: string | null;
}

export interface ScDiscoveryOptions {
  /** Per-RPC timeout (ms). Default 8000. */
  timeoutMs?: number;
  /** SC page size (SC caps `getActiveNodes` at 64). Default 64. */
  pageLimit?: number;
  /** Max pages to walk (64 × 5 = up to 320 nodes). Default 5. */
  maxPages?: number;
  /** Concurrent `getNodeMetadata` fetches. Default 4. */
  metadataConcurrency?: number;
}

/** Max multiaddrs accepted per node from `getNodeMetadata` (the SC caps at
 *  8; this guards against a hostile/compromised RPC). Mirrors l2-node
 *  sc_views `MAX_RETURNED_ENTRIES`. */
const MAX_METADATA_ENTRIES = 16;
/** Max bytes for a single on-chain multiaddr string before it's dropped. */
const MAX_MULTIADDR_LEN = 512;

// ── Hex / bytes / base64 helpers ──────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] & 0xff;
    out += (b < 16 ? '0' : '') + b.toString(16);
  }
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  // atob exists in browsers + the Tauri webview + modern Node.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }
}

/** Mirrors `encode_u64_minimal_hex`: minimal big-endian, even-length hex. */
function u64MinimalHex(v: number): string {
  if (v === 0) return '00';
  let hex = v.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return hex;
}

/** Decode minimal-BE bytes → number (caps at 2^53; fine for u64 ts/counts). */
function decodeU64Be(bytes: Uint8Array): number {
  if (!bytes || bytes.length === 0) return 0;
  if (bytes.length > 8) return 0;
  let n = 0;
  for (let i = 0; i < bytes.length; i++) n = n * 256 + (bytes[i] & 0xff);
  return n;
}

// ── Bech32 (BIP-173) — encode raw 32-byte pubkey as klv1... ───────────

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (let j = 0; j < 5; j++) {
      if ((top >>> j) & 1) chk ^= BECH32_GEN[j];
    }
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32Checksum(hrp: string, data: number[]): number[] {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) out.push((polymod >>> (5 * (5 - i))) & 31);
  return out;
}

function convertBits8to5(data: Uint8Array): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  for (let i = 0; i < data.length; i++) {
    acc = (acc << 8) | (data[i] & 0xff);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      ret.push((acc >>> bits) & 0x1f);
    }
  }
  if (bits > 0) ret.push((acc << (5 - bits)) & 0x1f);
  return ret;
}

function bech32EncodeKlv(rawBytes: Uint8Array): string {
  const hrp = 'klv';
  const data = convertBits8to5(rawBytes);
  const combined = data.concat(bech32Checksum(hrp, data));
  let out = hrp + '1';
  for (let i = 0; i < combined.length; i++) out += BECH32_CHARSET[combined[i]];
  return out;
}

// ── Multiaddr host extraction (with SSRF guard) ───────────────────────

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const o = parts.map((p) => parseInt(p, 10));
  for (let i = 0; i < 4; i++) {
    if (!(o[i] >= 0 && o[i] <= 255)) return false;
  }
  // 0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16, 172.16/12, 192.168/16,
  // 224/4 (multicast), 240/4 (reserved).
  if (o[0] === 0 || o[0] === 10 || o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;
  if (o[0] >= 224) return true;
  return false;
}

/** Build a dotted-quad from two 16-bit hextets (for embedded-IPv4 forms). */
function ipv4FromHextets(h1: number, h2: number): string {
  return [(h1 >> 8) & 0xff, h1 & 0xff, (h2 >> 8) & 0xff, h2 & 0xff].join('.');
}

function isPrivateIpv6(ip: string): boolean {
  let s = String(ip || '').toLowerCase().trim();
  if (!s) return true;
  const pct = s.indexOf('%'); // strip zone id
  if (pct >= 0) s = s.slice(0, pct);
  if (s === '::1' || s === '::') return true;
  // Link-local fe80::/10, ULA fc00::/7, multicast ff00::/8.
  if (/^fe[89ab]/.test(s)) return true;
  if (s.startsWith('fc') || s.startsWith('fd')) return true;
  if (s.startsWith('ff')) return true;
  // NAT64 well-known prefix 64:ff9b::/96 (and 64:ff9b:1::/48) — a hostile
  // operator could use it to reach an embedded private v4; reject outright.
  if (s.startsWith('64:ff9b:')) return true;
  // IPv4-mapped (::ffff:1.2.3.4) and IPv4-compatible (::1.2.3.4) dotted forms
  // — decode and apply the v4 rules so loopback/RFC1918/CGNAT can't sneak
  // in dressed as IPv6 (audit C1).
  const dotted = s.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) return isPrivateIpv4(dotted[1]);
  // IPv4-mapped hex form ::ffff:7f00:1
  const mappedHex = s.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    return isPrivateIpv4(ipv4FromHextets(parseInt(mappedHex[1], 16), parseInt(mappedHex[2], 16)));
  }
  // 6to4 2002:HHHH:HHHH::/16 carries the v4 in the next two hextets.
  if (s.startsWith('2002:')) {
    const m = s.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})/);
    if (!m) return true; // can't parse → fail closed
    return isPrivateIpv4(ipv4FromHextets(parseInt(m[1], 16), parseInt(m[2], 16)));
  }
  return false;
}

function isPrivateDnsName(name: string): boolean {
  const s = String(name || '').toLowerCase();
  if (!s) return true;
  if (s === 'localhost' || s.endsWith('.localhost')) return true;
  if (
    s.endsWith('.local') || s.endsWith('.internal') ||
    s.endsWith('.lan') || s.endsWith('.home')
  ) return true;
  return false;
}

function extractHostFromMultiaddr(ma: string): string | null {
  if (!ma || typeof ma !== 'string') return null;
  const parts = ma.split('/');
  for (let i = 0; i < parts.length - 1; i++) {
    const proto = parts[i];
    const val = parts[i + 1];
    if (!val) continue;
    if (proto === 'dns4' || proto === 'dns6' || proto === 'dns' || proto === 'dnsaddr') {
      // Reject an embedded port/path/garbage in the name segment, e.g.
      // `/dns4/internal-host:22/...` → `https://internal-host:22` would let
      // an operator target an arbitrary internal port (audit W3). The host
      // is then always served as `https://<host>` (implicit 443).
      if (/[:/\\@]/.test(val)) return null;
      if (isPrivateDnsName(val)) return null;
      return val;
    }
    if (proto === 'ip4') {
      // Must be a clean dotted-quad — no embedded port/garbage.
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) return null;
      if (isPrivateIpv4(val)) return null;
      return val;
    }
    if (proto === 'ip6') {
      if (isPrivateIpv6(val)) return null;
      return '[' + val + ']';
    }
  }
  return null;
}

function deriveApiEndpoint(multiaddrs: string[]): string | null {
  for (let i = 0; i < multiaddrs.length; i++) {
    const host = extractHostFromMultiaddr(multiaddrs[i]);
    if (host) return 'https://' + host;
  }
  return null;
}

function extractPeerIdFromMultiaddr(ma: string): string | null {
  if (!ma || typeof ma !== 'string') return null;
  const parts = ma.split('/');
  for (let i = 0; i < parts.length - 1; i++) {
    if ((parts[i] === 'p2p' || parts[i] === 'ipfs') && parts[i + 1]) {
      return parts[i + 1];
    }
  }
  return null;
}

function derivePeerId(multiaddrs: string[]): string | null {
  for (let i = 0; i < multiaddrs.length; i++) {
    const pid = extractPeerIdFromMultiaddr(multiaddrs[i]);
    if (pid) return pid;
  }
  return null;
}

// ── VM query ──────────────────────────────────────────────────────────

class ScRequireError extends Error {
  scRequireFailure = true;
}

async function vmQuery(
  rpc: string,
  sc: string,
  funcName: string,
  args: string[],
  timeoutMs: number,
): Promise<Uint8Array[]> {
  const url = rpc.replace(/\/+$/, '') + '/vm/query';
  const body = { scAddress: sc, funcName, args };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (!resp.ok) throw new Error('vm/query HTTP ' + resp.status);
  const json: any = await resp.json();
  const topError = (json && json.error) || '';
  const inner = json && json.data && json.data.data;
  const returnCode = (inner && inner.returnCode) || 'Ok';
  const returnMessage = (inner && inner.returnMessage) || '';
  if (topError) throw new Error('vm/query: ' + topError);
  if (returnCode !== 'Ok') {
    // SC-level require! failure (e.g. offset > total) — typed so callers can
    // map it to an empty page rather than a transport error.
    throw new ScRequireError(returnMessage || returnCode);
  }
  const rawList: string[] = (inner && inner.returnData) || [];
  return rawList.map((b64) => base64ToBytes(b64));
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Discover registered Ogmara nodes for a network directly from the on-chain
 * KApp. Returns every active node with its derived HTTPS endpoint (or null
 * when the node published no usable public host). Callers typically take
 * `.endpoint` of the entries where it's non-null as bootstrap candidates.
 *
 * Per-node metadata failures are isolated (the node is still returned with
 * empty multiaddrs / null endpoint). A whole-discovery transport failure
 * rejects — callers should `.catch(() => [])` if they want best-effort.
 */
export async function discoverNodesViaSc(
  network: ScNetwork,
  opts: ScDiscoveryOptions = {},
): Promise<ScDiscoveredNode[]> {
  const net = SC_NETWORKS[network];
  if (!net) throw new Error('unknown network: ' + network);

  const timeoutMs = opts.timeoutMs ?? 8000;
  const pageLimit = opts.pageLimit ?? 64;
  const maxPages = opts.maxPages ?? 5;
  const metadataConcurrency = opts.metadataConcurrency ?? 4;

  // Page getActiveNodes until a short page or the page cap.
  const nodes: ScDiscoveredNode[] = [];
  for (let pageIdx = 0; pageIdx < maxPages; pageIdx++) {
    const offset = pageIdx * pageLimit;
    let items: Uint8Array[];
    try {
      items = await vmQuery(net.rpc, net.sc, 'getActiveNodes', [
        u64MinimalHex(offset),
        u64MinimalHex(pageLimit),
      ], timeoutMs);
    } catch (e) {
      if (e instanceof ScRequireError) break; // offset past end → done
      throw e;
    }
    if (items.length % 2 !== 0) {
      throw new Error('getActiveNodes returned odd-length response');
    }
    for (let i = 0; i + 1 < items.length; i += 2) {
      const addr = items[i];
      const ts = items[i + 1];
      if (addr.length !== 32) continue; // protocol mismatch — skip
      nodes.push({
        walletHex: bytesToHex(addr),
        walletAddress: bech32EncodeKlv(addr),
        lastAnchorAt: decodeU64Be(ts),
        multiaddrs: [],
        endpoint: null,
        peerId: null,
      });
    }
    // Terminate on a short page based on RAW pairs the SC returned, NOT
    // accepted entries — otherwise a single skipped (non-32-byte) entry in
    // a full page would look "short" and silently drop later pages (audit).
    const rawPairs = Math.floor(items.length / 2);
    if (rawPairs < pageLimit) break;
  }

  // Enrich with metadata (multiaddrs + derived endpoint), bounded concurrency.
  let nextIdx = 0;
  async function worker(): Promise<void> {
    for (;;) {
      const idx = nextIdx++;
      if (idx >= nodes.length) return;
      const n = nodes[idx];
      let items: Uint8Array[] = [];
      try {
        items = await vmQuery(net.rpc, net.sc, 'getNodeMetadata', [n.walletHex], timeoutMs);
      } catch {
        items = [];
      }
      // Defense-in-depth against a hostile/compromised third-party RPC (the
      // SC itself caps at 8): bound entry count and per-multiaddr length
      // before decoding, mirroring l2-node sc_views MAX_RETURNED_ENTRIES
      // (audit W2). Oversized entries are dropped, not truncated.
      const addrs = items
        .slice(0, MAX_METADATA_ENTRIES)
        .map((b) => bytesToUtf8(b))
        .filter((s) => s.length <= MAX_MULTIADDR_LEN);
      n.multiaddrs = addrs;
      n.endpoint = deriveApiEndpoint(addrs);
      n.peerId = derivePeerId(addrs);
    }
  }
  const width = Math.min(metadataConcurrency, nodes.length);
  await Promise.all(Array.from({ length: width }, () => worker()));
  return nodes;
}

/**
 * Convenience: discover and return just the usable HTTPS endpoints for a
 * network (deduped, in SC order). This is what a bootstrap/picker wants —
 * a flat candidate list with the dead-seed problem gone.
 */
export async function discoverNodeUrlsViaSc(
  network: ScNetwork,
  opts?: ScDiscoveryOptions,
): Promise<string[]> {
  const nodes = await discoverNodesViaSc(network, opts);
  const seen = new Set<string>();
  const urls: string[] = [];
  for (const n of nodes) {
    if (n.endpoint && !seen.has(n.endpoint)) {
      seen.add(n.endpoint);
      urls.push(n.endpoint);
    }
  }
  return urls;
}
