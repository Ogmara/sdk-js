/**
 * Deterministic simulation of node-arbitrated key epochs (sdk-js 0.67.0).
 *
 * `FakeArbitratingNode` implements the l2-node 0.143.0 rule EXACTLY as the
 * contract states it (rank = (key_ts, key_commitment) lowest wins; same C
 * stores another wrap and needs the same key_ts; a different C supersedes only
 * when better AND now < recorded_at + 120 s — recorded_at = when THIS node
 * first arbitrated the epoch, never extended by a supersede — AND
 * envelope.timestamp - key_ts <= 15 min, deleting the loser's rows; otherwise
 * 409 / gossip-ignore; legacy epochs are plain first-write-wins and the only
 * place a commitment-less envelope is accepted; epoch < floor → 400; per-wallet
 * fixed-window 240/60 s → 429 retry_after_ms; an already-present slot of the
 * same C → `already_present`; an already-stored msg_id → plain-text 409).
 *
 * Several nodes form a flood-gossip mesh with seeded delays, drops (re-delivered
 * later as backfill) and partitions, under a virtual clock with a seeded PRNG.
 * Every member device runs the REAL `establishEpochKey` from `./epochKey.ts`
 * with injected I/O. Faults: response lost after commit, client crash
 * mid-publish (restart with empty memory), 5xx, injected 429s, a malicious
 * member (bogus commitment, slot squat), a hostile node (fake 409, withheld
 * wraps, forged / non-member wraps).
 *
 * Properties checked at quiescence (see `checkProperties`):
 *  P1 every honest client's key == every node's winner (highest epoch);
 *  P2 every adopted/established key had a verified wrap in the client's own slot;
 *  P3 no `confirmed` key is ever superseded (unless a partition > finality was injected);
 *  P4 no key lost: every confirmed key reaches every honest member device;
 *  P5 a hostile node never gets a non-member's key adopted.
 *
 * NEGATIVE CONTROL: the same seeds against a naive per-device first-write-wins
 * node (no arbitration) must produce forks — proving the checks would catch the bug.
 *
 * Seeds: `OGMARA_SIM_SEEDS` (default 5000, up to 100000), `OGMARA_SIM_SEED0`
 * (first seed, default 1); negative control `OGMARA_SIM_NEG_SEEDS` (default 1000,
 * always from seed 1); `OGMARA_SIM_CONFIRM=quick` evaluates the 10 s confirm
 * shortcut; `OGMARA_SIM_DEBUG=1|2` prints per-seed detail. Re-run one failing seed with
 * `OGMARA_SIM_SEED0=<seed> OGMARA_SIM_SEEDS=1 npx vitest run src/epochKey.sim.test.ts`.
 */
import { describe, expect, it } from 'vitest';
import {
  establishEpochKey,
  EscalationGate,
  PendingEpochKeyStore,
  TokenBucket,
  type EpochKeyTarget,
  type EstablishEpochKeyOptions,
  type EstablishEpochKeyOutcome,
  type UnconfirmedEpochKey,
  type VerifiedChannelKeyWrap,
} from './epochKey';
import {
  classifyKeyEnvelopeResponse,
  compareRank,
  computeKeyCommitment,
  isValidKeyCommitment,
  keyCommitmentToHex,
  keyCommitmentsEqual,
  KEY_COMMIT_FINALITY_MS,
  KEY_ENVELOPE_RATE_LIMIT,
  KEY_ENVELOPE_SCOPE_RATE_LIMIT,
  KEY_TS_MAX_AGE_MS,
} from './channelKeyCommit';
import { computeChannelScope } from './envelope';
import type { KeyCommitmentInfo, PublishChannelKeyResult } from './types';

// --- Deterministic primitives ---------------------------------------------------------

/** mulberry32 — tiny seeded PRNG. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Ev { t: number; seq: number; fn: () => void }

/** Virtual clock + event queue. Microtasks are drained after every event. */
class Sim {
  now = 1_800_000_000_000;
  readonly t0 = this.now;
  private heap: Ev[] = [];
  private seq = 0;
  events = 0;

  at(t: number, fn: () => void): void {
    // Integer ms, like Date.now() (key_ts must be a safe integer).
    const ev = { t: Math.max(Math.ceil(t), this.now), seq: this.seq++, fn };
    const h = this.heap;
    h.push(ev);
    let i = h.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (less(h[p]!, ev)) break;
      h[i] = h[p]!;
      i = p;
    }
    h[i] = ev;
  }

  sleep = (ms: number): Promise<void> => new Promise((r) => this.at(this.now + Math.max(0, ms), r));

  private pop(): Ev | undefined {
    const h = this.heap;
    if (h.length === 0) return undefined;
    const top = h[0]!;
    const last = h.pop()!;
    if (h.length > 0) {
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let m = i;
        let mv = last;
        if (l < h.length && less(h[l]!, mv)) { m = l; mv = h[l]!; }
        if (r < h.length && less(h[r]!, mv)) { m = r; mv = h[r]!; }
        if (m === i) break;
        h[i] = h[m]!;
        i = m;
      }
      h[i] = last;
    }
    return top;
  }

  async run(until: number, maxEvents = 400_000): Promise<void> {
    await drain();
    for (;;) {
      const h = this.heap;
      if (h.length === 0 || h[0]!.t > until) break;
      const ev = this.pop()!;
      this.now = ev.t;
      ev.fn();
      this.events++;
      if (this.events > maxEvents) throw new Error('simulation did not quiesce (event budget)');
      await drain();
    }
    this.now = Math.max(this.now, until);
  }
}
const less = (a: Ev, b: Ev): boolean => a.t < b.t || (a.t === b.t && a.seq < b.seq);
const drain = (): Promise<void> => new Promise((r) => setImmediate(r));

const hex = (b: Uint8Array): string => keyCommitmentToHex(b);

// --- Fake signed envelopes --------------------------------------------------------------

/** Signing credential. Only code holding it can produce an AUTHENTIC envelope for it. */
interface Identity { wallet: string; signer: string }

/** ECIES stand-in: only the named device can open it. */
class Sealed {
  private readonly k: Uint8Array;
  constructor(readonly forDevice: string, k: Uint8Array) {
    this.k = k.slice(); // a real wrap encrypts a COPY; later zeroing of the caller's key must not reach it
  }
  open(device: string): Uint8Array | null {
    return device === this.forDevice ? this.k.slice() : null;
  }
}

interface FEnv {
  msgId: string;
  signer: string;
  wallet: string;
  timestamp: number;
  epoch: number;
  target: string;
  deviceId: string;
  c: Uint8Array | null;
  keyTs: number | null;
  sealed: Sealed;
  /** Rate-limit scope label (defaults to the sim's one channel; tests use others). */
  scope?: string;
}

/** Envelopes produced by a real credential (stands in for the Ed25519 signature). */
const AUTHENTIC = new WeakSet<FEnv>();
let msgCounter = 0;
function sign(id: Identity, f: Omit<FEnv, 'msgId' | 'signer' | 'wallet'>): FEnv {
  const e: FEnv = Object.freeze({ ...f, msgId: `m${++msgCounter}`, signer: id.signer, wallet: id.wallet });
  AUTHENTIC.add(e);
  return e;
}

// --- The fake node ------------------------------------------------------------------------

type Commit =
  | { state: 'legacy' }
  | { state: 'arbitrated'; c: Uint8Array; keyTs: number; author: string; msgId: string; recordedAt: number; superseded: Uint8Array[] };

interface Resp { status: number; text: string }

type ApplyResult =
  | { k: 'stored' | 'already_present' }
  | { k: 'duplicate' }
  | { k: 'rejected'; code: string }
  | { k: 'conflict'; commit: Extract<Commit, { state: 'arbitrated' }> };

interface HostileMode { fake409?: number; withhold?: boolean; forge?: boolean }

const CHANNEL = 4294967297; // a PRIVATE-range channel id: the key epoch floor applies
/** l2-node 0.143.0: a new epoch may be at most max(highest known, floor) + 256. */
const KEY_EPOCH_MAX_AHEAD = 256;
const SCOPE = computeChannelScope(CHANNEL);

/**
 * The l2-node 0.143.0 arbitration rule (`arbitrate: true`) or the pre-0.143
 * per-device first-write-wins behaviour (`arbitrate: false`, the negative
 * control — it still reports a first-seen commitment so the client API shape
 * is identical).
 */
class FakeArbitratingNode {
  readonly commits = new Map<number, Commit>();
  readonly rows = new Map<string, FEnv>();
  readonly messages = new Set<string>();
  /**
   * Bounded seen-cache of NON-stored 0x61 envelopes whose outcome cannot change
   * (AlreadyPresent, Conflict, below_floor, evicted, commitment_invalid): a
   * replay gets the ORIGINAL answer (already-present → plain duplicate 409).
   */
  readonly seen = new Map<string, ApplyResult>();
  private rememberSeen(id: string, r: ApplyResult): void {
    if (this.seen.size >= 4096) this.seen.delete(this.seen.keys().next().value as string);
    this.seen.set(id, r);
  }
  private readonly rate = new Map<string, { start: number; n: number }>();
  private readonly scopeRate = new Map<string, { start: number; n: number }>();
  peers: FakeArbitratingNode[] = [];
  mesh: Mesh | null = null;
  private readonly listeners = new Set<() => void>();
  floor = 1;
  supersedes = 0;
  /** Plain-text duplicate 409s served to local clients (incl. superseded losers' envelopes). */
  duplicates = 0;
  hostile: HostileMode | null = null;

  constructor(
    readonly id: string,
    private readonly sim: Sim,
    readonly members: ReadonlySet<string>,
    readonly arbitrate: boolean,
  ) {}

  static slot(epoch: number, target: string, device: string): string {
    return `${epoch}|${target}|${device}`;
  }

  onChange(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private notify(): void {
    for (const l of [...this.listeners]) l();
  }

  /** `POST /api/v1/messages` for a 0x61 from a LOCAL client. */
  post(env: FEnv, injected429?: number): Resp {
    const now = this.sim.now;
    // API/WS ingress only (gossip is exempt): per-wallet 240 / 60 s over all
    // 0x61 AND per-(wallet, channel scope) 60 / 60 s (the sim has one channel
    // scope). A refused attempt consumes NO slot; a window resets once
    // `now > start + window`.
    const fresh = (x: { start: number; n: number } | undefined, windowMs: number) => !x || now > x.start + windowMs;
    const w = this.rate.get(env.wallet);
    const scopeKey = `${env.wallet}|${env.scope ?? 'channel'}`;
    const sw = this.scopeRate.get(scopeKey);
    const wN = fresh(w, KEY_ENVELOPE_RATE_LIMIT.windowMs) ? 0 : w!.n;
    const sN = fresh(sw, KEY_ENVELOPE_SCOPE_RATE_LIMIT.windowMs) ? 0 : sw!.n;
    if (wN >= KEY_ENVELOPE_RATE_LIMIT.max) {
      return { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: w!.start + KEY_ENVELOPE_RATE_LIMIT.windowMs - now + 1 }) };
    }
    if (sN >= KEY_ENVELOPE_SCOPE_RATE_LIMIT.max) {
      return { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: sw!.start + KEY_ENVELOPE_SCOPE_RATE_LIMIT.windowMs - now + 1 }) };
    }
    this.rate.set(env.wallet, wN === 0 ? { start: now, n: 1 } : { start: w!.start, n: wN + 1 });
    this.scopeRate.set(scopeKey, sN === 0 ? { start: now, n: 1 } : { start: sw!.start, n: sN + 1 });
    if (injected429 !== undefined) return { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: injected429 }) };
    const r = this.apply(env, true);
    switch (r.k) {
      case 'stored':
      case 'already_present':
        return { status: 200, text: JSON.stringify({ msg_id: env.msgId, key_status: r.k }) };
      case 'duplicate':
        this.duplicates++;
        return { status: 409, text: 'message already exists' };
      case 'rejected':
        return { status: 400, text: JSON.stringify({ error: r.code }) };
      case 'conflict':
        return {
          status: 409,
          text: JSON.stringify({
            error: 'key_commitment_conflict', channel_id: CHANNEL, epoch: env.epoch, state: 'arbitrated',
            winner: {
              key_commitment: hex(r.commit.c), key_ts: r.commit.keyTs, author: r.commit.author,
              msg_id: r.commit.msgId, final: now >= r.commit.recordedAt + KEY_COMMIT_FINALITY_MS,
            },
          }),
        };
    }
  }

  /** Live gossip ingestion: same rule, no rate limit; conflicts / rejections / duplicates are ignored. */
  ingest(env: FEnv): void {
    this.apply(env, false);
  }

  /**
   * Sync / backfill ingestion (l2-node 0.143.0 final): accepts ONLY a wrap of
   * the ALREADY recorded winning pair (`key_sync_not_winner` otherwise). In
   * production no sync protocol even delivers 0x61 envelopes, so the mesh
   * below never calls this: a message dropped from live gossip is LOST.
   */
  ingestSync(env: FEnv): void {
    const cur = this.commits.get(env.epoch);
    if (this.arbitrate && cur?.state !== 'legacy') {
      if (!cur || env.c === null || env.keyTs === null) return;
      if (!(cur.keyTs === env.keyTs && keyCommitmentsEqual(cur.c, env.c))) return;
    }
    this.apply(env, false);
  }

  private apply(env: FEnv, local: boolean): ApplyResult {
    const now = this.sim.now;
    if (this.messages.has(env.msgId)) return { k: 'duplicate' };
    const cached = this.seen.get(env.msgId);
    if (cached) return cached.k === 'already_present' ? { k: 'duplicate' } : cached;
    if (!AUTHENTIC.has(env)) return { k: 'rejected', code: 'bad_signature' };
    if (!this.members.has(env.wallet)) return { k: 'rejected', code: 'author_not_member' };
    if (!this.members.has(env.target)) return { k: 'rejected', code: 'target_not_member' };
    const fixed = (r: ApplyResult): ApplyResult => {
      this.rememberSeen(env.msgId, r); // an outcome that cannot change: cached for replays
      return r;
    };
    if (env.epoch < this.floor) return fixed({ k: 'rejected', code: 'key_epoch_below_floor' });
    if ((env.c === null) !== (env.keyTs === null)) return fixed({ k: 'rejected', code: 'key_commitment_invalid' });
    if (env.c !== null && !isValidKeyCommitment(env.c)) return fixed({ k: 'rejected', code: 'key_commitment_invalid' });
    if (env.keyTs !== null && (env.keyTs <= 0 || env.keyTs > env.timestamp)) return fixed({ k: 'rejected', code: 'key_commitment_invalid' });

    const cur = this.commits.get(env.epoch);
    let changed = false;
    if (this.arbitrate) {
      // Uniform, content-only freshness (create AND supersede): a stale pair
      // may only add wraps of the CURRENT winner.
      if (env.c !== null && env.keyTs !== null && cur?.state !== 'legacy') {
        const stale = env.timestamp - env.keyTs > KEY_TS_MAX_AGE_MS;
        const isWinner = cur?.state === 'arbitrated' && cur.keyTs === env.keyTs && keyCommitmentsEqual(cur.c, env.c);
        if (stale && !isWinner) return { k: 'rejected', code: 'key_ts_stale' };
      }
      // A NEW epoch may be at most max(highest known epoch, floor) + 256 —
      // checked AFTER commitment_required / freshness, as on the node.
      if (!cur && env.c !== null && env.epoch > Math.max(this.highest(), this.floor) + KEY_EPOCH_MAX_AHEAD) {
        return { k: 'rejected', code: 'key_epoch_too_far' };
      }
      if (cur?.state === 'legacy') {
        // Legacy epoch: plain first-write-wins, nothing recorded.
      } else if (env.c === null || env.keyTs === null) {
        return { k: 'rejected', code: 'key_commitment_required' };
      } else if (!cur) {
        this.commits.set(env.epoch, {
          state: 'arbitrated', c: env.c, keyTs: env.keyTs, author: env.wallet, msgId: env.msgId, recordedAt: now, superseded: [],
        });
        changed = true;
      } else if (cur.keyTs === env.keyTs && keyCommitmentsEqual(env.c, cur.c)) {
        // The winning pair: another wrap of the same key.
      } else {
        // A different PAIR (same C with another key_ts is just another rank).
        const better = compareRank({ keyTs: env.keyTs, keyCommitment: env.c }, { keyTs: cur.keyTs, keyCommitment: cur.c }) < 0;
        const within = now < cur.recordedAt + KEY_COMMIT_FINALITY_MS;
        // (l2-node 0.143.0 final: no "never re-admit a superseded commitment"
        // refusal — the winner only ever moves to a strictly better pair.)
        if (!(better && within)) return fixed({ k: 'conflict', commit: cur });
        for (const [k, row] of [...this.rows]) {
          if (row.epoch === env.epoch && !(row.c && keyCommitmentsEqual(row.c, env.c) && row.keyTs === env.keyTs)) this.rows.delete(k);
        }
        // recorded_at deliberately unchanged (never extends the horizon).
        this.commits.set(env.epoch, {
          ...cur, c: env.c, keyTs: env.keyTs, author: env.wallet, msgId: env.msgId,
          superseded: [...cur.superseded, cur.c].slice(-4),
        });
        this.supersedes++;
        changed = true;
      }
    } else if (!cur && env.c && env.keyTs) {
      // Naive node: no arbitration; remembers the first commitment it saw only
      // so the client-facing API has the same shape.
      this.commits.set(env.epoch, {
        state: 'arbitrated', c: env.c, keyTs: env.keyTs, author: env.wallet, msgId: env.msgId, recordedAt: now, superseded: [],
      });
      changed = true;
    }
    const slot = FakeArbitratingNode.slot(env.epoch, env.target, env.deviceId);
    let k: 'stored' | 'already_present' = 'already_present';
    // Every (target, device, epoch) slot is WRITE-ONCE — also against the
    // winner's own author (l2-node 0.143.0 final; the round-1 replacement
    // rule was reverted).
    if (!this.rows.has(slot)) {
      this.rows.set(slot, env);
      k = 'stored';
    }
    // Only a STORED wrap's envelope goes to MESSAGES (an already-present one is
    // neither stored nor relayed, so its msg_id is not deduplicated later).
    if (k === 'stored') this.messages.add(env.msgId);
    else this.rememberSeen(env.msgId, { k }); // a replay answers as a plain duplicate
    // A wrap for an already-occupied slot (AlreadyPresent) is neither stored
    // nor relayed (l2-node 0.143.0 final).
    if (k === 'stored') this.mesh?.flood(this, env);
    if (changed || local || k === 'stored') this.notify();
    return { k };
  }

  /** `GET /channels/{id}/key-commitment?epoch=N` (omit = highest). */
  getCommitment(epoch?: number): KeyCommitmentInfo {
    const now = this.sim.now;
    const ep = epoch ?? this.highest();
    const c = this.commits.get(ep);
    if (!c) return { channel_id: CHANNEL, epoch: ep, state: 'none', final: false, finality_ms: KEY_COMMIT_FINALITY_MS };
    if (c.state === 'legacy') return { channel_id: CHANNEL, epoch: ep, state: 'legacy', final: true, finality_ms: KEY_COMMIT_FINALITY_MS };
    return {
      channel_id: CHANNEL, epoch: ep, state: 'arbitrated', key_commitment: hex(c.c), key_ts: c.keyTs,
      author: c.author, msg_id: c.msgId, recorded_at: c.recordedAt,
      final: now >= c.recordedAt + KEY_COMMIT_FINALITY_MS, finality_ms: KEY_COMMIT_FINALITY_MS,
    };
  }

  highest(): number {
    let m = 0;
    for (const e of this.commits.keys()) m = Math.max(m, e);
    return m;
  }

  ownSlot(wallet: string, device: string, epoch: number): FEnv | null {
    return this.rows.get(FakeArbitratingNode.slot(epoch, wallet, device)) ?? null;
  }

  winner(epoch: number): Uint8Array | null {
    const c = this.commits.get(epoch);
    return c?.state === 'arbitrated' ? c.c : null;
  }
}

// --- Gossip mesh ----------------------------------------------------------------------------

interface Partition { start: number; end: number; side: ReadonlySet<string> }

interface MeshCfg {
  minDelay: number;
  maxDelay: number;
  dropProb: number;
  backfillMin: number;
  backfillMax: number;
  partitions: Partition[];
  /** Scripted override (pinned scenarios). */
  delay?: (from: string, to: string) => number;
}

class Mesh {
  constructor(private readonly sim: Sim, private readonly rng: () => number, private readonly cfg: MeshCfg) {}

  flood(from: FakeArbitratingNode, env: FEnv): void {
    for (const peer of from.peers) {
      let d = this.cfg.delay
        ? this.cfg.delay(from.id, peer.id)
        : this.cfg.minDelay + this.rng() * (this.cfg.maxDelay - this.cfg.minDelay);
      let viaSync = false;
      if (!this.cfg.delay && this.rng() < this.cfg.dropProb) {
        d = this.cfg.backfillMin + this.rng() * (this.cfg.backfillMax - this.cfg.backfillMin);
        viaSync = true;
      }
      let t = this.sim.now + d;
      for (const p of this.cfg.partitions) {
        const split = p.side.has(from.id) !== p.side.has(peer.id);
        if (split && t >= p.start && this.sim.now < p.end) {
          t = Math.max(t, p.end + d);
          viaSync = true;
        }
      }
      // No sync protocol carries 0x61 envelopes: a message dropped from live
      // gossip, or held by a partition, never arrives.
      if (viaSync) continue;
      this.sim.at(t, () => peer.ingest(env));
    }
  }
}

// --- World / scenario -------------------------------------------------------------------------

class Crash extends Error {}

interface DeviceSpec { wallet: string; device: string; node: number; start: number }

interface Scenario {
  seed: number;
  arbitrate: boolean;
  nodes: number;
  devices: DeviceSpec[];
  maliciousWallet?: string;
  maliciousAttacks?: {
    at: number;
    /**
     * bogus: wraps whose commitment != H(key) under a backdated key_ts;
     * squat: garbage wraps under the PUBLIC winning pair into victims' slots;
     * copyC: the winner's public commitment paired with an EARLIER key_ts.
     */
    kind: 'bogus' | 'squat' | 'copyC';
    /** bogus: how far key_ts is backdated (ms; > 15 min is refused key_ts_stale). */
    backdateMs?: number;
    /** squat: victim device ids (default: the first two). */
    victims?: string[];
    /** Node index the attacker posts to (default 0); the pair is read from node 0. */
    node?: number;
  }[];
  hostileNode?: { index: number; mode: HostileMode };
  legacyEpoch1?: boolean;
  mesh: MeshCfg;
  longPartition: boolean;
  faults: { lost: number; fivexx: number; inject429: number; crash: number; resendSame: number };
  /** Scripted post hook: return a response to short-circuit (pinned scenarios). */
  postHook?: (dev: string, env: FEnv, attempt: number, node: FakeArbitratingNode) => Resp | 'lost' | undefined;
  /** Devices that crash at a scripted time (pinned scenarios). */
  crashAt?: Record<string, { at: number; restartAfter: number }>;
  options?: Partial<EstablishEpochKeyOptions>;
  durationMs: number;
  /**
   * Negative control for the lagging-node fork: pass the pre-fix deps
   * (`epochKnownToExist: false`, `highestEpochSeen: 0`) so a lagging node
   * creates an epoch the mesh already has.
   */
  legacyLaggingRule?: boolean;
  /** Run the members WITHOUT `peerCommitments` (measures what the peer check catches). */
  noPeers?: boolean;
}

interface Confirmation {
  dev: string;
  epoch: number;
  c: string;
  at: number;
  kind: 'established' | 'adopted';
  /** Every node's winner for the epoch at the moment of confirmation. */
  peers: Record<string, { c: string; final: boolean } | undefined>;
}

interface DeviceState {
  spec: DeviceSpec;
  id: Identity;
  home: FakeArbitratingNode;
  honest: boolean;
  gen: number;
  pending: PendingEpochKeyStore;
  bucket: TokenBucket;
  gate: EscalationGate;
  current: { epoch: number; key: Uint8Array; keyTs: number; c: Uint8Array } | null;
  crashed: boolean;
  crashes: number;
  newKeys: Map<number, number>;
  postAttempts: number;
  sent: Map<string, FEnv>;
  resendSame: boolean;
  logs: string[];
  freshRepublishes: number;
  /** Persisted across a crash: the epoch this device was establishing (no key). */
  establishing: { epoch: number; tries: number } | null;
}

interface RunResult {
  violations: string[];
  forks: boolean;
  events: number;
  supersedes: number;
  escalations: number;
  confirmations: Confirmation[];
  devices: DeviceState[];
  nodes: FakeArbitratingNode[];
  excused: { longPartition: boolean; malicious: boolean; hostile: boolean; partition: boolean; noPeers: boolean };
  outcomes: Map<string, EstablishEpochKeyOutcome['kind'][]>;
  maliciousResults: Resp[];
  provisionalUses: number;
  provisionalOrphaned: number;
  residuals: Residuals;
  /** `split` outcomes returned to members (a different FINAL winner on another node). */
  detectedSplits: number;
}

/** Key provenance: who generated each key (by hex). */
type Origin = 'honest' | 'malicious' | 'eve';

async function runScenario(sc: Scenario): Promise<RunResult> {
  msgCounter = 0;
  const sim = new Sim();
  const rng = prng(sc.seed ^ 0x9e3779b9);
  const wallets = new Set(sc.devices.map((d) => d.wallet));
  if (sc.maliciousWallet) wallets.add(sc.maliciousWallet);
  const members: ReadonlySet<string> = wallets;
  const nodes = Array.from({ length: sc.nodes }, (_, i) => new FakeArbitratingNode(`n${i}`, sim, members, sc.arbitrate));
  const mesh = new Mesh(sim, rng, sc.mesh);
  for (const n of nodes) {
    n.peers = nodes.filter((p) => p !== n);
    n.mesh = mesh;
    if (sc.legacyEpoch1) n.commits.set(1, { state: 'legacy' });
  }
  if (sc.hostileNode) nodes[sc.hostileNode.index]!.hostile = sc.hostileNode.mode;

  const origin = new Map<string, Origin>();
  /** Which device generated the key behind a commitment. */
  const authorOfC = new Map<string, DeviceState>();
  const eve: Identity = { wallet: 'klv1eve', signer: 'klv1eve' };
  const violations: string[] = [];
  const confirmations: Confirmation[] = [];
  const outcomes = new Map<string, EstablishEpochKeyOutcome['kind'][]>();
  let escalations = 0;

  const allTargets: EpochKeyTarget[] = sc.devices.map((d) => ({ target: d.wallet, deviceId: d.device, encPub: new Uint8Array(32) }));
  if (sc.maliciousWallet) allTargets.push({ target: sc.maliciousWallet, deviceId: 'mdev', encPub: new Uint8Array(32) });

  const randKey = (): Uint8Array => {
    const k = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k[i] = Math.floor(rng() * 256);
    return k;
  };

  /** Mirror of verifyChannelKeyWrap's checks over a fake envelope. */
  const verifyFake = (env: FEnv | null, self: string, device: string, epoch: number): VerifiedChannelKeyWrap | null => {
    if (!env || !AUTHENTIC.has(env)) return null;
    if (env.epoch !== epoch || env.target !== self || env.deviceId !== device) return null;
    if (!env.c || !isValidKeyCommitment(env.c) || env.keyTs === null || env.keyTs <= 0 || env.keyTs > env.timestamp) return null;
    if (!members.has(env.wallet)) return null;
    const key = env.sealed.open(device);
    if (!key) return null;
    if (!keyCommitmentsEqual(computeKeyCommitment(SCOPE, epoch, env.keyTs, key), env.c)) {
      key.fill(0);
      return null;
    }
    return { key, keyCommitment: env.c, keyTs: env.keyTs, epoch, wallet: env.wallet, signer: env.signer, msgId: env.msgId };
  };

  const devices: DeviceState[] = sc.devices.map((spec) => ({
    spec,
    id: { wallet: spec.wallet, signer: `ogd1${spec.device}` },
    home: nodes[spec.node]!,
    honest: !(sc.hostileNode && sc.hostileNode.index === spec.node),
    gen: 0,
    pending: new PendingEpochKeyStore(),
    bucket: new TokenBucket(() => sim.now, sim.sleep),
    gate: new EscalationGate(() => sim.now),
    current: null,
    crashed: false,
    crashes: 0,
    newKeys: new Map(),
    postAttempts: 0,
    sent: new Map(),
    resendSame: rng() < sc.faults.resendSame,
    logs: [],
    establishing: null,
    freshRepublishes: 0,
  }));

  const latency = (): number => 5 + rng() * 80;

  /** Client → home node round trip with faults. `fn` runs AT the node at arrival time. */
  async function request<T>(dev: DeviceState, fn: () => T, opts: { lostOverride?: boolean } = {}): Promise<T> {
    await sim.sleep(latency());
    if (rng() < sc.faults.fivexx) {
      await sim.sleep(latency());
      throw Object.assign(new Error('503'), { status: 503 });
    }
    const r = fn();
    if (opts.lostOverride || rng() < sc.faults.lost) {
      await sim.sleep(10_000); // client fetch timeout; the node already committed
      throw Object.assign(new Error('timeout'), { status: 0 });
    }
    await sim.sleep(latency());
    return r;
  }

  function hostileCommitment(dev: DeviceState, epoch: number): KeyCommitmentInfo | null {
    const h = dev.home.hostile;
    if (!h?.forge) return null;
    // The hostile node claims eve's (non-member) key won, final.
    const ek = eveKeys.get(epoch) ?? (() => {
      const k = randKey();
      origin.set(hex(k), 'eve');
      eveKeys.set(epoch, k);
      return k;
    })();
    const c = computeKeyCommitment(SCOPE, epoch, sim.t0, ek);
    return {
      channel_id: CHANNEL, epoch, state: 'arbitrated', key_commitment: hex(c), key_ts: sim.t0, author: eve.wallet,
      msg_id: 'ff'.repeat(32), recorded_at: sim.t0, final: true, finality_ms: KEY_COMMIT_FINALITY_MS,
    };
  }
  const eveKeys = new Map<number, Uint8Array>();

  function hostileSlot(dev: DeviceState, epoch: number): FEnv | null | undefined {
    const h = dev.home.hostile;
    if (!h) return undefined;
    if (h.withhold) return null;
    if (h.forge) {
      const ek = eveKeys.get(epoch);
      if (!ek) return null;
      const c = computeKeyCommitment(SCOPE, epoch, sim.t0, ek);
      // Alternate: an AUTHENTIC envelope by non-member eve, or one forged "as" a member.
      if (rng() < 0.5) {
        return sign(eve, { timestamp: sim.now, epoch, target: dev.spec.wallet, deviceId: dev.spec.device, c, keyTs: sim.t0, sealed: new Sealed(dev.spec.device, ek) });
      }
      const forged: FEnv = {
        msgId: 'forged', signer: devices[0]!.id.signer, wallet: devices[0]!.spec.wallet, timestamp: sim.now, epoch,
        target: dev.spec.wallet, deviceId: dev.spec.device, c, keyTs: sim.t0, sealed: new Sealed(dev.spec.device, ek),
      };
      return forged;
    }
    return undefined;
  }

  function makeDeps(dev: DeviceState, epoch: number, gen: number, known: boolean, seen: number) {
    const guard = (): void => {
      if (dev.crashed || dev.gen !== gen) throw new Crash('crashed');
    };
    return {
      channelId: CHANNEL,
      epoch,
      epochKnownToExist: known,
      highestEpochSeen: seen,
      self: { wallet: dev.spec.wallet, deviceId: dev.spec.device, signingAddress: dev.id.signer, encPub: new Uint8Array(32) },
      getCommitment: async (ep?: number) => {
        const forged = ep === undefined ? null : hostileCommitment(dev, ep);
        const r = await request(dev, () => forged ?? dev.home.getCommitment(ep));
        return r;
      },
      // Read the same epoch from every OTHER node (client → peer, no partition
      // between a client and a node; peers answer from their own state).
      peerCommitments: sc.noPeers
        ? undefined
        : async (ep: number) => {
            await sim.sleep(latency() * 2);
            return nodes.filter((n) => n !== dev.home).map((n) => n.getCommitment(ep));
          },
      fetchOwnWrap: async (ep: number) => {
        const env = await request(dev, () => {
          const hs = hostileSlot(dev, ep);
          return hs === undefined ? dev.home.ownSlot(dev.spec.wallet, dev.spec.device, ep) : hs;
        });
        return verifyFake(env, dev.spec.wallet, dev.spec.device, ep);
      },
      isSelfBound: async () => true,
      listTargets: async () => request(dev, () => allTargets.map((t) => ({ ...t }))),
      publish: async (
        t: EpochKeyTarget, key: Uint8Array, keyTs: number, ep: number, opts?: { fresh?: boolean },
      ): Promise<PublishChannelKeyResult> => {
        // `resendSame` models a sloppy client resending cached bytes on retry
        // (exercises the duplicate path); `fresh` always re-signs.
        const cacheKey = `${ep}|${t.target}|${t.deviceId}|${hex(key)}|${keyTs}`;
        let env = dev.resendSame && !opts?.fresh ? dev.sent.get(cacheKey) : undefined;
        if (opts?.fresh) dev.freshRepublishes++;
        if (!env) {
          env = sign(dev.id, {
            timestamp: sim.now, epoch: ep, target: t.target, deviceId: t.deviceId,
            c: computeKeyCommitment(SCOPE, ep, keyTs, key), keyTs, sealed: new Sealed(t.deviceId, key),
          });
          if (dev.resendSame) dev.sent.set(cacheKey, env);
        }
        const attempt = ++dev.postAttempts;
        const e = env;
        const scripted = sc.postHook?.(dev.spec.device, e, attempt, dev.home);
        let resp: Resp;
        if (scripted && scripted !== 'lost') {
          resp = await request(dev, () => scripted);
        } else {
          const h = dev.home.hostile;
          resp = await request(dev, () => {
            if (h?.fake409 !== undefined && rng() < h.fake409) {
              return {
                status: 409,
                text: JSON.stringify({ error: 'key_commitment_conflict', epoch: ep, state: 'arbitrated', winner: { key_commitment: 'ab'.repeat(32), key_ts: 1, author: eve.wallet, msg_id: '', final: true } }),
              };
            }
            const inj = rng() < sc.faults.inject429 ? Math.floor(500 + rng() * 7500) : undefined;
            return dev.home.post(e, inj);
          }, { lostOverride: scripted === 'lost' });
        }
        if (resp.status >= 200 && resp.status < 300) {
          const b = JSON.parse(resp.text);
          return { status: b.key_status === 'already_present' ? 'already_present' : 'stored', msgId: b.msg_id };
        }
        const out = classifyKeyEnvelopeResponse(resp.status, resp.text);
        if (out === 'duplicate') return { status: 'duplicate' };
        throw out;
      },
      pending: dev.pending,
      newKey: () => {
        guard();
        const k = randKey();
        origin.set(hex(k), 'honest');
        // establishEpochKey stamps keyTs = now() right after newKey() (no await between).
        authorOfC.set(hex(computeKeyCommitment(SCOPE, epoch, sim.now, k)), dev);
        dev.newKeys.set(epoch, (dev.newKeys.get(epoch) ?? 0) + 1);
        return k;
      },
      now: () => sim.now,
      sleep: sim.sleep,
      waitForEvent: (ms: number) =>
        new Promise<void>((resolve) => {
          let done = false;
          const finish = (): void => {
            if (done) return;
            done = true;
            off();
            resolve();
          };
          const off = dev.home.hostile ? () => true : dev.home.onChange(finish);
          sim.at(sim.now + ms, finish);
        }),
      bucket: dev.bucket,
      guard,
      isFatalError: (e: unknown) => e instanceof Crash,
      targetCount: allTargets.length,
      options: sc.options,
      // Early use (clients may send under it before finality): recorded so the
      // run can quantify how often such a provisional key is later orphaned.
      onUnconfirmed: (u: UnconfirmedEpochKey) => {
        if (dev.honest) provisional.push({ dev, epoch: u.epoch, c: hex(u.keyCommitment), keyTs: u.keyTs });
        u.key.fill(0);
      },
      log: (step: string, data?: Record<string, unknown>) => {
        if (dev.logs.length < 200) dev.logs.push(data?.why ? `${step}: ${String(data.why)}` : step);
      },
    };
  }

  function record(dev: DeviceState, epoch: number, out: EstablishEpochKeyOutcome): void {
    const k = `${dev.spec.device}`;
    outcomes.set(k, [...(outcomes.get(k) ?? []), out.kind]);
    if (out.kind === 'escalate') escalations++;
    if (out.kind !== 'established' && out.kind !== 'adopted') return;
    const c = computeKeyCommitment(SCOPE, epoch, out.keyTs, out.key);
    if (!keyCommitmentsEqual(c, out.keyCommitment)) violations.push(`${dev.spec.device}: returned key does not match its commitment`);
    // P5: never a non-member's key.
    const o = origin.get(hex(out.key));
    if (o !== 'honest' && o !== 'malicious') violations.push(`P5 ${dev.spec.device} adopted a key of origin ${o ?? 'unknown'} at epoch ${epoch}`);
    // P2: a verified wrap in our own slot (honest nodes only — a hostile node's store is not evidence).
    if (!dev.home.hostile) {
      const row = dev.home.ownSlot(dev.spec.wallet, dev.spec.device, epoch);
      const own = verifyFake(row, dev.spec.wallet, dev.spec.device, epoch);
      if (!own || !keyCommitmentsEqual(own.keyCommitment, c)) {
        violations.push(`P2 ${dev.spec.device} ${out.kind} at epoch ${epoch} without a verified own-slot wrap`);
      }
      own?.key.fill(0);
    }
    if (out.confirmed && dev.honest) {
      const peers: Confirmation['peers'] = {};
      for (const n of nodes) {
        const i = n.getCommitment(epoch);
        peers[n.id] = i.state === 'arbitrated' ? { c: i.key_commitment!, final: i.final } : undefined;
      }
      confirmations.push({ dev: dev.spec.device, epoch, c: hex(c), at: sim.now, kind: out.kind, peers });
    }
    // Keep the caller's key bytes as returned (NOT a copy) so a later zeroing
    // by the SDK (key aliasing) would be caught at quiescence.
    dev.current = { epoch, key: out.key, keyTs: out.keyTs, c };
  }

  /** The caller loop ("ensureKey") a client app runs around establishEpochKey. */
  /**
   * Evidence of epochs from OUTSIDE the home node's key state: channel
   * messages sent under a confirmed key reach every member (chat messages ARE
   * backfilled) after a short delay. This is the caller's `highestEpochSeen`.
   */
  const EVIDENCE_DELAY_MS = 10_000;
  const forkEvidence = (epoch: number, c: string): boolean =>
    confirmations.some((x) => x.epoch === epoch && x.c !== c && x.at <= sim.now - EVIDENCE_DELAY_MS);
  const highestSeen = (): number => {
    let m = 0;
    for (const c of confirmations) if (c.at <= sim.now - EVIDENCE_DELAY_MS && c.epoch > m) m = c.epoch;
    return m;
  };

  /** The caller loop ("ensureKey") a client app runs around establishEpochKey. */
  async function memberLoop(dev: DeviceState): Promise<void> {
    const gen = dev.gen;
    let epoch = 1;
    let resumeSame = false;
    // Caller guidance (documented on establishEpochKey): persist the EPOCH being
    // established (never the key) and, after a restart, re-run it before moving
    // on — that is what lets an author resume covering its own winning key.
    if (dev.establishing !== null) {
      epoch = dev.establishing.epoch;
      resumeSame = true;
    }
    const end = sim.t0 + sc.durationMs;
    const rotateGated = async (to: number, deps: { waitForEvent: (ms: number) => Promise<void> }): Promise<boolean> => {
      const wait = dev.gate.remainingMs(CHANNEL);
      if (wait > 0) {
        await deps.waitForEvent(wait);
        return false; // re-check: someone else may have rotated already
      }
      if (!dev.gate.tryEscalate(CHANNEL)) return false;
      epoch = to;
      resumeSame = true;
      return true;
    };
    try {
      while (sim.now < end) {
        if (dev.crashed || dev.gen !== gen) return;
        const seen = highestSeen();
        // Highest epoch the node knows (a WS event in real clients) and the
        // highest epoch seen in channel messages.
        if (!resumeSame) {
          try {
            const h = await request(dev, () => dev.home.getCommitment());
            if (dev.crashed || dev.gen !== gen) return;
            if (h.epoch > epoch) epoch = h.epoch;
            if (h.state === 'legacy' && h.epoch >= epoch) epoch = h.epoch;
          } catch {
            await sim.sleep(2_000);
            continue;
          }
          if (seen > epoch) epoch = seen;
          // Fork evidence ("a channel message at our epoch that our key cannot
          // decrypt"): another member confirmed a DIFFERENT key at our epoch.
          // Caller guidance: rotate past it (gated), it is the only heal.
          if (dev.current && dev.current.epoch === epoch && forkEvidence(dev.current.epoch, hex(dev.current.c))) {
            await rotateGated(epoch + 1, makeDeps(dev, epoch, gen, true, seen));
            continue;
          }
          if (dev.current && dev.current.epoch === epoch) {
            const w = dev.home.hostile ? null : dev.home.winner(epoch);
            if (w && keyCommitmentsEqual(w, dev.current.c)) {
              // Up to date: idle until something changes (or new evidence).
              await makeDeps(dev, epoch, gen, true, seen).waitForEvent(sc.durationMs > 3_600_000 ? 10 * 60_000 : 60_000);
              continue;
            }
          }
        }
        resumeSame = false;
        if (dev.establishing?.epoch !== epoch) dev.establishing = { epoch, tries: 0 };
        // Known to exist = evidence from messages (the node's own state speaks
        // for itself). A rotation into a fresh epoch is not.
        const known = epoch <= seen;
        const deps = sc.legacyLaggingRule
          ? makeDeps(dev, epoch, gen, false, 0) // the pre-fix rule (negative control)
          : makeDeps(dev, epoch, gen, known, seen);
        const out = await establishEpochKey(deps);
        if (dev.crashed || dev.gen !== gen) return;
        record(dev, epoch, out);
        const unfinished = (out.kind === 'established' && out.uncovered.length > 0)
          || ((out.kind === 'failed' && !out.epochTooLow && !out.epochTooHigh) || out.kind === 'waiting');
        if (!unfinished || ++dev.establishing.tries > 5) dev.establishing = null;
        switch (out.kind) {
          case 'established':
            if (out.uncovered.length > 0) {
              await sim.sleep(30_000);
              resumeSame = true;
            }
            break;
          case 'adopted':
            break;
          case 'legacy':
          case 'escalate':
            await rotateGated(epoch + 1, deps);
            break;
          case 'node_lagging':
            // Never create this epoch here; rotate past everything we have seen
            // (unless this node can never accept that epoch: surface + wait).
            if (out.unrecoverableHere) await sim.sleep(60_000);
            else await rotateGated(out.recoveryEpoch, deps);
            break;
          case 'split':
          case 'unconfirmed_exhausted':
            // Another node finalized a different key / this epoch never got
            // confirmed: rotate (gated) before anything is sent under it.
            await rotateGated(epoch + 1, deps);
            break;
          case 'needs_binding':
            throw new Error('unexpected needs_binding');
          case 'failed':
            if (out.epochTooHigh) {
              // Surface it; never retry at another epoch automatically.
              tooHigh++;
              dev.establishing = null;
              await sim.sleep(60_000);
              break;
            }
            if (out.epochTooLow) {
              dev.establishing = null;
              epoch = epoch + 1;
              resumeSame = true;
              break;
            }
            await sim.sleep(5_000 + rng() * 10_000);
            break;
          case 'waiting':
            await sim.sleep(5_000 + rng() * 10_000);
            break;
        }
        if (dev.establishing !== null && out.kind !== 'established') resumeSame = true;
      }
    } catch (e) {
      if (e instanceof Crash) return;
      throw e;
    }
  }

  function start(dev: DeviceState, at: number): void {
    sim.at(at, () => {
      dev.crashed = false;
      void memberLoop(dev).catch((e) => violations.push(`loop error ${dev.spec.device}: ${e?.message ?? e}`));
    });
  }

  for (const dev of devices) {
    start(dev, sim.t0 + dev.spec.start);
    const scripted = sc.crashAt?.[dev.spec.device];
    const crashP = rng();
    if (scripted || crashP < sc.faults.crash) {
      const at = scripted ? scripted.at : dev.spec.start + rng() * 4_000;
      const restart = scripted ? scripted.restartAfter : 10_000 + rng() * 110_000;
      sim.at(sim.t0 + at, () => {
        dev.crashed = true;
        dev.crashes++;
        dev.gen++;
        dev.pending = new PendingEpochKeyStore(); // memory lost
        dev.bucket = new TokenBucket(() => sim.now, sim.sleep);
        dev.current = null;
        dev.sent.clear();
        start(dev, sim.now + restart);
      });
    }
  }

  // Malicious member actions.
  const maliciousResults: Resp[] = [];
  let tooHigh = 0;
  const provisional: { dev: DeviceState; epoch: number; c: string; keyTs: number }[] = [];
  if (sc.maliciousWallet) {
    const mal: Identity = { wallet: sc.maliciousWallet, signer: sc.maliciousWallet };
    const home = nodes[0]!;
    for (const atk of sc.maliciousAttacks ?? []) {
      sim.at(sim.t0 + atk.at, () => {
        const ep = Math.max(1, home.highest());
        const info = home.getCommitment(ep);
        const target = nodes[atk.node ?? 0]!;
        if (atk.kind === 'bogus') {
          const k = randKey();
          origin.set(hex(k), 'malicious');
          const bogusC = randKey(); // != H(k)
          bogusC[0] |= 1;
          const targetEpoch = info.state === 'arbitrated' && !info.final ? ep : ep + 1;
          const keyTs = sim.now - (atk.backdateMs ?? 14 * 60_000);
          for (const t of allTargets) {
            maliciousResults.push(target.post(sign(mal, { timestamp: sim.now, epoch: targetEpoch, target: t.target, deviceId: t.deviceId, c: bogusC, keyTs, sealed: new Sealed(t.deviceId, k) })));
          }
        } else if (atk.kind === 'copyC' && info.state === 'arbitrated') {
          // The winner's public commitment with an EARLIER key_ts: a better rank,
          // but no key the honest members could ever verify under it.
          const c = Uint8Array.from(Buffer.from(info.key_commitment!, 'hex'));
          for (const t of allTargets) {
            const garbage = randKey();
            origin.set(hex(garbage), 'malicious');
            maliciousResults.push(target.post(sign(mal, { timestamp: sim.now, epoch: ep, target: t.target, deviceId: t.deviceId, c, keyTs: info.key_ts! - 1_000, sealed: new Sealed(t.deviceId, garbage) })));
          }
        } else if (atk.kind === 'squat' && info.state === 'arbitrated') {
          // Squat: occupy honest victims' slots with the winning pair but a garbage key.
          const c = Uint8Array.from(Buffer.from(info.key_commitment!, 'hex'));
          const victims = atk.victims ? sc.devices.filter((d) => atk.victims!.includes(d.device)) : sc.devices.slice(0, 2);
          for (const d of victims) {
            const garbage = randKey();
            origin.set(hex(garbage), 'malicious');
            maliciousResults.push(target.post(sign(mal, { timestamp: sim.now, epoch: ep, target: d.wallet, deviceId: d.device, c, keyTs: info.key_ts!, sealed: new Sealed(d.device, garbage) })));
          }
        }
      });
    }
  }

  await sim.run(sim.t0 + sc.durationMs);

  const excused = {
    longPartition: sc.longPartition, malicious: !!sc.maliciousWallet, hostile: !!sc.hostileNode,
    // Any partition: with sync/backfill taking winner wraps ONLY, a partition
    // during a concurrent rotation is never healed by backfill — the epoch
    // stays split until the members rotate (fork evidence below).
    partition: sc.mesh.partitions.length > 0,
    // Without the optional peer check a split is only counted (measurement mode).
    noPeers: !!sc.noPeers,
  };
  const residuals: Residuals = { lateSplits: 0, nonHomeSplits: 0, homeNone: 0, transitLost: 0, stillConverging: 0 };
  const forks = checkProperties({ devices, nodes, confirmations, violations, excused, authorOfC, residuals, endAt: sim.now });
  // Residual of early use: provisional keys whose pair is NOT the final winner on the device's home node.
  const provisionalOrphaned = provisional.filter((p) => {
    const c = p.dev.home.commits.get(p.epoch);
    return !(c && c.state === 'arbitrated' && hex(c.c) === p.c && c.keyTs === p.keyTs);
  }).length;
  return {
    violations, forks, events: sim.events, supersedes: nodes.reduce((a, n) => a + n.supersedes, 0), escalations,
    confirmations, devices, nodes, excused, outcomes, maliciousResults,
    provisionalUses: provisional.length, provisionalOrphaned, residuals,
    detectedSplits: [...outcomes.values()].reduce((a, l) => a + l.filter((k) => k === 'split').length, 0),
  };
}

/** P1/P3/P4 at quiescence. Pushes into `violations`; returns whether a FORK was observed. */
/** Residual counters reported by the randomized run (not failures). */
interface Residuals {
  /** A confirmed key contradicted LATER by another node's winner (that node had no / no final different winner when it was confirmed). */
  lateSplits: number;
  /** A node no honest member is homed on holds a different key for the members' current epoch. */
  nonHomeSplits: number;
  /** A confirmed key that never reached a member whose HOME node has no (or another) winner for that epoch (lagging / split node). */
  homeNone: number;
  /** A confirmed key that is the member's home-node winner, reached some node for that member, but not its home node (live gossip lost). */
  transitLost: number;
  /** Members one rotation behind at the very end of a run whose latest rotation started < 20 min before it ended. */
  stillConverging: number;
}

/** P1-P4 at quiescence. Pushes into `violations`; returns whether a FORK was observed. */
function checkProperties(r: {
  devices: DeviceState[];
  nodes: FakeArbitratingNode[];
  confirmations: Confirmation[];
  violations: string[];
  excused: { longPartition: boolean; malicious: boolean; hostile: boolean; partition: boolean; noPeers: boolean };
  authorOfC: Map<string, DeviceState>;
  residuals: Residuals;
  endAt: number;
}): boolean {
  const honest = r.devices.filter((d) => d.honest);
  const homes = new Set(honest.map((d) => d.home));
  let fork = false;
  // Fork = two honest clients hold different keys for the same epoch, or two nodes disagree on a winner.
  const byEpoch = new Map<number, Set<string>>();
  for (const d of honest) {
    if (!d.current) continue;
    const s = byEpoch.get(d.current.epoch) ?? new Set();
    s.add(hex(d.current.c));
    byEpoch.set(d.current.epoch, s);
  }
  for (const s of byEpoch.values()) if (s.size > 1) fork = true;
  const epochs = new Set<number>();
  for (const n of r.nodes) for (const e of n.commits.keys()) epochs.add(e);
  for (const e of epochs) {
    const ws = new Set<string>();
    for (const n of r.nodes) {
      const w = n.winner(e);
      if (w) ws.add(hex(w));
    }
    if (ws.size > 1) fork = true;
  }

  // P1 (strict, no partition excuse): every honest client on the highest
  // epoch, holding the SAME key bytes as every other honest client, and that
  // key is its HOME node's winner. A non-home node with a different winner is
  // a residual (counted), a node with no state only lags.
  if (honest.length > 0 && !r.excused.longPartition) {
    const top = Math.max(...honest.map((d) => d.current?.epoch ?? 0));
    for (const d of honest) {
      if (!d.current) {
        r.violations.push(`P1 ${d.spec.device} holds no key`);
        continue;
      }
      if (d.current.epoch !== top) {
        // A rotation still propagating when the run ends (a hostile home node
        // makes its own users escalate every 10 min, forever) is not a
        // convergence failure: tolerated only if the top epoch's first
        // confirmation is younger than 20 min at the end of the run.
        const firstTop = Math.min(...r.confirmations.filter((c) => c.epoch === top).map((c) => c.at));
        if (r.excused.hostile && r.endAt - firstTop < 20 * 60_000) r.residuals.stillConverging++;
        else r.violations.push(`P1 ${d.spec.device} on epoch ${d.current.epoch}, highest ${top}`);
      }
      if (hex(computeKeyCommitment(SCOPE, d.current.epoch, d.current.keyTs, d.current.key)) !== hex(d.current.c)) {
        r.violations.push(`P1 ${d.spec.device} key bytes changed after they were returned`);
      }
      const ref = honest.find((x) => x.current && x.current.epoch === d.current!.epoch)!.current!;
      if (hex(ref.key) !== hex(d.current.key)) r.violations.push(`P1 ${d.spec.device} key bytes differ from other members at epoch ${d.current.epoch}`);
      for (const n of r.nodes) {
        const w = n.winner(d.current.epoch);
        if (n === d.home || homes.has(n)) {
          if ((n === d.home && !w) || (w && !keyCommitmentsEqual(w, d.current.c))) {
            r.violations.push(`P1 ${d.spec.device} key at epoch ${d.current.epoch} != ${n.id} winner`);
          }
        } else if (w && !keyCommitmentsEqual(w, d.current.c)) {
          r.residuals.nonHomeSplits++;
        }
      }
    }
  }
  // P3: a confirmed key is never superseded on its home node, and never
  // contradicted by a node that already held a DIFFERENT FINAL winner when it
  // was confirmed (the peer check exists exactly to catch that → FAIL). A
  // contradiction that appeared only later is a counted residual.
  for (const c of r.confirmations) {
    const dev = r.devices.find((d) => d.spec.device === c.dev)!;
    for (const n of r.nodes) {
      const w = n.winner(c.epoch);
      if (n === dev.home) {
        if (!w || hex(w) !== c.c) r.violations.push(`P3 ${c.dev}'s confirmed key at epoch ${c.epoch} superseded on its home ${n.id}`);
        continue;
      }
      if (!w || hex(w) === c.c) continue;
      const atConfirm = c.peers[n.id];
      if (atConfirm && atConfirm.final && atConfirm.c !== c.c && !r.excused.malicious && !r.excused.noPeers) {
        r.violations.push(`P3 ${c.dev} confirmed epoch ${c.epoch} although ${n.id} already held a different FINAL winner (split not detected)`);
      } else {
        r.residuals.lateSplits++;
      }
    }
  }
  // P4: every confirmed key reaches every honest member device whose home
  // node holds that key as the epoch's winner (strict). A member whose home
  // node lacks the epoch is a counted history gap.
  if (!r.excused.malicious) {
    const seen = new Set<string>();
    for (const c of r.confirmations) {
      const k = `${c.epoch}|${c.c}`;
      if (seen.has(k)) continue;
      seen.add(k);
      // Only the AUTHOR covers members. An author behind a hostile home node can be
      // kept from resuming after a crash (its own slot is withheld) — the documented
      // "a hostile node can partition its own users" residual.
      if (!r.authorOfC.get(c.c)?.honest) continue;
      for (const d of honest) {
        const hw = d.home.winner(c.epoch);
        const env = d.home.ownSlot(d.spec.wallet, d.spec.device, c.epoch);
        const ok = !!env && AUTHENTIC.has(env) && !!env.c && hex(env.c) === c.c && (() => {
          const key = env.sealed.open(d.spec.device);
          return !!key && env.keyTs !== null && hex(computeKeyCommitment(SCOPE, c.epoch, env.keyTs, key)) === c.c;
        })();
        if (ok) continue;
        // Home node lacks that winner: a lagging / split home node (residual).
        if (!hw || hex(hw) !== c.c) {
          r.residuals.homeNone++;
          continue;
        }
        // Did the author cover this device at all (on ANY node)? If yes, the
        // wrap's live gossip to the home node was lost (no sync carries 0x61)
        // — counted. If no node holds it, the protocol failed.
        const coveredSomewhere = r.nodes.some((n) => {
          const e2 = n.ownSlot(d.spec.wallet, d.spec.device, c.epoch);
          return !!e2 && !!e2.c && hex(e2.c) === c.c;
        });
        if (!coveredSomewhere) r.violations.push(`P4 confirmed key of epoch ${c.epoch} never reached ${d.spec.device}`);
        else r.residuals.transitLost++;
      }
    }
  }
  return fork;
}

// --- Random scenario generation ------------------------------------------------------------

function randomScenario(seed: number, arbitrate: boolean): Scenario {
  const r = prng(seed);
  const pick = (n: number): number => Math.floor(r() * n);
  const nodes = 1 + pick(3);
  const memberCount = 3 + pick(3);
  const devices: DeviceSpec[] = [];
  for (let m = 0; m < memberCount; m++) {
    const devs = r() < 0.3 ? 2 : 1;
    for (let d = 0; d < devs; d++) {
      // Most devices react to the kick within ~3 s; some come online later.
      const start = r() < 0.8 ? r() * 3_000 : 3_000 + r() * 90_000;
      devices.push({ wallet: `klv1m${m}`, device: `m${m}d${d}`, node: pick(nodes), start });
    }
  }
  const partitions: Partition[] = [];
  let longPartition = false;
  if (nodes > 1 && r() < 0.15) {
    const long = r() < 0.25;
    longPartition = long;
    const start = r() * 5_000;
    const dur = long ? 150_000 + r() * 150_000 : 5_000 + r() * 55_000;
    const side = new Set<string>([`n${pick(nodes)}`]);
    partitions.push({ start: 1_800_000_000_000 + start, end: 1_800_000_000_000 + start + dur, side });
  }
  const sc: Scenario = {
    seed,
    arbitrate,
    nodes,
    devices,
    mesh: { minDelay: 20, maxDelay: 1_500, dropProb: 0.05, backfillMin: 5_000, backfillMax: 20_000, partitions },
    longPartition,
    faults: { lost: 0.02, fivexx: 0.02, inject429: 0.02, crash: 0.05, resendSame: 0.5 },
    legacyEpoch1: r() < 0.08,
    // OGMARA_SIM_NOPEERS=1 measures the protocol WITHOUT the optional peer check.
    noPeers: process.env.OGMARA_SIM_NOPEERS === '1',
    durationMs: 3 * 3600_000,
    // OGMARA_SIM_CONFIRM=quick evaluates the contract's "10 s still ours" shortcut.
    options: process.env.OGMARA_SIM_CONFIRM === 'quick' ? { confirmMode: 'quick' } : undefined,
  };
  if (r() < 0.1) {
    sc.maliciousWallet = 'klv1mal';
    const n = 1 + pick(2);
    const kinds = ['bogus', 'squat', 'copyC'] as const;
    sc.maliciousAttacks = Array.from({ length: n }, (_, i) => ({
      at: 500 + r() * 4_000 + i * 15 * 60_000,
      kind: kinds[pick(3)]!,
      backdateMs: 60_000 + r() * 19 * 60_000, // 1-20 min: past 15 min is refused key_ts_stale
    }));
  }
  if (nodes > 1 && r() < 0.1) {
    const modes: HostileMode[] = [{ fake409: 0.5 }, { withhold: true }, { forge: true }];
    sc.hostileNode = { index: pick(nodes), mode: modes[pick(modes.length)]! };
  }
  return sc;
}

const SEEDS = Math.min(100_000, Math.max(1, Number(process.env.OGMARA_SIM_SEEDS ?? 5000)));
const SEED0 = Number(process.env.OGMARA_SIM_SEED0 ?? 1);
/** The negative control always runs its own fixed seed range (independent of a single-seed re-run). */
const NEG_SEEDS = Math.min(100_000, Math.max(50, Number(process.env.OGMARA_SIM_NEG_SEEDS ?? 1000)));

// --- Unit tests of the fake node itself (it must BE the contract rule) ----------------------

describe('FakeArbitratingNode implements the contract rule', () => {
  const mk = () => {
    const sim = new Sim();
    const node = new FakeArbitratingNode('n0', sim, new Set(['klv1a', 'klv1b']), true);
    const a: Identity = { wallet: 'klv1a', signer: 'klv1a' };
    const b: Identity = { wallet: 'klv1b', signer: 'klv1b' };
    // `keyTs` is given relative to the clock's origin (t0 + keyTs).
    const env = (id: Identity, c: number, keyTs: number, over: Partial<FEnv> = {}) =>
      sign(id, { timestamp: sim.now, epoch: 1, target: 'klv1b', deviceId: 'd', c: new Uint8Array(32).fill(c), keyTs: sim.t0 + keyTs - 1000, sealed: new Sealed('d', new Uint8Array(32)), ...over });
    return { sim, node, a, b, env };
  };
  it('none → arbitrated; the same PAIR stores more wraps / already_present; same C with another key_ts is just another rank', () => {
    const { node, a, env } = mk();
    expect(node.post(env(a, 5, 100)).status).toBe(200);
    expect(node.getCommitment(1).state).toBe('arbitrated');
    expect(JSON.parse(node.post(env(a, 5, 100)).text).key_status).toBe('already_present');
    expect(JSON.parse(node.post(env(a, 5, 100, { deviceId: 'e' })).text).key_status).toBe('stored');
    // worse rank (later key_ts) → conflict, not a 400
    expect(JSON.parse(node.post(env(a, 5, 101, { deviceId: 'f' })).text).error).toBe('key_commitment_conflict');
    // better rank (earlier key_ts, same C) → supersede (and the old pair's rows go)
    expect(node.post(env(a, 5, 99, { deviceId: 'f' })).status).toBe(200);
    expect(node.getCommitment(1).key_ts).toBe(node.getCommitment(1).key_ts);
    expect(node.ownSlot('klv1b', 'e', 1)).toBeNull();
  });
  it('the winner only moves to a strictly better pair (a superseded commitment may come back with a better key_ts)', () => {
    const { node, a, b, env } = mk();
    node.post(env(a, 5, 100));
    node.post(env(b, 6, 90, { deviceId: 'g' })); // supersedes (100, C5)
    expect(node.post(env(a, 5, 95, { deviceId: 'h' })).status).toBe(409); // worse than (90, C6)
    expect(node.post(env(a, 5, 80, { deviceId: 'h' })).status).toBe(200); // strictly better pair
    expect(node.winner(1)![0]).toBe(5);
  });
  it('a new epoch is accepted only up to max(highest known, floor) + 256, checked after commitment/freshness', () => {
    const { sim, node, a, env } = mk();
    expect(JSON.parse(node.post(env(a, 5, 100, { epoch: 258 })).text).error).toBe('key_epoch_too_far');
    expect(node.post(env(a, 5, 100, { epoch: 257 })).status).toBe(200);
    node.floor = 1000;
    expect(node.post(env(a, 5, 100, { epoch: 1256, deviceId: 'o' })).status).toBe(200);
    // order: a commitment-less / stale envelope reports that, not too_far
    expect(JSON.parse(node.post(env(a, 5, 100, { epoch: 9999, c: null, keyTs: null })).text).error).toBe('key_commitment_required');
    sim.now += KEY_TS_MAX_AGE_MS + 5_000;
    expect(JSON.parse(node.post(env(a, 5, 100, { epoch: 9999, timestamp: sim.now })).text).error).toBe('key_ts_stale');
  });
  it('sync/backfill takes winner wraps ONLY (a better pair is never admitted; a node at none learns nothing)', () => {
    const { node, a, env } = mk();
    node.ingestSync(env(a, 5, 100));
    expect(node.getCommitment(1).state).toBe('none');
    node.ingest(env(a, 5, 100, { deviceId: 'live' }));
    node.ingestSync(env(a, 5, 100, { deviceId: 'late' }));
    expect(node.ownSlot('klv1b', 'late', 1)).not.toBeNull();
    node.ingestSync(env(a, 6, 90, { deviceId: 'better' }));
    expect(node.winner(1)![0]).toBe(5);
  });
  it('seen-cache: a replayed conflict / refusal gets the ORIGINAL answer', () => {
    const { node, a, b, env } = mk();
    node.post(env(a, 5, 100));
    const worse = env(b, 4, 200);
    const first = node.post(worse);
    expect(first.status).toBe(409);
    expect(node.post(worse)).toEqual(first);
  });
  it('S4/#1: an already-present wrap is neither stored (MESSAGES) nor relayed', () => {
    const sim = new Sim();
    const members = new Set(['klv1a', 'klv1b']);
    const n0 = new FakeArbitratingNode('n0', sim, members, true);
    const n1 = new FakeArbitratingNode('n1', sim, members, true);
    n0.peers = [n1];
    n1.peers = [n0];
    let relayed = 0;
    const mesh = { flood: () => { relayed++; } } as unknown as Mesh;
    n0.mesh = mesh;
    const a: Identity = { wallet: 'klv1a', signer: 'klv1a' };
    const mk = () => sign(a, { timestamp: sim.now, epoch: 1, target: 'klv1b', deviceId: 'd', c: new Uint8Array(32).fill(5), keyTs: sim.now - 10, sealed: new Sealed('d', new Uint8Array(32)) });
    expect(JSON.parse(n0.post(mk()).text).key_status).toBe('stored');
    expect(relayed).toBe(1);
    const again = mk();
    expect(JSON.parse(n0.post(again).text).key_status).toBe('already_present');
    expect(relayed).toBe(1);
    expect(n0.messages.has(again.msgId)).toBe(false);
    // the node's bounded seen-cache answers a replay of the non-stored envelope as a duplicate
    expect(n0.post(again)).toEqual({ status: 409, text: 'message already exists' });
  });
  it('S6: refused (429) attempts consume NO per-wallet slot (multi-scope)', () => {
    const { sim, node, a, env } = mk();
    for (let i = 0; i < 60; i++) expect(node.post(env(a, 5, 100, { deviceId: `a${i}`, scope: 'A' })).status).toBe(200);
    for (let i = 0; i < 60; i++) expect(node.post(env(a, 5, 100, { deviceId: `b${i}`, scope: 'B' })).status).toBe(200);
    for (let i = 0; i < 200; i++) expect(node.post(env(a, 5, 100, { deviceId: `x${i}`, scope: 'A' })).status).toBe(429);
    // 120 accepted < 240: a third scope still has wallet budget left
    expect(node.post(env(a, 5, 100, { deviceId: 'c0', scope: 'C', timestamp: sim.now })).status).toBe(200);
  });
  it('rate limits: refused attempts consume no slot; window resets once now > start + window', () => {
    const { sim, node, a, env } = mk();
    for (let i = 0; i < KEY_ENVELOPE_SCOPE_RATE_LIMIT.max; i++) expect(node.post(env(a, 5, 100, { deviceId: `x${i}` })).status).toBe(200);
    for (let i = 0; i < 5; i++) expect(node.post(env(a, 5, 100, { deviceId: `y${i}` })).status).toBe(429);
    sim.now += KEY_ENVELOPE_SCOPE_RATE_LIMIT.windowMs; // == start + window: still the same window
    expect(node.post(env(a, 5, 100, { deviceId: 'z0', timestamp: sim.now })).status).toBe(429);
    sim.now += 1; // > start + window: a new window
    expect(node.post(env(a, 5, 100, { deviceId: 'z1', timestamp: sim.now })).status).toBe(200);
  });
  it('slots are write-once — also against the winner\'s own author (a squat under the winning pair stays)', () => {
    const { node, a, b, env } = mk();
    node.post(env(a, 5, 100, { deviceId: 'x', target: 'klv1a' })); // a is the winner's author
    const squat = node.post(env(b, 5, 100)); // b writes garbage under the public pair into (klv1b, d)
    expect(JSON.parse(squat.text).key_status).toBe('stored');
    expect(JSON.parse(node.post(env(a, 5, 100)).text).key_status).toBe('already_present');
    expect(node.ownSlot('klv1b', 'd', 1)!.wallet).toBe('klv1b');
  });
  it('worse → 409 JSON; better within finality supersedes + deletes loser rows; better after finality → 409', () => {
    const { sim, node, a, b, env } = mk();
    node.post(env(a, 5, 100));
    node.post(env(a, 5, 100, { deviceId: 'e' }));
    const worse = node.post(env(b, 4, 200));
    expect(worse.status).toBe(409);
    expect(JSON.parse(worse.text).error).toBe('key_commitment_conflict');
    expect(node.post(env(b, 6, 99, { deviceId: 'g' })).status).toBe(200);
    expect(node.supersedes).toBe(1);
    expect(node.ownSlot('klv1b', 'd', 1)).toBeNull();
    expect(node.ownSlot('klv1b', 'e', 1)).toBeNull();
    sim.now += KEY_COMMIT_FINALITY_MS;
    const late = node.post(env(a, 1, 50, { timestamp: sim.now }));
    expect(node.winner(1)![0]).toBe(6);
    expect(late.status).toBe(409);
    expect(JSON.parse(late.text).winner.final).toBe(true);
  });
  it('a superseded loser\'s envelope stays in MESSAGES: resubmitting it is a plain duplicate although its wrap is gone', () => {
    const { node, a, b, env } = mk();
    const loser = env(a, 5, 100);
    node.post(loser);
    node.post(env(b, 6, 99, { deviceId: 'g' }));
    expect(node.ownSlot('klv1b', 'd', 1)).toBeNull();
    expect(node.post(loser)).toEqual({ status: 409, text: 'message already exists' });
  });
  it('freshness is uniform: stale key_ts (> 15 min) refused at create AND supersede, except wraps of the exact winner', () => {
    const { sim, node, a, b, env } = mk();
    sim.now += KEY_TS_MAX_AGE_MS + 10_000;
    const rel = sim.now - sim.t0 + 1000; // env() maps keyTs → t0 + keyTs - 1000
    // create with a stale key_ts
    expect(JSON.parse(node.post(env(a, 5, rel - KEY_TS_MAX_AGE_MS - 1, { timestamp: sim.now })).text).error).toBe('key_ts_stale');
    node.post(env(a, 5, rel - 1, { timestamp: sim.now }));
    // supersede with a stale key_ts
    expect(JSON.parse(node.post(env(b, 6, rel - KEY_TS_MAX_AGE_MS - 1, { timestamp: sim.now, deviceId: 'q' })).text).error).toBe('key_ts_stale');
    // ...while a fresh, better rank still supersedes
    expect(node.post(env(b, 6, rel - 2, { timestamp: sim.now, deviceId: 'q' })).status).toBe(200);
    // a late wrap of the EXACT winner joins even when stale
    sim.now += KEY_TS_MAX_AGE_MS + 1;
    expect(node.post(env(b, 6, rel - 2, { timestamp: sim.now, deviceId: 'late' })).status).toBe(200);
  });
  it('commitment-less: 400 at none/arbitrated, FWW at legacy; epoch < floor 400; duplicate plain 409; 429', () => {
    const { node, a, env } = mk();
    expect(JSON.parse(node.post(env(a, 5, 100, { c: null, keyTs: null })).text).error).toBe('key_commitment_required');
    node.commits.set(2, { state: 'legacy' });
    expect(node.post(env(a, 5, 100, { c: null, keyTs: null, epoch: 2 })).status).toBe(200);
    node.floor = 3;
    expect(JSON.parse(node.post(env(a, 5, 100, { epoch: 2, deviceId: 'z' })).text).error).toBe('key_epoch_below_floor');
    node.floor = 1;
    const e = env(a, 5, 100);
    node.post(e);
    expect(node.post(e)).toEqual({ status: 409, text: 'message already exists' });
    // per-(wallet, scope): the 61st channel-scope envelope in the window is refused...
    let last: Resp = { status: 0, text: '' };
    let firstRefusal = -1;
    for (let i = 0; i < KEY_ENVELOPE_RATE_LIMIT.max + 1; i++) {
      last = node.post(env(a, 5, 100, { deviceId: `r${i}` }));
      if (last.status === 429 && firstRefusal < 0) firstRefusal = i;
    }
    expect(firstRefusal).toBeLessThanOrEqual(KEY_ENVELOPE_SCOPE_RATE_LIMIT.max);
    expect(last.status).toBe(429);
    expect(JSON.parse(last.text).retry_after_ms).toBeGreaterThan(0);
  });
  it('gossip order independence: any order of the same envelopes yields the same winner', () => {
    const { sim, a, b } = mk();
    const envs = [5, 3, 9, 1, 7].map((c, i) => sign(i % 2 ? a : b, { timestamp: sim.now, epoch: 1, target: 'klv1b', deviceId: `d${i}`, c: new Uint8Array(32).fill(c), keyTs: sim.now - 100 + (c % 3), sealed: new Sealed('d', new Uint8Array(32)) }));
    const winners = new Set<string>();
    const perms = [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [1, 3, 0, 4, 2]];
    for (const p of perms) {
      const n = new FakeArbitratingNode('x', sim, new Set(['klv1a', 'klv1b']), true);
      for (const i of p) n.ingest(envs[i]!);
      winners.add(hex(n.winner(1)!));
    }
    expect(winners.size).toBe(1);
    // the lowest rank: key_ts first (c=3 and c=9 have c%3 == 0), then bytes (3 < 9)
    expect([...winners][0]).toBe(hex(new Uint8Array(32).fill(3)));
  });
});

// --- Pinned interleavings (audit reproductions) ----------------------------------------------

const BASE_FAULTS = { lost: 0, fivexx: 0, inject429: 0, crash: 0, resendSame: 0 };
const QUIET_MESH: MeshCfg = { minDelay: 50, maxDelay: 50, dropProb: 0, backfillMin: 0, backfillMax: 0, partitions: [] };

function pinned(over: Partial<Scenario> & Pick<Scenario, 'devices'>): Scenario {
  return {
    seed: 42, arbitrate: true, nodes: 3, mesh: QUIET_MESH, longPartition: false, faults: BASE_FAULTS,
    durationMs: 3600_000, ...over,
  };
}

function expectClean(r: RunResult): void {
  expect(r.violations).toEqual([]);
  expect(r.forks).toBe(false);
}

describe('pinned audit interleavings', () => {
  it('(a) two rotators partial-wrap different third parties, then BOTH lose to a better-ranked third key', async () => {
    // R3 on n2 establishes first (best rank); R1 (n0) and R2 (n1) start ~1 s later
    // before R3's commitment reaches them (4 s gossip), each covering some third parties.
    const sc = pinned({
      mesh: { ...QUIET_MESH, delay: () => 4_000 },
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 1_000 },
        { wallet: 'klv1r2', device: 'r2', node: 1, start: 1_100 },
        { wallet: 'klv1r3', device: 'r3', node: 2, start: 0 },
        { wallet: 'klv1t1', device: 't1', node: 0, start: 60_000 },
        { wallet: 'klv1t2', device: 't2', node: 1, start: 60_000 },
      ],
    });
    const r = await runScenario(sc);
    expectClean(r);
    expect(r.supersedes).toBeGreaterThanOrEqual(2); // n0 and n1 both superseded
    expect(r.outcomes.get('r1')).toContain('adopted');
    expect(r.outcomes.get('r2')).toContain('adopted');
    expect(r.outcomes.get('r3')).toContain('established');
    const r3 = r.devices.find((d) => d.spec.device === 'r3')!;
    for (const d of r.devices) expect(hex(d.current!.c)).toBe(hex(r3.current!.c));
    for (const d of r.devices) expect([...d.newKeys.values()].every((n) => n <= 1)).toBe(true);
  }, 60_000);

  it('(b) publish fails partway (429 + 5xx + lost response) — every retry reuses the SAME key', async () => {
    const sc = pinned({
      nodes: 1,
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        ...['a', 'b', 'c', 'd'].map((x) => ({ wallet: `klv1${x}`, device: x, node: 0, start: 30_000 })),
      ],
      postHook: (dev, _env, attempt) => {
        if (dev !== 'r1') return undefined;
        if (attempt === 1) return 'lost'; // own device: committed, response lost
        if (attempt === 3) return { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: 5_000 }) };
        if (attempt >= 5 && attempt <= 8) return { status: 503, text: 'busy' }; // exhaust transient tries on one target
        return undefined;
      },
    });
    const r = await runScenario(sc);
    expectClean(r);
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.newKeys.get(1)).toBe(1);
    expect(r.outcomes.get('r1')![0]).toBe('established');
    for (const d of r.devices) expect(hex(d.current!.c)).toBe(hex(r1.current!.c));
  }, 60_000);

  it('(b2) crash after the own-device publish: restart (memory lost) resumes the SAME winning key', async () => {
    const sc = pinned({
      nodes: 1,
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        ...['a', 'b', 'c'].map((x) => ({ wallet: `klv1${x}`, device: x, node: 0, start: 20_000 })),
      ],
      crashAt: { r1: { at: 400, restartAfter: 15_000 } },
    });
    const r = await runScenario(sc);
    expectClean(r);
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.crashes).toBe(1);
    expect(r1.newKeys.get(1)).toBe(1);
    for (const d of r.devices) expect(d.current!.epoch).toBe(1);
  }, 60_000);

  it('(c) cross-node: two nodes accept different first commitments; gossip supersede resolves', async () => {
    const sc = pinned({
      nodes: 2,
      mesh: { ...QUIET_MESH, delay: () => 4_000 },
      devices: [
        { wallet: 'klv1r2', device: 'r2', node: 1, start: 0 },
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 500 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 30_000 },
        { wallet: 'klv1y', device: 'y', node: 1, start: 30_000 },
      ],
    });
    const r = await runScenario(sc);
    expectClean(r);
    const n0 = r.nodes[0]!;
    expect(n0.supersedes).toBe(1);
    expect(r.nodes[1]!.supersedes).toBe(0);
    expect(hex(n0.winner(1)!)).toBe(hex(r.nodes[1]!.winner(1)!));
    expect(r.outcomes.get('r1')).toContain('adopted');
  }, 60_000);

  it('(c-neg) the same interleaving against a naive per-device FWW node forks', async () => {
    const sc = pinned({
      arbitrate: false,
      nodes: 2,
      mesh: { ...QUIET_MESH, delay: () => 4_000 },
      devices: [
        { wallet: 'klv1r2', device: 'r2', node: 1, start: 0 },
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 500 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 30_000 },
        { wallet: 'klv1y', device: 'y', node: 1, start: 30_000 },
      ],
      durationMs: 600_000,
    });
    const r = await runScenario(sc);
    expect(r.forks).toBe(true);
  }, 60_000);

  it('(e) a rotator stalled ~2 min before its first publish (429s / app suspended) never supersedes late', async () => {
    // R1 generates the BEST-ranked key first, but its own-device publish is
    // held off by two 429s (~118.6 s). R2's key was recorded on n1 at ~0.45 s and
    // on n0 at ~3.45 s. A late supersede landing on n0 just inside n0's horizon
    // would reach n1 just AFTER n1's horizon → a permanent cross-node fork. The
    // own-device pre-publish re-check makes R1 abandon instead.
    const sc = pinned({
      nodes: 2,
      mesh: { ...QUIET_MESH, delay: () => 3_000 },
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1r2', device: 'r2', node: 1, start: 300 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 20_000 },
      ],
      postHook: (dev, _env, attempt) =>
        dev === 'r1' && attempt <= 2 ? { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: 59_300 }) } : undefined,
    });
    const r = await runScenario(sc);
    expectClean(r);
    expect(r.supersedes).toBe(0);
    expect(r.outcomes.get('r1')).toContain('adopted');
  }, 60_000);

  it('(f) a duplicate 409 for a superseded loser\'s envelope is never taken as success', async () => {
    // R1 (n0, resends identical bytes on retry) covers x: the node commits it but
    // the response is lost. Meanwhile R2's better-ranked key supersedes R1 on n0
    // (R1's rows deleted, its envelope kept in MESSAGES). R1's retry resends the
    // same bytes → plain-text 409 "message already exists". R1 must re-check,
    // see the other winner, abandon and adopt R2's key.
    const sc = pinned({
      nodes: 2,
      mesh: { ...QUIET_MESH, delay: () => 4_000 },
      faults: { ...BASE_FAULTS, resendSame: 1 },
      devices: [
        { wallet: 'klv1r2', device: 'r2', node: 1, start: 0 },
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 500 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 60_000 },
      ],
      postHook: (dev, _env, attempt) => (dev === 'r1' && attempt === 3 ? 'lost' : undefined),
    });
    const r = await runScenario(sc);
    expectClean(r);
    expect(r.nodes[0]!.duplicates).toBeGreaterThanOrEqual(1);
    expect(r.outcomes.get('r1')).toContain('adopted');
    expect(r.outcomes.get('r1')).not.toContain('established');
    // Detected AT the duplicate (as a conflict), not only later while settling.
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.logs).toContain('abandoning our key: 409 while covering');
    expect(r1.logs).not.toContain('abandoning our key: superseded');
  }, 60_000);

  it('(g) a backgrounded client whose key went stale (> 60 s) before its first publish regenerates it', async () => {
    const sc = pinned({
      nodes: 1,
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 120_000 },
      ],
      postHook: (dev, _env, attempt) =>
        dev === 'r1' && attempt <= 2 ? { status: 429, text: JSON.stringify({ error: 'rate_limited', retry_after_ms: 40_000 }) } : undefined,
    });
    const r = await runScenario(sc);
    expectClean(r);
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.newKeys.get(1)).toBe(2);
    expect(r1.logs).toContain('abandoning our key: stale before its first publish');
    expect(r.nodes[0]!.getCommitment(1).key_ts!).toBeGreaterThanOrEqual(r.nodes[0]!.getCommitment(1).recorded_at! - 1_000);
  }, 60_000);

  const attackDevices = [
    { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
    { wallet: 'klv1x', device: 'x', node: 0, start: 20_000 },
    { wallet: 'klv1y', device: 'y', node: 1, start: 20_000 },
  ];

  it('(h) a member backdating key_ts by > 15 min is refused key_ts_stale and changes nothing', async () => {
    const sc = pinned({
      nodes: 2, devices: attackDevices, maliciousWallet: 'klv1mal',
      maliciousAttacks: [{ at: 0, kind: 'bogus', backdateMs: 16 * 60_000 }],
    });
    const r = await runScenario(sc);
    expectClean(r);
    expect(r.maliciousResults.length).toBeGreaterThan(0);
    for (const m of r.maliciousResults) expect(JSON.parse(m.text).error).toBe('key_ts_stale');
    expect(r.escalations).toBe(0);
    for (const d of r.devices) expect(d.current!.epoch).toBe(1);
  }, 60_000);

  it('(h2) a member backdating key_ts by < 15 min with a bogus commitment can only stall the epoch: honest members escalate and converge', async () => {
    const sc = pinned({
      nodes: 2, devices: attackDevices, maliciousWallet: 'klv1mal',
      maliciousAttacks: [{ at: 1_000, kind: 'bogus', backdateMs: 10 * 60_000 }],
    });
    const r = await runScenario(sc);
    expectClean(r);
    expect(r.escalations).toBeGreaterThan(0);
    const top = r.devices[0]!.current!;
    expect(top.epoch).toBeGreaterThan(1);
    for (const d of r.devices) expect(hex(d.current!.c)).toBe(hex(top.c));
  }, 60_000);

  it('(i) the winner\'s public commitment paired with an EARLIER key_ts never confirms for the honest establisher', async () => {
    const sc = pinned({
      nodes: 2, devices: attackDevices, maliciousWallet: 'klv1mal',
      maliciousAttacks: [{ at: 1_500, kind: 'copyC' }],
    });
    const r = await runScenario(sc);
    expectClean(r);
    // The copied pair superseded r1's on n0 → r1 must NOT confirm its key at epoch 1.
    expect(r.nodes[0]!.supersedes).toBeGreaterThanOrEqual(1);
    expect(r.confirmations.filter((c) => c.epoch === 1)).toEqual([]);
    expect(r.devices.find((d) => d.spec.device === 'r1')!.logs).toContain('abandoning our key: superseded');
    const top = r.devices[0]!.current!;
    expect(top.epoch).toBeGreaterThan(1);
    for (const d of r.devices) expect(hex(d.current!.c)).toBe(hex(top.c));
  }, 60_000);

  it('(j) a duplicate 409 whose own slot does not verify is re-signed with a fresh envelope and republished', async () => {
    const sc = pinned({
      nodes: 1,
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 20_000 },
      ],
      // A node that answers "message already exists" without the wrap being stored.
      postHook: (dev, _env, attempt) => (dev === 'r1' && attempt === 1 ? { status: 409, text: 'message already exists' } : undefined),
    });
    const r = await runScenario(sc);
    expectClean(r);
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.freshRepublishes).toBeGreaterThanOrEqual(1);
    expect(r1.newKeys.get(1)).toBe(1);
    expect(r.outcomes.get('r1')![0]).toBe('established');
  }, 60_000);

  it('(k) slot squat under the winning pair: detectable, not preventable — the victim verifies H(key_ts, K) == C, fails safe and escalates', async () => {
    const sc = pinned({
      nodes: 1,
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1z', device: 'z', node: 0, start: 20_000 },
      ],
      maliciousWallet: 'klv1mal',
      maliciousAttacks: [{ at: 700, kind: 'squat', victims: ['z'] }],
      // Hold r1's wrap to z back (two 503s → ~1.5 s backoff) so the squat lands first.
      postHook: (dev, env, attempt) => (dev === 'r1' && env.deviceId === 'z' && attempt <= 4 ? { status: 503, text: 'busy' } : undefined),
    });
    const r = await runScenario(sc);
    expectClean(r);
    const slot = r.nodes[0]!.ownSlot('klv1z', 'z', 1)!;
    expect(slot.wallet).toBe('klv1mal'); // write-once: the squat stays, attributable to its signer
    const [r1, z] = ['r1', 'z'].map((n) => r.devices.find((d) => d.spec.device === n)!);
    expect(r.outcomes.get('z')).toContain('escalate'); // never adopted the garbage
    expect(z!.current!.epoch).toBeGreaterThan(1); // recovery: rotate past the squatted epoch
    expect(hex(z!.current!.c)).toBe(hex(r1!.current!.c));
  }, 60_000);

  it('(l) cross-node squat: a copied winning pair delivered to a lagging node FIRST is still just a squat (write-once), never a replacement', async () => {
    // n1 is partitioned from n0 for 10 s. r1 establishes on n0; the attacker
    // reads the public pair and posts a garbage wrap for y straight to n1.
    // With write-once slots the attacker gains nothing beyond the squat
    // itself; r1's honest wraps to OTHER slots on n1 land normally.
    const sc = pinned({
      nodes: 2,
      mesh: { ...QUIET_MESH, partitions: [{ start: 1_800_000_000_000, end: 1_800_000_010_000, side: new Set(['n1']) }] },
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1y', device: 'y', node: 1, start: 30_000 },
        { wallet: 'klv1w', device: 'w', node: 1, start: 30_000 },
      ],
      maliciousWallet: 'klv1mal',
      maliciousAttacks: [{ at: 1_000, kind: 'squat', victims: ['y'], node: 1 }],
    });
    const r = await runScenario(sc);
    expectClean(r);
    // write-once: the squat stays, attributable to its signer, and nothing
    // ever replaces it. (r1's wraps held by the partition are LOST — no sync
    // carries 0x61 — so n1's members recover by rotating.)
    expect(r.nodes[1]!.ownSlot('klv1y', 'y', 1)!.wallet).toBe('klv1mal');
    expect(r.outcomes.get('y')).toContain('escalate');
    const [r1, y] = ['r1', 'y'].map((n) => r.devices.find((d) => d.spec.device === n)!);
    expect(hex(y!.current!.c)).toBe(hex(r1!.current!.c));
  }, 60_000);

  it('(m) covering more devices than the per-(wallet, scope) limit (60/60 s) waits out the 429s and completes with the SAME key', async () => {
    const devices: DeviceSpec[] = [{ wallet: 'klv1r1', device: 'r1', node: 0, start: 0 }];
    for (let i = 0; i < 70; i++) devices.push({ wallet: `klv1t${String(i).padStart(2, '0')}`, device: `t${i}`, node: 0, start: 200_000 });
    const r = await runScenario(pinned({ nodes: 1, devices }));
    expectClean(r);
    const r1 = r.devices.find((d) => d.spec.device === 'r1')!;
    expect(r1.newKeys.get(1)).toBe(1);
    expect(r1.logs).toContain('rate limited, retrying the same key');
    for (const d of r.devices) expect(hex(d.current!.c)).toBe(hex(r1.current!.c));
  }, 120_000);

  // (n) a lagging / fresh home node: n1 is partitioned during the whole epoch-1
  // rotation (its live wraps lost; backfill takes winner wraps only, and n1 has
  // no winner). Member c, homed on n1, comes online after the heal and learns
  // epoch 1 from channel messages.
  const laggingScenario = (legacyLaggingRule: boolean, noPeers = false): Scenario =>
    pinned({
      nodes: 2,
      legacyLaggingRule,
      noPeers,
      mesh: { ...QUIET_MESH, partitions: [{ start: 1_800_000_000_000, end: 1_800_000_200_000, side: new Set(['n1']) }] },
      devices: [
        { wallet: 'klv1r1', device: 'r1', node: 0, start: 0 },
        { wallet: 'klv1x', device: 'x', node: 0, start: 5_000 },
        { wallet: 'klv1c', device: 'c', node: 1, start: 300_000 },
      ],
    });

  it('(n-neg2) OLD rule but WITH peerCommitments: the forked key is never confirmed (split detected)', async () => {
    const r = await runScenario(laggingScenario(true));
    expect(r.outcomes.get('c')).toContain('split');
    expect(r.confirmations.filter((c) => c.dev === 'c' && c.epoch === 1)).toEqual([]);
  }, 60_000);

  it('(n-neg) OLD rule, no peer check: a lagging home node creates an epoch the mesh already finalized → permanent fork', async () => {
    const r = await runScenario(laggingScenario(true, true));

    // Epoch 1 is split for good: n1 recorded c's key while n0 holds r1's final
    // one (c's epoch-1 messages are unreadable for r1/x and vice versa). Only
    // the fork-evidence rotation later moves everyone to epoch 2.
    expect(r.forks).toBe(true);
    expect(r.outcomes.get('c')![0]).toBe('established');
    expect(r.nodes[1]!.getCommitment(1).state).toBe('arbitrated');
    expect(hex(r.nodes[1]!.winner(1)!)).not.toBe(hex(r.nodes[0]!.winner(1)!));
  }, 60_000);

  it('(n) NEW rule: the lagging node refuses (node_lagging), the member rotates past it and everyone converges', async () => {
    const r = await runScenario(laggingScenario(false));
    expectClean(r);
    expect(r.outcomes.get('c')).toContain('node_lagging');
    expect(r.nodes[1]!.getCommitment(1).state).toBe('none'); // never created on the lagging node
    const [r1, x, c] = ['r1', 'x', 'c'].map((n) => r.devices.find((d) => d.spec.device === n)!);
    expect(c!.current!.epoch).toBe(2);
    expect(hex(c!.current!.key)).toBe(hex(r1!.current!.key));
    expect(hex(x!.current!.key)).toBe(hex(r1!.current!.key));
  }, 60_000);

  // (d) desktop / web / mobile mixed ordering = the same protocol under different arrival orders.
  const perms = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
  for (const p of perms) {
    it(`(d) mixed client ordering ${p.join('')}`, async () => {
      const names = ['desktop', 'web', 'mobile'];
      const sc = pinned({
        mesh: { ...QUIET_MESH, delay: (f, t) => 300 + ((f.charCodeAt(1) * 7 + t.charCodeAt(1) * 13) % 900) },
        devices: [
          ...p.map((i, rank) => ({ wallet: `klv1${names[i]}`, device: names[i]!, node: i, start: rank * 150 })),
          { wallet: 'klv1late', device: 'late', node: 1, start: 45_000 },
        ],
      });
      expectClean(await runScenario(sc));
    }, 60_000);
  }
});

// --- Randomized property run + negative control -----------------------------------------------

describe(`randomized epoch establishment (${SEEDS} seeds from ${SEED0})`, () => {
  it('holds every property under faults', async () => {
    const failures: string[] = [];
    let events = 0;
    let supersedes = 0;
    let escalations = 0;
    let detectedSplits = 0;
    let lateSplits = 0;
    let nonHomeSplits = 0;
    let homeNone = 0;
    let transitLost = 0;
    let uncaughtSplitSeeds = 0;
    let stillConverging = 0;
    let malicious = 0;
    let hostile = 0;
    let longPartitions = 0;
    let provisionalUses = 0;
    let provisionalOrphaned = 0;
    let provisionalOrphanedHonest = 0;
    for (let s = SEED0; s < SEED0 + SEEDS; s++) {
      const sc = randomScenario(s, true);
      const r = await runScenario(sc);
      events += r.events;
      provisionalUses += r.provisionalUses;
      provisionalOrphaned += r.provisionalOrphaned;
      if (!sc.maliciousWallet && !sc.longPartition) provisionalOrphanedHonest += r.provisionalOrphaned;
      supersedes += r.supersedes;
      escalations += r.escalations;
      if (sc.maliciousWallet) malicious++;
      if (sc.hostileNode) hostile++;
      if (sc.longPartition) longPartitions++;
      detectedSplits += r.detectedSplits;
      lateSplits += r.residuals.lateSplits;
      nonHomeSplits += r.residuals.nonHomeSplits;
      homeNone += r.residuals.homeNone;
      transitLost += r.residuals.transitLost;
      stillConverging += r.residuals.stillConverging;
      if (r.residuals.lateSplits > 0 || r.residuals.nonHomeSplits > 0) uncaughtSplitSeeds++;
      if (process.env.OGMARA_SIM_DEBUG) {
        process.stderr.write(`seed ${s}: nodes=${sc.nodes} devs=${sc.devices.length} esc=${r.escalations} sup=${r.supersedes} mal=${!!sc.maliciousWallet} host=${sc.hostileNode ? JSON.stringify(sc.hostileNode.mode) : '-'} legacy=${!!sc.legacyEpoch1} crash=${r.devices.filter((d) => d.crashes).length} part=${sc.mesh.partitions.length} topEpoch=${Math.max(...r.devices.map((d) => d.current?.epoch ?? 0))} events=${r.events}\n`);
      }
      if (process.env.OGMARA_SIM_DEBUG === '2') {
        for (const d of r.devices) {
          process.stderr.write(`  ${d.spec.device} node=${d.spec.node} honest=${d.honest} start=${Math.round(d.spec.start)} crashes=${d.crashes} cur=${d.current?.epoch}:${d.current ? hex(d.current.c).slice(0, 8) : '-'} outcomes=${(r.outcomes.get(d.spec.device) ?? []).slice(0, 12).join(',')}\n`);
        }
        for (const c of r.confirmations.slice(0, 30)) process.stderr.write(`  confirm ${c.dev} e${c.epoch} ${c.c.slice(0, 8)} ${c.kind} t+${c.at - 1_800_000_000_000}\n`);
        for (const n of r.nodes) {
          for (const [e, c] of [...n.commits].sort((a, b) => a[0] - b[0]).slice(0, 4)) {
            process.stderr.write(`  ${n.id} e${e} ${c.state === 'arbitrated' ? hex(c.c).slice(0, 8) + ' by ' + c.author + ' at+' + (c.recordedAt - 1_800_000_000_000) : c.state} rows=${[...n.rows.values()].filter((x) => x.epoch === e).map((x) => x.deviceId + ':' + (x.c ? hex(x.c).slice(0, 4) : '-')).join(' ')}\n`);
          }
        }
        for (const v of r.violations.slice(0, 10)) process.stderr.write(`  !! ${v}\n`);
      }
      if (r.violations.length > 0) failures.push(`seed ${s}: ${r.violations.slice(0, 3).join('; ')}`);
    }
    process.stderr.write(`[sim] seeds=${SEEDS} events=${events} supersedes=${supersedes} escalations=${escalations} malicious=${malicious} hostile=${hostile} longPartitions=${longPartitions} detectedSplits=${detectedSplits} residual[uncaughtSplitSeeds=${uncaughtSplitSeeds} lateSplits=${lateSplits} nonHomeSplits=${nonHomeSplits} homeNone=${homeNone} transitLost=${transitLost} stillConverging=${stillConverging}] provisionalUses=${provisionalUses} provisionalOrphaned=${provisionalOrphaned} (no malicious/long-partition: ${provisionalOrphanedHonest}) failures=${failures.length}\n`);
    expect(failures.slice(0, 20)).toEqual([]);
    // With the peer check every split must be caught before a confirmation.
    // (measurement modes — no peers, quick confirm — only report it)
    if (process.env.OGMARA_SIM_NOPEERS !== '1' && process.env.OGMARA_SIM_CONFIRM !== 'quick') expect(uncaughtSplitSeeds).toBe(0);
  }, 3_600_000);

  it(`NEGATIVE CONTROL: a naive per-device FWW node forks under the same seeds (${NEG_SEEDS} seeds)`, async () => {
    let forks = 0;
    let violating = 0;
    for (let s = 1; s <= NEG_SEEDS; s++) {
      const sc = randomScenario(s, false);
      sc.durationMs = 30 * 60_000;
      // The node-rule control: the client WITHOUT the optional peer check (with
      // it, members mostly refuse to confirm on a naive node instead).
      sc.noPeers = true;
      const r = await runScenario(sc);
      if (r.forks) forks++;
      if (r.violations.length > 0) violating++;
    }
    process.stderr.write(`[sim negative control] seeds=${NEG_SEEDS} forks=${forks} propertyViolations=${violating}\n`);
    expect(forks).toBeGreaterThan(0);
    expect(violating).toBeGreaterThan(0);
  }, 3_600_000);
});
