/** Synthetic transport for consumer tests, never a database/authentication substitute.
 * Owners are supplied as explicit fixtures; no bearer, provider or network is trusted.
 * It deliberately separates historical approval receipts from current registry state.
 */
import { canonicalizeJson } from '../../src/jcs.js';
import {
  parseSignupStart, parseSignupCancel, parseIntroPolicy, parseIntroToken, verifyIntroToken,
  verifySignupStart, verifySignupCancel, verifyIntroPolicy,
  signupRequestDigest, signupKeyId, signupSubjectId, assertSignupFresh,
} from '../../src/signup-codec.js';

export type SignupRuntime = 'claude' | 'codex' | 'buzz' | 'openclaw' | 'hermes' | 'other';
export type SignupState = 'pending' | 'live' | 'rejected' | 'expired' | 'cancelled';
export type SignupFlag = 'true' | 'paused' | 'false';
export interface FakeOwner {
  sub: string;
  email: string;
  email_verified: boolean;
  azp: string;
}
export interface StartReceipt {
  schema_version: '1.0'; signup_id: string; state: 'pending';
  proposed_domain: string; user_code: string; approval_url: string;
  expires_at_ms: number; poll_interval_ms: 5000;
}
export interface ApprovalReceipt {
  state: 'live'; domain: string; incarnation: string; subject_agent_id: string;
}
export interface LivePoll extends ApprovalReceipt {
  schema_version: '1.0'; signup_id: string; public_key: string; live_at_ms: number;
}
export type SignupPoll = LivePoll
  | { schema_version: '1.0'; signup_id: string; state: 'pending'; proposed_domain: string; expires_at_ms: number; poll_interval_ms: 5000 }
  | { schema_version: '1.0'; signup_id: string; state: 'expired'; expires_at_ms: number }
  | { schema_version: '1.0'; signup_id: string; state: 'cancelled' | 'rejected'; decided_at_ms: number };
export interface CurrentAgent {
  domain: string; public_key: string; incarnation: string; revision: number;
  status: 'registered'; identity_status: 'active' | 'suspended';
}
export interface FakeCard {
  schema_version: '1.0'; user_code: string; state: SignupState;
  chosen: string; proposed_domain: string; key_fingerprint: string;
  runtime: SignupRuntime; created_at_ms: number; expires_at_ms: number;
  renames_left: number; held_names: string[]; introducer: { domain: string; owner: null } | null;
  final_domain: string | null;
}
export interface SignupErrorBody { error: string; code: string }
export interface FakeResult<T> { status: number; body: T | SignupErrorBody }
interface Row {
  id: string; key: string; request_digest: string; email_hash: string;
  receipt: StartReceipt; chosen: string; proposed: string; runtime: SignupRuntime;
  state: SignupState; renames: number; created: number; decided: number | null;
  owner_sub: string | null; approval: ApprovalReceipt | null; live_at: number | null;
  intro_id: string | null; introducer: string | null;
}
interface StartInput {
  proof: { signup_id: string; public_key: string; issued_at_ms: number };
  name: string; owner_email: string; runtime: SignupRuntime; introduced_by: string | null;
}
export interface SignupFakeOptions {
  now?: () => number;
  flag?: SignupFlag;
  audience?: string;
  approvalOrigin?: string;
  ownerClientId?: string;
  /** Defaults to the shared frozen registry derivation. */
  subjectAgentId?: (domain: string, incarnation: string) => string | Promise<string>;
}
export interface StartBarrier {
  /** Resolves after validation/freshness but before the synthetic serialized write. */
  entered: Promise<void>;
  release(): void;
}
const email = (value: string) => value.trim().toLowerCase();
const codeKey = (value: string) => value.toUpperCase().replace('-', '');
const fail = (status: number, code: string): FakeResult<never> => ({ status, body: { error: code, code } });
const ok = <T>(body: T, status = 200): FakeResult<T> => ({ status, body: structuredClone(body) });
const resultError = (cause: unknown): FakeResult<never> => {
  const error = cause as { status?: unknown; code?: unknown };
  return fail(typeof error.status === 'number' ? error.status : 503,
    typeof error.code === 'string' ? error.code : 'E_SIGNUP_UNAVAILABLE');
};

export class SignupFake {
  flag: SignupFlag;
  schemaAvailable = true;
  limiter: 'allow' | 'deny' | 'unavailable' = 'allow';
  readonly audience: string;
  readonly ownerClientId: string;
  readonly calls = { reads: 0, writes: 0, limiter: 0 };
  private readonly clock: () => number;
  private readonly origin: string;
  private readonly subject: NonNullable<SignupFakeOptions['subjectAgentId']>;
  private readonly rows = new Map<string, Row>();
  private readonly agents = new Map<string, CurrentAgent>();
  private readonly ownership = new Map<string, string>();
  private readonly held = new Map<string, string[]>();
  private readonly introAllowed = new Map<string, boolean>();
  private readonly nonces = new Set<string>();
  private nextNumber = 0;
  private nextIncarnation = 0;
  private barrier: { entered(): void; wait: Promise<void> } | null = null;

  constructor(options: SignupFakeOptions = {}) {
    this.flag = options.flag ?? 'false';
    this.clock = options.now ?? (() => 1793000000000);
    this.audience = options.audience ?? 'api.signup.test';
    this.origin = options.approvalOrigin ?? 'https://signup.test';
    this.ownerClientId = options.ownerClientId ?? 'test-owner-app';
    this.subject = options.subjectAgentId ?? signupSubjectId;
  }

  holdNextStart(): StartBarrier {
    if (this.barrier) throw new Error('A start barrier already exists');
    let entered!: () => void;
    let release!: () => void;
    const entry = new Promise<void>(resolve => { entered = resolve; });
    const wait = new Promise<void>(resolve => { release = resolve; });
    this.barrier = { entered, wait };
    return { entered: entry, release };
  }

  private gate(writes = false, limited = false): FakeResult<never> | null {
    if (this.flag !== 'true' && this.flag !== 'paused') return fail(404, 'E_NOT_FOUND');
    if (writes && this.flag === 'paused') return fail(503, 'E_SIGNUP_PAUSED');
    if (limited) {
      this.calls.limiter++;
      if (this.limiter === 'unavailable') return fail(503, 'E_RATE_LIMIT_UNAVAILABLE');
      if (this.limiter === 'deny') return fail(429, 'E_RATE_LIMITED');
    }
    if (!this.schemaAvailable) return fail(503, 'E_SIGNUP_UNAVAILABLE');
    return null;
  }

  private ownerError(owner: FakeOwner): FakeResult<never> | null {
    if (owner.azp !== this.ownerClientId || !/^(auth0|google-oauth2)\|/.test(owner.sub)) return fail(403, 'E_OWNER_CONNECTION');
    if (owner.email_verified !== true) return fail(403, 'E_EMAIL_UNVERIFIED');
    return null;
  }

  private async ownerRow(userCode: string, owner: FakeOwner): Promise<Row | FakeResult<never>> {
    const auth = this.ownerError(owner);
    if (auth) return auth;
    this.calls.reads++;
    const row = [...this.rows.values()].find(value => codeKey(value.receipt.user_code) === codeKey(userCode));
    if (!row) return fail(404, 'E_SIGNUP_NOT_FOUND');
    if (row.email_hash !== await signupRequestDigest(email(owner.email))) return fail(403, 'E_SIGNUP_OWNER_MISMATCH');
    return row;
  }

  private state(row: Row): SignupState {
    return row.state === 'pending' && this.clock() >= row.receipt.expires_at_ms ? 'expired' : row.state;
  }

  async start(bytes: string): Promise<FakeResult<StartReceipt>> {
    const unavailable = this.gate(true, true);
    if (unavailable) return unavailable;
    try {
      const request = parseSignupStart(bytes) as StartInput;
      await verifySignupStart(request, this.audience);
      const digest = await signupRequestDigest(bytes);
      this.calls.reads++;
      const old = this.rows.get(request.proof.signup_id);
      if (old) return this.repeatStart(old, request.proof.public_key, digest);
      assertSignupFresh(request.proof.issued_at_ms, this.clock());
      let intro: { id: string; introducer: string } | null = null;
      let introAuthority: CurrentAgent | null = null;
      if (request.introduced_by !== null) {
        const parsed = parseIntroToken(request.introduced_by);
        introAuthority = this.lookup(parsed.introducer);
        if (!introAuthority) return fail(422, 'E_INTRO_INVALID');
        await verifyIntroToken(parsed, introAuthority, this.clock(), this.audience);
        intro = parsed;
      }
      const barrier = this.barrier;
      this.barrier = null;
      if (barrier) { barrier.entered(); await barrier.wait; }
      // The held call represents an already evaluated request whose write may land
      // after a later primary lookup found no row. A stale lookup is a snapshot.
      const emailHash = await signupRequestDigest(email(request.owner_email));
      const concurrent = this.rows.get(request.proof.signup_id);
      if (concurrent) return this.repeatStart(concurrent, request.proof.public_key, digest);
      if ([...this.agents.values()].some(agent => agent.public_key === request.proof.public_key)) return fail(409, 'E_KEY_REGISTERED');
      const pending = [...this.rows.values()].filter(row => this.state(row) === 'pending');
      if (pending.some(row => row.key === request.proof.public_key)) return fail(409, 'E_KEY_PENDING');
      if (pending.filter(row => row.email_hash === emailHash).length >= 2) return fail(429, 'E_RATE_LIMITED');
      if (intro && introAuthority) {
        if ([...this.rows.values()].some(row => row.intro_id === intro!.id)) return fail(422, 'E_INTRO_USED');
        const current = this.agents.get(intro.introducer);
        if (!current || current.public_key !== introAuthority.public_key || current.incarnation !== introAuthority.incarnation || current.revision !== introAuthority.revision) return fail(422, 'E_INTRO_INVALID');
        const owner = this.ownership.get(intro.introducer);
        if (current.identity_status !== 'active' || (owner !== undefined && this.introAllowed.get(owner) === false)) return fail(422, 'E_INTRO_UNAVAILABLE');
      }
      if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(request.name) || /-\d{4}$/.test(request.name)) return fail(400, 'E_NAME_FORMAT');
      const number = (++this.nextNumber).toString().padStart(4, '0');
      const domain = `${request.name}-${number}.z.viz`;
      const alphabet = 'BCDFGHJKLMNPQRSTVWXZ';
      let codeNumber = this.nextNumber;
      let rawCode = '';
      for (let index = 0; index < 8; index++) { rawCode = alphabet[codeNumber % alphabet.length] + rawCode; codeNumber = Math.floor(codeNumber / alphabet.length); }
      const userCode = `${rawCode.slice(0, 4)}-${rawCode.slice(4)}`;
      const created = this.clock();
      const receipt: StartReceipt = {
        schema_version: '1.0', signup_id: request.proof.signup_id, state: 'pending',
        proposed_domain: domain, user_code: userCode,
        approval_url: `${this.origin}/approve/${userCode}`,
        expires_at_ms: created + 86400000, poll_interval_ms: 5000,
      };
      this.rows.set(request.proof.signup_id, {
        id: request.proof.signup_id, key: request.proof.public_key, request_digest: digest,
        email_hash: emailHash, receipt, chosen: request.name, proposed: domain,
        runtime: request.runtime, state: 'pending', renames: 0, created, decided: null,
        owner_sub: null, approval: null, live_at: null,
        intro_id: intro?.id ?? null, introducer: intro?.introducer ?? null,
      });
      this.calls.writes++;
      return ok(receipt, 201);
    } catch (cause) { return resultError(cause); }
  }

  private repeatStart(row: Row, key: string, digest: string): FakeResult<StartReceipt> {
    return row.key === key && row.request_digest === digest
      ? ok(row.receipt) : fail(409, 'E_SIGNUP_ID_CONFLICT');
  }

  async poll(id: string): Promise<FakeResult<SignupPoll>> {
    const unavailable = this.gate(false, true);
    if (unavailable) return unavailable.status === 429 ? fail(429, 'E_SLOW_DOWN') : unavailable;
    this.calls.reads++;
    const row = this.rows.get(id);
    if (!row) return fail(404, 'E_SIGNUP_NOT_FOUND');
    const common = { schema_version: '1.0' as const, signup_id: id };
    const state = this.state(row);
    if (state === 'live') return ok({ ...common, ...row.approval!, public_key: row.key, live_at_ms: row.live_at! });
    if (state === 'expired') return ok({ ...common, state, expires_at_ms: row.receipt.expires_at_ms });
    if (state === 'pending') return ok({ ...common, state, proposed_domain: row.proposed, expires_at_ms: row.receipt.expires_at_ms, poll_interval_ms: 5000 });
    return ok({ ...common, state, decided_at_ms: row.decided! });
  }

  async ownerCard(code: string, owner: FakeOwner): Promise<FakeResult<FakeCard>> {
    const unavailable = this.gate();
    if (unavailable) return unavailable;
    const row = await this.ownerRow(code, owner);
    if ('status' in row) return row;
    const fingerprint = (await signupKeyId(row.key)).slice(7, 23);
    return ok({ schema_version: '1.0', user_code: row.receipt.user_code, state: this.state(row),
      chosen: row.chosen, proposed_domain: row.proposed, key_fingerprint: fingerprint,
      runtime: row.runtime, created_at_ms: row.created, expires_at_ms: row.receipt.expires_at_ms,
      renames_left: 10 - row.renames, held_names: this.held.get(owner.sub) ?? [],
      introducer: row.introducer ? { domain: row.introducer, owner: null } : null, final_domain: row.approval?.domain ?? null });
  }

  async rename(code: string, owner: FakeOwner, choice: { chosen: string } | { held: string }): Promise<FakeResult<{ proposed_domain: string; renames_left: number }>> {
    const unavailable = this.gate(true);
    if (unavailable) return unavailable;
    const row = await this.ownerRow(code, owner);
    if ('status' in row) return row;
    if (row.state !== 'pending') return fail(409, 'E_SIGNUP_FINAL');
    if (this.state(row) === 'expired') return fail(410, 'E_SIGNUP_EXPIRED');
    if (row.renames >= 10) return fail(429, 'E_RENAME_LIMIT');
    let domain: string;
    let chosen: string;
    if ('held' in choice) {
      if (!this.held.get(owner.sub)?.includes(choice.held)) return fail(409, 'E_NAME_TAKEN');
      domain = choice.held;
      chosen = domain.slice(0, -6);
    } else {
      chosen = choice.chosen;
      if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(chosen) || /-\d{4}$/.test(chosen)) return fail(400, 'E_NAME_FORMAT');
      domain = `${chosen}-${(++this.nextNumber).toString().padStart(4, '0')}.z.viz`;
    }
    if (this.agents.has(domain) || [...this.rows.values()].some(value => value !== row && this.state(value) === 'pending' && value.proposed === domain)) return fail(409, 'E_NAME_TAKEN');
    row.chosen = chosen; row.proposed = domain; row.renames++;
    this.calls.writes++;
    return ok({ proposed_domain: domain, renames_left: 10 - row.renames });
  }

  async approve(code: string, owner: FakeOwner, proposed_domain: string): Promise<FakeResult<ApprovalReceipt>> {
    const unavailable = this.gate(true);
    if (unavailable) return unavailable;
    const row = await this.ownerRow(code, owner);
    if ('status' in row) return row;
    if (row.state === 'live') return row.owner_sub === owner.sub && row.approval!.domain === proposed_domain
      ? ok(row.approval!) : fail(409, 'E_SIGNUP_FINAL');
    if (row.state !== 'pending') return fail(409, 'E_SIGNUP_FINAL');
    if (this.state(row) === 'expired') return fail(410, 'E_SIGNUP_EXPIRED');
    if (row.proposed !== proposed_domain) return fail(409, 'E_SIGNUP_STALE_VIEW');
    if ([...this.agents.values()].some(agent => agent.public_key === row.key)) return fail(409, 'E_KEY_REGISTERED');
    if (this.agents.has(proposed_domain)) return fail(409, 'E_NAME_TAKEN');
    if ([...this.ownership.values()].filter(sub => sub === owner.sub).length >= 25) return fail(429, 'E_OWNER_LIMIT');
    const incarnation = (++this.nextIncarnation).toString(16).padStart(32, '0');
    const subject_agent_id = await this.subject(proposed_domain, incarnation);
    // No await occurs after evaluating the current constraints and before commit.
    if (row.state !== 'pending') return fail(409, 'E_SIGNUP_FINAL');
    if (this.state(row) === 'expired') return fail(410, 'E_SIGNUP_EXPIRED');
    if (this.agents.has(proposed_domain)) return fail(409, 'E_NAME_TAKEN');
    if ([...this.agents.values()].some(agent => agent.public_key === row.key)) return fail(409, 'E_KEY_REGISTERED');
    if ([...this.ownership.values()].filter(sub => sub === owner.sub).length >= 25) return fail(429, 'E_OWNER_LIMIT');
    const approval: ApprovalReceipt = { state: 'live', domain: proposed_domain, incarnation, subject_agent_id };
    row.approval = approval; row.state = 'live'; row.owner_sub = owner.sub;
    row.live_at = this.clock(); row.decided = row.live_at;
    this.agents.set(proposed_domain, { domain: proposed_domain, public_key: row.key, incarnation,
      revision: 0, status: 'registered', identity_status: 'active' });
    this.ownership.set(proposed_domain, owner.sub);
    this.held.set(owner.sub, (this.held.get(owner.sub) ?? []).filter(value => value !== proposed_domain));
    this.calls.writes++;
    return ok(approval);
  }

  async reject(code: string, owner: FakeOwner): Promise<FakeResult<{ state: 'rejected' }>> {
    const unavailable = this.gate();
    if (unavailable) return unavailable;
    const row = await this.ownerRow(code, owner);
    if ('status' in row) return row;
    if (row.state !== 'pending') return fail(409, 'E_SIGNUP_FINAL');
    if (this.state(row) === 'expired') return fail(410, 'E_SIGNUP_EXPIRED');
    row.state = 'rejected'; row.owner_sub = owner.sub; row.decided = this.clock();
    this.calls.writes++;
    return ok({ state: 'rejected' });
  }

  async cancel(id: string, bytes: string): Promise<FakeResult<{ state: 'cancelled' }>> {
    const unavailable = this.gate(true, true);
    if (unavailable) return unavailable;
    try {
      const request = parseSignupCancel(bytes) as { signup_id: string; audience: string; nonce: string; issued_at_ms: number };
      if (request.signup_id !== id) return fail(400, 'E_SIGNUP_SHAPE');
      if (request.audience !== this.audience) return fail(401, 'E_SIGNUP_AUD');
      const row = this.rows.get(id);
      if (!row) return fail(404, 'E_SIGNUP_NOT_FOUND');
      await verifySignupCancel(request, row.key, this.audience);
      assertSignupFresh(request.issued_at_ms, this.clock());
      const scope = `${id}:${request.nonce}`;
      if (this.nonces.has(scope)) return fail(409, 'E_REPLAY');
      if (this.state(row) !== 'pending') return fail(409, 'E_SIGNUP_FINAL');
      this.nonces.add(scope); row.state = 'cancelled'; row.decided = this.clock();
      this.calls.writes++;
      return ok({ state: 'cancelled' });
    } catch (cause) { return resultError(cause); }
  }

  async introPolicy(domain: string, bytes: string): Promise<FakeResult<{ allow_agent_intros: boolean; incarnation: string; checked_at_ms: number }>> {
    const unavailable = this.gate(false, true);
    if (unavailable) return unavailable;
    try {
      const body = parseIntroPolicy(bytes) as { domain: string; incarnation: string; audience: string; issued_at_ms: number };
      if (body.domain !== domain) return fail(400, 'E_POLICY_SHAPE');
      if (body.audience !== this.audience) return fail(401, 'E_SIGNUP_AUD');
      const current = this.agents.get(domain);
      if (!current) return fail(404, 'E_AGENT_NOT_FOUND');
      await verifyIntroPolicy(body, current.public_key, this.audience);
      assertSignupFresh(body.issued_at_ms, this.clock());
      if (current.incarnation !== body.incarnation || current.identity_status !== 'active') return fail(403, 'E_IDENTITY_INACTIVE');
      const owner = this.ownership.get(domain);
      return ok({ allow_agent_intros: owner === undefined || this.introAllowed.get(owner) !== false,
        incarnation: current.incarnation, checked_at_ms: this.clock() });
    } catch (cause) { return resultError(cause); }
  }

  /** Fetch-compatible adapter. The explicit owner is a fixture, never a trusted bearer.
   * The fake covers consumer states, not provider validation, counters, reserved-name
   * policy, public social display or D1 concurrency/rollback guarantees.
   */
  transport(owner?: FakeOwner): (input: Request | string | URL, init?: RequestInit) => Promise<Response> {
    return async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      const path = url.pathname;
      let result: FakeResult<unknown>;
      const mutation = (path === '/v1/signup/start' || path.endsWith('/cancel') || path.endsWith('/approve') || path.endsWith('/name'));
      const unavailable = this.gate(mutation);
      if (unavailable) return new Response(JSON.stringify(unavailable.body), { status: unavailable.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
      try {
        if (path === '/v1/signup/start' && request.method === 'POST') result = await this.start(await request.text());
        else if (/^\/v1\/signup\/[^/]+$/.test(path) && request.method === 'GET') result = await this.poll(decodeURIComponent(path.split('/')[3]));
        else if (/^\/v1\/signup\/[^/]+\/cancel$/.test(path) && request.method === 'POST') result = await this.cancel(decodeURIComponent(path.split('/')[3]), await request.text());
        else if (/^\/v1\/agent\/[^/]+\/intro-policy$/.test(path) && request.method === 'POST') result = await this.introPolicy(decodeURIComponent(path.split('/')[3]), await request.text());
        else if (path.startsWith('/v1/owner/signups/') && owner) {
          const [, , , , code, operation] = path.split('/');
          if (request.method === 'GET' && !operation) result = await this.ownerCard(code, owner);
          else if (request.method === 'POST' && operation === 'approve') result = await this.approve(code, owner, (await request.json() as { proposed_domain: string }).proposed_domain);
          else if (request.method === 'POST' && operation === 'reject') result = await this.reject(code, owner);
          else if (request.method === 'PUT' && operation === 'name') result = await this.rename(code, owner, await request.json() as { chosen: string } | { held: string });
          else result = fail(404, 'E_NOT_FOUND');
        } else result = fail(404, 'E_NOT_FOUND');
      } catch (cause) { result = resultError(cause); }
      return new Response(JSON.stringify(result.body), { status: result.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
    };
  }

  /** Current public lookup is separate from historical poll/approval. */
  lookup(domain: string): CurrentAgent | null { return structuredClone(this.agents.get(domain) ?? null); }
  setHeldNames(ownerSub: string, domains: string[]): void { this.held.set(ownerSub, [...domains]); }
  setIntroAllowed(ownerSub: string, allowed: boolean): void { this.introAllowed.set(ownerSub, allowed); }
  disown(domain: string): void { this.ownership.delete(domain); }
  deleteAgent(domain: string): void { this.agents.delete(domain); this.ownership.delete(domain); }
  seedCurrentAgent(agent: CurrentAgent, ownerSub?: string): void {
    this.agents.set(agent.domain, structuredClone(agent));
    if (ownerSub) this.ownership.set(agent.domain, ownerSub);
  }
  rotateKey(domain: string, public_key: string): void {
    const agent = this.agents.get(domain);
    if (!agent) throw new Error('No current agent');
    agent.public_key = public_key; agent.revision++;
  }
  suspend(domain: string): void {
    const agent = this.agents.get(domain);
    if (!agent) throw new Error('No current agent');
    agent.identity_status = 'suspended'; agent.revision++;
  }

  /** Read errors, malformed bodies and stale policy responses must deny intros. */
  static introAllowedByResponse(response: FakeResult<unknown>, now: number): boolean {
    if (typeof response.body !== 'object' || response.body === null || Array.isArray(response.body)) return false;
    const body = response.body as { allow_agent_intros?: unknown; checked_at_ms?: unknown; incarnation?: unknown };
    return response.status === 200 && body.allow_agent_intros === true
      && typeof body.checked_at_ms === 'number' && Number.isSafeInteger(body.checked_at_ms)
      && body.checked_at_ms <= now && now - body.checked_at_ms <= 300000
      && typeof body.incarnation === 'string' && /^[a-f0-9]{32}$/.test(body.incarnation);
  }
}

/** Canonical request helper for consumers; request bytes remain private test data. */
export const fakeCanonicalRequest = (body: unknown): string => canonicalizeJson(body);
