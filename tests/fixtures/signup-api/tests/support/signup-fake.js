/** Synthetic transport for consumer tests, never a database/authentication substitute.
 * Owners are supplied as explicit fixtures; no bearer, provider or network is trusted.
 * It deliberately separates historical approval receipts from current registry state.
 */
import { canonicalizeJson } from '../../src/jcs.js';
import { parseSignupStart, parseSignupCancel, parseIntroPolicy, parseIntroToken, verifyIntroToken, verifySignupStart, verifySignupCancel, verifyIntroPolicy, signupRequestDigest, signupKeyId, signupSubjectId, assertSignupFresh, } from '../../src/signup-codec.js';
const email = (value) => value.trim().toLowerCase();
const codeKey = (value) => value.toUpperCase().replace('-', '');
const fail = (status, code) => ({ status, body: { error: code, code } });
const ok = (body, status = 200) => ({ status, body: structuredClone(body) });
const resultError = (cause) => {
    const error = cause;
    return fail(typeof error.status === 'number' ? error.status : 503, typeof error.code === 'string' ? error.code : 'E_SIGNUP_UNAVAILABLE');
};
export class SignupFake {
    flag;
    schemaAvailable = true;
    limiter = 'allow';
    audience;
    ownerClientId;
    calls = { reads: 0, writes: 0, limiter: 0 };
    clock;
    origin;
    subject;
    rows = new Map();
    agents = new Map();
    ownership = new Map();
    held = new Map();
    introAllowed = new Map();
    nonces = new Set();
    nextNumber = 0;
    nextIncarnation = 0;
    barrier = null;
    constructor(options = {}) {
        this.flag = options.flag ?? 'false';
        this.clock = options.now ?? (() => 1793000000000);
        this.audience = options.audience ?? 'api.signup.test';
        this.origin = options.approvalOrigin ?? 'https://signup.test';
        this.ownerClientId = options.ownerClientId ?? 'test-owner-app';
        this.subject = options.subjectAgentId ?? signupSubjectId;
    }
    holdNextStart() {
        if (this.barrier)
            throw new Error('A start barrier already exists');
        let entered;
        let release;
        const entry = new Promise(resolve => { entered = resolve; });
        const wait = new Promise(resolve => { release = resolve; });
        this.barrier = { entered, wait };
        return { entered: entry, release };
    }
    gate(writes = false, limited = false) {
        if (this.flag !== 'true' && this.flag !== 'paused')
            return fail(404, 'E_NOT_FOUND');
        if (writes && this.flag === 'paused')
            return fail(503, 'E_SIGNUP_PAUSED');
        if (limited) {
            this.calls.limiter++;
            if (this.limiter === 'unavailable')
                return fail(503, 'E_RATE_LIMIT_UNAVAILABLE');
            if (this.limiter === 'deny')
                return fail(429, 'E_RATE_LIMITED');
        }
        if (!this.schemaAvailable)
            return fail(503, 'E_SIGNUP_UNAVAILABLE');
        return null;
    }
    ownerError(owner) {
        if (owner.azp !== this.ownerClientId || !/^(auth0|google-oauth2)\|/.test(owner.sub))
            return fail(403, 'E_OWNER_CONNECTION');
        if (owner.email_verified !== true)
            return fail(403, 'E_EMAIL_UNVERIFIED');
        return null;
    }
    async ownerRow(userCode, owner) {
        const auth = this.ownerError(owner);
        if (auth)
            return auth;
        this.calls.reads++;
        const row = [...this.rows.values()].find(value => codeKey(value.receipt.user_code) === codeKey(userCode));
        if (!row)
            return fail(404, 'E_SIGNUP_NOT_FOUND');
        if (row.email_hash !== await signupRequestDigest(email(owner.email)))
            return fail(403, 'E_SIGNUP_OWNER_MISMATCH');
        return row;
    }
    state(row) {
        return row.state === 'pending' && this.clock() >= row.receipt.expires_at_ms ? 'expired' : row.state;
    }
    async start(bytes) {
        const unavailable = this.gate(true, true);
        if (unavailable)
            return unavailable;
        try {
            const request = parseSignupStart(bytes);
            await verifySignupStart(request, this.audience);
            const digest = await signupRequestDigest(bytes);
            this.calls.reads++;
            const old = this.rows.get(request.proof.signup_id);
            if (old)
                return this.repeatStart(old, request.proof.public_key, digest);
            assertSignupFresh(request.proof.issued_at_ms, this.clock());
            let intro = null;
            let introAuthority = null;
            if (request.introduced_by !== null) {
                const parsed = parseIntroToken(request.introduced_by);
                introAuthority = this.lookup(parsed.introducer);
                if (!introAuthority)
                    return fail(422, 'E_INTRO_INVALID');
                await verifyIntroToken(parsed, introAuthority, this.clock(), this.audience);
                intro = parsed;
            }
            const barrier = this.barrier;
            this.barrier = null;
            if (barrier) {
                barrier.entered();
                await barrier.wait;
            }
            // The held call represents an already evaluated request whose write may land
            // after a later primary lookup found no row. A stale lookup is a snapshot.
            const emailHash = await signupRequestDigest(email(request.owner_email));
            const concurrent = this.rows.get(request.proof.signup_id);
            if (concurrent)
                return this.repeatStart(concurrent, request.proof.public_key, digest);
            if ([...this.agents.values()].some(agent => agent.public_key === request.proof.public_key))
                return fail(409, 'E_KEY_REGISTERED');
            const pending = [...this.rows.values()].filter(row => this.state(row) === 'pending');
            if (pending.some(row => row.key === request.proof.public_key))
                return fail(409, 'E_KEY_PENDING');
            if (pending.filter(row => row.email_hash === emailHash).length >= 2)
                return fail(429, 'E_RATE_LIMITED');
            if (intro && introAuthority) {
                if ([...this.rows.values()].some(row => row.intro_id === intro.id))
                    return fail(422, 'E_INTRO_USED');
                const current = this.agents.get(intro.introducer);
                if (!current || current.public_key !== introAuthority.public_key || current.incarnation !== introAuthority.incarnation || current.revision !== introAuthority.revision)
                    return fail(422, 'E_INTRO_INVALID');
                const owner = this.ownership.get(intro.introducer);
                if (current.identity_status !== 'active' || (owner !== undefined && this.introAllowed.get(owner) === false))
                    return fail(422, 'E_INTRO_UNAVAILABLE');
            }
            if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(request.name) || /-\d{4}$/.test(request.name))
                return fail(400, 'E_NAME_FORMAT');
            const number = (++this.nextNumber).toString().padStart(4, '0');
            const domain = `${request.name}-${number}.z.viz`;
            const alphabet = 'BCDFGHJKLMNPQRSTVWXZ';
            let codeNumber = this.nextNumber;
            let rawCode = '';
            for (let index = 0; index < 8; index++) {
                rawCode = alphabet[codeNumber % alphabet.length] + rawCode;
                codeNumber = Math.floor(codeNumber / alphabet.length);
            }
            const userCode = `${rawCode.slice(0, 4)}-${rawCode.slice(4)}`;
            const created = this.clock();
            const receipt = {
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
        }
        catch (cause) {
            return resultError(cause);
        }
    }
    repeatStart(row, key, digest) {
        return row.key === key && row.request_digest === digest
            ? ok(row.receipt) : fail(409, 'E_SIGNUP_ID_CONFLICT');
    }
    async poll(id) {
        const unavailable = this.gate(false, true);
        if (unavailable)
            return unavailable.status === 429 ? fail(429, 'E_SLOW_DOWN') : unavailable;
        this.calls.reads++;
        const row = this.rows.get(id);
        if (!row)
            return fail(404, 'E_SIGNUP_NOT_FOUND');
        const common = { schema_version: '1.0', signup_id: id };
        const state = this.state(row);
        if (state === 'live')
            return ok({ ...common, ...row.approval, public_key: row.key, live_at_ms: row.live_at });
        if (state === 'expired')
            return ok({ ...common, state, expires_at_ms: row.receipt.expires_at_ms });
        if (state === 'pending')
            return ok({ ...common, state, proposed_domain: row.proposed, expires_at_ms: row.receipt.expires_at_ms, poll_interval_ms: 5000 });
        return ok({ ...common, state, decided_at_ms: row.decided });
    }
    async ownerCard(code, owner) {
        const unavailable = this.gate();
        if (unavailable)
            return unavailable;
        const row = await this.ownerRow(code, owner);
        if ('status' in row)
            return row;
        const fingerprint = (await signupKeyId(row.key)).slice(7, 23);
        return ok({ schema_version: '1.0', user_code: row.receipt.user_code, state: this.state(row),
            chosen: row.chosen, proposed_domain: row.proposed, key_fingerprint: fingerprint,
            runtime: row.runtime, created_at_ms: row.created, expires_at_ms: row.receipt.expires_at_ms,
            renames_left: 10 - row.renames, held_names: this.held.get(owner.sub) ?? [],
            introducer: row.introducer ? { domain: row.introducer, owner: null } : null, final_domain: row.approval?.domain ?? null });
    }
    async rename(code, owner, choice) {
        const unavailable = this.gate(true);
        if (unavailable)
            return unavailable;
        const row = await this.ownerRow(code, owner);
        if ('status' in row)
            return row;
        if (row.state !== 'pending')
            return fail(409, 'E_SIGNUP_FINAL');
        if (this.state(row) === 'expired')
            return fail(410, 'E_SIGNUP_EXPIRED');
        if (row.renames >= 10)
            return fail(429, 'E_RENAME_LIMIT');
        let domain;
        let chosen;
        if ('held' in choice) {
            if (!this.held.get(owner.sub)?.includes(choice.held))
                return fail(409, 'E_NAME_TAKEN');
            domain = choice.held;
            chosen = domain.slice(0, -6);
        }
        else {
            chosen = choice.chosen;
            if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(chosen) || /-\d{4}$/.test(chosen))
                return fail(400, 'E_NAME_FORMAT');
            domain = `${chosen}-${(++this.nextNumber).toString().padStart(4, '0')}.z.viz`;
        }
        if (this.agents.has(domain) || [...this.rows.values()].some(value => value !== row && this.state(value) === 'pending' && value.proposed === domain))
            return fail(409, 'E_NAME_TAKEN');
        row.chosen = chosen;
        row.proposed = domain;
        row.renames++;
        this.calls.writes++;
        return ok({ proposed_domain: domain, renames_left: 10 - row.renames });
    }
    async approve(code, owner, proposed_domain) {
        const unavailable = this.gate(true);
        if (unavailable)
            return unavailable;
        const row = await this.ownerRow(code, owner);
        if ('status' in row)
            return row;
        if (row.state === 'live')
            return row.owner_sub === owner.sub && row.approval.domain === proposed_domain
                ? ok(row.approval) : fail(409, 'E_SIGNUP_FINAL');
        if (row.state !== 'pending')
            return fail(409, 'E_SIGNUP_FINAL');
        if (this.state(row) === 'expired')
            return fail(410, 'E_SIGNUP_EXPIRED');
        if (row.proposed !== proposed_domain)
            return fail(409, 'E_SIGNUP_STALE_VIEW');
        if ([...this.agents.values()].some(agent => agent.public_key === row.key))
            return fail(409, 'E_KEY_REGISTERED');
        if (this.agents.has(proposed_domain))
            return fail(409, 'E_NAME_TAKEN');
        if ([...this.ownership.values()].filter(sub => sub === owner.sub).length >= 25)
            return fail(429, 'E_OWNER_LIMIT');
        const incarnation = (++this.nextIncarnation).toString(16).padStart(32, '0');
        const subject_agent_id = await this.subject(proposed_domain, incarnation);
        // No await occurs after evaluating the current constraints and before commit.
        if (row.state !== 'pending')
            return fail(409, 'E_SIGNUP_FINAL');
        if (this.state(row) === 'expired')
            return fail(410, 'E_SIGNUP_EXPIRED');
        if (this.agents.has(proposed_domain))
            return fail(409, 'E_NAME_TAKEN');
        if ([...this.agents.values()].some(agent => agent.public_key === row.key))
            return fail(409, 'E_KEY_REGISTERED');
        if ([...this.ownership.values()].filter(sub => sub === owner.sub).length >= 25)
            return fail(429, 'E_OWNER_LIMIT');
        const approval = { state: 'live', domain: proposed_domain, incarnation, subject_agent_id };
        row.approval = approval;
        row.state = 'live';
        row.owner_sub = owner.sub;
        row.live_at = this.clock();
        row.decided = row.live_at;
        this.agents.set(proposed_domain, { domain: proposed_domain, public_key: row.key, incarnation,
            revision: 0, status: 'registered', identity_status: 'active' });
        this.ownership.set(proposed_domain, owner.sub);
        this.held.set(owner.sub, (this.held.get(owner.sub) ?? []).filter(value => value !== proposed_domain));
        this.calls.writes++;
        return ok(approval);
    }
    async reject(code, owner) {
        const unavailable = this.gate();
        if (unavailable)
            return unavailable;
        const row = await this.ownerRow(code, owner);
        if ('status' in row)
            return row;
        if (row.state !== 'pending')
            return fail(409, 'E_SIGNUP_FINAL');
        if (this.state(row) === 'expired')
            return fail(410, 'E_SIGNUP_EXPIRED');
        row.state = 'rejected';
        row.owner_sub = owner.sub;
        row.decided = this.clock();
        this.calls.writes++;
        return ok({ state: 'rejected' });
    }
    async cancel(id, bytes) {
        const unavailable = this.gate(true, true);
        if (unavailable)
            return unavailable;
        try {
            const request = parseSignupCancel(bytes);
            if (request.signup_id !== id)
                return fail(400, 'E_SIGNUP_SHAPE');
            if (request.audience !== this.audience)
                return fail(401, 'E_SIGNUP_AUD');
            const row = this.rows.get(id);
            if (!row)
                return fail(404, 'E_SIGNUP_NOT_FOUND');
            await verifySignupCancel(request, row.key, this.audience);
            assertSignupFresh(request.issued_at_ms, this.clock());
            const scope = `${id}:${request.nonce}`;
            if (this.nonces.has(scope))
                return fail(409, 'E_REPLAY');
            if (this.state(row) !== 'pending')
                return fail(409, 'E_SIGNUP_FINAL');
            this.nonces.add(scope);
            row.state = 'cancelled';
            row.decided = this.clock();
            this.calls.writes++;
            return ok({ state: 'cancelled' });
        }
        catch (cause) {
            return resultError(cause);
        }
    }
    async introPolicy(domain, bytes) {
        const unavailable = this.gate(false, true);
        if (unavailable)
            return unavailable;
        try {
            const body = parseIntroPolicy(bytes);
            if (body.domain !== domain)
                return fail(400, 'E_POLICY_SHAPE');
            if (body.audience !== this.audience)
                return fail(401, 'E_SIGNUP_AUD');
            const current = this.agents.get(domain);
            if (!current)
                return fail(404, 'E_AGENT_NOT_FOUND');
            await verifyIntroPolicy(body, current.public_key, this.audience);
            assertSignupFresh(body.issued_at_ms, this.clock());
            if (current.incarnation !== body.incarnation || current.identity_status !== 'active')
                return fail(403, 'E_IDENTITY_INACTIVE');
            const owner = this.ownership.get(domain);
            return ok({ allow_agent_intros: owner === undefined || this.introAllowed.get(owner) !== false,
                incarnation: current.incarnation, checked_at_ms: this.clock() });
        }
        catch (cause) {
            return resultError(cause);
        }
    }
    /** Fetch-compatible adapter. The explicit owner is a fixture, never a trusted bearer.
     * The fake covers consumer states, not provider validation, counters, reserved-name
     * policy, public social display or D1 concurrency/rollback guarantees.
     */
    transport(owner) {
        return async (input, init) => {
            const request = input instanceof Request ? input : new Request(input, init);
            const url = new URL(request.url);
            const path = url.pathname;
            let result;
            const mutation = (path === '/v1/signup/start' || path.endsWith('/cancel') || path.endsWith('/approve') || path.endsWith('/name'));
            const unavailable = this.gate(mutation);
            if (unavailable)
                return new Response(JSON.stringify(unavailable.body), { status: unavailable.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
            try {
                if (path === '/v1/signup/start' && request.method === 'POST')
                    result = await this.start(await request.text());
                else if (/^\/v1\/signup\/[^/]+$/.test(path) && request.method === 'GET')
                    result = await this.poll(decodeURIComponent(path.split('/')[3]));
                else if (/^\/v1\/signup\/[^/]+\/cancel$/.test(path) && request.method === 'POST')
                    result = await this.cancel(decodeURIComponent(path.split('/')[3]), await request.text());
                else if (/^\/v1\/agent\/[^/]+\/intro-policy$/.test(path) && request.method === 'POST')
                    result = await this.introPolicy(decodeURIComponent(path.split('/')[3]), await request.text());
                else if (path.startsWith('/v1/owner/signups/') && owner) {
                    const [, , , , code, operation] = path.split('/');
                    if (request.method === 'GET' && !operation)
                        result = await this.ownerCard(code, owner);
                    else if (request.method === 'POST' && operation === 'approve')
                        result = await this.approve(code, owner, (await request.json()).proposed_domain);
                    else if (request.method === 'POST' && operation === 'reject')
                        result = await this.reject(code, owner);
                    else if (request.method === 'PUT' && operation === 'name')
                        result = await this.rename(code, owner, await request.json());
                    else
                        result = fail(404, 'E_NOT_FOUND');
                }
                else
                    result = fail(404, 'E_NOT_FOUND');
            }
            catch (cause) {
                result = resultError(cause);
            }
            return new Response(JSON.stringify(result.body), { status: result.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
        };
    }
    /** Current public lookup is separate from historical poll/approval. */
    lookup(domain) { return structuredClone(this.agents.get(domain) ?? null); }
    setHeldNames(ownerSub, domains) { this.held.set(ownerSub, [...domains]); }
    setIntroAllowed(ownerSub, allowed) { this.introAllowed.set(ownerSub, allowed); }
    disown(domain) { this.ownership.delete(domain); }
    deleteAgent(domain) { this.agents.delete(domain); this.ownership.delete(domain); }
    seedCurrentAgent(agent, ownerSub) {
        this.agents.set(agent.domain, structuredClone(agent));
        if (ownerSub)
            this.ownership.set(agent.domain, ownerSub);
    }
    rotateKey(domain, public_key) {
        const agent = this.agents.get(domain);
        if (!agent)
            throw new Error('No current agent');
        agent.public_key = public_key;
        agent.revision++;
    }
    suspend(domain) {
        const agent = this.agents.get(domain);
        if (!agent)
            throw new Error('No current agent');
        agent.identity_status = 'suspended';
        agent.revision++;
    }
    /** Read errors, malformed bodies and stale policy responses must deny intros. */
    static introAllowedByResponse(response, now) {
        if (typeof response.body !== 'object' || response.body === null || Array.isArray(response.body))
            return false;
        const body = response.body;
        return response.status === 200 && body.allow_agent_intros === true
            && typeof body.checked_at_ms === 'number' && Number.isSafeInteger(body.checked_at_ms)
            && body.checked_at_ms <= now && now - body.checked_at_ms <= 300000
            && typeof body.incarnation === 'string' && /^[a-f0-9]{32}$/.test(body.incarnation);
    }
}
/** Canonical request helper for consumers; request bytes remain private test data. */
export const fakeCanonicalRequest = (body) => canonicalizeJson(body);
