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
    schema_version: '1.0';
    signup_id: string;
    state: 'pending';
    proposed_domain: string;
    user_code: string;
    approval_url: string;
    expires_at_ms: number;
    poll_interval_ms: 5000;
}
export interface ApprovalReceipt {
    state: 'live';
    domain: string;
    incarnation: string;
    subject_agent_id: string;
}
export interface LivePoll extends ApprovalReceipt {
    schema_version: '1.0';
    signup_id: string;
    public_key: string;
    live_at_ms: number;
}
export type SignupPoll = LivePoll | {
    schema_version: '1.0';
    signup_id: string;
    state: 'pending';
    proposed_domain: string;
    expires_at_ms: number;
    poll_interval_ms: 5000;
} | {
    schema_version: '1.0';
    signup_id: string;
    state: 'expired';
    expires_at_ms: number;
} | {
    schema_version: '1.0';
    signup_id: string;
    state: 'cancelled' | 'rejected';
    decided_at_ms: number;
};
export interface CurrentAgent {
    domain: string;
    public_key: string;
    incarnation: string;
    revision: number;
    status: 'registered';
    identity_status: 'active' | 'suspended';
}
export interface FakeCard {
    schema_version: '1.0';
    user_code: string;
    state: SignupState;
    chosen: string;
    proposed_domain: string;
    key_fingerprint: string;
    runtime: SignupRuntime;
    created_at_ms: number;
    expires_at_ms: number;
    renames_left: number;
    held_names: string[];
    introducer: {
        domain: string;
        owner: null;
    } | null;
    final_domain: string | null;
}
export interface SignupErrorBody {
    error: string;
    code: string;
}
export interface FakeResult<T> {
    status: number;
    body: T | SignupErrorBody;
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
export declare class SignupFake {
    flag: SignupFlag;
    schemaAvailable: boolean;
    limiter: 'allow' | 'deny' | 'unavailable';
    readonly audience: string;
    readonly ownerClientId: string;
    readonly calls: {
        reads: number;
        writes: number;
        limiter: number;
    };
    private readonly clock;
    private readonly origin;
    private readonly subject;
    private readonly rows;
    private readonly agents;
    private readonly ownership;
    private readonly held;
    private readonly introAllowed;
    private readonly nonces;
    private nextNumber;
    private nextIncarnation;
    private barrier;
    constructor(options?: SignupFakeOptions);
    holdNextStart(): StartBarrier;
    private gate;
    private ownerError;
    private ownerRow;
    private state;
    start(bytes: string): Promise<FakeResult<StartReceipt>>;
    private repeatStart;
    poll(id: string): Promise<FakeResult<SignupPoll>>;
    ownerCard(code: string, owner: FakeOwner): Promise<FakeResult<FakeCard>>;
    rename(code: string, owner: FakeOwner, choice: {
        chosen: string;
    } | {
        held: string;
    }): Promise<FakeResult<{
        proposed_domain: string;
        renames_left: number;
    }>>;
    approve(code: string, owner: FakeOwner, proposed_domain: string): Promise<FakeResult<ApprovalReceipt>>;
    reject(code: string, owner: FakeOwner): Promise<FakeResult<{
        state: 'rejected';
    }>>;
    cancel(id: string, bytes: string): Promise<FakeResult<{
        state: 'cancelled';
    }>>;
    introPolicy(domain: string, bytes: string): Promise<FakeResult<{
        allow_agent_intros: boolean;
        incarnation: string;
        checked_at_ms: number;
    }>>;
    /** Fetch-compatible adapter. The explicit owner is a fixture, never a trusted bearer.
     * The fake covers consumer states, not provider validation, counters, reserved-name
     * policy, public social display or D1 concurrency/rollback guarantees.
     */
    transport(owner?: FakeOwner): (input: Request | string | URL, init?: RequestInit) => Promise<Response>;
    /** Current public lookup is separate from historical poll/approval. */
    lookup(domain: string): CurrentAgent | null;
    setHeldNames(ownerSub: string, domains: string[]): void;
    setIntroAllowed(ownerSub: string, allowed: boolean): void;
    disown(domain: string): void;
    deleteAgent(domain: string): void;
    seedCurrentAgent(agent: CurrentAgent, ownerSub?: string): void;
    rotateKey(domain: string, public_key: string): void;
    suspend(domain: string): void;
    /** Read errors, malformed bodies and stale policy responses must deny intros. */
    static introAllowedByResponse(response: FakeResult<unknown>, now: number): boolean;
}
/** Canonical request helper for consumers; request bytes remain private test data. */
export declare const fakeCanonicalRequest: (body: unknown) => string;
