import { createPrivateKey } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { run, type Deps } from "../src/main.js";
import { LocalKey } from "../src/keys.js";
import { buildStart, keyFingerprint, requestDigest } from "../src/join/codec.js";
import { PendingSignupStore, type PendingAttempt } from "../src/join/store.js";
import { SignupFake, type FakeOwner, type StartReceipt } from "./fixtures/signup-api/tests/support/signup-fake.js";

// Synthetic draft API fake420f0c2. These tests neither enroll a real identity nor
// substitute for final server/provider acceptance. Every local key is disposable.
const ID = "00000000-0000-4000-8000-000000000001";
const ORIGIN = "https://api.zipviz.ai";
const EMAIL = "fixture-owner@example.invalid";
const EPOCH = 1793000000000;
const OWNER: FakeOwner = { sub: "auth0|synthetic-owner", email: EMAIL, email_verified: true, azp: "test-owner-app" };
type Recorded = { url: string; method: string; body: string | null; at: number };
type Hook = (request: Recorded, fallback: () => Promise<Response>) => Promise<Response>;
const response = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const attempt = (bytes: string): PendingAttempt => ({ request_b64url: Buffer.from(bytes).toString("base64url"), request_digest: requestDigest(bytes), issued_at_ms: (JSON.parse(bytes) as { proof: { issued_at_ms: number } }).proof.issued_at_ms });

function fixture() {
  const home = mkdtempSync(path.join(tmpdir(), "zipviz-join-synthetic-"));
  const zipvizHome = path.join(home, ".zipviz");
  let clock = EPOCH;
  const fake = new SignupFake({ flag: "true", now: () => clock, audience: "api.zipviz.ai", approvalOrigin: "https://zipviz.ai" });
  const transport = fake.transport();
  const requests: Recorded[] = [];
  const waits: number[] = [];
  const stdout: string[] = [];
  const stderr: string[] = [];
  let hook: Hook | undefined;
  let onSleep: ((ms: number) => void | Promise<void>) | undefined;
  const store = new PendingSignupStore(zipvizHome);
  const deps: Deps = {
    zipvizHome, stdout: s => { stdout.push(s); }, stderr: s => { stderr.push(s); },
    now: () => clock,
    joinId: () => ID,
    sleep: async ms => { waits.push(ms); clock += ms; await onSleep?.(ms); },
    fetch: async (url, init) => {
      const request: Recorded = { url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : null, at: clock };
      requests.push(request);
      const fallback = async () => {
        const parsed = new URL(url);
        if (fake.flag === "true" && parsed.pathname === "/v1/signup/availability") {
          const name = parsed.searchParams.get("name");
          return response({ name, valid: true, code: null, example: `${name}-NNNN.z.viz` });
        }
        const current = parsed.pathname.match(/^\/v1\/agent\/([^/]+)$/);
        if (current && request.method === "GET") {
          const agent = fake.lookup(decodeURIComponent(current[1]!));
          return agent ? response(agent) : response({ code: "E_AGENT_NOT_FOUND", error: "Agent not found" }, 404);
        }
        return transport(url, init);
      };
      return hook ? hook(request, fallback) : fallback();
    },
  };
  const cli = async (...args: string[]) => {
    const start = stdout.length;
    const code = await run([...args, "--json"], deps);
    const text = stdout.slice(start).join("");
    return { code, body: JSON.parse(text) as Record<string, unknown>, text };
  };
  const start = () => cli("join", "--name", "fixture", "--owner-email", EMAIL, "--runtime", "other");
  const resume = () => cli("join", "start", "--resume", ID);
  const receipt = async () => (await store.read(ID)).receipt as unknown as StartReceipt;
  const approve = async () => {
    const r = await receipt();
    const result = await fake.approve(r.user_code, OWNER, r.proposed_domain);
    expect(result.status).toBe(200);
    return r.proposed_domain;
  };
  const seed = async () => {
    const key = await store.generate(ID);
    const bytes = buildStart(key, { signupId: ID, name: "fixture", ownerEmail: EMAIL, runtime: "other", introducedBy: null, audience: "api.zipviz.ai", issuedAtMs: clock });
    await store.create(ID, attempt(bytes), { registry_origin: ORIGIN, audience: "api.zipviz.ai" });
    return { key, bytes };
  };
  return { home, zipvizHome, store, fake, deps, requests, waits, stdout, stderr, cli, start, resume, receipt, approve, seed,
    setHook: (next: Hook | undefined) => { hook = next; }, setSleep: (next: typeof onSleep) => { onSleep = next; },
    advance: (ms: number) => { clock += ms; }, now: () => clock,
    cleanup: () => { rmSync(home, { recursive: true, force: true }); } };
}

const fixtures: ReturnType<typeof fixture>[] = [];
const setup = () => { const h = fixture(); fixtures.push(h); return h; };
afterEach(() => { for (const h of fixtures.splice(0)) h.cleanup(); });
const starts = (h: ReturnType<typeof fixture>) => h.requests.filter(r => new URL(r.url).pathname === "/v1/signup/start");

describe("join lifecycle against the pinned synthetic draft transport", () => {
  it("persists a private attempt before send, prints a fingerprint and keeps private material out of every request/log", async () => {
    const h = setup();
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === "/v1/signup/start") {
        const record = await h.store.read(ID);
        expect(record.attempts).toHaveLength(1);
        expect(Buffer.from(record.attempts[0]!.request_b64url, "base64url").toString()).toBe(r.body);
        expect(statSync(h.store.metadataPathFor(ID)).mode & 0o777).toBe(0o600);
        expect(statSync(h.store.keyPathFor(ID)).mode & 0o777).toBe(0o600);
      }
      return next();
    });
    const result = await h.start();
    expect(result.code).toBe(0);
    expect(result.body).toMatchObject({ state: "pending", signup_id: ID });
    const key = await h.store.loadKey(ID);
    expect(JSON.stringify(result.body)).toContain(keyFingerprint(key.publicKey));
    const pem = readFileSync(h.store.keyPathFor(ID), "utf8");
    for (const request of h.requests) expect(request.body ?? "").not.toContain(pem);
    const logs = h.stdout.join("") + h.stderr.join("");
    expect(logs).not.toContain(EMAIL);
    expect(logs).not.toContain(starts(h)[0]!.body!);
    expect(logs).not.toContain("PRIVATE KEY");
    expect(h.requests.every(r => new URL(r.url).origin === ORIGIN)).toBe(true);
  });

  it("recovers a lost201 with exactly the same canonical attempt and then takes current state only from poll", async () => {
    const h = setup();
    let first = true;
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === "/v1/signup/start" && first) { first = false; await next(); throw new Error("synthetic lost response"); }
      return next();
    });
    expect((await h.start()).code).toBe(0);
    expect(starts(h)).toHaveLength(2);
    expect(starts(h)[1]!.body).toBe(starts(h)[0]!.body);
    expect((await h.store.read(ID)).attempts).toHaveLength(1);
    const domain = await h.approve();
    const status = await h.cli("join", "status", ID);
    expect(status.body).toMatchObject({ state: "live", domain });
    expect(existsSync(h.store.keyPathFor(ID))).toBe(true);
    expect(existsSync(path.join(h.zipvizHome, "keys", `${domain}.key`))).toBe(false);
  });

  it("prints the safe human handoff before --wait starts polling while preserving one final JSON result", async () => {
    const h = setup();
    let handedOff = false;
    h.setSleep(async ms => {
      expect(ms).toBe(5000);
      expect(h.requests.filter(r => new URL(r.url).pathname === `/v1/signup/${ID}`)).toHaveLength(0);
      expect(h.stdout).toHaveLength(0);
      const receipt = await h.receipt();
      const key = await h.store.loadKey(ID);
      const handoff = h.stderr.join("");
      expect(handoff).toContain(receipt.approval_url);
      expect(handoff).toContain(receipt.user_code);
      expect(handoff).toContain(keyFingerprint(key.publicKey));
      expect(handoff).not.toContain(EMAIL);
      expect(handoff).not.toContain(starts(h)[0]!.body!);
      expect(handoff).not.toContain("PRIVATE KEY");
      handedOff = true;
      await h.approve();
    });
    const result = await h.cli("join", "--name", "fixture", "--owner-email", EMAIL, "--runtime", "other", "--wait");
    expect(handedOff).toBe(true);
    expect(result.code).toBe(0);
    expect(result.body).toMatchObject({ ok: true, state: "live", signup_id: ID });
    expect(h.stdout).toHaveLength(1);
    expect(JSON.parse(h.stdout[0]!)).toEqual(result.body);
    expect(existsSync(h.store.keyPathFor(ID))).toBe(true);
  });

  it("retries the identical attempt when the response body stream fails after successful headers", async () => {
    const h = setup();
    let first = true;
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === "/v1/signup/start" && first) {
        first = false;
        const committed = await next();
        expect(committed.status).toBe(201);
        const stream = new ReadableStream<Uint8Array>({
          start(controller) { controller.error(new Error(`${EMAIL}: synthetic response-stream failure`)); },
        });
        return new Response(stream, { status: 201, headers: { "content-type": "application/json" } });
      }
      return next();
    });
    const result = await h.start();
    expect(result.code).toBe(0);
    expect(result.body).toMatchObject({ state: "pending" });
    expect(starts(h)).toHaveLength(2);
    expect(starts(h)[1]!.body).toBe(starts(h)[0]!.body);
    expect(h.waits).toEqual([1000]);
    expect((await h.store.read(ID)).attempts).toHaveLength(1);
    expect(h.stdout.join("") + h.stderr.join("")).not.toContain(EMAIL);
    expect(h.fake.calls.writes).toBe(1);
  });

  it.each(["network", "unavailable"])("bounds uncertain %s retries while preserving exact bytes for the next restart", async kind => {
    const h = setup();
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname !== "/v1/signup/start") return next();
      if (kind === "network") throw new Error(`${EMAIL}: synthetic private transport diagnostic`);
      return response({ code: "E_SIGNUP_UNAVAILABLE", error: `${EMAIL}: synthetic private server diagnostic` }, 503);
    });
    const result = await h.start();
    expect(result.body).toMatchObject({ ok: false, error: { code: kind === "network" ? "E_NETWORK" : "E_SIGNUP_UNAVAILABLE" } });
    expect(h.waits).toEqual([1000, 2000]);
    expect(starts(h)).toHaveLength(3);
    expect(new Set(starts(h).map(r => r.body)).size).toBe(1);
    expect((await h.store.read(ID)).attempts).toHaveLength(1);
    expect(h.stdout.join("") + h.stderr.join("")).not.toContain(EMAIL);
    const original = starts(h)[0]!.body;
    h.setHook(undefined);
    expect((await h.resume()).code).toBe(0);
    expect(starts(h)[3]!.body).toBe(original);
    expect((await h.store.read(ID)).attempts).toHaveLength(1);
  });

  it.each([
    ["--introduced-by", "synthetic-invalid-token"],
    ["--aud", "https://wrong-audience.example.invalid"],
  ])("rejects invalid %s before creating a local key", async (flag, value) => {
    const h = setup();
    const result = await h.cli("join", "--name", "fixture", "--owner-email", EMAIL, "--runtime", "other", flag!, value!);
    expect(result.code).not.toBe(0);
    expect(h.requests).toHaveLength(0);
    expect(existsSync(h.zipvizHome)).toBe(false);
  });

  it("refuses a restart against another registry before sending or changing retained files", async () => {
    const h = setup();
    await h.seed();
    const key = readFileSync(h.store.keyPathFor(ID));
    const metadata = readFileSync(h.store.metadataPathFor(ID));
    const result = await h.cli("--api", "https://other-registry.example.invalid", "join", "start", "--resume", ID);
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_JOIN_REGISTRY" } });
    expect(h.requests).toHaveLength(0);
    expect(readFileSync(h.store.metadataPathFor(ID))).toEqual(metadata);
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(key);
  });

  it("retains A1 byte-for-byte and sweeps it after a late original commit makes A2 conflict", async () => {
    const h = setup();
    const barrier = h.fake.holdNextStart();
    let original: ReturnType<SignupFake["start"]> | undefined;
    let firstBytes = "";
    let sent = 0;
    h.setSleep(() => { h.advance(301000); });
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname !== "/v1/signup/start") return next();
      sent++;
      if (sent === 1) {
        firstBytes = r.body!; original = h.fake.start(firstBytes); await barrier.entered;
        throw new Error("synthetic timeout while preverified A1 is held");
      }
      if (sent === 3) {
        const record = await h.store.read(ID);
        expect(record.attempts).toHaveLength(2);
        expect(Buffer.from(record.attempts[0]!.request_b64url, "base64url").toString()).toBe(firstBytes);
        barrier.release(); expect((await original!).status).toBe(201);
      }
      return next();
    });
    expect((await h.start()).body).toMatchObject({ state: "pending" });
    const sentBytes = starts(h).map(r => r.body);
    expect(sentBytes).toHaveLength(4);
    expect(sentBytes[1]).toBe(firstBytes);
    expect(sentBytes[2]).not.toBe(firstBytes);
    expect(sentBytes[3]).toBe(firstBytes);
    const record = await h.store.read(ID);
    expect(record.attempts).toHaveLength(2);
    expect(record.attempts[0]!.request_digest).toBe(requestDigest(firstBytes));
    expect(record.receipt).toBeDefined();
    expect(h.fake.calls.writes).toBe(1);
  });

  it("keeps A2's receipt when A2 commits before the released A1", async () => {
    const h = setup();
    const barrier = h.fake.holdNextStart();
    let original: ReturnType<SignupFake["start"]> | undefined;
    let sent = 0;
    h.setSleep(() => { h.advance(301000); });
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname !== "/v1/signup/start") return next();
      sent++;
      if (sent === 1) { original = h.fake.start(r.body!); await barrier.entered; throw new Error("synthetic timeout"); }
      const result = await next();
      if (sent === 3) { expect(result.status).toBe(201); barrier.release(); expect((await original!).status).toBe(409); }
      return result;
    });
    expect((await h.start()).code).toBe(0);
    expect(starts(h)).toHaveLength(3);
    const record = await h.store.read(ID);
    expect(record.attempts).toHaveLength(2);
    expect(record.receipt).toBeDefined();
    expect((await h.fake.start(starts(h)[2]!.body!)).status).toBe(200);
    expect(h.fake.calls.writes).toBe(1);
  });

  it("restarts from the newest durable attempt after a crash between append and send", async () => {
    const h = setup();
    const { key, bytes } = await h.seed();
    const barrier = h.fake.holdNextStart();
    const original = h.fake.start(bytes);
    await barrier.entered;
    h.advance(301000);
    const newer = buildStart(key, { signupId: ID, name: "fixture", ownerEmail: EMAIL, runtime: "other", introducedBy: null, audience: "api.zipviz.ai", issuedAtMs: h.now() });
    await h.store.appendAttempt(ID, attempt(newer));
    // No send of A2 occurred before this simulated process restart.
    barrier.release(); expect((await original).status).toBe(201);
    expect((await h.resume()).code).toBe(0);
    expect(starts(h).map(r => r.body)).toEqual([newer, bytes]);
    expect((await h.store.read(ID)).attempts.map(a => a.request_digest)).toEqual([requestDigest(bytes), requestDigest(newer)]);
  });

  it("refreshes retained attempts after a concurrent append commits before an older in-memory attempt conflicts", async () => {
    const h = setup();
    const { key, bytes } = await h.seed();
    let newer = "";
    let raced = false;
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === "/v1/signup/start" && !raced) {
        raced = true;
        expect(r.body).toBe(bytes);
        h.advance(301000);
        newer = buildStart(key, { signupId: ID, name: "fixture", ownerEmail: EMAIL, runtime: "other", introducedBy: null, audience: "api.zipviz.ai", issuedAtMs: h.now() });
        await h.store.appendAttempt(ID, attempt(newer));
        expect((await h.fake.start(newer)).status).toBe(201);
        const response = await next();
        expect(response.status).toBe(409);
        return response;
      }
      return next();
    });
    expect((await h.resume()).body).toMatchObject({ ok: true, state: "pending" });
    expect(starts(h).map(r => r.body)).toEqual([bytes, newer]);
    const record = await h.store.read(ID);
    expect(record.attempts.map(a => a.request_digest)).toEqual([requestDigest(bytes), requestDigest(newer)]);
    expect(record.receipt).toBeDefined();
    expect(h.fake.calls.writes).toBe(1);
  });

  it("recognizes the default service document when signup is disabled and creates no local key", async () => {
    const h = setup();
    h.setHook(async r => {
      expect(new URL(r.url).pathname).toBe("/v1/signup/availability");
      expect(r.method).toBe("GET");
      return response({ service: "ZipViz Agent Registry", version: "synthetic", endpoints: ["/v1/agent/:domain"] });
    });
    const result = await h.start();
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_SIGNUP_DISABLED" } });
    expect(h.requests).toHaveLength(1);
    expect(h.requests.every(r => r.method === "GET")).toBe(true);
    expect(existsSync(h.zipvizHome)).toBe(false);
  });

  it("refuses a foreign signup row after every retained attempt conflicts and preserves the pending key", async () => {
    const h = setup();
    const { key } = await h.seed();
    h.advance(301000);
    const newer = buildStart(key, { signupId: ID, name: "fixture", ownerEmail: EMAIL, runtime: "other", introducedBy: null, audience: "api.zipviz.ai", issuedAtMs: h.now() });
    await h.store.appendAttempt(ID, attempt(newer));
    // Public deterministic TEST-ONLY seed; no enrolled identity.
    const foreign = new LocalKey("test-only", "unused", createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x22)]), format: "der", type: "pkcs8" }));
    const foreignBytes = buildStart(foreign, { signupId: ID, name: "fixture", ownerEmail: EMAIL, runtime: "other", introducedBy: null, audience: "api.zipviz.ai", issuedAtMs: h.now() });
    expect((await h.fake.start(foreignBytes)).status).toBe(201);
    const before = readFileSync(h.store.keyPathFor(ID));
    const result = await h.resume();
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_UNEXPECTED_RESPONSE" } });
    expect(starts(h)).toHaveLength(2);
    expect((await h.store.read(ID)).receipt).toBeUndefined();
    expect((await h.cli("join", "adopt", ID)).code).not.toBe(0);
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(before);
  });

  it("stops at eight stale attempts without overwriting or dropping any attempt", async () => {
    const h = setup();
    h.setHook(async (r, next) => { if (new URL(r.url).pathname === "/v1/signup/start") h.advance(301000); return next(); });
    const result = await h.start();
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_JOIN_RETRY_LIMIT" } });
    expect(starts(h)).toHaveLength(8);
    const record = await h.store.read(ID);
    expect(record.attempts).toHaveLength(8);
    expect(record.attempts.map(a => Buffer.from(a.request_b64url, "base64url").toString())).toEqual(starts(h).map(r => r.body));
    expect(new Set(record.attempts.map(a => a.request_digest)).size).toBe(8);
    expect(existsSync(h.store.keyPathFor(ID))).toBe(true);
  });

  it("status ignores an unsafe pending store and never creates or mutates local keys", async () => {
    const h = setup();
    expect((await h.start()).code).toBe(0);
    const key = readFileSync(h.store.keyPathFor(ID));
    const metadata = readFileSync(h.store.metadataPathFor(ID));
    chmodSync(path.join(h.zipvizHome, "keys", "pending"), 0o755);
    const before = readdirSync(path.join(h.zipvizHome, "keys"));
    const mark = h.requests.length;
    expect((await h.cli("join", "status", ID)).body).toMatchObject({ state: "pending" });
    expect(h.requests.slice(mark).map(r => r.method)).toEqual(["GET"]);
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(key);
    expect(readFileSync(h.store.metadataPathFor(ID))).toEqual(metadata);
    expect(readdirSync(path.join(h.zipvizHome, "keys"))).toEqual(before);
  });

  it("poll404 leaves all attempts intact and never starts a replacement signup", async () => {
    const h = setup();
    await h.seed();
    const key = readFileSync(h.store.keyPathFor(ID));
    const metadata = readFileSync(h.store.metadataPathFor(ID));
    const result = await h.cli("join", "status", ID);
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_SIGNUP_NOT_FOUND" } });
    expect(starts(h)).toHaveLength(0);
    expect(readFileSync(h.store.metadataPathFor(ID))).toEqual(metadata);
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(key);
  });

  it("wait honors Retry-After on E_SLOW_DOWN and the pending poll interval without real timers", async () => {
    const h = setup();
    expect((await h.start()).code).toBe(0);
    let polls = 0;
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === `/v1/signup/${ID}`) {
        polls++;
        if (polls === 1) return response({ code: "E_SLOW_DOWN", error: "synthetic rate limit" }, 429, { "retry-after": "12" });
      }
      return next();
    });
    h.setSleep(async () => { if (polls === 2) await h.approve(); });
    expect((await h.cli("join", "status", ID, "--wait")).body).toMatchObject({ state: "live" });
    expect(h.waits).toEqual([12000, 5000]);
  });

  it("cancel signs with the pending key and reaches terminal state while retaining local recovery data", async () => {
    const h = setup();
    expect((await h.start()).code).toBe(0);
    const before = readFileSync(h.store.keyPathFor(ID));
    expect((await h.cli("join", "cancel", ID)).body).toMatchObject({ state: "cancelled" });
    const sent = h.requests.find(r => new URL(r.url).pathname.endsWith("/cancel"))!;
    expect(sent.body).toContain("zipviz.signup.cancel");
    expect((await h.fake.cancel(ID, sent.body!)).body).toMatchObject({ code: "E_REPLAY" });
    expect((await h.cli("join", "status", ID)).body).toMatchObject({ state: "cancelled" });
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(before);
    expect((await h.store.read(ID)).attempts).toHaveLength(1);
  });

  it("adopts only explicitly after historical approval and the current full lookup agree", async () => {
    const h = setup();
    expect((await h.start()).code).toBe(0);
    const before = readFileSync(h.store.keyPathFor(ID));
    const domain = await h.approve();
    const mark = h.requests.length;
    expect((await h.cli("join", "adopt", ID)).body).toMatchObject({ ok: true, domain });
    expect(h.requests.slice(mark).map(r => new URL(r.url).pathname)).toEqual([`/v1/signup/${ID}`, `/v1/agent/${domain}`]);
    expect(readFileSync(path.join(h.zipvizHome, "keys", `${domain}.key`))).toEqual(before);
    expect(existsSync(h.store.keyPathFor(ID))).toBe(false);
    expect(existsSync(h.store.metadataPathFor(ID))).toBe(false);
    expect(existsSync(path.join(h.zipvizHome, "bots.json"))).toBe(false);
    expect(h.requests.slice(mark).every(r => r.method === "GET")).toBe(true);
  });

  it.each(["rotated", "suspended", "deleted", "reregistered", "wrong-domain", "unregistered", "missing-incarnation"])("refuses adoption when current identity is %s", async kind => {
    const h = setup();
    expect((await h.start()).code).toBe(0);
    const domain = await h.approve();
    const original = h.fake.lookup(domain)!;
    const before = readFileSync(h.store.keyPathFor(ID));
    if (kind === "rotated") h.fake.rotateKey(domain, "ab".repeat(32));
    if (kind === "suspended") h.fake.suspend(domain);
    if (kind === "deleted") h.fake.deleteAgent(domain);
    if (kind === "reregistered") h.fake.seedCurrentAgent({ ...original, incarnation: "ef".repeat(16) });
    h.setHook(async (r, next) => {
      if (new URL(r.url).pathname === `/v1/agent/${domain}`) {
        if (kind === "wrong-domain") return response({ ...original, domain: "elsewhere.z.viz" });
        if (kind === "unregistered") return response({ ...original, status: "unregistered" });
        if (kind === "missing-incarnation") { const rest: Record<string, unknown> = { ...original }; delete rest.incarnation; return response(rest); }
      }
      return next();
    });
    expect((await h.cli("join", "adopt", ID)).body).toMatchObject({ ok: false, error: { code: "E_UNEXPECTED_RESPONSE" } });
    expect(readFileSync(h.store.keyPathFor(ID))).toEqual(before);
    expect(existsSync(h.store.metadataPathFor(ID))).toBe(true);
    expect(existsSync(path.join(h.zipvizHome, "keys", `${domain}.key`))).toBe(false);
  });

  it("never clobbers an existing domain key or symlink during explicit adoption", async () => {
    for (const symlink of [false, true]) {
      const h = setup();
      expect((await h.start()).code).toBe(0);
      const domain = await h.approve();
      const destination = path.join(h.zipvizHome, "keys", `${domain}.key`);
      const marker = path.join(h.home, "synthetic-existing-key");
      writeFileSync(marker, "synthetic marker", { mode: 0o600 });
      if (symlink) symlinkSync(marker, destination);
      else writeFileSync(destination, "synthetic existing key", { mode: 0o600 });
      const result = await h.cli("join", "adopt", ID);
      expect(result.body).toMatchObject({ ok: false, error: { code: "E_KEY_EXISTS" } });
      expect(existsSync(h.store.keyPathFor(ID))).toBe(true);
      expect(readFileSync(marker, "utf8")).toBe("synthetic marker");
      expect(readFileSync(destination, "utf8")).toBe(symlink ? "synthetic marker" : "synthetic existing key");
    }
  });
});
