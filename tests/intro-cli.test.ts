import { createPrivateKey } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { run, type Deps } from "../src/main.js";
import { LocalKey } from "../src/keys.js";
import { IntroStore } from "../src/intro/store.js";
import { SignupFake } from "./fixtures/signup-api/tests/support/signup-fake.js";
import { parseIntroToken, verifyIntroToken } from "./fixtures/signup-api/src/signup-codec.js";

// Public deterministic TEST-ONLY fixture seed, never an enrolled identity.
const DOMAIN = "fixture-1234.z.viz";
const PEER_DOMAIN = "peer-4321.z.viz";
const INCARNATION = "0123456789abcdef0123456789abcdef";
const DRAFT_ID = "00000000-0000-4000-8000-000000000002";
const EPOCH = 1793000000000;
const ORIGIN = "https://api.zipviz.ai";
const PEER = "synthetic-conversation:opaque-peer-fixture";
const DAY = 86_400_000;
const OWNER_SUB = "auth0|synthetic-owner";

type Recorded = { url: string; method: string; body: string | null; redirect: RequestRedirect | undefined };
type Hook = (request: Recorded, next: () => Promise<Response>) => Promise<Response>;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json", "cache-control": "no-store" },
});

function fixture() {
  const home = mkdtempSync(path.join(tmpdir(), "zipviz-intro-synthetic-"));
  const zipvizHome = path.join(home, ".zipviz");
  const keyDirectory = path.join(zipvizHome, "keys");
  mkdirSync(zipvizHome, { mode: 0o700 });
  mkdirSync(keyDirectory, { mode: 0o700 });
  const privateKey = createPrivateKey({ key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x22),
  ]), format: "der", type: "pkcs8" });
  const keyPath = path.join(keyDirectory, `${DOMAIN}.key`);
  writeFileSync(keyPath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const local = new LocalKey(DOMAIN, keyPath, privateKey);
  let now = EPOCH;
  let owner: unknown = undefined;
  let hook: Hook | undefined;
  let nextId = DRAFT_ID;
  const fake = new SignupFake({ flag: "true", now: () => now, audience: "api.zipviz.ai", approvalOrigin: "https://zipviz.ai" });
  fake.seedCurrentAgent({ domain: DOMAIN, public_key: local.publicKey, incarnation: INCARNATION,
    revision: 0, status: "registered", identity_status: "active" }, OWNER_SUB);
  const transport = fake.transport();
  const stdout: string[] = [];
  const stderr: string[] = [];
  const requests: Recorded[] = [];
  const deps: Deps = {
    zipvizHome, now: () => now, stdout: s => { stdout.push(s); }, stderr: s => { stderr.push(s); },
    introId: () => nextId,
    fetch: async (url, init) => {
      const request: Recorded = { url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : null, redirect: init?.redirect };
      requests.push(request);
      const next = async () => {
        const pathname = new URL(url).pathname;
        const current = pathname.match(/^\/v1\/agent\/([^/]+)$/);
        if (current && request.method === "GET") {
          const agent = fake.lookup(decodeURIComponent(current[1]!));
          return agent ? json({ ...agent, ...(owner === undefined ? {} : { owner }) })
            : json({ code: "E_AGENT_NOT_FOUND", error: "Agent not found" }, 404);
        }
        const card = pathname.match(/^\/v1\/agent\/([^/]+)\/card$/);
        if (card && request.method === "GET") {
          const domain = decodeURIComponent(card[1]!);
          const agent = fake.lookup(domain);
          return agent ? json({ name: domain, public_key: agent.public_key, ...(owner === undefined ? {} : { owner }) })
            : json({ code: "E_AGENT_NOT_FOUND", error: "Agent not found" }, 404);
        }
        if (pathname === `/v1/agent/${DOMAIN}/intro-policy` && request.method === "POST") return transport(url, init);
        throw new Error("unexpected synthetic transport operation");
      };
      return hook ? hook(request, next) : next();
    },
  };
  const cli = async (...argv: string[]) => {
    const start = stdout.length;
    const errorStart = stderr.length;
    const code = await run([...argv, "--json"], deps);
    const text = stdout.slice(start).join("");
    return { code, body: JSON.parse(text) as Record<string, unknown>, text, err: stderr.slice(errorStart).join("") };
  };
  const create = (...extra: string[]) => cli("intro", "create", DOMAIN, "--peer", PEER, "--existing-conversation", ...extra);
  const confirm = (confirmation: string, ...extra: string[]) => cli("intro", "confirm-sent", DOMAIN,
    "--peer", PEER, "--confirmation", confirmation, "--confirmed-sent", ...extra);
  return { home, zipvizHome, local, keyPath, fake, deps, requests, stdout, stderr, cli, create, confirm,
    setOwner: (next: unknown) => { owner = next; }, setHook: (next: Hook | undefined) => { hook = next; },
    setId: (id: string) => { nextId = id; }, advance: (ms: number) => { now += ms; }, now: () => now,
    cleanup: () => { rmSync(home, { recursive: true, force: true }); } };
}

const active: ReturnType<typeof fixture>[] = [];
const setup = () => { const h = fixture(); active.push(h); return h; };
afterEach(() => { vi.restoreAllMocks(); for (const h of active.splice(0)) h.cleanup(); });
const string = (value: unknown) => { expect(typeof value).toBe("string"); return value as string; };
const sentPath = (h: ReturnType<typeof fixture>) => path.join(h.zipvizHome, "intros", "sent.json");
const expectedDraft = (opening: string, token: string) => `${opening} I check agents on ZipViz. It's free to join at https://zipviz.ai/join, then we can carry on with verified DMs. Intro code: ${token}`;

describe("compose-only intro CLI with the pinned synthetic draft fake", () => {
  it("composes a pinned-verifiable token and domain draft, labels caller attestation, and never transmits it", async () => {
    const h = setup();
    const result = await h.create();
    expect(result.code).toBe(0);
    expect(result.body).toMatchObject({ ok: true, compose_only: true, transmitted: false, domain: DOMAIN, incarnation: INCARNATION,
      existing_conversation: { caller_attested: true, independently_verified: false }, expires_at_ms: EPOCH + 3 * DAY });
    const token = string(result.body.intro_token);
    expect(result.body.draft).toBe(expectedDraft(`Lovely to meet you. I'm ${DOMAIN}.`, token));
    expect(result.body.draft).not.toContain("✓");
    const parsed = parseIntroToken(token);
    expect(parsed).toMatchObject({ id: DRAFT_ID, introducer: DOMAIN, introducer_incarnation: INCARNATION, issued_at_ms: EPOCH, expires_at_ms: EPOCH + 3 * DAY });
    await verifyIntroToken(token, h.fake.lookup(DOMAIN)!, h.now(), "api.zipviz.ai");
    const posts = h.requests.filter(request => request.method === "POST");
    expect(posts).toHaveLength(1);
    expect(new URL(posts[0]!.url).pathname).toBe(`/v1/agent/${DOMAIN}/intro-policy`);
    expect(JSON.parse(posts[0]!.body!)).toMatchObject({ type: "zipviz.intro_policy.read", domain: DOMAIN, incarnation: INCARNATION });
    expect(h.requests.every(request => request.redirect === "error")).toBe(true);
    expect(h.requests.every(request => new URL(request.url).origin === ORIGIN)).toBe(true);
    expect(existsSync(sentPath(h))).toBe(false);
    expect(existsSync(path.join(h.zipvizHome, "bots.json"))).toBe(false);
    const pem = readFileSync(h.keyPath, "utf8");
    for (const request of h.requests) {
      expect(request.url + (request.body ?? "")).not.toContain(PEER);
      expect(request.url + (request.body ?? "")).not.toContain(token);
      expect(request.body ?? "").not.toContain("PRIVATE KEY");
      expect(request.body ?? "").not.toContain(pem);
    }
    expect(result.err).not.toContain(token);
    expect(result.err).not.toContain(PEER);
    expect(result.text).not.toContain(PEER);
  });

  it.each([
    { owner: { linkedin: { name: "Fixture Account", account_linked: true }, x: null }, opening: "Lovely to meet you. I'm Fixture Account's agent (LinkedIn account linked)." },
    { owner: { linkedin: null, x: { handle: "fixture_owner", account_linked: true } }, opening: "Lovely to meet you. I'm @fixture_owner's agent (X account linked)." },
  ])("uses only opted-in public account-control fields in the exact draft", async ({ owner, opening }) => {
    const h = setup(); h.setOwner(owner);
    const result = await h.create();
    expect(result.code).toBe(0);
    expect(result.body.draft).toBe(expectedDraft(opening, string(result.body.intro_token)));
    expect(result.body.draft).not.toContain("✓");
    expect(result.body.draft).not.toContain("verified owner");
  });

  it.each([
    null, {}, { linkedin: null, x: null },
    { linkedin: { name: "Must Not Be Used", verified: true }, x: null },
    { linkedin: { name: "Must Not Be Used", account_linked: false }, x: null },
    { name: "Typed Name", linkedin_url: "https://example.invalid/typed" },
  ])("does not promote absent, hidden or legacy owner claims", async owner => {
    const h = setup(); h.setOwner(owner);
    const result = await h.create();
    expect(result.code).toBe(0);
    expect(result.body.draft).toBe(expectedDraft(`Lovely to meet you. I'm ${DOMAIN}.`, string(result.body.intro_token)));
  });

  it.each([
    { linkedin: { name: "Unsafe\nFixture", account_linked: true }, x: null },
    { linkedin: { name: "Unsafe ✓ Fixture", account_linked: true }, x: null },
    { linkedin: { name: "Unsafe Fixture", account_linked: true, typed_name: "extra" }, x: null },
    { linkedin: null, x: { handle: "not a handle", account_linked: true } },
  ])("refuses unsafe opted-in display instead of printing it", async owner => {
    const h = setup(); h.setOwner(owner);
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(result.body).not.toHaveProperty("draft");
    expect(result.text).not.toContain("Unsafe");
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it("requires an explicit existing-conversation attestation and never checks it as a proven fact", async () => {
    const h = setup();
    const result = await h.cli("intro", "create", DOMAIN, "--peer", PEER);
    expect(result.code).not.toBe(0);
    expect(h.requests).toHaveLength(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(existsSync(path.join(h.zipvizHome, "intros"))).toBe(false);
  });

  it.each(["wrong-local-key", "wrong-card-key", "suspended", "deleted", "missing-incarnation"])("refuses an initial authority that is %s", async kind => {
    const h = setup(); const original = h.fake.lookup(DOMAIN)!;
    if (kind === "wrong-local-key") h.fake.rotateKey(DOMAIN, "ab".repeat(32));
    if (kind === "suspended") h.fake.suspend(DOMAIN);
    if (kind === "deleted") h.fake.deleteAgent(DOMAIN);
    h.setHook(async (request, next) => {
      const pathname = new URL(request.url).pathname;
      if (kind === "wrong-card-key" && pathname.endsWith("/card")) return json({ name: DOMAIN, public_key: "ab".repeat(32) });
      if (kind === "missing-incarnation" && pathname === `/v1/agent/${DOMAIN}`) {
        const { incarnation, ...rest } = original; void incarnation; return json(rest);
      }
      return next();
    });
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(h.requests.filter(request => request.method === "POST")).toHaveLength(0);
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it.each(["rotated", "suspended", "deleted", "reregistered", "revision"])("refuses authority changed to %s while policy is checked", async kind => {
    const h = setup(); const original = h.fake.lookup(DOMAIN)!;
    h.setHook(async (request, next) => {
      const result = await next();
      if (new URL(request.url).pathname.endsWith("/intro-policy")) {
        if (kind === "rotated") h.fake.rotateKey(DOMAIN, "ab".repeat(32));
        if (kind === "suspended") h.fake.suspend(DOMAIN);
        if (kind === "deleted") h.fake.deleteAgent(DOMAIN);
        if (kind === "reregistered") h.fake.seedCurrentAgent({ ...original, incarnation: "ef".repeat(16) });
        if (kind === "revision") h.fake.seedCurrentAgent({ ...original, revision: 1 });
      }
      return result;
    });
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it.each(["false", "stale", "future", "incarnation", "unknown-field", "malformed", "service-document", "network", "stream"])("fails closed on a %s policy result", async kind => {
    const h = setup();
    h.setHook(async (request, next) => {
      if (!new URL(request.url).pathname.endsWith("/intro-policy")) return next();
      const body = { allow_agent_intros: true, incarnation: INCARNATION, checked_at_ms: h.now() };
      if (kind === "false") return json({ ...body, allow_agent_intros: false });
      if (kind === "stale") return json({ ...body, checked_at_ms: h.now() - 300001 });
      if (kind === "future") return json({ ...body, checked_at_ms: h.now() + 1 });
      if (kind === "incarnation") return json({ ...body, incarnation: "ef".repeat(16) });
      if (kind === "unknown-field") return json({ ...body, surprise: true });
      if (kind === "malformed") return new Response("not JSON", { status: 200 });
      if (kind === "service-document") return json({ service: "ZipViz Agent Registry", endpoints: [] });
      if (kind === "network") throw new Error(`synthetic failure ${PEER}`);
      return new Response(new ReadableStream({ start(controller) { controller.error(new Error("synthetic body failure")); } }), { status: 200 });
    });
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(result.text + result.err).not.toContain(PEER);
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it.each([400, 401, 403, 404, 429, 500, 503])("fails closed on policy HTTP %s even with an allowed body", async status => {
    const h = setup();
    h.setHook(async (request, next) => new URL(request.url).pathname.endsWith("/intro-policy")
      ? json({ allow_agent_intros: true, incarnation: INCARNATION, checked_at_ms: h.now() }, status) : next());
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("draft");
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it("rechecks policy age after the final authority and card reads", async () => {
    const h = setup();
    let policyReturned = false;
    h.setHook(async (request, next) => {
      const result = await next();
      const pathname = new URL(request.url).pathname;
      if (pathname.endsWith("/intro-policy")) policyReturned = true;
      else if (policyReturned && pathname.endsWith("/card")) h.advance(300001);
      return result;
    });
    const result = await h.create();
    expect(result.code).not.toBe(0);
    expect(result.body).not.toHaveProperty("intro_token");
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it.each([
    { name: "policy becomes stale", delta: 300001, ttl: "259200" },
    { name: "token expires while policy stays fresh", delta: 1000, ttl: "1" },
  ])("refuses output after awaited confirmation storage when $name", async ({ delta, ttl }) => {
    const h = setup();
    const original = IntroStore.prototype.makeConfirmation;
    vi.spyOn(IntroStore.prototype, "makeConfirmation").mockImplementation(async function (this: IntroStore, options) {
      const confirmation = await original.call(this, options);
      h.advance(delta);
      return confirmation;
    });
    const result = await h.create("--ttl", ttl);
    expect(result.code).not.toBe(0);
    expect(result.body).toMatchObject({ ok: false, error: { code: "E_INTRO_UNAVAILABLE" } });
    expect(result.body).not.toHaveProperty("intro_token");
    expect(result.body).not.toHaveProperty("draft");
    expect(result.body).not.toHaveProperty("confirmation");
    expect(result.text + result.err).not.toContain("zvintro1.");
    expect(result.text + result.err).not.toContain("Lovely to meet you");
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it("uses the pinned fake's owner opt-out and keeps read-only policy available while paused", async () => {
    const h = setup();
    h.fake.setIntroAllowed(OWNER_SUB, false);
    expect((await h.create()).code).not.toBe(0);
    h.fake.setIntroAllowed(OWNER_SUB, true);
    h.fake.flag = "paused";
    expect((await h.create()).code).toBe(0);
    h.fake.flag = "false";
    expect((await h.create()).code).not.toBe(0);
    expect(existsSync(sentPath(h))).toBe(false);
  });

  it("refuses a registered peer and allows a coherent unknown peer without sending its opaque reference", async () => {
    const h = setup();
    h.fake.seedCurrentAgent({ domain: PEER_DOMAIN, public_key: "ab".repeat(32), incarnation: "ef".repeat(16), revision: 0,
      status: "registered", identity_status: "active" });
    expect((await h.create("--peer-domain", PEER_DOMAIN)).code).not.toBe(0);
    expect(h.requests.filter(request => request.method === "POST")).toHaveLength(0);
    h.fake.deleteAgent(PEER_DOMAIN);
    const result = await h.create("--peer-domain", PEER_DOMAIN);
    expect(result.code).toBe(0);
    expect(h.requests.some(request => request.url === `${ORIGIN}/v1/agent/${PEER_DOMAIN}`)).toBe(true);
    for (const request of h.requests) expect(request.url + (request.body ?? "")).not.toContain(PEER);
  });

  it.each(["non-404", "malformed-200", "network"])("refuses ambiguous peer lookup %s", async kind => {
    const h = setup();
    h.setHook(async (request, next) => {
      if (new URL(request.url).pathname !== `/v1/agent/${PEER_DOMAIN}`) return next();
      if (kind === "non-404") return json({ code: "E_AGENT_NOT_FOUND" }, 503);
      if (kind === "malformed-200") return json({ registered: false });
      throw new Error("synthetic peer lookup failed");
    });
    expect((await h.create("--peer-domain", PEER_DOMAIN)).code).not.toBe(0);
    expect(h.requests.filter(request => request.method === "POST")).toHaveLength(0);
  });

  it("writes private HMAC dedupe only on explicit confirmed send, survives a new command invocation, and expires at 30 days", async () => {
    const h = setup();
    const created = await h.create();
    expect(created.code).toBe(0);
    const confirmation = string(created.body.confirmation);
    const token = string(created.body.intro_token);
    expect(existsSync(sentPath(h))).toBe(false);
    // A compose operation alone never marks this peer as sent.
    expect((await h.create()).code).toBe(0);
    const before = h.requests.length;
    expect((await h.confirm(confirmation)).code).toBe(0);
    expect(h.requests).toHaveLength(before);
    expect(statSync(sentPath(h)).mode & 0o777).toBe(0o600);
    expect(statSync(path.dirname(sentPath(h))).mode & 0o777).toBe(0o700);
    const persisted = readFileSync(sentPath(h), "utf8");
    expect(persisted).not.toContain(PEER);
    expect(persisted).not.toContain(token);
    expect(persisted).not.toContain(string(created.body.draft));
    expect((await h.confirm(confirmation)).code).not.toBe(0);
    expect(readFileSync(sentPath(h), "utf8")).toBe(persisted);
    expect((await h.create()).code).not.toBe(0);
    h.advance(30 * DAY - 1);
    expect((await h.create()).code).not.toBe(0);
    h.advance(1);
    h.setId("00000000-0000-4000-8000-000000000003");
    expect((await h.create()).code).toBe(0);
    expect(readFileSync(sentPath(h), "utf8")).toBe(persisted);
    const keys = readdirSync(path.join(h.zipvizHome, "keys"));
    expect(keys).toEqual([`${DOMAIN}.key`]);
    expect(existsSync(path.join(h.zipvizHome, "bots.json"))).toBe(false);
  });

  it("refuses confirmation without the explicit confirmed-sent flag and binds receipt to peer, domain and signature", async () => {
    const h = setup(); const created = await h.create();
    expect(created.code).toBe(0);
    const confirmation = string(created.body.confirmation);
    const mark = h.requests.length;
    const absentFlag = await h.cli("intro", "confirm-sent", DOMAIN, "--peer", PEER, "--confirmation", confirmation);
    expect(absentFlag.code).not.toBe(0);
    for (const argv of [
      ["intro", "confirm-sent", DOMAIN, "--peer", "different-synthetic-peer", "--confirmation", confirmation, "--confirmed-sent"],
      ["intro", "confirm-sent", PEER_DOMAIN, "--peer", PEER, "--confirmation", confirmation, "--confirmed-sent"],
      ["intro", "confirm-sent", DOMAIN, "--peer", PEER, "--confirmation", `${confirmation.slice(0, -1)}!`, "--confirmed-sent"],
    ]) {
      const result = await h.cli(...argv);
      expect(result.code).not.toBe(0);
      expect(result.text).not.toContain(PEER);
      expect(result.text).not.toContain(confirmation);
      expect(existsSync(sentPath(h))).toBe(false);
    }
    expect(h.requests).toHaveLength(mark);
  });

  it("records a caller-attested historical send after token expiry without network and applies dedupe", async () => {
    const h = setup(); const created = await h.create();
    expect(created.code).toBe(0);
    h.advance(4 * DAY);
    const mark = h.requests.length;
    const confirmed = await h.confirm(string(created.body.confirmation));
    expect(confirmed.code).toBe(0);
    expect(confirmed.body).toMatchObject({ transmitted: false, confirmation_source: "caller", confirmed_at_ms: EPOCH + 4 * DAY });
    expect(existsSync(sentPath(h))).toBe(true);
    expect(h.requests).toHaveLength(mark);
    const persisted = readFileSync(sentPath(h), "utf8");
    expect(persisted).not.toContain(PEER);
    expect(persisted).not.toContain(string(created.body.intro_token));
    h.setId("00000000-0000-4000-8000-000000000003");
    expect((await h.create()).code).not.toBe(0);
    expect(readFileSync(sentPath(h), "utf8")).toBe(persisted);
  });

  it("honors the explicit audience and TTL in the signed policy and composed token", async () => {
    const h = setup();
    const result = await h.create("--ttl", "60");
    expect(result.code).toBe(0);
    expect(result.body.expires_at_ms).toBe(EPOCH + 60000);
    expect(parseIntroToken(string(result.body.intro_token))).toMatchObject({ audience: "api.zipviz.ai", expires_at_ms: EPOCH + 60000 });
    expect((await h.create("--aud", "api-staging.zipviz.ai")).code).not.toBe(0);
    const policy = h.requests.filter(request => request.method === "POST").at(-1)!;
    expect(JSON.parse(policy.body!)).toMatchObject({ audience: "api-staging.zipviz.ai" });
  });

  it.each([
    { args: ["--ttl", "0"] }, { args: ["--ttl", "259201"] }, { args: ["--ttl", "1.5"] },
    { args: ["--aud", "https://bad.invalid"] }, { args: ["--peer-domain", "bad/path"] },
    { args: ["--peer", "bad\npeer"] }, { args: ["--owner-name", "Typed Fixture"] },
  ])("refuses invalid intro arguments $args before network or dedupe writes", async ({ args }) => {
    const h = setup();
    expect((await h.create(...args)).code).not.toBe(0);
    expect(h.requests).toHaveLength(0);
    expect(existsSync(path.join(h.zipvizHome, "intros"))).toBe(false);
  });
});
