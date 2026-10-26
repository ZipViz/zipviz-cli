/** Synthetic DRAFT API420f0c2 vectors; never identity enrollment or live acceptance. */
import { createHash, createPrivateKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalizeJson, type JsonValue } from "../src/a2a/jcs.js";
import { CliError } from "../src/errors.js";
import { LocalKey } from "../src/keys.js";
import { buildIntro, buildIntroPolicy, composeIntro, INTRO_POLICY_MAX_AGE_MS, INTRO_TTL_MAX_MS, validatePolicyResult } from "../src/intro/codec.js";
import { parseIntroPolicy, parseIntroToken, verifyIntroPolicy, verifyIntroToken, assertSignupFresh, signupSigningBytes } from "./fixtures/signup-api/src/signup-codec.js";
import { SignupFake } from "./fixtures/signup-api/tests/support/signup-fake.js";

interface Vector {
  id: string;
  kind: "start" | "cancel" | "intro" | "policy";
  request_bytes: string;
  unsigned_jcs: string;
  signing_bytes_hex: string;
  request_digest: string;
  token?: string;
  expected: { status: number; code: string | null };
}
interface Fixture {
  test_only: true;
  now_ms: number;
  audience: string;
  keys: Record<"agent" | "introducer", { test_only_seed_hex: string; public_key: string }>;
  authority: { domain: string; public_key: string; incarnation: string; revision: number };
  vectors: Vector[];
}
const bytes = readFileSync(new URL("../test-vectors/signup-v1.json", import.meta.url));
const fixture = JSON.parse(bytes.toString("utf8")) as Fixture;
const vector = (id: string) => fixture.vectors.find(item => item.id === id)!;
const key = new LocalKey("synthetic-introducer", "unused-synthetic-path", createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(fixture.keys.introducer.test_only_seed_hex, "hex")]),
  format: "der", type: "pkcs8",
}));
const options = { domain: fixture.authority.domain, incarnation: fixture.authority.incarnation,
  audience: fixture.audience, id: "00000000-0000-4000-8000-000000000002", issuedAtMs: fixture.now_ms,
  expiresAtMs: fixture.now_ms + INTRO_TTL_MAX_MS };
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

describe("intro codec against pinned draft vectors", () => {
  it("keeps the exact upstream bytes and includes all intro/policy cases", () => {
    expect(hash(bytes)).toBe("9500affd45a4084bf20a3371ffe4209680f406d58b266049590fef2ed2ce432a");
    expect(hash(readFileSync(new URL("../test-vectors/signup-api/tests/support/signup-fake.ts", import.meta.url))))
      .toBe("1009df5fac822cc019007eaa4748bb3c9ec81703784bd2f1d24bc8757f859cdd");
    expect(fixture.vectors.filter(item => item.kind === "intro")).toHaveLength(8);
    expect(fixture.vectors.filter(item => item.kind === "policy")).toHaveLength(5);
    expect(key.publicKey).toBe(fixture.authority.public_key);
  });

  it("produces the exact canonical intro signature, bytes and token", async () => {
    const expected = vector("intro.valid");
    const token = buildIntro(key, options);
    const text = Buffer.from(token.slice(9), "base64url").toString("utf8");
    expect(token).toBe(expected.token);
    expect(text).toBe(expected.request_bytes);
    expect(hash(text)).toBe(expected.request_digest);
    expect(token.length).toBeLessThanOrEqual(1024);
    expect(token).not.toContain("=");
    const parsed = parseIntroToken(token);
    expect(Buffer.from(signupSigningBytes(parsed, "ZipViz intro v1")).toString("hex")).toBe(expected.signing_bytes_hex);
    expect(await verifyIntroToken(parsed, fixture.authority, fixture.now_ms, fixture.audience)).toMatchObject({ intro: { introducer: options.domain } });
    expect(text).not.toContain(fixture.keys.introducer.test_only_seed_hex);
    expect(text).not.toContain("PRIVATE KEY");
  });

  it("produces the exact signed read-policy bytes accepted by the pinned fake while paused", async () => {
    const expected = vector("policy.valid");
    const policy = buildIntroPolicy(key, options);
    expect(policy).toBe(expected.request_bytes);
    expect(hash(policy)).toBe(expected.request_digest);
    expect(Buffer.from(signupSigningBytes(parseIntroPolicy(policy), "ZipViz intro-policy v1")).toString("hex")).toBe(expected.signing_bytes_hex);
    const fake = new SignupFake({ flag: "paused", now: () => fixture.now_ms, audience: fixture.audience });
    fake.seedCurrentAgent({ ...fixture.authority, status: "registered", identity_status: "active" });
    const result = await fake.introPolicy(options.domain, policy);
    expect(result.status).toBe(200);
    expect(validatePolicyResult(result.body, options.incarnation, fixture.now_ms)).toEqual({ allow_agent_intros: true, incarnation: options.incarnation, checked_at_ms: fixture.now_ms });
    expect(policy).not.toContain("peer");
    expect(policy).not.toContain("zvintro1.");
  });

  it.each(fixture.vectors.filter(item => item.kind === "intro" || item.kind === "policy"))("preserves $id exact rejection or acceptance", async item => {
    let actual: { status: number; code: string | null };
    try {
      if (item.kind === "intro") await verifyIntroToken(parseIntroToken(item.token!), fixture.authority, fixture.now_ms, fixture.audience);
      else {
        const request = parseIntroPolicy(item.request_bytes);
        await verifyIntroPolicy(request, key.publicKey, fixture.audience);
        assertSignupFresh(request.issued_at_ms, fixture.now_ms);
      }
      actual = { status: 200, code: null };
    } catch (cause) {
      const error = cause as { status: number; code: string };
      actual = { status: error.status, code: error.code };
    }
    expect(actual).toEqual(item.expected);
  });

  it("separates policy and intro signing domains", async () => {
    const policy = JSON.parse(buildIntroPolicy(key, options)) as Record<string, JsonValue>;
    const unsigned = { ...policy };
    delete unsigned.signature;
    policy.signature = { alg: "Ed25519", key_id: `sha256:${hash(Buffer.from(key.publicKey, "hex"))}`,
      value_base64url: key.sign(`ZipViz intro v1\0${canonicalizeJson(unsigned)}`).toString("base64url") };
    await expect(verifyIntroPolicy(parseIntroPolicy(canonicalizeJson(policy)), key.publicKey, fixture.audience)).rejects.toMatchObject({ code: "E_POLICY_PROOF" });
  });

  it.each([
    { id: "not-a-uuid" }, { id: "ABCDEFAB-1234-4ABC-8ABC-ABCDEFABCDEF" },
    { domain: "fixture.z.viz.evil.example" }, { domain: "Fixture.z.viz" }, { domain: "fixture-.z.viz" }, { domain: `${"a".repeat(21)}.z.viz` },
    { incarnation: "ab".repeat(15) }, { incarnation: "AB".repeat(16) },
    { audience: "" }, { audience: "https://api.zipviz.ai" },
    { issuedAtMs: -1 }, { issuedAtMs: 0.5 }, { issuedAtMs: Number.MAX_SAFE_INTEGER + 1 },
    { expiresAtMs: options.issuedAtMs }, { expiresAtMs: options.issuedAtMs - 1 },
    { expiresAtMs: options.issuedAtMs + INTRO_TTL_MAX_MS + 1 },
  ])("refuses malformed intro fields %j", patch => {
    expect(() => buildIntro(key, { ...options, ...patch })).toThrow(CliError);
  });

  it("accepts the 72-hour boundary and keeps maximum allowed text fields within the token size cap", () => {
    expect(buildIntro(key, options)).toBe(vector("intro.valid").token);
    const token = buildIntro(key, { ...options, domain: `${"a".repeat(20)}.${"b".repeat(20)}.viz`, audience: "a".repeat(253) });
    expect(token.length).toBeLessThanOrEqual(1024);
    expect(parseIntroToken(token).audience).toHaveLength(253);
  });
});

describe("fresh fail-closed intro policy", () => {
  const allowed = { allow_agent_intros: true, incarnation: options.incarnation, checked_at_ms: fixture.now_ms };
  it("accepts fresh and exactly-five-minute-old permission", () => {
    expect(validatePolicyResult(allowed, options.incarnation, fixture.now_ms)).toEqual(allowed);
    expect(validatePolicyResult({ ...allowed, checked_at_ms: fixture.now_ms - INTRO_POLICY_MAX_AGE_MS }, options.incarnation, fixture.now_ms)).toMatchObject({ allow_agent_intros: true });
  });
  it.each([null, [], {}, { ...allowed, allow_agent_intros: false }, { ...allowed, allow_agent_intros: 1 },
    { ...allowed, incarnation: "ef".repeat(16) }, { ...allowed, checked_at_ms: fixture.now_ms + 1 },
    { ...allowed, checked_at_ms: fixture.now_ms - INTRO_POLICY_MAX_AGE_MS - 1 }, { ...allowed, checked_at_ms: -1 },
    { ...allowed, checked_at_ms: 0.5 }, { ...allowed, checked_at_ms: "1793000000000" }, { ...allowed, extra: true },
  ])("refuses malformed, stale or denied permission %j", body => {
    expect(() => validatePolicyResult(body, options.incarnation, fixture.now_ms)).toThrowError(expect.objectContaining({ code: "E_INTRO_UNAVAILABLE" }));
  });
});

describe("exact compose-only intro copy", () => {
  const token = buildIntro(key, options);
  const suffix = ` I check agents on ZipViz. It's free to join at https://zipviz.ai/join, then we can carry on with verified DMs. Intro code: ${token}`;
  it("uses the exact account-linked LinkedIn wording and never a checkmark", () => {
    const text = composeIntro(options.domain, { linkedin: { name: "Fixture Account", account_linked: true }, x: null }, token);
    expect(text).toBe(`Lovely to meet you. I'm Fixture Account's agent (LinkedIn account linked).${suffix}`);
    expect(text).not.toContain("✓");
    expect(text).not.toContain("—");
    expect(text).not.toContain("verified owner");
  });
  it("uses an opted-in X handle, never a display name", () => {
    const text = composeIntro(options.domain, { linkedin: null, x: { handle: "fixture_account", account_linked: true } }, token);
    expect(text).toBe(`Lovely to meet you. I'm @fixture_account's agent (X account linked).${suffix}`);
  });
  it.each([undefined, null, {}, { name: "Caller Typed" }, { linkedin: { name: "Hidden Account", account_linked: false } },
    { linkedin: { name: "Legacy Verified", verified: true } }, { x: { display_name: "Typed Display", verified: true } },
    { linkedin: { name: "Must Not Be Promoted", account_linked: "true" } }, { x: { handle: "fixture_account", account_linked: 1 } },
  ])("uses only the domain when no account-linked public field is eligible: %j", owner => {
    expect(composeIntro(options.domain, owner, token)).toBe(`Lovely to meet you. I'm ${options.domain}.${suffix}`);
  });
  it("selects LinkedIn consistently when both eligible public account fields exist", () => {
    expect(composeIntro(options.domain, { linkedin: { name: "Fixture Account", account_linked: true }, x: { handle: "fixture_account", account_linked: true } }, token))
      .toContain("Fixture Account's agent (LinkedIn account linked)");
  });
  it("preserves safe Unicode exactly as the linked public account supplied it", () => {
    expect(composeIntro(options.domain, { linkedin: { name: "Fixture 🧪", account_linked: true } }, token))
      .toBe(`Lovely to meet you. I'm Fixture 🧪's agent (LinkedIn account linked).${suffix}`);
  });
  it.each(["", " Fixture", "Fixture ", "a".repeat(101), "Fixture\nAccount", "Fixture\u001bAccount", "Fixture\u202eAccount",
    "Fixture\u061cAccount", "Fixture\u200eAccount", "Fixture\ud800Account", "Fixture ✓", "Fixture—Account"])("refuses unsafe linked display %j", name => {
    expect(() => composeIntro(options.domain, { linkedin: { name, account_linked: true }, x: null }, token)).toThrowError(expect.objectContaining({ code: "E_UNEXPECTED_RESPONSE" }));
  });
  it.each([{ handle: "@fixture", account_linked: true }, { handle: "a".repeat(16), account_linked: true },
    { handle: "fixture", account_linked: true, name: "Typed Display" }, { handle: "fixture\n", account_linked: true },
  ])("refuses malformed linked X fields %j", x => {
    expect(() => composeIntro(options.domain, { x }, token)).toThrow(CliError);
  });
  it.each(["untrusted", "zvintro1.A=", "zvintro1.abc\n", "zvintro1." + "a".repeat(1024)])("refuses malformed token syntax %s", malformed => {
    expect(() => composeIntro(options.domain, null, malformed)).toThrow(CliError);
  });
});
