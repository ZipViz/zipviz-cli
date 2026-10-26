/** Synthetic DRAFT fixtures pinned to API commit 420f0c2; not final server acceptance. */
import { createHash, createPrivateKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalizeJson, type JsonValue } from "../src/a2a/jcs.js";
import { LocalKey } from "../src/keys.js";
import {
  buildStart, buildCancel, keyId, keyFingerprint, requestDigest,
  subjectAgentId, validatePoll, validateReceipt,
} from "../src/join/codec.js";
import {
  SIGNUP_DOMAINS, assertSignupFresh, parseSignupStart, parseSignupCancel,
  parseIntroPolicy, parseIntroToken, verifySignupStart, verifySignupCancel,
  verifyIntroPolicy, verifyIntroToken, signupSigningBytes,
  type StartRequest, type Cancel,
} from "./fixtures/signup-api/src/signup-codec.js";

type Vector = {
  id: string; kind: "start" | "cancel" | "intro" | "policy";
  request_bytes: string; unsigned_jcs: string; signing_bytes_hex: string;
  key_id: string; bound_digest: string | null; request_digest: string;
  signature: string; token?: string; expected: { status: number; code: string | null };
};
type Vectors = {
  test_only: true; now_ms: number; audience: string;
  keys: Record<"agent" | "introducer", { test_only_seed_hex: string; public_key: string }>;
  authority: { domain: string; public_key: string; incarnation: string; revision: number };
  subject_identity: { registry_origin: string; domain: string; incarnation: string; subject_agent_id: string };
  vectors: Vector[];
};
const vectorBytes = readFileSync(new URL("../test-vectors/signup-v1.json", import.meta.url));
const vectors = JSON.parse(vectorBytes.toString("utf8")) as Vectors;
const digest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const byId = (id: string) => vectors.vectors.find(vector => vector.id === id)!;
function testKey(which: "agent" | "introducer" = "agent"): LocalKey {
  const seed = Buffer.from(vectors.keys[which].test_only_seed_hex, "hex");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const key = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
  return new LocalKey("synthetic-test-key", "unused-synthetic-path", key);
}
async function verdict(vector: Vector): Promise<{ status: number; code: string | null }> {
  try {
    if (vector.kind === "start") {
      const request = parseSignupStart(vector.request_bytes);
      await verifySignupStart(request, vectors.audience);
      assertSignupFresh(request.proof.issued_at_ms, vectors.now_ms);
    } else if (vector.kind === "cancel") {
      const request = parseSignupCancel(vector.request_bytes);
      await verifySignupCancel(request, vectors.keys.agent.public_key, vectors.audience);
      assertSignupFresh(request.issued_at_ms, vectors.now_ms);
    } else if (vector.kind === "policy") {
      const request = parseIntroPolicy(vector.request_bytes);
      await verifyIntroPolicy(request, vectors.keys.introducer.public_key, vectors.audience);
      assertSignupFresh(request.issued_at_ms, vectors.now_ms);
    } else {
      await verifyIntroToken(parseIntroToken(vector.token!), vectors.authority, vectors.now_ms, vectors.audience);
    }
    return { status: vector.kind === "start" ? 201 : 200, code: null };
  } catch (cause) {
    const error = cause as { status: number; code: string };
    return { status: error.status, code: error.code };
  }
}

describe("pinned DRAFT signup vectors", () => {
  it("reproduces the committed typed fake from the untouched pinned TypeScript source", () => {
    const result = spawnSync(process.execPath, [new URL("../scripts/build-signup-fixture.mjs", import.meta.url).pathname, "--check"], { encoding: "utf8" });
    expect(result.stderr).toBe("");
    expect(result.status, result.stdout).toBe(0);
  });
  it("verifies the exact upstream vector and fake bytes", () => {
    expect(vectors.test_only).toBe(true);
    expect(digest(vectorBytes)).toBe("9500affd45a4084bf20a3371ffe4209680f406d58b266049590fef2ed2ce432a");
    expect(digest(readFileSync(new URL("../test-vectors/signup-api/tests/support/signup-fake.ts", import.meta.url))))
      .toBe("1009df5fac822cc019007eaa4748bb3c9ec81703784bd2f1d24bc8757f859cdd");
    for (const [file, expected] of [
      ["bytes.js", "afcb6c0eb0a854f40320063455d96dc2909f0fecb3fa795fff2c47192c7041d0"],
      ["jcs.js", "00572f5b0af4fb8ba96b072db55e2a572158d2f79ff43e32e36c14f487e2d870"],
      ["signup-codec.js", "0320b79f10bdf2a1e442c9c3663e8d1c1306fc22051c0473d1d2910a939998a9"],
    ]) {
      expect(digest(readFileSync(new URL(`../test-vectors/signup-api/src/${file}`, import.meta.url)))).toBe(expected);
    }
    expect(vectors.vectors).toHaveLength(38);
    expect(new Set(vectors.vectors.map(vector => vector.id)).size).toBe(38);
    for (const which of ["agent", "introducer"] as const) expect(testKey(which).publicKey).toBe(vectors.keys[which].public_key);
  });

  it.each(vectors.vectors)("$id retains exact digest, unsigned JCS, signature and domain-separated signing bytes", vector => {
    const parsed = JSON.parse(vector.request_bytes) as Record<string, JsonValue>;
    const signed = (vector.kind === "start" ? parsed.proof : parsed) as Record<string, JsonValue>;
    const { signature, ...unsigned } = signed;
    expect(canonicalizeJson(unsigned)).toBe(vector.unsigned_jcs);
    expect(signature).toMatchObject({ key_id: vector.key_id, value_base64url: vector.signature });
    expect(requestDigest(vector.request_bytes)).toBe(vector.request_digest);
    expect(Buffer.from(signupSigningBytes(signed, SIGNUP_DOMAINS[vector.kind])).toString("hex")).toBe(vector.signing_bytes_hex);
    if (vector.kind === "start") expect(signed.bound_digest).toBe(vector.bound_digest);
  });

  it.each(vectors.vectors)("$id matches the pinned API codec's exact status/code", async vector => {
    expect(await verdict(vector)).toEqual(vector.expected);
  });

  it("the production start signer reproduces all genuine start request bytes", () => {
    for (const id of ["start.valid", "start.changed-name-still-valid", "start.with-intro", "start.past-boundary", "start.future-boundary", "start.stale-past", "start.stale-future", "start.wrong-audience"]) {
      const vector = byId(id);
      const request = JSON.parse(vector.request_bytes) as StartRequest;
      const bytes = buildStart(testKey(), {
        signupId: request.proof.signup_id, name: request.name, ownerEmail: request.owner_email,
        runtime: request.runtime, introducedBy: request.introduced_by,
        audience: request.proof.audience, issuedAtMs: request.proof.issued_at_ms,
      });
      expect(bytes, id).toBe(vector.request_bytes);
      expect(requestDigest(bytes), id).toBe(vector.request_digest);
    }
  });

  it("the production cancel signer reproduces the exact canonical cancel vector", () => {
    const vector = byId("cancel.valid");
    const request = JSON.parse(vector.request_bytes) as Cancel;
    expect(buildCancel(testKey(), { signupId: request.signup_id, audience: request.audience,
      nonce: request.nonce, issuedAtMs: request.issued_at_ms })).toBe(vector.request_bytes);
  });

  it("hashes raw decoded key bytes and reproduces the bound subject identity", () => {
    expect(keyId(testKey().publicKey)).toBe(byId("start.valid").key_id);
    expect(keyFingerprint(testKey().publicKey)).toBe("10ba 682c 8ad1 3513");
    const identity = vectors.subject_identity;
    expect(subjectAgentId(identity.registry_origin, identity.domain, identity.incarnation)).toBe(identity.subject_agent_id);
  });

  it("validates generated-name length separately from the final clean-name length", () => {
    const request = JSON.parse(byId("start.valid").request_bytes) as StartRequest;
    const options = { signupId: request.proof.signup_id, name: "a".repeat(15), ownerEmail: request.owner_email,
      runtime: request.runtime, introducedBy: null, audience: request.proof.audience, issuedAtMs: request.proof.issued_at_ms };
    expect(JSON.parse(buildStart(testKey(), options)).name).toHaveLength(15);
    for (const name of ["a".repeat(16), "-fixture", "fixture-", "fixture-1234", "Fixture", "xn--bad/"]) {
      expect(() => buildStart(testKey(), { ...options, name })).toThrow();
    }
    const common = { schema_version: "1.0", signup_id: options.signupId, state: "pending", expires_at_ms: vectors.now_ms, poll_interval_ms: 5000 };
    expect(validatePoll({ ...common, proposed_domain: `${"a".repeat(20)}.z.viz` }, options.signupId)).toBeDefined();
    expect(() => validatePoll({ ...common, proposed_domain: `${"a".repeat(21)}.z.viz` }, options.signupId)).toThrow();
  });

  it("normalizes the owner email before binding and never serializes the signing key", () => {
    const vector = byId("start.valid");
    const request = JSON.parse(vector.request_bytes) as StartRequest;
    const bytes = buildStart(testKey(), { signupId: request.proof.signup_id, name: request.name,
      ownerEmail: `  ${request.owner_email.toUpperCase()}  `, runtime: request.runtime, introducedBy: null,
      audience: request.proof.audience, issuedAtMs: request.proof.issued_at_ms });
    expect(bytes).toBe(vector.request_bytes);
    expect(bytes).not.toContain(vectors.keys.agent.test_only_seed_hex);
    expect(bytes).not.toContain("PRIVATE KEY");
  });
});

describe("join response validation", () => {
  const signupId = (JSON.parse(byId("start.valid").request_bytes) as StartRequest).proof.signup_id;
  const receipt = {
    schema_version: "1.0", signup_id: signupId, state: "pending", proposed_domain: "fixture-1234.z.viz",
    user_code: "BCDF-GHJK", approval_url: "https://zipviz.ai/approve/BCDF-GHJK", expires_at_ms: vectors.now_ms + 86400000, poll_interval_ms: 5000,
  };
  it("accepts a historical creation receipt and checks approval link origin/path/code", () => {
    expect(validateReceipt(receipt, signupId)).toEqual(receipt);
    for (const approval_url of ["https://evil.example/approve/BCDF-GHJK", "https://zipviz.ai.evil.example/approve/BCDF-GHJK", "https://zipviz.ai/approve/BBBB-BBBB", "javascript:alert(1)"]) {
      expect(() => validateReceipt({ ...receipt, approval_url }, signupId)).toThrow("unexpected join response");
    }
    expect(() => validateReceipt({ ...receipt, owner_email: "synthetic@example.invalid" }, signupId)).toThrow();
    expect(() => validateReceipt({ ...receipt, poll_interval_ms: 1 }, signupId)).toThrow();
  });
  it("accepts each closed poll shape and binds live identity to configured registry origin", () => {
    const pending = { schema_version: receipt.schema_version, signup_id: signupId, state: "pending",
      proposed_domain: receipt.proposed_domain, expires_at_ms: receipt.expires_at_ms, poll_interval_ms: 5000 };
    expect(validatePoll(pending, signupId)).toEqual(pending);
    const identity = vectors.subject_identity;
    const live = { schema_version: "1.0", signup_id: signupId, state: "live", domain: identity.domain,
      public_key: testKey().publicKey, incarnation: identity.incarnation, subject_agent_id: identity.subject_agent_id, live_at_ms: vectors.now_ms };
    expect(validatePoll(live, signupId)).toEqual(live);
    expect(() => validatePoll(live, signupId, "https://other.example")).toThrow();
    for (const malformed of [{ ...live, incarnation: "ff".repeat(16) }, { ...live, public_key: "INVALID" }, { ...live, domain: "fixture.z.viz.evil.example" }, { ...live, live_at_ms: 0.5 }, { ...live, owner: {} }]) {
      expect(() => validatePoll(malformed, signupId)).toThrow();
    }
    for (const state of ["cancelled", "rejected"] as const) {
      const poll = { schema_version: "1.0", signup_id: signupId, state, decided_at_ms: vectors.now_ms };
      expect(validatePoll(poll, signupId)).toEqual(poll);
    }
    const expired = { schema_version: "1.0", signup_id: signupId, state: "expired", expires_at_ms: vectors.now_ms };
    expect(validatePoll(expired, signupId)).toEqual(expired);
  });
});
