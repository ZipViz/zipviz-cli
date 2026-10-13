/**
 * Public v1 /verify signature test vectors (test-vectors/v1-verify.json).
 *
 * Verification of a v1 envelope happens on the registry, not in this CLI, so this
 * file carries a small reference verifier that follows the documented rule exactly
 * (see test-vectors/README.md). The CLI's own signer is checked against the `valid`
 * case byte for byte, both directly (LocalKey.sign) and end to end (`zipviz verify`).
 *
 * TEST ONLY keys: both are derived from the published seeds in the JSON file.
 * No network: the end-to-end check uses the in-memory FakeRegistry.
 */
import { createPrivateKey, createPublicKey, randomUUID, verify as edVerify, type KeyObject } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LocalKey } from "../src/keys.js";
import { makeHarness, type Harness } from "./harness.js";

// Only randomUUID is pinned, and only where a test asks for it, so `zipviz verify`
// builds the exact message of the `valid` case. Everything else is real node:crypto.
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, randomUUID: vi.fn(actual.randomUUID) };
});

type Envelope = Record<string, unknown>;
type Expected = { verified: boolean; reason: string | null };
type VectorCase = {
  id: string;
  description: string;
  public_key: string;
  now: string;
  /** Only on the exact-boundary cases: timestamp minus `now`, in milliseconds. */
  timestamp_offset_ms?: number;
  body: string;
  envelope: Envelope;
  signed_bytes: string | null;
  expected: Expected;
};
type TestKey = { label: string; seed_utf8: string; public_key: string };
type VectorFile = {
  name: string;
  format_version: number;
  warning: string;
  rule: { window_ms: number };
  test_keys: Record<"A" | "B", TestKey>;
  cases: VectorCase[];
};

const vectors = JSON.parse(
  readFileSync(new URL("../test-vectors/v1-verify.json", import.meta.url), "utf8"),
) as VectorFile;
const byId = (id: string): VectorCase => {
  const found = vectors.cases.find((c) => c.id === id);
  if (!found) throw new Error(`missing vector case ${id}`);
  return found;
};
const valid = byId("valid");
const KEY_A = vectors.test_keys.A;
const KEY_B = vectors.test_keys.B;

// ---------------------------------------------------------------------------
// Reference verifier: the v1 rule, nothing more.
// ---------------------------------------------------------------------------

const WINDOW_MS = 300_000;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const PUBLIC_KEY_RE = /^[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** The exact bytes a v1 signature covers: fixed key order, no whitespace, UTF-8. */
function v1SignedBytes(from: string, message: string, timestamp: string): string {
  return JSON.stringify({ v: 1, from, message, timestamp });
}

function publicKeyObject(hex: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

function testPrivateKey(seedUtf8: string): KeyObject {
  const seed = Buffer.from(seedUtf8, "utf8");
  if (seed.length !== 32) throw new Error("test seed must be exactly 32 bytes");
  return createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function rawPublicKeyHex(key: KeyObject): string {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}

/** Strict standard base64 (with padding) that decodes to exactly 64 bytes. */
function decodeSignature(value: string): Buffer | null {
  const bytes = Buffer.from(value, "base64");
  return bytes.length === 64 && bytes.toString("base64") === value ? bytes : null;
}

function parseTimestamp(value: string): number | null {
  if (!TIMESTAMP_RE.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Verify one POST /v1/verify body against the public key registered for `from`,
 * at the given time. Each vector breaks exactly one thing, so check order does not
 * change any vector's result; this order is the one the README documents.
 */
function verifyV1(body: string, publicKeyHex: string, now: string): Expected {
  const fail = (reason: string): Expected => ({ verified: false, reason });
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return fail("E_FIELD_MISSING");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return fail("E_FIELD_MISSING");
  const env = parsed as Envelope;
  const { from, message, timestamp, signature } = env;
  if (typeof from !== "string" || typeof message !== "string" || typeof timestamp !== "string" || typeof signature !== "string") {
    return fail("E_FIELD_MISSING");
  }
  if (from === "" || timestamp === "" || signature === "") return fail("E_FIELD_EMPTY");
  const signedAt = parseTimestamp(timestamp);
  if (signedAt === null) return fail("E_TIMESTAMP_FORMAT");
  const sig = decodeSignature(signature);
  if (sig === null) return fail("E_SIG_FORMAT");
  if (!PUBLIC_KEY_RE.test(publicKeyHex)) throw new Error("vector public key must be 64 lowercase hex characters");
  const payload = Buffer.from(v1SignedBytes(from, message, timestamp), "utf8");
  if (!edVerify(null, payload, publicKeyObject(publicKeyHex), sig)) return fail("E_SIG_MISMATCH");
  const age = Date.parse(now) - signedAt;
  if (age > WINDOW_MS) return fail("E_TIMESTAMP_STALE");
  if (age < -WINDOW_MS) return fail("E_TIMESTAMP_FUTURE");
  return { verified: true, reason: null };
}

/** Ed25519 check only (no field, format or freshness rules), for near-miss assertions. */
function signatureOver(bytes: string, signatureB64: string, publicKeyHex: string): boolean {
  return edVerify(null, Buffer.from(bytes, "utf8"), publicKeyObject(publicKeyHex), Buffer.from(signatureB64, "base64"));
}

const str = (c: VectorCase, field: string): string => {
  const value = c.envelope[field];
  if (typeof value !== "string") throw new Error(`${c.id}: envelope.${field} is not a string`);
  return value;
};

// ---------------------------------------------------------------------------

describe("v1 /verify test vectors: file", () => {
  it("labels both keys TEST ONLY and derives them from their published 32-byte seeds", () => {
    expect(vectors.warning).toMatch(/^TEST ONLY\./);
    for (const key of [KEY_A, KEY_B]) {
      expect(key.label).toMatch(/^TEST ONLY /);
      expect(key.seed_utf8).toMatch(/TEST-ONLY/);
      expect(rawPublicKeyHex(testPrivateKey(key.seed_utf8))).toBe(key.public_key);
    }
    expect(KEY_A.public_key).not.toBe(KEY_B.public_key);
    expect(vectors.rule.window_ms).toBe(WINDOW_MS);
  });

  it("covers every case in the brief, with unique ids and only the test keys", () => {
    const ids = vectors.cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(expect.arrayContaining([
      "valid",
      "message_changed_one_char",
      "wrong_key",
      "replayed_different_from",
      "timestamp_too_old",
      "timestamp_too_far_in_future",
      "timestamp_just_inside_window",
      "timestamp_malformed",
      "signature_truncated",
      "empty_field",
      "whitespace_added_to_message",
      "envelope_key_order_changed",
      "timestamp_exactly_at_window_past",
      "timestamp_exactly_at_window_future",
    ]));
    for (const c of vectors.cases) {
      expect([KEY_A.public_key, KEY_B.public_key]).toContain(c.public_key);
      expect(parseTimestamp(c.now)).not.toBeNull();
    }
  });

  it.each(vectors.cases.map((c) => [c.id, c] as const))("%s: envelope and signed_bytes match the raw body", (_id, c) => {
    const parsed = JSON.parse(c.body) as Envelope;
    expect(parsed).toEqual(c.envelope);
    expect(Object.keys(parsed)).toEqual(Object.keys(c.envelope));
    expect(c.signed_bytes).toBe(v1SignedBytes(str(c, "from"), str(c, "message"), str(c, "timestamp")));
  });
});

describe("v1 /verify test vectors: reference verifier", () => {
  it.each(vectors.cases.map((c) => [c.id, c] as const))("%s", (_id, c) => {
    expect(verifyV1(c.body, c.public_key, c.now)).toEqual(c.expected);
  });

  it("returns the same verdict for the parsed envelope as for the raw body", () => {
    for (const c of vectors.cases) {
      expect(verifyV1(JSON.stringify(c.envelope), c.public_key, c.now)).toEqual(c.expected);
    }
  });
});

describe("v1 /verify test vectors: each failing case breaks exactly one thing", () => {
  const validMessage = str(valid, "message");
  const validSignature = str(valid, "signature");

  it("tamper and replay cases reuse the valid signature unchanged", () => {
    for (const id of [
      "message_changed_one_char", "wrong_key", "replayed_different_from", "whitespace_added_to_message",
      "envelope_key_order_changed", "envelope_whitespace_formatting",
    ]) {
      expect(str(byId(id), "signature"), id).toBe(validSignature);
    }
  });

  it("changes exactly one character of the message", () => {
    const changed = str(byId("message_changed_one_char"), "message");
    expect(changed).toHaveLength(validMessage.length);
    expect([...changed].filter((ch, i) => ch !== validMessage[i])).toHaveLength(1);
  });

  it("adds only whitespace to the message, and only after signing", () => {
    const c = byId("whitespace_added_to_message");
    expect(str(c, "message")).not.toBe(validMessage);
    expect(str(c, "message").trimEnd()).toBe(validMessage);
    expect(c.public_key).toBe(valid.public_key);
  });

  it("wrong_key differs from valid only in the registered key", () => {
    const c = byId("wrong_key");
    expect(c.body).toBe(valid.body);
    expect(c.public_key).toBe(KEY_B.public_key);
    expect(valid.public_key).toBe(KEY_A.public_key);
  });

  it("replay keeps the same key, so only the signed `from` makes it fail", () => {
    const c = byId("replayed_different_from");
    expect(c.public_key).toBe(valid.public_key);
    expect(str(c, "from")).not.toBe(str(valid, "from"));
    expect(str(c, "message")).toBe(validMessage);
    expect(str(c, "timestamp")).toBe(str(valid, "timestamp"));
  });

  it("timing, format and empty-field cases carry a genuine signature over their own bytes", () => {
    for (const id of [
      "timestamp_too_old", "timestamp_too_far_in_future", "timestamp_just_inside_window",
      "timestamp_exactly_at_window_past", "timestamp_exactly_at_window_future", "timestamp_malformed", "empty_field",
    ]) {
      const c = byId(id);
      expect(signatureOver(c.signed_bytes!, str(c, "signature"), c.public_key), id).toBe(true);
    }
  });

  it("puts the window cases one second either side of the 5 minute limit", () => {
    const offset = (id: string) => Date.parse(byId(id).now) - Date.parse(str(byId(id), "timestamp"));
    expect(offset("timestamp_too_old")).toBe(WINDOW_MS + 1000);
    expect(offset("timestamp_too_far_in_future")).toBe(-(WINDOW_MS + 1000));
    expect(offset("timestamp_just_inside_window")).toBe(WINDOW_MS - 1000);
  });

  it("puts the exact-boundary cases at exactly -300000 and +300000 ms, stated explicitly, and accepts both", () => {
    const boundary = [
      ["timestamp_exactly_at_window_past", -WINDOW_MS],
      ["timestamp_exactly_at_window_future", WINDOW_MS],
    ] as const;
    for (const [id, offsetMs] of boundary) {
      const c = byId(id);
      expect(c.timestamp_offset_ms, id).toBe(offsetMs);
      expect(Date.parse(str(c, "timestamp")) - Date.parse(c.now), id).toBe(offsetMs);
      expect(c.public_key, id).toBe(valid.public_key);
      expect(str(c, "message"), id).toBe(validMessage);
      expect(c.expected, id).toEqual({ verified: true, reason: null });
    }
  });

  it("uses a timestamp that no ISO 8601 parser accepts", () => {
    expect(Number.isNaN(Date.parse(str(byId("timestamp_malformed"), "timestamp")))).toBe(true);
  });

  it("truncates the valid signature by exactly one byte", () => {
    const truncated = Buffer.from(str(byId("signature_truncated"), "signature"), "base64");
    expect(truncated).toHaveLength(63);
    expect(truncated.equals(Buffer.from(validSignature, "base64").subarray(0, 63))).toBe(true);
  });

  it("signed_with_sorted_keys is a real signature, just over the wrong (alphabetical) bytes", () => {
    const c = byId("signed_with_sorted_keys");
    const sorted = JSON.stringify({ from: str(c, "from"), message: str(c, "message"), timestamp: str(c, "timestamp"), v: 1 });
    expect(signatureOver(sorted, str(c, "signature"), c.public_key)).toBe(true);
    expect(signatureOver(c.signed_bytes!, str(c, "signature"), c.public_key)).toBe(false);
  });

  it("keeps non-ASCII unescaped and escapes control characters in the signed bytes", () => {
    const signed = byId("valid_unicode_and_escapes").signed_bytes!;
    expect(signed).toContain("Grüße 👋");
    expect(signed).toContain("\\\"quoted\\\" back\\\\slash\\nsecond line\\tafter tab");
  });
});

describe("v1 /verify test vectors: the CLI's own signer", () => {
  it("LocalKey.sign reproduces the valid case's signature byte for byte", () => {
    const key = new LocalKey(str(valid, "from"), "unused-test-only-path", testPrivateKey(KEY_A.seed_utf8));
    expect(key.publicKey).toBe(KEY_A.public_key);
    expect(key.sign(valid.signed_bytes!).toString("base64")).toBe(str(valid, "signature"));
    for (const id of [
      "timestamp_just_inside_window", "timestamp_exactly_at_window_past", "timestamp_exactly_at_window_future",
      "valid_unicode_and_escapes",
    ]) {
      const c = byId(id);
      expect(key.sign(c.signed_bytes!).toString("base64"), id).toBe(str(c, "signature"));
    }
  });

  describe("`zipviz verify` end to end (in-memory registry, no network)", () => {
    let h: Harness;
    beforeEach(() => {
      h = makeHarness();
    });
    afterEach(() => {
      vi.useRealTimers();
      h.cleanup();
    });

    it("sends exactly the valid case's request body and signed bytes", async () => {
      const domain = str(valid, "from");
      const keysDir = path.join(h.home, ".zipviz", "keys");
      mkdirSync(keysDir, { recursive: true, mode: 0o700 });
      const pem = testPrivateKey(KEY_A.seed_utf8).export({ format: "pem", type: "pkcs8" });
      writeFileSync(path.join(keysDir, `${domain}.key`), pem, { mode: 0o600 });
      h.registry.addAgent(domain, KEY_A.public_key);

      const uuid = /^zipviz-cli key proof (.+)$/.exec(str(valid, "message"))?.[1];
      expect(uuid).toBeDefined();
      vi.mocked(randomUUID).mockReturnValueOnce(uuid as ReturnType<typeof randomUUID>);
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date(str(valid, "timestamp")));

      const r = await h.cliJson("verify", domain);
      expect(r.code).toBe(0);
      expect(r.body).toMatchObject({ ok: true, local_key: true, signature_verified: true });

      const sent = h.registry.requests.filter((q) => q.method === "POST" && new URL(q.url).pathname === "/v1/verify");
      expect(sent).toHaveLength(1);
      expect(sent[0]!.body).toBe(valid.body);
      const env = JSON.parse(sent[0]!.body!) as Envelope;
      expect(v1SignedBytes(String(env.from), String(env.message), String(env.timestamp))).toBe(valid.signed_bytes);
      expect(verifyV1(sent[0]!.body!, KEY_A.public_key, valid.now)).toEqual({ verified: true, reason: null });
    });
  });
});
