import { readFileSync } from "node:fs";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";
import { computeEventId, parseConditions, verifyBuzzEvent } from "../src/buzz/index.js";
import {
  AGENT_PUBKEY,
  AGENT_SECRET,
  OWNER_SECRET,
  authTag,
  signEvent,
  withAuth,
  type TestEvent,
} from "./buzz-helpers.js";

const signedExample = JSON.parse(readFileSync(new URL("./fixtures/nip-oa/signed-event.json", import.meta.url), "utf8")) as TestEvent;

function expectAuthFailure(event: unknown, reason: string) {
  const result = verifyBuzzEvent(event);
  expect(result.owner_auth).toMatchObject({ present: true, valid: false, reason });
  expect(result.owner_auth).not.toHaveProperty("owner_pubkey");
  expect(result.owner_auth).not.toHaveProperty("owner_npub");
  expect(result.owner_auth).not.toHaveProperty("conditions");
  expect(result.owner_auth).not.toHaveProperty("clauses");
  return result;
}

describe("NIP-01 event verification", () => {
  it("EVENT_BAD_ID for non-object input and invalid id", () => {
    for (const value of [null, [], "event", 4]) {
      expect(verifyBuzzEvent(value).event.reason).toBe("EVENT_BAD_ID");
    }
    const event = signEvent();
    event.id = "A".repeat(64);
    expect(verifyBuzzEvent(event).event.reason).toBe("EVENT_BAD_ID");
    const missing = { ...signEvent() } as Record<string, unknown>;
    delete missing.id;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_ID");
  });

  it("EVENT_BAD_PUBKEY for malformed and uppercase public keys", () => {
    for (const pubkey of ["A".repeat(64), "f".repeat(63)]) {
      expect(verifyBuzzEvent({ ...signEvent(), pubkey }).event.reason).toBe("EVENT_BAD_PUBKEY");
    }
    const missing = { ...signEvent() } as Record<string, unknown>;
    delete missing.pubkey;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_PUBKEY");
  });

  it("EVENT_BAD_CREATED_AT for missing, non-integer, unsafe, or negative timestamps", () => {
    const valid = signEvent();
    for (const created_at of ["1", -1, 1.5, 2 ** 53]) {
      expect(verifyBuzzEvent({ ...valid, created_at }).event.reason).toBe("EVENT_BAD_CREATED_AT");
    }
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.created_at;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_CREATED_AT");
  });

  it("EVENT_BAD_KIND for values outside the NIP-01 integer range", () => {
    const valid = signEvent();
    for (const kind of [65536, -1, 1.5, "1"]) {
      expect(verifyBuzzEvent({ ...valid, kind }).event.reason).toBe("EVENT_BAD_KIND");
    }
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.kind;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_KIND");
  });

  it("EVENT_BAD_TAGS for invalid tag structures and lone surrogates", () => {
    const valid = signEvent();
    for (const tags of [null, "tag", [1], [["x", 1]], [["\ud800"]]]) {
      expect(verifyBuzzEvent({ ...valid, tags }).event.reason).toBe("EVENT_BAD_TAGS");
    }
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.tags;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_TAGS");
  });

  it("accepts empty tags without treating them as owner authorisation", () => {
    const event = signEvent(AGENT_SECRET, { tags: [[]] });
    const result = verifyBuzzEvent(event);
    expect(result.event.valid).toBe(true);
    expect(result.owner_auth).toEqual({ present: false, valid: false });
    expect(result.ok).toBe(true);
  });

  it("EVENT_BAD_CONTENT for non-string values, missing content, and lone surrogates", () => {
    const valid = signEvent();
    expect(verifyBuzzEvent({ ...valid, content: 1 }).event.reason).toBe("EVENT_BAD_CONTENT");
    expect(verifyBuzzEvent({ ...valid, content: "\ud800" }).event.reason).toBe("EVENT_BAD_CONTENT");
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.content;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_CONTENT");
  });

  it("matches ecosystem JSON escaping for control characters", () => {
    const event = signEvent(AGENT_SECRET, { content: "a\u0001b" });
    const preimage = `[0,"${event.pubkey}",${event.created_at},${event.kind},[],"a\\u0001b"]`;
    expect(computeEventId(event)).toBe(bytesToHex(sha256(utf8ToBytes(preimage))));
    expect(verifyBuzzEvent(event).event.valid).toBe(true);
  });

  it("EVENT_BAD_SIG for malformed, missing, or uppercase signatures", () => {
    const valid = signEvent();
    for (const sig of ["A".repeat(128), "f".repeat(127)]) {
      expect(verifyBuzzEvent({ ...valid, sig }).event.reason).toBe("EVENT_BAD_SIG");
    }
    const missing = { ...valid } as Record<string, unknown>;
    delete missing.sig;
    expect(verifyBuzzEvent(missing).event.reason).toBe("EVENT_BAD_SIG");
  });

  it("EVENT_PUBKEY_NOT_ON_CURVE for a formatted x coordinate without a point", () => {
    const invalidX = [...Array(256).keys()]
        .map((n) => n.toString(16).padStart(64, "0"))
        .find((x) => {
        try {
          schnorr.utils.lift_x(BigInt(`0x${x}`));
          return false;
        } catch {
          return true;
        }
      })!;
    expect(() => schnorr.utils.lift_x(BigInt(`0x${invalidX}`))).toThrow();
    expect(verifyBuzzEvent({ ...signEvent(), pubkey: invalidX }).event.reason).toBe("EVENT_PUBKEY_NOT_ON_CURVE");
  });

  it("EVENT_PUBKEY_NOT_ON_CURVE for an x coordinate at or above the field prime", () => {
    const outOfFieldX = "f".repeat(64);
    expect(() => schnorr.utils.lift_x(BigInt(`0x${outOfFieldX}`))).toThrow();
    expect(verifyBuzzEvent({ ...signEvent(), pubkey: outOfFieldX }).event.reason).toBe("EVENT_PUBKEY_NOT_ON_CURVE");
  });

  it("EVENT_ID_MISMATCH when signed fields no longer match the identifier", () => {
    const event = signEvent();
    expect(verifyBuzzEvent({ ...event, content: "changed" }).event.reason).toBe("EVENT_ID_MISMATCH");
  });

  it("EVENT_SIG_INVALID when a changed event has a recomputed id but old signature", () => {
    const original = signEvent();
    const changed = signEvent(AGENT_SECRET, { content: "changed" });
    expect(verifyBuzzEvent({ ...changed, sig: original.sig }).event.reason).toBe("EVENT_SIG_INVALID");
  });

  it("EVENT_SIG_INVALID when one signature nibble is changed", () => {
    const event = signEvent();
    const sig = `${event.sig.slice(0, -1)}${event.sig.endsWith("0") ? "1" : "0"}`;
    expect(verifyBuzzEvent({ ...event, sig }).event.reason).toBe("EVENT_SIG_INVALID");
  });

  it("EVENT_ID_MISMATCH for changed content", () => {
    const event = signEvent();
    expect(verifyBuzzEvent({ ...event, content: `${event.content}!` }).event.reason).toBe("EVENT_ID_MISMATCH");
  });

  it("ignores extra top-level fields", () => {
    const event = signEvent();
    const result = verifyBuzzEvent({ ...event, ignored: "not signed" });
    expect(result.event.valid).toBe(true);
    expect(result.event).not.toHaveProperty("ignored");
  });
});

describe("NIP-OA owner authorisation", () => {
  it("returns absent when there is no auth tag and ignores unrelated tags", () => {
    expect(verifyBuzzEvent(signEvent()).owner_auth).toEqual({ present: false, valid: false });
    const event = signEvent(AGENT_SECRET, { tags: [["alt", "text"]] });
    expect(verifyBuzzEvent(event)).toMatchObject({ ok: true, owner_auth: { present: false, valid: false } });
  });

  it("AUTH_MULTIPLE_TAGS for two auth tags", () => {
    const event = signEvent(AGENT_SECRET, { tags: [authTag(OWNER_SECRET, AGENT_PUBKEY), authTag("0000000000000000000000000000000000000000000000000000000000000003", AGENT_PUBKEY)] });
    expectAuthFailure(event, "AUTH_MULTIPLE_TAGS");
  });

  it.each([3, 5])("spec invalid vector: auth tag with %i elements", (count) => {
    const event = signEvent();
    const tag = authTag(OWNER_SECRET, event.pubkey);
    const adjusted = count < 4 ? tag.slice(0, count) : [...tag, "extra"];
    const result = expectAuthFailure(withAuth(event, adjusted), "AUTH_TAG_ELEMENT_COUNT");
    expect(result.event.valid).toBe(true);
  });

  it.each([
    ["kind=1&", "AUTH_CONDITIONS_MALFORMED"],
    ["kind=01", "AUTH_CONDITION_BAD_DECIMAL"],
  ])("spec invalid vector: conditions %s", (conditions, reason) => {
    expectAuthFailure(withAuth(signEvent(), authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)), reason);
  });

  it("spec invalid vector: self-attestation", () => {
    const event = signEvent();
    expectAuthFailure(withAuth(event, authTag(AGENT_SECRET, event.pubkey)), "AUTH_SELF_ATTESTATION");
  });

  it("spec invalid vector: authorisation is not checked on an event with an invalid id or signature", () => {
    for (const field of ["id", "sig"] as const) {
      const invalid = { ...signedExample, [field]: field === "id" ? "0".repeat(64) : `${signedExample.sig.slice(0, -1)}0` };
      const result = verifyBuzzEvent(invalid);
      expect(result.event.reason).toBe(field === "id" ? "EVENT_ID_MISMATCH" : "EVENT_SIG_INVALID");
      expectAuthFailure(invalid, "AUTH_EVENT_INVALID");
    }
  });

  it("AUTH_OWNER_PUBKEY_FORMAT for uppercase and short keys", () => {
    for (const owner of ["A".repeat(64), "f".repeat(63)]) {
      const tag = authTag();
      tag[1] = owner;
      expectAuthFailure(withAuth(signEvent(), tag), "AUTH_OWNER_PUBKEY_FORMAT");
    }
  });

  it("AUTH_OWNER_PUBKEY_NOT_ON_CURVE for a formatted owner key without a point", () => {
    const tag = authTag();
    tag[1] = "00".repeat(32);
    expect(() => schnorr.utils.lift_x(BigInt(`0x${tag[1]}`))).toThrow();
    expectAuthFailure(withAuth(signEvent(), tag), "AUTH_OWNER_PUBKEY_NOT_ON_CURVE");
  });

  it("AUTH_OWNER_PUBKEY_NOT_ON_CURVE for an owner x coordinate at or above the field prime", () => {
    const outOfFieldX = "f".repeat(64);
    expect(() => schnorr.utils.lift_x(BigInt(`0x${outOfFieldX}`))).toThrow();
    const tag = authTag(OWNER_SECRET, AGENT_PUBKEY);
    tag[1] = outOfFieldX;
    const event = signEvent(AGENT_SECRET, { tags: [tag] });
    expectAuthFailure(event, "AUTH_OWNER_PUBKEY_NOT_ON_CURVE");
  });

  it.each([
    "&kind=1",
    "kind=1&&created_at<5",
    "kind=1 ",
    "kind=é",
  ])("AUTH_CONDITIONS_MALFORMED for %s", (conditions) => {
    expectAuthFailure(withAuth(signEvent(), authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)), "AUTH_CONDITIONS_MALFORMED");
  });

  it.each(["Kind=1", "kind<1", "foo=1", "created_at=5"])("AUTH_CONDITION_UNSUPPORTED for %s", (conditions) => {
    expectAuthFailure(withAuth(signEvent(), authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)), "AUTH_CONDITION_UNSUPPORTED");
  });

  it.each(["kind=", "kind=-1", "kind=+1", "kind=1e3"])("AUTH_CONDITION_BAD_DECIMAL for %s", (conditions) => {
    expectAuthFailure(withAuth(signEvent(), authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)), "AUTH_CONDITION_BAD_DECIMAL");
  });

  it.each(["kind=65536", "created_at<4294967296", `kind=${"9".repeat(100)}`])("AUTH_CONDITION_OUT_OF_RANGE for %s", (conditions) => {
    expectAuthFailure(withAuth(signEvent(), authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)), "AUTH_CONDITION_OUT_OF_RANGE");
  });

  it("accepts condition boundaries and preserves repeated clauses", () => {
    const event = signEvent(AGENT_SECRET, { kind: 65535, created_at: 4294967294 });
    const conditions = "kind=65535&created_at<4294967295&kind=65535";
    const result = verifyBuzzEvent(withAuth(event, authTag(OWNER_SECRET, event.pubkey, conditions)));
    expect(result.ok).toBe(true);
    expect(result.owner_auth.clauses).toHaveLength(3);
  });

  it("accepts empty conditions", () => {
    const event = signEvent();
    expect(verifyBuzzEvent(withAuth(event, authTag(OWNER_SECRET, event.pubkey, ""))).owner_auth.valid).toBe(true);
  });

  it("AUTH_SIG_FORMAT for uppercase or short signatures", () => {
    for (const sig of ["A".repeat(128), "f".repeat(127)]) {
      const tag = authTag();
      tag[3] = sig;
      expectAuthFailure(withAuth(signEvent(), tag), "AUTH_SIG_FORMAT");
    }
  });

  it("AUTH_SIG_INVALID when signed by another key or over different clause ordering", () => {
    const event = signEvent();
    const wrongSigner = authTag("0000000000000000000000000000000000000000000000000000000000000003", event.pubkey, "kind=1");
    wrongSigner[1] = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    expectAuthFailure(withAuth(event, wrongSigner), "AUTH_SIG_INVALID");
    const originalConditions = "created_at<1713957000&kind=1";
    const reordered = authTag(OWNER_SECRET, event.pubkey, originalConditions);
    reordered[2] = "kind=1&created_at<1713957000";
    expectAuthFailure(withAuth(event, reordered), "AUTH_SIG_INVALID");
  });

  it("AUTH_CONDITION_UNMET for kind and strict timestamp mismatches", () => {
    const event = signEvent(AGENT_SECRET, { kind: 1, created_at: 5 });
    for (const conditions of ["kind=2", "created_at<5", "created_at>5"]) {
      expectAuthFailure(withAuth(event, authTag(OWNER_SECRET, event.pubkey, conditions)), "AUTH_CONDITION_UNMET");
    }
  });

  it("evaluates each condition when the second clause fails", () => {
    const event = signEvent();
    const conditions = "kind=1&created_at<1713956400";
    const result = expectAuthFailure(withAuth(event, authTag(OWNER_SECRET, event.pubkey, conditions)), "AUTH_CONDITION_UNMET");
    expect(result.owner_auth.message).toContain("created_at<1713956400");
    expect(result.owner_auth.message).not.toContain("kind=1");
  });

  it("AUTH_EVENT_INVALID takes precedence over multiple tags on an invalid event", () => {
    const event = signEvent(AGENT_SECRET, { tags: [authTag(OWNER_SECRET, AGENT_PUBKEY), authTag("0000000000000000000000000000000000000000000000000000000000000003", AGENT_PUBKEY)] });
    event.id = "0".repeat(64);
    expectAuthFailure(event, "AUTH_EVENT_INVALID");
  });

  it("does not depend on the verifier's local clock", () => {
    const event = withAuth(signEvent(AGENT_SECRET, { created_at: 1713956400 }), authTag(OWNER_SECRET, AGENT_PUBKEY, "created_at<1713957000"));
    const results: boolean[] = [];
    try {
      for (const timestamp of ["1970-01-01T00:00:00.000Z", "2024-04-24T00:00:00.000Z", "2100-01-01T00:00:00.000Z"]) {
        vi.useFakeTimers();
        vi.setSystemTime(new Date(timestamp));
        results.push(verifyBuzzEvent(event).ok);
      }
    } finally {
      vi.useRealTimers();
    }
    expect(results).toEqual([true, true, true]);
  });

  it("parseConditions exposes clauses with exact text and values", () => {
    expect(parseConditions("kind=1&created_at<5")).toMatchObject({
      ok: true,
      clauses: [
        { clause: "kind=1", field: "kind", op: "=", value: 1 },
        { clause: "created_at<5", field: "created_at", op: "<", value: 5 },
      ],
    });
  });
});
