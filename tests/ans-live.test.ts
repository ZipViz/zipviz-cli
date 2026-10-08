import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyAnsBinding, type AnsEvidence } from "../src/ans/verify.js";

const fixture = new URL("./fixtures/ans/godaddy-live-v1/", import.meta.url);
const text = (file: string) => readFileSync(new URL(file, fixture), "utf8");
const provenance = JSON.parse(text("provenance.json")) as { name: string; verificationTime: string };
const evidence: AnsEvidence = {
  badge: JSON.parse(text("badge.json")),
  identityChainPem: text("identity-chain.pem"), trustAnchorPem: text("ca.pem"),
  raKey: JSON.parse(text("log-key.jwk")), kmsKey: JSON.parse(text("log-key.jwk")),
  now: Date.parse(provenance.verificationTime),
};

describe("captured GoDaddy V1 badge", () => {
  it("checks real certificate/log binding while leaving revocation unchecked", () => {
    expect(verifyAnsBinding(provenance.name, evidence)).toMatchObject({
      valid: false, reason: "ANS_REVOCATION_NOT_CHECKED",
      certificate: { valid: true }, transparency_log: { valid: true },
      scope: { producer_signature: "not checked", revocation: "not checked", live_log: "not proved" },
    });
  });
});

// All fixtures below are derived from public data; no live request is made by tests.
import { base64urlnopad } from "@scure/base";
import { canonicalizeJson } from "../src/a2a/jcs.js";
import { readPinnedKey, producerHeader, verifyDetachedEs256, badgeSignaturePayload } from "../src/ans/signature.js";
import { eventLeafHash } from "../src/ans/leaf.js";
import { toHex } from "../src/ans/bytes.js";
import { buildAnsEvidence, signDetached } from "./ans-build.js";
import { run, type Deps } from "../src/main.js";

type LiveBadge = {
  schemaVersion: string; status: string; signature: string;
  payload: { logId: string; producer: { keyId: string; signature: string; event: Record<string, unknown> } };
  merkleProof: { leafHash: string; leafIndex: number; treeSize: number; treeVersion: number; path: string[]; rootHash: string; rootSignature: string };
};
const clone = () => structuredClone(evidence.badge) as LiveBadge;
const encode = (s: string) => base64urlnopad.encode(new TextEncoder().encode(s));
function changeHeader(compact: string, mutate: (header: Record<string, unknown>) => void): string {
  const parts = compact.split(".");
  const h = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(parts[0]!))) as Record<string, unknown>;
  mutate(h); parts[0] = encode(canonicalizeJson(h as never)); return parts.join(".");
}
function flip(compact: string): string {
  const p = compact.split("."); const bytes = base64urlnopad.decode(p[2]!);
  bytes[0] = bytes[0]! ^ 1; p[2] = base64urlnopad.encode(bytes); return p.join(".");
}

describe("live profile strictness", () => {
  it.each([
    ["leaf", (b: LiveBadge) => { b.merkleProof.leafHash = "00".repeat(32); }],
    ["root", (b: LiveBadge) => { b.merkleProof.rootHash = Buffer.alloc(32).toString("base64"); }],
    ["path", (b: LiveBadge) => { b.merkleProof.path[0] = Buffer.alloc(32).toString("base64"); }],
    ["missing path", (b: LiveBadge) => { b.merkleProof.path.pop(); }],
    ["extra path", (b: LiveBadge) => { b.merkleProof.path.push(Buffer.alloc(32).toString("base64")); }],
    ["leaf index", (b: LiveBadge) => { b.merkleProof.leafIndex++; }],
    ["tree size", (b: LiveBadge) => { b.merkleProof.treeSize++; }],
    ["tree version", (b: LiveBadge) => { b.merkleProof.treeVersion = 2; }],
    ["hex path alias", (b: LiveBadge) => { b.merkleProof.path[0] = "00".repeat(32); }],
    ["unpadded root", (b: LiveBadge) => { b.merkleProof.rootHash = b.merkleProof.rootHash.slice(0, -1); }],
    ["root signature", (b: LiveBadge) => { b.merkleProof.rootSignature = flip(b.merkleProof.rootSignature); }],
    ["log signature", (b: LiveBadge) => { b.signature = flip(b.signature); }],
    ["producer signature", (b: LiveBadge) => { b.payload.producer.signature = flip(b.payload.producer.signature); }],
    ["name", (b: LiveBadge) => { b.payload.producer.event.ansName = "ans://v1.0.0.other.goos.ag"; }],
    ["certificate fingerprint", (b: LiveBadge) => { (b.payload.producer.event.attestations as { identityCert: { fingerprint: string } }).identityCert.fingerprint = `SHA256:${"00".repeat(32)}`; }],
  ] as const)("rejects a real badge with altered %s", (_, mutate) => {
    const b = clone(); mutate(b);
    const result = verifyAnsBinding(provenance.name, { ...evidence, badge: b });
    expect(result.reason).not.toBe("ANS_REVOCATION_NOT_CHECKED");
    expect(result.transparency_log?.valid).not.toBe(true);
  });

  it("rejects ambiguous proof profiles and untrusted log pins", () => {
    const b = clone();
    expect(verifyAnsBinding(provenance.name, { ...evidence, badge: { ...b, inclusionProof: b.merkleProof } }).reason).toBe("ANS_INPUT_INVALID");
    const wrong = { ...(evidence.raKey as Record<string, unknown>), kid: "wrong" };
    expect(verifyAnsBinding(provenance.name, { ...evidence, raKey: wrong }).reason).toBe("ANS_SIGNATURE_INVALID");
    expect(verifyAnsBinding(provenance.name, { ...evidence, kmsKey: wrong }).reason).toBe("ANS_SIGNATURE_INVALID");
  });

  it.each([
    ["camel-case alias", (h: Record<string, unknown>) => { h.raId = h.raid; delete h.raid; }],
    ["both spellings", (h: Record<string, unknown>) => { h.raId = h.raid; }],
    ["algorithm", (h: Record<string, unknown>) => { h.alg = "none"; }],
    ["type", (h: Record<string, unknown>) => { h.typ = "ans-badge"; }],
    ["key referral", (h: Record<string, unknown>) => { h.jku = "https://example.com/key"; }],
    ["timestamp", (h: Record<string, unknown>) => { h.timestamp = 1.5; }],
  ] as const)("rejects live header %s before signature verification", (_, mutate) => {
    const compact = changeHeader(clone().signature, mutate);
    expect(() => verifyDetachedEs256(compact, new Uint8Array(), readPinnedKey(evidence.raKey, "log"), true)).toThrow();
    expect(() => producerHeader(compact)).toThrow();
  });

  it("rejects duplicate or noncanonical protected JSON", () => {
    const b = clone(); const p = b.signature.split(".");
    const raw = new TextDecoder().decode(base64urlnopad.decode(p[0]!));
    p[0] = encode(raw.replace('{', '{"alg":"ES256",'));
    expect(() => producerHeader(p.join("."))).toThrow();
    p[0] = encode(` ${raw}`);
    expect(() => producerHeader(p.join("."))).toThrow();
  });

  it("binds producer authority and kid inside an otherwise valid log envelope", () => {
    const built = buildAnsEvidence();
    const old = built.evidence.badge as { payload: LiveBadge["payload"] };
    const stamp = Math.floor(built.now / 1000);
    const producer = (raid: string, kid: string) => signDetached(badgeSignaturePayload(old.payload.producer.event as never),
      { alg: "ES256", kid, raid, timestamp: stamp, typ: "JWT" }, built.raPrivate);
    const make = (raid: string, kid = built.raPrivate.kid!, changeCheckpoint?: (p: Record<string, unknown>) => void) => {
      const payload = structuredClone(old.payload);
      payload.producer.keyId = built.raPrivate.kid!;
      payload.producer.signature = producer(raid, kid);
      const header = { alg: "ES256", kid: built.kmsPrivate.kid!, raid: "separate-log-authority", timestamp: stamp, typ: "JWT" };
      const signature = signDetached(badgeSignaturePayload({ payload, schemaVersion: "V1" } as never), header, built.kmsPrivate);
      const envelope = { payload, schemaVersion: "V1", signature };
      const leaf = eventLeafHash(envelope as never);
      const checkpointObject = { checkpointFormat: "c2sp/v1", origin: "transparency.ans.godaddy.com", rootHash: `${base64urlnopad.encode(leaf)}=`, timestamp: stamp, treesize: 1 };
      changeCheckpoint?.(checkpointObject);
      const checkpoint = badgeSignaturePayload(checkpointObject);
      const rootSignature = signDetached(checkpoint, header, built.kmsPrivate).replace("..", `.${base64urlnopad.encode(checkpoint)}.`);
      const badge = { ...envelope, status: "ACTIVE", merkleProof: { leafHash: toHex(leaf), leafIndex: 0, treeSize: 1, treeVersion: 1, path: [], rootHash: Buffer.from(leaf).toString("base64"), rootSignature } };
      return { ...built.evidence, badge, raKey: built.evidence.kmsKey };
    };
    expect(verifyAnsBinding(built.name, make("id-A")).reason).toBe("ANS_REVOCATION_NOT_CHECKED");
    expect(verifyAnsBinding(built.name, make("wrong-authority")).reason).toBe("ANS_EVENT_MISMATCH");
    expect(verifyAnsBinding(built.name, make("id-A", "wrong-kid")).reason).toBe("ANS_EVENT_MISMATCH");
    for (const mutate of [
      (p: Record<string, unknown>) => { p.origin = "other.example.com"; },
      (p: Record<string, unknown>) => { p.checkpointFormat = "other/v1"; },
      (p: Record<string, unknown>) => { p.timestamp = stamp + 1; },
      (p: Record<string, unknown>) => { p.treesize = 2; },
      (p: Record<string, unknown>) => { p.rootHash = base64urlnopad.encode(new Uint8Array(32)); },
      (p: Record<string, unknown>) => { p.extra = true; },
    ]) {
      // Every altered checkpoint has a valid pinned-key signature: semantic binding must fail.
      expect(verifyAnsBinding(built.name, make("id-A", built.raPrivate.kid!, mutate)).reason).toBe("ANS_PROOF_INVALID");
    }
  });
});

it("returns exit 10 / binding_checked true for real data and exit 7 for its tampered copy", async () => {
  // Keep the capture time fixed so certificate expiry does not rot the fixture.
  const { vi } = await import("vitest"); vi.spyOn(Date, "now").mockReturnValue(evidence.now!);
  try {
    const execute = async (badge: unknown) => {
      const output: string[] = [];
      const deps: Deps = { stdout: s => output.push(s), stderr: () => {},
        fetch: async () => { throw new Error("no live requests"); }, zipvizHome: "/tmp/unused-ans-live",
        readStdin: async () => new TextEncoder().encode(JSON.stringify({ badge, identityChainPem: evidence.identityChainPem })) };
      const code = await run(["check", "--ans", provenance.name, "--json", "--bundle", "-", "--ca", new URL("ca.pem", fixture).pathname,
        "--ra-jwk", new URL("log-key.jwk", fixture).pathname, "--kms-jwk", new URL("log-key.jwk", fixture).pathname], deps);
      return { code, body: JSON.parse(output.join("")) as Record<string, unknown> };
    };
    expect(await execute(evidence.badge)).toMatchObject({ code: 10, body: { binding_checked: true, valid: false, reason: "ANS_REVOCATION_NOT_CHECKED" } });
    const bad = clone(); bad.merkleProof.rootSignature = flip(bad.merkleProof.rootSignature);
    expect(await execute(bad)).toMatchObject({ code: 7, body: { binding_checked: false, reason: "ANS_SIGNATURE_INVALID" } });
  } finally { vi.restoreAllMocks(); }
});

it("accepts a signed 514-character checkpoint with a 100,000,000-leaf proof", async () => {
  const { createHash } = await import("node:crypto");
  const { verifyLiveCheckpoint } = await import("../src/ans/signature.js");
  const built = buildAnsEvidence();
  const payload = structuredClone((built.evidence.badge as { payload: LiveBadge["payload"] }).payload);
  const stamp = Math.floor(built.now / 1000);
  const logKey = { ...(built.evidence.kmsKey as Record<string, unknown>), kid: "logkey01" };
  const header = { alg: "ES256", kid: "logkey01", raid: `RA-TL-${"a".repeat(64)}`, timestamp: stamp, typ: "JWT" };
  payload.producer.keyId = built.raPrivate.kid!;
  payload.producer.signature = signDetached(badgeSignaturePayload(payload.producer.event as never),
    { alg: "ES256", kid: built.raPrivate.kid!, raid: "id-A", timestamp: stamp, typ: "JWT" }, built.raPrivate);
  const signature = signDetached(badgeSignaturePayload({ payload, schemaVersion: "V1" } as never), header, built.kmsPrivate);
  const envelope = { payload, schemaVersion: "V1", signature };
  const leaf = eventLeafHash(envelope as never);
  const treeSize = 100_000_000;
  // A first-leaf proof for this size has 27 sibling subtrees; no huge tree allocation.
  const path = Array.from({ length: 27 }, (_, index) => Buffer.alloc(32, index + 1));
  let root: Uint8Array = leaf;
  for (const sibling of path) root = createHash("sha256").update(Buffer.concat([Buffer.from([1]), root, sibling])).digest();
  const checkpoint = badgeSignaturePayload({ checkpointFormat: "c2sp/v1", origin: "transparency.ans.godaddy.com",
    rootHash: `${base64urlnopad.encode(root)}=`, timestamp: stamp, treesize: treeSize });
  const rootSignature = signDetached(checkpoint, header, built.kmsPrivate).replace("..", `.${base64urlnopad.encode(checkpoint)}.`);
  expect(rootSignature.length).toBe(514);
  expect(verifyLiveCheckpoint(rootSignature, root, treeSize, readPinnedKey(logKey, "log")).kid).toBe("logkey01");
  const badge = { ...envelope, status: "ACTIVE", merkleProof: { leafHash: toHex(leaf), leafIndex: 0,
    treeSize, treeVersion: 1, path: path.map(node => node.toString("base64")), rootHash: Buffer.from(root).toString("base64"), rootSignature } };
  const valid = verifyAnsBinding(built.name, { ...built.evidence, badge, raKey: logKey, kmsKey: logKey });
  expect(valid).toMatchObject({ reason: "ANS_REVOCATION_NOT_CHECKED", transparency_log: { valid: true, tree_size: treeSize } });

});

it("rejects attached checkpoints exceeding the total or individual segment caps", () => {
  const badge = clone();
  // Existing parser limits: header 8192 + payload 8192 + signature 512 + two separators.
  badge.merkleProof.rootSignature = "a".repeat(8192 + 8192 + 512 + 3);
  expect(verifyAnsBinding(provenance.name, { ...evidence, badge }))
    .toMatchObject({ reason: "ANS_INPUT_INVALID", message: "rootSignature must be a non-empty string" });
  const parts = clone().merkleProof.rootSignature.split(".");
  parts[1] = "a".repeat(8193);
  badge.merkleProof.rootSignature = parts.join(".");
  expect(verifyAnsBinding(provenance.name, { ...evidence, badge }).reason).toBe("ANS_SIG_MALFORMED");
});
