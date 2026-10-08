import { readFileSync } from "node:fs";
import { base64urlnopad } from "@scure/base";
import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalizeJson } from "../src/a2a/jcs.js";
import { fromHex, toHex } from "../src/ans/bytes.js";
import { eventLeafHash } from "../src/ans/leaf.js";
import { leafHash } from "../src/ans/merkle.js";
import { parseSha256Fingerprint } from "../src/ans/certificate.js";
import { badgeSignaturePayload, rootSignaturePayload } from "../src/ans/signature.js";
import { ANS_DRAFT, verifyAnsBinding, type AnsEvidence } from "../src/ans/verify.js";
import { buildAnsEvidence, signDetached } from "./ans-build.js";

const encoder = new TextEncoder();
const draftDir = new URL("./fixtures/ans/draft-narajala-courtney-ansv2-01/", import.meta.url);

function evidenceWith(base: AnsEvidence, badge: unknown): AnsEvidence {
  return { ...base, badge };
}

describe("ANS binding verification", () => {
  it("locks the JCS leaf and lowercase-hex root payload conventions", () => {
    const event = { b: 1, a: 2 };
    const canonical = canonicalizeJson(event);
    expect(canonical).toBe('{"a":2,"b":1}');
    expect(toHex(eventLeafHash(event))).toBe(toHex(leafHash(encoder.encode(canonical))));
    const root = fromHex("ab".repeat(32));
    expect(root).toBeDefined();
    expect(new TextDecoder().decode(rootSignaturePayload(root!))).toBe(`"${"ab".repeat(32)}"`);
  });

  it("checks the certificate and inclusion proof without calling the name currently verified", () => {
    const built = buildAnsEvidence({ intermediate: true });
    const result = verifyAnsBinding(built.name, built.evidence);
    expect(result).toMatchObject({
      valid: false,
      reason: "ANS_REVOCATION_NOT_CHECKED",
      draft: ANS_DRAFT,
      name: built.name,
      version: "1.5.0",
      host: "support.example.com",
      certificate: { valid: true, fingerprint_sha256: built.fingerprint },
      transparency_log: {
        valid: true,
        leaf_index: 3,
        tree_size: 7,
        event_type: "AGENT_REGISTERED",
        status: "ACTIVE",
        ra_id: "id-A",
        ra_kid: "ra-1",
        kms_kid: "kms-1",
      },
      scope: {
        identity_certificate: "checked",
        transparency_log: "checked",
        producer_signature: "not checked",
        revocation: "not checked",
        live_log: "not proved",
        dane: "not checked",
        reputation: "not checked",
        behaviour: "not checked",
      },
    });
    expect(result.pins?.ca_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result).not.toHaveProperty("score");
    expect(JSON.stringify(result)).not.toMatch(/\bverified\b/i);
    expect(JSON.stringify(result)).not.toContain(built.raPrivate.d);
  });

  it("does not pass a renewal or an unsigned status, and rejects a signed revocation", () => {
    const renewed = buildAnsEvidence({ eventType: "AGENT_RENEWED" });
    expect(verifyAnsBinding(renewed.name, renewed.evidence).reason).toBe("ANS_REVOCATION_NOT_CHECKED");
    const deprecated = buildAnsEvidence({ status: "DEPRECATED" });
    expect(verifyAnsBinding(deprecated.name, deprecated.evidence).reason).toBe("ANS_REVOCATION_NOT_CHECKED");
    const revoked = buildAnsEvidence({ status: "REVOKED", eventType: "AGENT_REVOKED" });
    const revokedResult = verifyAnsBinding(revoked.name, revoked.evidence);
    expect(revokedResult).toMatchObject({
      valid: false,
      reason: "ANS_REVOKED",
      transparency_log: { valid: true, event_type: "AGENT_REVOKED" },
    });
    const expired = buildAnsEvidence({ status: "EXPIRED", eventType: "AGENT_REGISTERED" });
    expect(verifyAnsBinding(expired.name, expired.evidence).reason).toBe("ANS_EXPIRED");
  });

  it("fails closed on certificate, event, proof, and signature mismatches", () => {
    const built = buildAnsEvidence();
    const other = buildAnsEvidence();
    expect(verifyAnsBinding(built.name, { ...built.evidence, trustAnchorPem: other.evidence.trustAnchorPem }).reason).toBe("ANS_CERT_UNTRUSTED");
    expect(verifyAnsBinding("ans://v9.9.9.support.example.com", built.evidence).reason).toBe("ANS_NAME_UNBOUND");

    const host = structuredClone(built.evidence.badge) as { payload: { producer: { event: { agent: { host: string } } } } };
    host.payload.producer.event.agent.host = "other.example.com";
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, host)).reason).toBe("ANS_EVENT_MISMATCH");

    const fingerprint = structuredClone(built.evidence.badge) as { payload: { producer: { event: { attestations: { identityCert: { fingerprint: string } } } } } };
    fingerprint.payload.producer.event.attestations.identityCert.fingerprint = `SHA256:${"ab".repeat(32)}`;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, fingerprint)).reason).toBe("ANS_FINGERPRINT_MISMATCH");

    const path = structuredClone(built.evidence.badge) as { inclusionProof: { path: string[] } };
    path.inclusionProof.path[0] = `${path.inclusionProof.path[0]!.slice(0, -1)}${path.inclusionProof.path[0]!.endsWith("0") ? "1" : "0"}`;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, path)).reason).toBe("ANS_PROOF_INVALID");

    const signature = structuredClone(built.evidence.badge) as { inclusionProof: { rootSignature: string } };
    const [protectedPart, signaturePart] = signature.inclusionProof.rootSignature.split("..");
    const signatureBytes = base64urlnopad.decode(signaturePart!);
    signatureBytes[0] = signatureBytes[0]! ^ 0xff;
    signature.inclusionProof.rootSignature = `${protectedPart}..${base64urlnopad.encode(signatureBytes)}`;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, signature)).reason).toBe("ANS_SIGNATURE_INVALID");

    const upper = structuredClone(built.evidence.badge) as { inclusionProof: { rootHash: string } };
    upper.inclusionProof.rootHash = upper.inclusionProof.rootHash.toUpperCase();
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, upper)).reason).toBe("ANS_REVOCATION_NOT_CHECKED");

    const leaf = new X509Certificate(built.evidence.identityChainPem);
    expect(verifyAnsBinding(built.name, { ...built.evidence, now: Date.parse(leaf.validTo) + 60_000 }).reason).toBe("ANS_CERT_EXPIRED");
    expect(verifyAnsBinding(built.name, { ...built.evidence, now: Date.parse(leaf.validFrom) - 60_000 }).reason).toBe("ANS_CERT_NOT_YET_VALID");
    const past = buildAnsEvidence({ expiresAt: "2020-01-01T00:00:00Z" });
    expect(verifyAnsBinding(past.name, past.evidence).reason).toBe("ANS_EXPIRED");
    expect(verifyAnsBinding(built.name, { ...built.evidence, raKey: built.raPrivate }).reason).toBe("ANS_KEY_INVALID");
  });

  it("does not treat the draft appendix as a verifiable vector", () => {
    const text = readFileSync(new URL("a4-badge.txt", draftDir), "utf8");
    expect(text).toContain('"leafIndex": 1234567');
    expect(text).toContain('"treeSize": 9876543');
    expect(text).toContain("...same structure as A.3...");
    expect(() => JSON.parse(text)).toThrow();

    const event = JSON.parse(readFileSync(new URL("a3-event.json", draftDir), "utf8")) as { ansName: string; attestations: { identityCert: { fingerprint: string } } };
    expect(event.ansName).toBe("ans://v1.5.0.support.example.com");
    expect(event.attestations.identityCert.fingerprint).toBe("SHA256:22b8a804...");
    expect(parseSha256Fingerprint(event.attestations.identityCert.fingerprint)).toBeUndefined();
    const truncated = JSON.parse(readFileSync(new URL("a4-truncated.json", draftDir), "utf8")) as unknown;
    const built = buildAnsEvidence({ host: "support.example.com", version: "1.5.0" });
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, truncated)).reason).toBe("ANS_PROOF_INVALID");
    const swapped = structuredClone(built.evidence.badge) as { payload: { producer: { event: { attestations: { identityCert: { fingerprint: string } } } } } };
    swapped.payload.producer.event.attestations.identityCert.fingerprint = event.attestations.identityCert.fingerprint;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, swapped)).reason).toBe("ANS_FINGERPRINT_MISMATCH");

    const repaired = structuredClone(truncated) as { payload: { producer: { event: { attestations: { identityCert: { fingerprint: string } } } } } };
    repaired.payload.producer.event.attestations.identityCert.fingerprint = `SHA256:${built.fingerprint}`;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, repaired)).reason).toBe("ANS_PROOF_INVALID");
  });
});

type Badge = {
  status: string;
  signature: string;
  payload: {
    producer: {
      event: {
        ansName: string;
        raId: string;
        agent: { version: string };
        issuedAt?: string;
      };
    };
  };
  inclusionProof?: {
    leafHash: string;
    leafIndex: number;
    path: string[];
    rootSignature: string;
  };
};

function badgeOf(evidence: AnsEvidence): Badge {
  return structuredClone(evidence.badge) as Badge;
}

function flipCompact(compact: string): string {
  const [protectedPart, signaturePart] = compact.split("..");
  const bytes = base64urlnopad.decode(signaturePart!);
  bytes[0] = bytes[0]! ^ 0xff;
  return `${protectedPart}..${base64urlnopad.encode(bytes)}`;
}

describe("ANS negative checks", () => {
  it("does not report a revoked or status-flipped badge as verified", () => {
    const built = buildAnsEvidence({ status: "REVOKED", eventType: "AGENT_REGISTERED" });
    const asserted = verifyAnsBinding(built.name, built.evidence);
    expect(asserted.valid).toBe(false);
    expect(asserted.reason).toBe("ANS_REVOKED");
    expect(JSON.stringify(asserted)).not.toMatch(/\bverified\b/i);

    const flipped = badgeOf(built.evidence);
    flipped.status = "ACTIVE";
    const result = verifyAnsBinding(built.name, evidenceWith(built.evidence, flipped));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("ANS_REVOCATION_NOT_CHECKED");
    expect(result.transparency_log).toMatchObject({ valid: true, status: "ACTIVE", event_type: "AGENT_REGISTERED" });
    expect(result.scope).toMatchObject({ revocation: "not checked", live_log: "not proved" });
    expect(JSON.stringify(result)).not.toMatch(/\bverified\b/i);

    const stale = buildAnsEvidence({ status: "ACTIVE", eventType: "AGENT_REGISTERED" });
    expect(verifyAnsBinding(stale.name, stale.evidence)).toMatchObject({
      valid: false,
      reason: "ANS_REVOCATION_NOT_CHECKED",
      transparency_log: { valid: true },
    });
  });

  it("fails closed on signature, identity, proof, and certificate-chain defects", () => {
    const built = buildAnsEvidence({ intermediate: true });
    const raFlipped = badgeOf(built.evidence);
    raFlipped.signature = flipCompact(raFlipped.signature);
    const forged = verifyAnsBinding(built.name, evidenceWith(built.evidence, raFlipped));
    expect(forged.reason).toBe("ANS_SIGNATURE_INVALID");
    expect(forged.transparency_log?.valid).not.toBe(true);

    const other = buildAnsEvidence();
    expect(verifyAnsBinding(built.name, { ...built.evidence, kmsKey: other.evidence.kmsKey }).reason).toBe("ANS_SIGNATURE_INVALID");

    const mismatched = badgeOf(built.evidence);
    mismatched.signature = signDetached(
      badgeSignaturePayload(mismatched.payload as never),
      { alg: "ES256", kid: built.raPrivate.kid!, raId: "other-ra", timestamp: Math.floor(built.now / 1000), typ: "ans-badge" },
      built.raPrivate,
    );
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, mismatched)).reason).toBe("ANS_EVENT_MISMATCH");

    const version = badgeOf(built.evidence);
    version.payload.producer.event.agent.version = "v9.9.9";
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, version)).reason).toBe("ANS_EVENT_MISMATCH");
    const renamed = badgeOf(built.evidence);
    renamed.payload.producer.event.ansName = "ans://v1.5.0.other.example.com";
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, renamed)).reason).toBe("ANS_EVENT_MISMATCH");

    const future = buildAnsEvidence({ issuedAt: "2099-01-01T00:00:00Z" });
    expect(verifyAnsBinding(future.name, future.evidence).reason).toBe("ANS_EVENT_MISMATCH");

    const otherEntry = badgeOf(built.evidence);
    otherEntry.inclusionProof!.leafIndex = built.alternateProof.leafIndex;
    otherEntry.inclusionProof!.path = built.alternateProof.path;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, otherEntry)).reason).toBe("ANS_PROOF_INVALID");
    const wrongIndex = badgeOf(built.evidence);
    wrongIndex.inclusionProof!.leafIndex = built.alternateProof.leafIndex;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, wrongIndex)).reason).toBe("ANS_PROOF_INVALID");

    const missing = badgeOf(built.evidence);
    delete missing.inclusionProof;
    expect(verifyAnsBinding(built.name, evidenceWith(built.evidence, missing)).reason).toBe("ANS_INPUT_INVALID");

    expect(verifyAnsBinding(built.name, {
      ...built.evidence,
      identityChainPem: built.intermediatePem!,
    }).message).toContain("identity certificate is a CA");

    const plainMiddle = buildAnsEvidence({ intermediate: true, intermediateCa: false });
    expect(verifyAnsBinding(plainMiddle.name, plainMiddle.evidence).message).toContain("intermediate certificate is not a CA");

    const plainAnchor = buildAnsEvidence({ anchorCa: false });
    expect(verifyAnsBinding(plainAnchor.name, plainAnchor.evidence).message).toContain("trust anchor is not a self-signed CA");

    const shortAnchor = buildAnsEvidence({ caDays: 1, leafDays: 30 });
    const anchorExpiry = Date.parse(new X509Certificate(shortAnchor.evidence.trustAnchorPem).validTo) + 60_000;
    expect(Date.parse(new X509Certificate(shortAnchor.evidence.identityChainPem).validTo)).toBeGreaterThan(anchorExpiry);
    expect(verifyAnsBinding(shortAnchor.name, { ...shortAnchor.evidence, now: anchorExpiry }).message).toContain("trust anchor has expired");

    const shortMiddle = buildAnsEvidence({ intermediate: true, midDays: 1, leafDays: 30, caDays: 30 });
    const middleExpiry = Date.parse(new X509Certificate(shortMiddle.intermediatePem!).validTo) + 60_000;
    expect(verifyAnsBinding(shortMiddle.name, { ...shortMiddle.evidence, now: middleExpiry }).message).toContain("intermediate certificate has expired");
  });
});
