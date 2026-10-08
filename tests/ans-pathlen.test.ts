import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { readBasicConstraints } from "../src/ans/basic-constraints.js";
import { verifyAnsBinding } from "../src/ans/verify.js";
import { buildAnsEvidence } from "./ans-build.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function pemBlocks(value: string): string[] {
  return value.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

describe("RFC 5280 path length", () => {
  it("rejects a pathlen-0 root that signed an intermediate, as openssl verify does", () => {
    const built = buildAnsEvidence({ intermediate: true, anchorPathLen: 0 });
    const directory = mkdtempSync(path.join(tmpdir(), "zipviz-ans-pathlen-"));
    directories.push(directory);
    const root = path.join(directory, "root.pem");
    const middle = path.join(directory, "mid.pem");
    const leaf = path.join(directory, "leaf.pem");
    writeFileSync(root, built.evidence.trustAnchorPem);
    writeFileSync(middle, built.intermediatePem ?? "");
    writeFileSync(leaf, pemBlocks(built.evidence.identityChainPem)[0] ?? "");
    const openssl = spawnSync("openssl", ["verify", "-CAfile", root, "-untrusted", middle, leaf], { encoding: "utf8" });
    expect(openssl.status).not.toBe(0);
    expect(`${openssl.stdout}${openssl.stderr}`).toMatch(/path length constraint exceeded/i);

    const anchor = new X509Certificate(built.evidence.trustAnchorPem);
    expect(readBasicConstraints(anchor)).toEqual({ ca: true, pathLen: 0 });
    const result = verifyAnsBinding(built.name, built.evidence);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("ANS_CERT_UNTRUSTED");
    expect(result.message).toBe("certificate path length constraint exceeded");
    expect(result.reason).not.toBe("ANS_REVOCATION_NOT_CHECKED");
  });

  it("accepts a leaf signed by a pathlen-0 root and one intermediate under pathlen 1", () => {
    const direct = buildAnsEvidence({ anchorPathLen: 0 });
    expect(verifyAnsBinding(direct.name, direct.evidence).reason).toBe("ANS_REVOCATION_NOT_CHECKED");
    const oneHop = buildAnsEvidence({ intermediate: true, anchorPathLen: 1 });
    expect(readBasicConstraints(new X509Certificate(oneHop.evidence.trustAnchorPem)).pathLen).toBe(1);
    expect(verifyAnsBinding(oneHop.name, oneHop.evidence).reason).toBe("ANS_REVOCATION_NOT_CHECKED");
  });
});
