import { execFileSync } from "node:child_process";
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { base64urlnopad } from "@scure/base";
import { canonicalizeJson, type JsonValue } from "../src/a2a/jcs.js";
import type { JsonObject } from "../src/a2a/schema.js";
import type { EcPrivateJwk, EcPublicJwk } from "../src/a2a/jwk.js";
import { signJws } from "../src/a2a/jws.js";
import { toHex } from "../src/ans/bytes.js";
import { eventLeafHash } from "../src/ans/leaf.js";
import { inclusionProof, leafHash, merkleRoot } from "../src/ans/merkle.js";
import { badgeSignaturePayload, rootSignaturePayload } from "../src/ans/signature.js";
import type { AnsEvidence } from "../src/ans/verify.js";

const encoder = new TextEncoder();

export type BuiltAns = {
  name: string;
  now: number;
  evidence: AnsEvidence;
  raPrivate: EcPrivateJwk;
  kmsPrivate: EcPrivateJwk;
  fingerprint: string;
  intermediatePem?: string;
  alternateProof: { leafIndex: number; path: string[]; leafHash: string };
};

type BuildOptions = {
  host?: string;
  version?: string;
  status?: "ACTIVE" | "DEPRECATED" | "REVOKED" | "EXPIRED";
  eventType?: "AGENT_REGISTERED" | "AGENT_RENEWED" | "AGENT_REVOKED";
  leafIndex?: number;
  extraLeaves?: number;
  intermediate?: boolean;
  intermediateCa?: boolean;
  anchorCa?: boolean;
  /** RFC 5280 pathLenConstraint on the pinned CA. Omitted means no limit. */
  anchorPathLen?: number;
  caDays?: number;
  midDays?: number;
  leafDays?: number;
  producerSignature?: string;
  issuedAt?: string;
  expiresAt?: string;
  san?: string;
};

function p256(kid: string): { publicKey: EcPublicJwk; privateKey: EcPrivateJwk } {
  const exported = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const base = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: String(exported.x),
    y: String(exported.y),
    kid,
    alg: "ES256",
  };
  return { publicKey: base, privateKey: { ...base, d: String(exported.d) } };
}

export function signDetached(payload: Uint8Array, header: JsonObject, privateKey: EcPrivateJwk): string {
  const protectedJson = canonicalizeJson(header);
  const protectedB64 = base64urlnopad.encode(encoder.encode(protectedJson));
  const signature = signJws("ES256", encoder.encode(`${protectedB64}.${base64urlnopad.encode(payload)}`), privateKey);
  return `${protectedB64}..${base64urlnopad.encode(signature)}`;
}

function header(kid: string, raId: string, timestamp: number, typ: string): JsonObject {
  return { alg: "ES256", kid, raId, timestamp, typ };
}

function openssl(cwd: string, args: string[]): void {
  execFileSync("openssl", args, { cwd, stdio: "pipe" });
}

function certificates(dir: string, name: string, san: string, options: BuildOptions): { leaf: string; chain: string; anchor: string; intermediate?: string } {
  const anchorCa = options.anchorCa !== false;
  const pathLen = options.anchorPathLen === undefined ? "" : `,pathlen:${options.anchorPathLen}`;
  openssl(dir, [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", String(options.caDays ?? 30),
    "-subj", "/CN=ANS Test Private CA",
    "-addext", anchorCa ? `basicConstraints=critical,CA:TRUE${pathLen}` : "basicConstraints=critical,CA:FALSE",
    "-addext", anchorCa ? "keyUsage=critical,keyCertSign,cRLSign" : "keyUsage=critical,digitalSignature",
    "-addext", "subjectKeyIdentifier=hash",
    "-keyout", "ca.key", "-out", "ca.pem",
  ]);
  const intermediate = options.intermediate === true;
  const issuerKey = intermediate ? "mid.key" : "ca.key";
  const issuerPem = intermediate ? "mid.pem" : "ca.pem";
  if (intermediate) {
    const midCa = options.intermediateCa !== false;
    openssl(dir, ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "mid.key", "-subj", "/CN=ANS Test Intermediate", "-out", "mid.csr"]);
    writeFileSync(path.join(dir, "mid.cnf"), `${midCa ? "basicConstraints=critical,CA:TRUE,pathlen:0" : "basicConstraints=critical,CA:FALSE"}\nkeyUsage=critical,${midCa ? "keyCertSign,cRLSign" : "digitalSignature"}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`);
    openssl(dir, ["x509", "-req", "-in", "mid.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "mid.pem", "-days", String(options.midDays ?? 30), "-extfile", "mid.cnf"]);
  }
  openssl(dir, ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "leaf.key", "-subj", `/CN=${name}`, "-out", "leaf.csr"]);
  writeFileSync(path.join(dir, "leaf.cnf"), `basicConstraints=CA:FALSE\nsubjectAltName=URI:${san}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`);
  openssl(dir, ["x509", "-req", "-in", "leaf.csr", "-CA", issuerPem, "-CAkey", issuerKey, "-CAcreateserial", "-out", "leaf.pem", "-days", String(options.leafDays ?? 30), "-extfile", "leaf.cnf"]);
  const leaf = readFileSync(path.join(dir, "leaf.pem"), "utf8");
  const mid = intermediate ? readFileSync(path.join(dir, "mid.pem"), "utf8") : undefined;
  return { leaf, chain: mid === undefined ? leaf : `${leaf}${mid}`, anchor: readFileSync(path.join(dir, "ca.pem"), "utf8"), intermediate: mid };
}

export function buildAnsEvidence(options: BuildOptions = {}): BuiltAns {
  const host = options.host ?? "support.example.com";
  const version = options.version ?? "1.5.0";
  const name = `ans://v${version}.${host}`;
  const dir = mkdtempSync(path.join(tmpdir(), "zipviz-ans-"));
  try {
    const issued = certificates(dir, host, options.san ?? name, options);
    const leafCert = new X509Certificate(issued.leaf);
    const anchorCert = new X509Certificate(issued.anchor);
    const notBefore = Math.max(Date.parse(leafCert.validFrom), Date.parse(anchorCert.validFrom));
    const notAfter = Math.min(Date.parse(leafCert.validTo), Date.parse(anchorCert.validTo));
    const now = notBefore + Math.min(60_000, Math.max(1_000, Math.floor((notAfter - notBefore) / 2)));
    const fingerprint = leafCert.fingerprint256.replaceAll(":", "").toLowerCase();
    const event: JsonObject = {
      ansId: "550e8400-e29b-41d4-a716-446655440000",
      ansName: name,
      eventType: options.eventType ?? "AGENT_REGISTERED",
      agent: {
        host,
        name: "Acme Support Agent",
        version: `v${version}`,
        providerId: "PID-8294",
      },
      attestations: {
        identityCert: { fingerprint: `SHA256:${fingerprint}`, type: "X509-OV-CLIENT" },
      },
      expiresAt: options.expiresAt ?? new Date(now + 20 * 86_400_000).toISOString(),
      issuedAt: options.issuedAt ?? new Date(now - 86_400_000).toISOString(),
      raId: "id-A",
      timestamp: new Date(now - 86_400_000).toISOString(),
    };
    const extra = options.extraLeaves ?? 6;
    const leafIndex = options.leafIndex ?? 3;
    const leaves: Uint8Array[] = [];
    for (let index = 0; index < extra + 1; index++) {
      leaves.push(encoder.encode(canonicalizeJson(index === leafIndex ? event : { pad: index })));
    }
    const root = merkleRoot(leaves);
    const proof = inclusionProof(leaves, leafIndex);
    const otherIndex = leafIndex === 0 ? 1 : 0;
    const otherProof = inclusionProof(leaves, otherIndex);
    const ra = p256("ra-1");
    const kms = p256("kms-1");
    const stamp = Math.floor(now / 1000);
    const payload: JsonObject = {
      logId: "550e8400-e29b-41d4-a716-446655440000",
      producer: {
        event,
        keyId: "id-B",
        signature: options.producerSignature ?? "not-checked",
      },
    };
    const badge = {
      schemaVersion: "V1",
      status: options.status ?? "ACTIVE",
      payload,
      signature: signDetached(badgeSignaturePayload(payload), header(ra.publicKey.kid!, "id-A", stamp, "ans-badge"), ra.privateKey),
      inclusionProof: {
        leafHash: toHex(eventLeafHash(event as JsonValue)),
        leafIndex,
        treeSize: leaves.length,
        treeVersion: 1,
        path: proof.map((node) => toHex(node)),
        rootHash: toHex(root),
        rootSignature: signDetached(rootSignaturePayload(root), header(kms.publicKey.kid!, "kms", stamp, "ans-sth"), kms.privateKey),
      },
    };
    return {
      name,
      now,
      fingerprint,
      intermediatePem: issued.intermediate,
      alternateProof: {
        leafIndex: otherIndex,
        path: otherProof.map((node) => toHex(node)),
        leafHash: toHex(leafHash(leaves[otherIndex]!)),
      },
      raPrivate: ra.privateKey,
      kmsPrivate: kms.privateKey,
      evidence: {
        identityChainPem: issued.chain,
        trustAnchorPem: issued.anchor,
        badge,
        raKey: ra.publicKey,
        kmsKey: kms.publicKey,
        now,
      },
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
