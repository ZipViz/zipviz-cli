import { X509Certificate } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { assertPathLength } from "./basic-constraints.js";
import { fromHex, toHex } from "./bytes.js";
import { parseAnsName, type AnsName } from "./name.js";
import { AnsError } from "./reasons.js";
import { sameBytes } from "./signature.js";

const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const MAX_CHAIN = 6;

export type CertificateBinding = {
  fingerprint: string;
  anchorFingerprint: string;
  subject: string;
};

function readCerts(pem: string, label: string): X509Certificate[] {
  if (typeof pem !== "string" || pem.length === 0 || pem.length > 256 * 1024) {
    throw new AnsError("ANS_CERT_INVALID", `${label} PEM is missing or too large`);
  }
  const blocks = pem.match(PEM_RE);
  if (!blocks) throw new AnsError("ANS_CERT_INVALID", `${label} PEM does not contain a certificate`);
  try {
    return blocks.map((block) => new X509Certificate(block));
  } catch {
    throw new AnsError("ANS_CERT_INVALID", `${label} PEM is not a valid X.509 certificate`);
  }
}

function assertCurrent(cert: X509Certificate, now: number, label: string): void {
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  if (!Number.isFinite(from) || !Number.isFinite(to)) {
    throw new AnsError("ANS_CERT_INVALID", `${label} has an unreadable validity period`);
  }
  if (now < from) throw new AnsError("ANS_CERT_NOT_YET_VALID", `${label} is not yet valid`);
  if (now > to) throw new AnsError("ANS_CERT_EXPIRED", `${label} has expired`);
}

function issuedBy(cert: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function uriNames(cert: X509Certificate): string[] {
  const san = cert.subjectAltName;
  if (!san) return [];
  return san.split(/, (?=[A-Za-z][A-Za-z0-9]*:)/).flatMap((part) => part.startsWith("URI:") ? [part.slice(4)] : []);
}

export function certificateFingerprint(cert: X509Certificate): string {
  return toHex(sha256(cert.raw));
}

/** `SHA256:` plus 32 bytes of hex, the Appendix A.3 fingerprint form. Colons are allowed. */
export function parseSha256Fingerprint(value: string): string | undefined {
  const match = /^SHA256:([0-9a-fA-F:]+)$/i.exec(value.trim());
  if (!match) return undefined;
  const hex = match[1]!.replaceAll(":", "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return undefined;
  return hex;
}

export function fingerprintsEqual(left: string, right: string): boolean {
  const leftBytes = fromHex(left);
  const rightBytes = fromHex(right);
  if (!leftBytes || !rightBytes) return false;
  return sameBytes(leftBytes, rightBytes);
}

/**
 * Identity certificate chain from draft §5.4 and §12.1: a URI SAN carries the
 * ANSName, and the chain validates to the caller's pinned Private CA.
 */
export function verifyIdentityCertificate(input: {
  name: AnsName;
  identityChainPem: string;
  trustAnchorPem: string;
  now: number;
}): CertificateBinding {
  const presented = readCerts(input.identityChainPem, "identity certificate");
  const anchors = readCerts(input.trustAnchorPem, "trust anchor");
  if (anchors.length !== 1) {
    throw new AnsError("ANS_CERT_INVALID", "trust anchor PEM must contain exactly one certificate");
  }
  const anchor = anchors[0]!;
  if (presented.length < 1 || presented.length > MAX_CHAIN) {
    throw new AnsError("ANS_CERT_INVALID", "identity chain must contain 1 to 6 certificates");
  }
  const chain = presented.length > 1 && presented[presented.length - 1]!.raw.equals(anchor.raw)
    ? presented.slice(0, -1)
    : presented;
  const leaf = chain[0]!;
  if (leaf.raw.equals(anchor.raw)) {
    throw new AnsError("ANS_CERT_INVALID", "identity certificate is the trust anchor");
  }
  if (leaf.ca) throw new AnsError("ANS_CERT_INVALID", "identity certificate is a CA certificate");
  assertCurrent(anchor, input.now, "trust anchor");
  if (!anchor.ca || !issuedBy(anchor, anchor)) {
    throw new AnsError("ANS_CERT_UNTRUSTED", "trust anchor is not a self-signed CA certificate");
  }
  for (let index = 0; index < chain.length; index++) {
    const cert = chain[index]!;
    const issuer = index + 1 < chain.length ? chain[index + 1]! : anchor;
    const label = index === 0 ? "identity certificate" : "intermediate certificate";
    assertCurrent(cert, input.now, label);
    if (index > 0 && !cert.ca) throw new AnsError("ANS_CERT_UNTRUSTED", "intermediate certificate is not a CA");
    if (index + 1 < chain.length && !issuer.ca) {
      throw new AnsError("ANS_CERT_UNTRUSTED", "intermediate certificate is not a CA");
    }
    if (!issuedBy(cert, issuer)) {
      throw new AnsError("ANS_CERT_UNTRUSTED", `${label} was not issued by its issuer in the chain`);
    }
  }
  assertPathLength(anchor, chain.slice(1).reverse());
  const bound = uriNames(leaf).some((san) => {
    try {
      return parseAnsName(san).name === input.name.name;
    } catch (error) {
      if (error instanceof AnsError && error.reason === "ANS_NAME_INVALID") return false;
      throw error;
    }
  });
  if (!bound) throw new AnsError("ANS_NAME_UNBOUND", "identity certificate has no URI SAN for this ANS name");
  return {
    fingerprint: certificateFingerprint(leaf),
    anchorFingerprint: certificateFingerprint(anchor),
    subject: leaf.subject,
  };
}
