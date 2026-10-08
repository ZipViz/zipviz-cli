import { X509Certificate } from "node:crypto";
import { AnsError } from "./reasons.js";

const BASIC_CONSTRAINTS_OID = Uint8Array.of(0x55, 0x1d, 0x13);

type Tlv = { tag: number; value: Uint8Array; next: number };

function fail(message: string): never {
  throw new AnsError("ANS_CERT_UNTRUSTED", message);
}

function readLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
  const first = bytes[offset];
  if (first === undefined) fail("certificate basic constraints could not be read");
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 3) fail("certificate basic constraints could not be read");
  const start = offset + 1;
  if (bytes[start] === 0x00) fail("certificate basic constraints could not be read");
  let length = 0;
  for (let index = 0; index < count; index++) {
    const part = bytes[start + index];
    if (part === undefined) fail("certificate basic constraints could not be read");
    length = (length << 8) | part;
  }
  if (length < 128) fail("certificate basic constraints could not be read");
  return { length, next: start + count };
}

function readTlv(bytes: Uint8Array, offset: number): Tlv {
  const tag = bytes[offset];
  if (tag === undefined || (tag & 0x1f) === 0x1f) fail("certificate basic constraints could not be read");
  const length = readLength(bytes, offset + 1);
  const end = length.next + length.length;
  if (end > bytes.length) fail("certificate basic constraints could not be read");
  return { tag, value: bytes.subarray(length.next, end), next: end };
}

function children(value: Uint8Array): Tlv[] {
  const items: Tlv[] = [];
  let offset = 0;
  while (offset < value.length) {
    const child = readTlv(value, offset);
    if (child.next <= offset) fail("certificate basic constraints could not be read");
    items.push(child);
    offset = child.next;
  }
  return items;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) if (left[index] !== right[index]) return false;
  return true;
}

function readNonNegativeInteger(value: Uint8Array): number {
  if (value.length === 0 || value.length > 4) fail("certificate path length constraint is invalid");
  if ((value[0]! & 0x80) !== 0) fail("certificate path length constraint is invalid");
  if (value.length > 1 && value[0] === 0x00 && (value[1]! & 0x80) === 0) {
    fail("certificate path length constraint is invalid");
  }
  let number = 0;
  for (const byte of value) number = (number * 256) + byte;
  if (!Number.isSafeInteger(number)) fail("certificate path length constraint is invalid");
  return number;
}

function parseBasicConstraintsValue(value: Uint8Array): { ca: boolean; pathLen: number | null } {
  const sequence = readTlv(value, 0);
  if (sequence.tag !== 0x30 || sequence.next !== value.length) fail("certificate basic constraints could not be read");
  const fields = children(sequence.value);
  let ca = false;
  let sawCa = false;
  let pathLen: number | null = null;
  let index = 0;
  const booleanField = fields[index];
  if (booleanField?.tag === 0x01) {
    if (booleanField.value.length !== 1 || (booleanField.value[0] !== 0x00 && booleanField.value[0] !== 0xff)) {
      fail("certificate basic constraints could not be read");
    }
    ca = booleanField.value[0] === 0xff;
    sawCa = true;
    index++;
  }
  const integerField = fields[index];
  if (integerField !== undefined) {
    if (integerField.tag !== 0x02 || !sawCa || !ca) fail("certificate path length constraint is invalid");
    pathLen = readNonNegativeInteger(integerField.value);
    index++;
  }
  if (index !== fields.length) fail("certificate basic constraints could not be read");
  return { ca, pathLen };
}

/** RFC 5280 BasicConstraints from the certificate DER. Absent means cA false and no path limit. */
export function readBasicConstraints(cert: X509Certificate): { ca: boolean; pathLen: number | null } {
  const raw = new Uint8Array(cert.raw);
  const certificate = readTlv(raw, 0);
  if (certificate.tag !== 0x30 || certificate.next !== raw.length) fail("certificate basic constraints could not be read");
  const tbs = children(certificate.value)[0];
  if (tbs?.tag !== 0x30) fail("certificate basic constraints could not be read");
  const extensionWrappers = children(tbs.value).filter((child) => child.tag === 0xa3);
  if (extensionWrappers.length > 1) fail("certificate basic constraints could not be read");
  if (extensionWrappers.length === 0) return { ca: false, pathLen: null };
  const extensionSequence = readTlv(extensionWrappers[0]!.value, 0);
  if (extensionSequence.tag !== 0x30 || extensionSequence.next !== extensionWrappers[0]!.value.length) {
    fail("certificate basic constraints could not be read");
  }
  let found: { ca: boolean; pathLen: number | null } | null = null;
  for (const extension of children(extensionSequence.value)) {
    if (extension.tag !== 0x30) fail("certificate basic constraints could not be read");
    const parts = children(extension.value);
    const oid = parts[0];
    if (oid?.tag !== 0x06 || !sameBytes(oid.value, BASIC_CONSTRAINTS_OID)) continue;
    const value = parts[parts.length - 1];
    if (value?.tag !== 0x04) fail("certificate basic constraints could not be read");
    if (found) fail("certificate basic constraints could not be read");
    found = parseBasicConstraintsValue(value.value);
  }
  const constraints = found ?? { ca: false, pathLen: null };
  if (constraints.ca !== cert.ca) fail("certificate basic constraints could not be read");
  return constraints;
}

/**
 * RFC 5280 4.2.1.9 and 6.1.4 (l)–(m). The trust anchor's pathLenConstraint limits
 * how many non-self-issued intermediates may follow it. Node's X509Certificate
 * does not enforce that constraint.
 */
export function assertPathLength(anchor: X509Certificate, intermediatesFromAnchor: readonly X509Certificate[]): void {
  let remaining = readBasicConstraints(anchor).pathLen;
  for (const certificate of intermediatesFromAnchor) {
    const selfIssued = certificate.subject === certificate.issuer;
    if (!selfIssued && remaining !== null) {
      if (remaining <= 0) fail("certificate path length constraint exceeded");
      remaining -= 1;
    }
    const constraints = readBasicConstraints(certificate);
    if (!constraints.ca) fail("intermediate certificate is not a CA");
    if (constraints.pathLen !== null) {
      remaining = remaining === null ? constraints.pathLen : Math.min(remaining, constraints.pathLen);
    }
  }
}
