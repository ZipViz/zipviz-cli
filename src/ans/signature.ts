import { timingSafeEqual } from "node:crypto";
import { base64urlnopad } from "@scure/base";
import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { parsePublicJwk, type PublicJwk } from "../a2a/jwk.js";
import { verifyJws } from "../a2a/jws.js";
import { KeyError } from "../a2a/reasons.js";
import { toHex } from "./bytes.js";
import { hasDuplicateMembers, isPlainObject } from "./json.js";
import { AnsError } from "./reasons.js";

// Matches the existing compact-JWS segment bounds, well below the whole-input cap.
export const MAX_ATTACHED_JWS_LENGTH = 8192 + 8192 + 512 + 2;

const encoder = new TextEncoder();
const HEADER_KEYS = new Set(["alg", "kid", "raId", "timestamp", "typ"]);
const TOKEN = /^[\x21-\x7e]{1,128}$/;

export type PinnedKey = PublicJwk & { kid: string };

export type ProtectedHeader = {
  kid: string;
  raId: string;
  timestamp: number;
  typ: string;
};

export function readPinnedKey(value: unknown, role: string): PinnedKey {
  try {
    const key = parsePublicJwk(value);
    if (key.kty !== "EC") throw new AnsError("ANS_KEY_INVALID", `${role} key must be a P-256 public JWK`);
    if (key.alg !== undefined && key.alg !== "ES256") {
      throw new AnsError("ANS_KEY_INVALID", `${role} key alg must be ES256`);
    }
    if (key.use !== undefined && key.use !== "sig") {
      throw new AnsError("ANS_KEY_INVALID", `${role} key use must be sig`);
    }
    if (key.kid === undefined || !TOKEN.test(key.kid)) {
      throw new AnsError("ANS_KEY_INVALID", `${role} key kid must be 1 to 128 visible ASCII characters`);
    }
    return { ...key, kid: key.kid };
  } catch (error) {
    if (error instanceof AnsError) throw error;
    if (error instanceof KeyError) throw new AnsError("ANS_KEY_INVALID", `${role} key is not a public P-256 JWK`);
    throw new AnsError("ANS_KEY_INVALID", `${role} key is not a public P-256 JWK`);
  }
}

/**
 * Profile-specific compact JWS, draft §5.6: `BASE64URL(JCS(header))..BASE64URL(signature)`.
 * Draft-01 uses raId; captured live V1 uses raid/JWT and an attached checkpoint.
 * The protected header contains exactly the five parameters for its profile.
 * Key-referral parameters are rejected so verification cannot fetch another key.
 */
function readSignature(compact: string, live: boolean, attached: boolean = false) {
  const match = /^([A-Za-z0-9_-]{1,8192})\.([A-Za-z0-9_-]{0,8192})\.([A-Za-z0-9_-]{1,512})$/.exec(compact);
  if (!match || (attached ? !match[2] : !!match[2])) throw new AnsError("ANS_SIG_MALFORMED", `signature is not an ${attached ? "attached" : "detached"} compact JWS`);
  const protectedPart = match[1]!;
  const payloadPart = match[2]!;
  const signaturePart = match[3]!;
  let headerBytes: Uint8Array;
  let signature: Uint8Array;
  try {
    headerBytes = base64urlnopad.decode(protectedPart);
    signature = base64urlnopad.decode(signaturePart);
    if (signature.length !== 64) throw new Error("ES256 signature length");
    if (base64urlnopad.encode(headerBytes) !== protectedPart || base64urlnopad.encode(signature) !== signaturePart) {
      throw new Error("non-canonical base64url");
    }
  } catch {
    throw new AnsError("ANS_SIG_MALFORMED", "signature encoding is not canonical base64url");
  }
  let headerText: string;
  try {
    headerText = new TextDecoder("utf-8", { fatal: true }).decode(headerBytes);
  } catch {
    throw new AnsError("ANS_SIG_MALFORMED", "protected header is not UTF-8");
  }
  let parsed: unknown;
  try {
    if (hasDuplicateMembers(headerText)) throw new Error("duplicate header member");
    parsed = JSON.parse(headerText) as unknown;
  } catch {
    throw new AnsError("ANS_SIG_MALFORMED", "protected header is not JSON");
  }
  if (!isPlainObject(parsed)) throw new AnsError("ANS_SIG_MALFORMED", "protected header is not a JSON object");
  let canonical: string;
  try {
    canonical = canonicalizeJson(parsed as JsonValue);
  } catch {
    throw new AnsError("ANS_SIG_MALFORMED", "protected header is not canonical JSON");
  }
  if (canonical !== headerText) throw new AnsError("ANS_SIG_MALFORMED", "protected header is not JCS canonical");
  const authorityField = live ? "raid" : "raId";
  const allowed = live ? new Set(["alg", "kid", "raid", "timestamp", "typ"]) : HEADER_KEYS;
  const keys = Object.keys(parsed);
  if (keys.some((name) => !allowed.has(name)) || allowed.size !== keys.length) {
    throw new AnsError("ANS_SIG_MALFORMED", `protected header must contain only alg, kid, typ, timestamp, and ${authorityField}`);
  }
  if (parsed.alg !== "ES256") throw new AnsError("ANS_SIG_MALFORMED", "signature alg must be ES256");
  if (typeof parsed.kid !== "string" || !TOKEN.test(parsed.kid)) {
    throw new AnsError("ANS_SIG_MALFORMED", "signature kid is missing or invalid");
  }
  if (typeof parsed.typ !== "string" || !TOKEN.test(parsed.typ) || (live && parsed.typ !== "JWT")) {
    throw new AnsError("ANS_SIG_MALFORMED", "signature typ is missing or invalid");
  }
  const authority = parsed[authorityField];
  if (typeof authority !== "string" || !TOKEN.test(authority)) {
    throw new AnsError("ANS_SIG_MALFORMED", `signature ${authorityField} is missing or invalid`);
  }
  if (typeof parsed.timestamp !== "number" || !Number.isSafeInteger(parsed.timestamp) || parsed.timestamp < 0) {
    throw new AnsError("ANS_SIG_MALFORMED", "signature timestamp must be a non-negative integer");
  }
  return { protectedPart, payloadPart, signature, header: {
    kid: parsed.kid, raId: authority, timestamp: parsed.timestamp, typ: parsed.typ,
  } };
}

function checkSignature(parts: ReturnType<typeof readSignature>, payload: Uint8Array, key: PinnedKey): ProtectedHeader {
  if (parts.header.kid !== key.kid) {
    throw new AnsError("ANS_SIGNATURE_INVALID", `signature kid ${parts.header.kid} does not match the pinned key ${key.kid}`);
  }
  const signingInput = encoder.encode(`${parts.protectedPart}.${base64urlnopad.encode(payload)}`);
  if (!verifyJws("ES256", signingInput, parts.signature, key)) {
    throw new AnsError("ANS_SIGNATURE_INVALID", "ES256 signature does not verify with the pinned key");
  }
  return parts.header;
}

export function verifyDetachedEs256(compact: string, payload: Uint8Array, key: PinnedKey, live = false): ProtectedHeader {
  return checkSignature(readSignature(compact, live), payload, key);
}

/** Header inspection is authenticated by the enclosing verified log signature.
 * This does NOT independently verify the producer's signature. */
export function producerHeader(compact: string): ProtectedHeader {
  return readSignature(compact, true).header;
}

/** The live root JWS signs a structured C2SP checkpoint, not a bare root. */
export function verifyLiveCheckpoint(compact: string, root: Uint8Array, treeSize: number, key: PinnedKey): ProtectedHeader {
  const parts = readSignature(compact, true, true);
  let bytes: Uint8Array;
  let payload: unknown;
  try {
    bytes = base64urlnopad.decode(parts.payloadPart);
    if (base64urlnopad.encode(bytes) !== parts.payloadPart) throw new Error("encoding");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (hasDuplicateMembers(text)) throw new Error("duplicate");
    payload = JSON.parse(text) as unknown;
    if (canonicalizeJson(payload as JsonValue) !== text) throw new Error("JCS");
  } catch {
    throw new AnsError("ANS_SIG_MALFORMED", "checkpoint payload is not canonical JSON/base64url");
  }
  const header = checkSignature(parts, bytes, key);
  if (!isPlainObject(payload) || Object.keys(payload).length !== 5 ||
      payload.checkpointFormat !== "c2sp/v1" || payload.origin !== "transparency.ans.godaddy.com" ||
      payload.treesize !== treeSize || payload.timestamp !== header.timestamp ||
      // This provider emits padded URL-safe base64 inside its checkpoint.
      payload.rootHash !== `${base64urlnopad.encode(root)}=`) {
    throw new AnsError("ANS_PROOF_INVALID", "signed checkpoint does not match the proof root, tree size, origin, format, or timestamp");
  }
  return header;
}

/** JCS of the lowercase hex root. §9.1 signs R; §5.6 requires a JSON payload. */
export function rootSignaturePayload(root: Uint8Array): Uint8Array {
  return encoder.encode(canonicalizeJson(toHex(root)));
}

/** JCS of the badge `payload` object. The Appendix A.4 RA signature is its sibling. */
export function badgeSignaturePayload(payload: JsonValue): Uint8Array {
  return encoder.encode(canonicalizeJson(payload));
}

export function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
