import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { jwkThumbprint } from "../a2a/jwk.js";
import { fromHex, toHex } from "./bytes.js";
import {
  fingerprintsEqual,
  parseSha256Fingerprint,
  verifyIdentityCertificate,
} from "./certificate.js";
import { isPlainObject } from "./json.js";
import { eventLeafHash } from "./leaf.js";
import { parseAnsName } from "./name.js";
import { verifyInclusion } from "./merkle.js";
import { AnsError, type AnsReason } from "./reasons.js";
import {
  badgeSignaturePayload,
  MAX_ATTACHED_JWS_LENGTH,
  readPinnedKey,
  producerHeader,
  verifyLiveCheckpoint,
  rootSignaturePayload,
  sameBytes,
  verifyDetachedEs256,
} from "./signature.js";

/** Current individual submission implemented by this verifier. */
export const ANS_DRAFT = "draft-narajala-courtney-ansv2-01";

export const ANS_NOTE =
  "Checks the ANS name, identity certificate, and transparency-log inclusion. Revocation is not checked. Live log freshness is not proved. No DANE, reputation, or behaviour check.";

const STATUSES = new Set(["ACTIVE", "DEPRECATED", "REVOKED", "EXPIRED"]);
const EVENT_TYPES = new Set(["AGENT_REGISTERED", "AGENT_RENEWED", "AGENT_REVOKED"]);
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

export type AnsScope = {
  identity_certificate: "checked";
  transparency_log: "checked";
  producer_signature: "not checked";
  revocation: "not checked";
  live_log: "not proved";
  dane: "not checked";
  reputation: "not checked";
  behaviour: "not checked";
};

export type AnsPins = {
  ra_jwk_thumbprint: string;
  kms_jwk_thumbprint: string;
  ca_sha256?: string;
};

export type AnsEvidence = {
  identityChainPem: string;
  trustAnchorPem: string;
  badge: unknown;
  raKey: unknown;
  kmsKey: unknown;
  /** Milliseconds since the Unix epoch. The CLI uses the current time. */
  now?: number;
};

export type TransparencyLogResult = {
  valid: boolean;
  leaf_index?: number;
  tree_size?: number;
  tree_version?: number;
  root_hash?: string;
  event_type?: string;
  status?: string;
  ra_id?: string;
  ra_kid?: string;
  kms_kid?: string;
  profile?: "draft-01" | "godaddy-live-v1";
  producer_kid?: string;
  log_ra_id?: string;
};

export type AnsVerification = {
  valid: boolean;
  draft: typeof ANS_DRAFT;
  name: string;
  version?: string;
  host?: string;
  reason?: AnsReason;
  message?: string;
  certificate?: { valid: boolean; fingerprint_sha256?: string; subject?: string };
  transparency_log?: TransparencyLogResult;
  pins?: AnsPins;
  scope: AnsScope;
  note: typeof ANS_NOTE;
};

const SCOPE: AnsScope = {
  identity_certificate: "checked",
  transparency_log: "checked",
  producer_signature: "not checked",
  revocation: "not checked",
  live_log: "not proved",
  dane: "not checked",
  reputation: "not checked",
  behaviour: "not checked",
};

type SealedEvent = {
  raw: JsonValue;
  ansName: string;
  eventType: string;
  host: string;
  version: string;
  fingerprint: string;
  raId: string;
  issuedAt?: number;
  expiresAt?: number;
};

type BadgeProof = {
  leafHash: Uint8Array;
  leafIndex: number;
  treeSize: number;
  treeVersion: number;
  path: Uint8Array[];
  rootHash: Uint8Array;
  rootSignature: string;
};

type Badge = {
  live: boolean;
  producerSignature: string;
  producerKeyId: string;
  status: string;
  payload: JsonValue;
  signature: string;
  event: SealedEvent;
  proof: BadgeProof;
};

function fail(reason: AnsReason, message: string): never {
  throw new AnsError(reason, message);
}

function requiredString(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    fail("ANS_INPUT_INVALID", `${field} must be a non-empty string`);
  }
  return value;
}

function requiredInteger(value: unknown, field: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    fail("ANS_INPUT_INVALID", `${field} must be an integer >= ${minimum}`);
  }
  return value;
}

function digest(value: unknown, field: string): Uint8Array {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    fail("ANS_PROOF_INVALID", `${field} is not a SHA-256 hex digest`);
  }
  return fromHex(value.toLowerCase())!;
}

/** Standard padded base64 only; never guess encoding from a digest's shape. */
function base64Digest(value: unknown, field: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    fail("ANS_PROOF_INVALID", `${field} is not a SHA-256 base64 digest`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== value) {
    fail("ANS_PROOF_INVALID", `${field} is not canonical base64`);
  }
  return bytes;
}

function utcMillis(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !TIMESTAMP.test(value)) fail("ANS_INPUT_INVALID", `${field} is not a UTC timestamp`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail("ANS_INPUT_INVALID", `${field} is not a UTC timestamp`);
  return parsed;
}

function readEvent(value: unknown): SealedEvent {
  if (!isPlainObject(value)) fail("ANS_INPUT_INVALID", "sealed event must be a JSON object");
  const agent = value.agent;
  const attestations = value.attestations;
  if (!isPlainObject(agent) || !isPlainObject(attestations) || !isPlainObject(attestations.identityCert)) {
    fail("ANS_INPUT_INVALID", "sealed event is missing agent or identityCert");
  }
  const eventType = requiredString(value.eventType, "eventType");
  if (!EVENT_TYPES.has(eventType)) fail("ANS_INPUT_INVALID", "eventType is not a known ANS lifecycle event");
  try {
    canonicalizeJson(value as JsonValue);
  } catch {
    fail("ANS_INPUT_INVALID", "sealed event is not canonicalizable JSON");
  }
  return {
    raw: value as JsonValue,
    ansName: requiredString(value.ansName, "ansName"),
    eventType,
    host: requiredString(agent.host, "agent.host"),
    version: requiredString(agent.version, "agent.version"),
    fingerprint: requiredString(attestations.identityCert.fingerprint, "identityCert.fingerprint"),
    raId: requiredString(value.raId, "raId"),
    issuedAt: utcMillis(value.issuedAt, "issuedAt"),
    expiresAt: utcMillis(value.expiresAt, "expiresAt"),
  };
}

function readBadge(value: unknown): Badge {
  if (!isPlainObject(value)) fail("ANS_INPUT_INVALID", "badge must be a JSON object");
  if (value.schemaVersion !== "V1") fail("ANS_INPUT_INVALID", "badge schemaVersion must be V1");
  const status = requiredString(value.status, "status");
  if (!STATUSES.has(status)) fail("ANS_INPUT_INVALID", "badge status is not a known ANS registration state");
  if (!isPlainObject(value.payload) || !isPlainObject(value.payload.producer)) {
    fail("ANS_INPUT_INVALID", "badge payload is missing");
  }
  requiredString(value.payload.logId, "logId");
  requiredString(value.payload.producer.keyId, "producer.keyId");
  requiredString(value.payload.producer.signature, "producer.signature");
  if (typeof value.signature !== "string") fail("ANS_INPUT_INVALID", "badge signature is missing");
  const live = Object.hasOwn(value, "merkleProof");
  if (live && Object.hasOwn(value, "inclusionProof")) fail("ANS_INPUT_INVALID", "badge must use exactly one proof profile");
  const proof = live ? value.merkleProof : value.inclusionProof;
  if (!isPlainObject(proof) || !Array.isArray(proof.path)) fail("ANS_INPUT_INVALID", "inclusion proof is missing");
  if (proof.path.length > 64) fail("ANS_PROOF_INVALID", "inclusion proof path is too long");
  const event = readEvent(value.payload.producer.event);
  try {
    canonicalizeJson(value.payload as JsonValue);
  } catch {
    fail("ANS_INPUT_INVALID", "badge payload is not canonicalizable JSON");
  }
  if (live && proof.treeVersion !== 1) fail("ANS_PROOF_INVALID", "live proof treeVersion must be 1");
  return {
    live,
    producerSignature: value.payload.producer.signature as string,
    producerKeyId: value.payload.producer.keyId as string,
    status,
    payload: value.payload as JsonValue,
    signature: value.signature,
    event,
    proof: {
      leafHash: digest(proof.leafHash, "leafHash"),
      leafIndex: requiredInteger(proof.leafIndex, "leafIndex", 0),
      treeSize: requiredInteger(proof.treeSize, "treeSize", 1),
      treeVersion: requiredInteger(proof.treeVersion, "treeVersion", 0),
      path: proof.path.map((node, index) => (live ? base64Digest : digest)(node, `path[${index}]`)),
      rootHash: (live ? base64Digest : digest)(proof.rootHash, "rootHash"),
      rootSignature: requiredString(proof.rootSignature, "rootSignature", live ? MAX_ATTACHED_JWS_LENGTH : 512),
    },
  };
}

export function verifyAnsBinding(name: string, evidence: AnsEvidence): AnsVerification {
  const result: AnsVerification = {
    valid: false,
    draft: ANS_DRAFT,
    name,
    scope: SCOPE,
    note: ANS_NOTE,
  };
  try {
    const parsed = parseAnsName(name);
    result.name = parsed.name;
    result.version = parsed.version;
    result.host = parsed.host;
    const now = evidence.now ?? Date.now();
    if (!Number.isFinite(now)) fail("ANS_INPUT_INVALID", "verification time is not a finite timestamp");
    const raKey = readPinnedKey(evidence.raKey, "registration authority");
    const kmsKey = readPinnedKey(evidence.kmsKey, "KMS");
    result.pins = {
      ra_jwk_thumbprint: jwkThumbprint(raKey),
      kms_jwk_thumbprint: jwkThumbprint(kmsKey),
    };
    const certificate = verifyIdentityCertificate({
      name: parsed,
      identityChainPem: evidence.identityChainPem,
      trustAnchorPem: evidence.trustAnchorPem,
      now,
    });
    result.pins.ca_sha256 = certificate.anchorFingerprint;
    result.certificate = {
      valid: true,
      fingerprint_sha256: certificate.fingerprint,
      subject: certificate.subject,
    };
    const badge = readBadge(evidence.badge);
    let sealedName: string;
    try {
      sealedName = parseAnsName(badge.event.ansName).name;
    } catch {
      fail("ANS_EVENT_MISMATCH", "sealed event ansName is not a valid ANS name");
    }
    if (sealedName !== parsed.name) fail("ANS_EVENT_MISMATCH", "sealed event ansName does not match the requested name");
    if (badge.event.host.toLowerCase() !== parsed.host) {
      fail("ANS_EVENT_MISMATCH", "sealed event host does not match the ANS name");
    }
    if (badge.event.version !== `v${parsed.version}`) {
      fail("ANS_EVENT_MISMATCH", "sealed event version does not match the ANS name");
    }
    const sealedFingerprint = parseSha256Fingerprint(badge.event.fingerprint);
    if (!sealedFingerprint || !fingerprintsEqual(sealedFingerprint, certificate.fingerprint)) {
      fail("ANS_FINGERPRINT_MISMATCH", "identity certificate fingerprint does not match the sealed event");
    }
    const envelope = { payload: badge.payload, schemaVersion: "V1", signature: badge.signature };
    const leaf = eventLeafHash(badge.live ? envelope : badge.event.raw);
    if (!sameBytes(leaf, badge.proof.leafHash)) {
      fail("ANS_PROOF_INVALID", "leaf hash does not match the sealed event");
    }
    if (!verifyInclusion(leaf, badge.proof.leafIndex, badge.proof.treeSize, badge.proof.path, badge.proof.rootHash)) {
      fail("ANS_PROOF_INVALID", "inclusion proof does not recompute the signed root");
    }
    const kms = badge.live
      ? verifyLiveCheckpoint(badge.proof.rootSignature, badge.proof.rootHash, badge.proof.treeSize, kmsKey)
      : verifyDetachedEs256(badge.proof.rootSignature, rootSignaturePayload(badge.proof.rootHash), kmsKey);
    const ra = verifyDetachedEs256(badge.signature, badgeSignaturePayload(badge.live ? { payload: badge.payload, schemaVersion: "V1" } : badge.payload), raKey, badge.live);
    const producer = badge.live ? producerHeader(badge.producerSignature) : undefined;
    if (producer && producer.kid !== badge.producerKeyId) {
      fail("ANS_EVENT_MISMATCH", "producer signature kid does not match producer.keyId");
    }
    if ((producer ?? ra).raId !== badge.event.raId) {
      fail("ANS_EVENT_MISMATCH", "registration authority signature raId does not match the sealed event");
    }
    result.transparency_log = {
      valid: true,
      profile: badge.live ? "godaddy-live-v1" : "draft-01",
      ...(producer ? { producer_kid: producer.kid, log_ra_id: ra.raId } : {}),
      leaf_index: badge.proof.leafIndex,
      tree_size: badge.proof.treeSize,
      tree_version: badge.proof.treeVersion,
      root_hash: toHex(badge.proof.rootHash),
      event_type: badge.event.eventType,
      status: badge.status,
      ra_id: badge.event.raId,
      ra_kid: ra.kid,
      kms_kid: kms.kid,
    };
    if (badge.event.issuedAt !== undefined && badge.event.issuedAt > now) {
      fail("ANS_EVENT_MISMATCH", "sealed event issuedAt is in the future");
    }
    if (badge.event.expiresAt !== undefined && badge.event.expiresAt < now) {
      fail("ANS_EXPIRED", "sealed event expiresAt is in the past");
    }
    if (badge.event.eventType === "AGENT_REVOKED") {
      fail("ANS_REVOKED", "signed event is AGENT_REVOKED");
    }
    if (badge.status === "REVOKED") {
      fail("ANS_REVOKED", "badge status is REVOKED");
    }
    if (badge.status === "EXPIRED") fail("ANS_EXPIRED", "badge status is EXPIRED");
    if (badge.event.eventType !== "AGENT_REGISTERED" && badge.event.eventType !== "AGENT_RENEWED") {
      fail("ANS_EVENT_MISMATCH", "signed event is not a registration or renewal");
    }
    // status, treeSize, and leafIndex are outside both signatures. An ACTIVE
    // badge is indistinguishable from a REVOKED badge whose status was flipped,
    // and an old registration proof stays valid after a later revocation.
    fail(
      "ANS_REVOCATION_NOT_CHECKED",
      "revocation was not checked and log freshness was not proved, so this is not a current verification",
    );
  } catch (error) {
    if (!(error instanceof AnsError)) throw error;
    result.reason = error.reason;
    result.message = error.message;
    return result;
  }
}
