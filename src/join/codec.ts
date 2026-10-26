import { createHash } from "node:crypto";
import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { CliError } from "../errors.js";
import type { LocalKey } from "../keys.js";

export const SIGNUP_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const SIGNUP_DOMAIN_RE = /^[a-z0-9-]{1,20}\.z\.viz$/;
const KEY_RE = /^[0-9a-f]{64}$/;
const INCARNATION_RE = /^[0-9a-f]{32}$/;
const CODE_RE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;
const RUNTIMES = ["claude", "codex", "buzz", "openclaw", "hermes", "other"] as const;
export type SignupRuntime = typeof RUNTIMES[number];
export interface StartReceipt {
  schema_version: "1.0";
  signup_id: string;
  state: "pending";
  proposed_domain: string;
  user_code: string;
  approval_url: string;
  expires_at_ms: number;
  poll_interval_ms: 5000;
}
export interface LivePoll {
  schema_version: "1.0";
  signup_id: string;
  state: "live";
  domain: string;
  public_key: string;
  incarnation: string;
  subject_agent_id: string;
  live_at_ms: number;
}
export type SignupPoll = LivePoll
  | { schema_version: "1.0"; signup_id: string; state: "pending"; proposed_domain: string; expires_at_ms: number; poll_interval_ms: 5000 }
  | { schema_version: "1.0"; signup_id: string; state: "expired"; expires_at_ms: number }
  | { schema_version: "1.0"; signup_id: string; state: "rejected" | "cancelled"; decided_at_ms: number };

export type StartOptions = {
  signupId: string; name: string; ownerEmail: string; runtime: SignupRuntime;
  introducedBy: string | null; audience: string; issuedAtMs: number;
};
export type CancelOptions = { signupId: string; audience: string; nonce: string; issuedAtMs: number };
const unexpected = () => new CliError("E_UNEXPECTED_RESPONSE", "registry returned an unexpected join response");
const integerMs = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function requestDigest(bytes: string): string {
  return createHash("sha256").update(bytes, "utf8").digest("hex");
}

export function keyId(publicKey: string): string {
  if (!KEY_RE.test(publicKey)) throw new CliError("E_KEY_INVALID", "join requires a raw Ed25519 public key");
  return `sha256:${createHash("sha256").update(Buffer.from(publicKey, "hex")).digest("hex")}`;
}

export function keyFingerprint(publicKey: string): string {
  return keyId(publicKey).slice(7, 23).match(/.{4}/g)!.join(" ");
}

function validateCommon(signupId: string, audience: string, issuedAtMs: number): void {
  if (!SIGNUP_ID_RE.test(signupId)) throw new CliError("E_USAGE", "signup id must be a lowercase UUIDv4", 2);
  if (!/^[a-z0-9][a-z0-9.:-]{0,252}$/.test(audience)) throw new CliError("E_USAGE", "audience must be a configured registry audience", 2);
  if (!integerMs(issuedAtMs)) throw new CliError("E_USAGE", "issued_at_ms must be a nonnegative safe integer", 2);
}

function signObject(key: LocalKey, domain: string, object: { [key: string]: JsonValue }): JsonValue {
  const payload = `${domain}\0${canonicalizeJson(object)}`;
  const signature = key.sign(payload);
  if (signature.byteLength !== 64) throw new CliError("E_KEY_INVALID", "join requires an Ed25519 key");
  return { ...object, signature: { alg: "Ed25519", key_id: keyId(key.publicKey), value_base64url: signature.toString("base64url") } };
}

export function buildStart(key: LocalKey, options: StartOptions): string {
  const { signupId, name, runtime, introducedBy, audience, issuedAtMs } = options;
  validateCommon(signupId, audience, issuedAtMs);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(name) || /-\d{4}$/.test(name)) {
    throw new CliError("E_NAME_FORMAT", "name must be 1 to 15 lowercase letters, digits or hyphens, without an assigned -NNNN suffix", 2);
  }
  if (!RUNTIMES.includes(runtime)) throw new CliError("E_RUNTIME", "runtime must be claude, codex, buzz, openclaw, hermes or other", 2);
  const ownerEmail = options.ownerEmail.trim().toLowerCase();
  if (ownerEmail.length < 3 || ownerEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail)) {
    throw new CliError("E_SIGNUP_SHAPE", "owner email must be a valid email address", 2);
  }
  if (introducedBy !== null && (typeof introducedBy !== "string" || introducedBy.length > 1024 || !/^zvintro1\.[A-Za-z0-9_-]+$/.test(introducedBy))) {
    throw new CliError("E_INTRO_INVALID", "introduced_by must be a ZipViz intro token", 2);
  }
  const boundDigest = requestDigest(canonicalizeJson({ introduced_by: introducedBy, owner_email: ownerEmail, runtime }));
  const proof = signObject(key, "ZipViz signup-start v1", {
    schema_version: "1.0", type: "zipviz.signup.start", signup_id: signupId,
    public_key: key.publicKey, audience, issued_at_ms: issuedAtMs, bound_digest: boundDigest,
  });
  const bytes = canonicalizeJson({ proof, name, owner_email: ownerEmail, runtime, introduced_by: introducedBy });
  if (Buffer.byteLength(bytes, "utf8") > 4096) throw new CliError("E_SIGNUP_SHAPE", "join request exceeds 4096 bytes", 2);
  return bytes;
}

export function buildCancel(key: LocalKey, options: CancelOptions): string {
  validateCommon(options.signupId, options.audience, options.issuedAtMs);
  if (!SIGNUP_ID_RE.test(options.nonce)) throw new CliError("E_USAGE", "cancel nonce must be a lowercase UUIDv4", 2);
  return canonicalizeJson(signObject(key, "ZipViz signup-cancel v1", {
    schema_version: "1.0", type: "zipviz.signup.cancel", signup_id: options.signupId,
    audience: options.audience, nonce: options.nonce, issued_at_ms: options.issuedAtMs,
  }));
}

function objectWithKeys(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw unexpected();
  const object = value as Record<string, unknown>;
  if (Object.keys(object).sort().join("\0") !== [...keys].sort().join("\0")) throw unexpected();
  return object;
}

export function validateReceipt(value: unknown, signupId: string, approvalOrigin = "https://zipviz.ai"): StartReceipt {
  const body = objectWithKeys(value, ["schema_version", "signup_id", "state", "proposed_domain", "user_code", "approval_url", "expires_at_ms", "poll_interval_ms"]);
  if (body.schema_version !== "1.0" || body.signup_id !== signupId || !SIGNUP_ID_RE.test(signupId)
      || body.state !== "pending" || typeof body.proposed_domain !== "string" || !SIGNUP_DOMAIN_RE.test(body.proposed_domain)
      || typeof body.user_code !== "string" || !CODE_RE.test(body.user_code)
      || body.approval_url !== `${approvalOrigin}/approve/${body.user_code}`
      || !integerMs(body.expires_at_ms) || body.poll_interval_ms !== 5000) throw unexpected();
  return body as unknown as StartReceipt;
}

/** ELU-845 identity binding; the registry origin is configuration, never response data. */
export function subjectAgentId(registryOrigin: string, domain: string, incarnation: string): string {
  const payload = canonicalizeJson({ registry_origin: registryOrigin, domain, incarnation });
  return `sub1_${createHash("sha256").update(`ZipViz subject-id v1\0${payload}`, "utf8").digest("base64url")}`;
}

export function validatePoll(value: unknown, signupId: string, registryOrigin = "https://api.zipviz.ai"): SignupPoll {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw unexpected();
  const state = (value as Record<string, unknown>).state;
  let keys: string[];
  if (state === "pending") keys = ["proposed_domain", "expires_at_ms", "poll_interval_ms"];
  else if (state === "live") keys = ["domain", "public_key", "incarnation", "subject_agent_id", "live_at_ms"];
  else if (state === "expired") keys = ["expires_at_ms"];
  else if (state === "cancelled" || state === "rejected") keys = ["decided_at_ms"];
  else throw unexpected();
  const body = objectWithKeys(value, ["schema_version", "signup_id", "state", ...keys]);
  if (body.schema_version !== "1.0" || body.signup_id !== signupId || !SIGNUP_ID_RE.test(signupId)) throw unexpected();
  if (state === "pending") {
    if (typeof body.proposed_domain !== "string" || !SIGNUP_DOMAIN_RE.test(body.proposed_domain)
        || !integerMs(body.expires_at_ms) || body.poll_interval_ms !== 5000) throw unexpected();
  } else if (state === "live") {
    if (typeof body.domain !== "string" || !SIGNUP_DOMAIN_RE.test(body.domain)
        || typeof body.public_key !== "string" || !KEY_RE.test(body.public_key)
        || typeof body.incarnation !== "string" || !INCARNATION_RE.test(body.incarnation)
        || !integerMs(body.live_at_ms)
        || body.subject_agent_id !== subjectAgentId(registryOrigin, body.domain, body.incarnation)) throw unexpected();
  } else if (!integerMs(state === "expired" ? body.expires_at_ms : body.decided_at_ms)) throw unexpected();
  return body as unknown as SignupPoll;
}
