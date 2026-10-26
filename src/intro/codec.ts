import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { CliError } from "../errors.js";
import { keyId, SIGNUP_ID_RE } from "../join/codec.js";
import type { LocalKey } from "../keys.js";
import { isValidVizAgentDomain } from "../viz.js";

export const INTRO_TTL_MAX_MS = 259_200_000;
export const INTRO_POLICY_MAX_AGE_MS = 300_000;
/** Frozen intro wire bound, including existing sovereign/delegated identities. */
export const INTRO_DOMAIN_RE = /^[a-z0-9][a-z0-9-]{0,19}\.(?:[a-z0-9][a-z0-9-]{0,19}\.)?viz$/;
const INCARNATION_RE = /^[0-9a-f]{32}$/;
const AUDIENCE_RE = /^[a-z0-9][a-z0-9.:-]{0,252}$/;
const UNSAFE_DISPLAY_RE = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029\u2713\u2014]/u;
const unavailable = () => new CliError("E_INTRO_UNAVAILABLE", "introductions are not currently allowed");
const invalid = () => new CliError("E_INTRO_INVALID", "intro fields do not match the frozen intro contract", 2);
const milliseconds = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

export interface IntroPolicyOptions {
  domain: string;
  incarnation: string;
  audience: string;
  issuedAtMs: number;
}
export interface IntroOptions extends IntroPolicyOptions {
  id: string;
  expiresAtMs: number;
}
export interface AllowedIntroPolicy {
  allow_agent_intros: true;
  incarnation: string;
  checked_at_ms: number;
}

function validateCommon(options: IntroPolicyOptions): void {
  if (!isValidVizAgentDomain(options.domain) || !INTRO_DOMAIN_RE.test(options.domain)
    || !INCARNATION_RE.test(options.incarnation) || !AUDIENCE_RE.test(options.audience)
    || !milliseconds(options.issuedAtMs)) throw invalid();
}

function signed(key: LocalKey, domain: string, unsigned: Record<string, JsonValue>): JsonValue {
  const signature = key.sign(`${domain}\0${canonicalizeJson(unsigned)}`);
  if (signature.length !== 64) throw new CliError("E_KEY_INVALID", "intro signing requires an Ed25519 key");
  return { ...unsigned, signature: { alg: "Ed25519", key_id: keyId(key.publicKey), value_base64url: signature.toString("base64url") } };
}

/** Local composition only. Current registry authority and policy are checked by the caller. */
export function buildIntro(key: LocalKey, options: IntroOptions): string {
  validateCommon(options);
  if (!SIGNUP_ID_RE.test(options.id) || !milliseconds(options.expiresAtMs)
    || options.expiresAtMs <= options.issuedAtMs || options.expiresAtMs - options.issuedAtMs > INTRO_TTL_MAX_MS) throw invalid();
  const bytes = canonicalizeJson(signed(key, "ZipViz intro v1", {
    schema_version: "1.0", type: "zipviz.intro", id: options.id,
    introducer: options.domain, introducer_incarnation: options.incarnation,
    audience: options.audience, issued_at_ms: options.issuedAtMs, expires_at_ms: options.expiresAtMs,
  }));
  const token = `zvintro1.${Buffer.from(bytes, "utf8").toString("base64url")}`;
  if (token.length > 1024) throw invalid();
  return token;
}

/** A signed read request; it carries no peer reference, intro token or message content. */
export function buildIntroPolicy(key: LocalKey, options: IntroPolicyOptions): string {
  validateCommon(options);
  return canonicalizeJson(signed(key, "ZipViz intro-policy v1", {
    schema_version: "1.0", type: "zipviz.intro_policy.read", domain: options.domain,
    incarnation: options.incarnation, audience: options.audience, issued_at_ms: options.issuedAtMs,
  }));
}

/** A non-200 HTTP response must be refused before this closed body validator is called. */
export function validatePolicyResult(body: unknown, incarnation: string, now: number): AllowedIntroPolicy {
  if (!record(body) || Object.keys(body).sort().join() !== "allow_agent_intros,checked_at_ms,incarnation"
    || body.allow_agent_intros !== true || !INCARNATION_RE.test(incarnation) || body.incarnation !== incarnation
    || !milliseconds(body.checked_at_ms) || !milliseconds(now)
    || body.checked_at_ms > now || now - body.checked_at_ms > INTRO_POLICY_MAX_AGE_MS) throw unavailable();
  return { allow_agent_intros: true, incarnation, checked_at_ms: body.checked_at_ms };
}

function accountDisplay(owner: unknown): { name: string; provider: "LinkedIn" | "X" } | null {
  if (!record(owner)) return null;
  const linkedin = owner.linkedin;
  if (record(linkedin) && linkedin.account_linked === true) {
    if (Object.keys(linkedin).sort().join() !== "account_linked,name" || typeof linkedin.name !== "string"
      || linkedin.name.length < 1 || linkedin.name.length > 100 || linkedin.name.trim() !== linkedin.name
      || UNSAFE_DISPLAY_RE.test(linkedin.name)) throw new CliError("E_UNEXPECTED_RESPONSE", "public linked-account display is unsafe");
    return { name: linkedin.name, provider: "LinkedIn" };
  }
  const x = owner.x;
  if (record(x) && x.account_linked === true) {
    if (Object.keys(x).sort().join() !== "account_linked,handle" || typeof x.handle !== "string"
      || !/^[A-Za-z0-9_]{1,15}$/.test(x.handle)) throw new CliError("E_UNEXPECTED_RESPONSE", "public linked-account display is unsafe");
    return { name: `@${x.handle}`, provider: "X" };
  }
  return null;
}

/** Fill only the frozen public account-linked fields; caller-supplied names are never accepted. */
export function composeIntro(domain: string, owner: unknown, token: string): string {
  if (!isValidVizAgentDomain(domain) || !INTRO_DOMAIN_RE.test(domain)
    || token.length > 1024 || !/^zvintro1\.[A-Za-z0-9_-]+$/.test(token)) throw invalid();
  const display = accountDisplay(owner);
  const opening = display ? `Lovely to meet you. I'm ${display.name}'s agent (${display.provider} account linked).`
    : `Lovely to meet you. I'm ${domain}.`;
  return `${opening} I check agents on ZipViz. It's free to join at https://zipviz.ai/join, then we can carry on with verified DMs. Intro code: ${token}`;
}
