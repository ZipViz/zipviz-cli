import { canonicalizeJson, isPlainObject, parseCanonicalJson } from './jcs.js';
import { base64UrlDecode, base64UrlEncode, concatBytes, decodeUtf8, fromHex, sha256, toHex, utf8 } from './bytes.js';

export const SIGNUP_BODY_MAX_BYTES = 4096;
export const SIGNUP_FRESHNESS_MS = 300000;
export const SIGNUP_DOMAINS = Object.freeze({
  start: 'ZipViz signup-start v1', cancel: 'ZipViz signup-cancel v1',
  intro: 'ZipViz intro v1', policy: 'ZipViz intro-policy v1',
});
export const SIGNUP_RUNTIME_VALUES = Object.freeze(['claude', 'codex', 'buzz', 'openclaw', 'hermes', 'other']);
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const INCARNATION = /^[0-9a-f]{32}$/;
const DOMAIN = /^[a-z0-9][a-z0-9-]{0,19}\.(?:[a-z0-9][a-z0-9-]{0,19}\.)?viz$/;
const SIGNATURE_KEYS = ['alg', 'key_id', 'value_base64url'];

export class SignupCodecError extends Error {
  constructor(status, code) { super(code); this.name = 'SignupCodecError'; this.status = status; this.code = code; }
}
function refuse(status, code) { throw new SignupCodecError(status, code); }
function exact(value, keys) {
  return isPlainObject(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|');
}
function milliseconds(value) { return Number.isSafeInteger(value) && value >= 0; }
function signatureShape(value) {
  return exact(value, SIGNATURE_KEYS) && value.alg === 'Ed25519'
    && typeof value.key_id === 'string' && /^sha256:[0-9a-f]{64}$/.test(value.key_id)
    && typeof value.value_base64url === 'string' && /^[A-Za-z0-9_-]{86}$/.test(value.value_base64url)
    && base64UrlDecode(value.value_base64url)?.length === 64;
}
function signedShape(value, type, keys) {
  return exact(value, [...keys, 'schema_version', 'type', 'issued_at_ms', 'signature'])
    && value.schema_version === '1.0' && value.type === type && milliseconds(value.issued_at_ms)
    && typeof value.audience === 'string' && value.audience.length > 0 && value.audience.length <= 253
    && signatureShape(value.signature);
}

// Limit the stream before decoding, parsing or cryptographic work. Admission
// bindings are run by the route before calling this helper.
export async function readSignupBody(request, shapeCode = 'E_SIGNUP_SHAPE') {
  if (!request.body) refuse(400, shapeCode);
  const reader = request.body.getReader(); const chunks = []; let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      total += value.byteLength;
      if (total > SIGNUP_BODY_MAX_BYTES) { await reader.cancel(); refuse(413, shapeCode); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const text = decodeUtf8(bytes); if (text === null) refuse(400, shapeCode);
  return text;
}
function canonicalBody(text, code) {
  if (typeof text !== 'string') refuse(400, code);
  if (utf8(text).byteLength > SIGNUP_BODY_MAX_BYTES) refuse(413, code);
  const body = parseCanonicalJson(text); if (!isPlainObject(body)) refuse(400, code);
  return body;
}
export function normalizeSignupEmail(email) {
  if (typeof email !== 'string') refuse(400, 'E_SIGNUP_SHAPE');
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) refuse(400, 'E_SIGNUP_SHAPE');
  return normalized;
}
export function parseSignupStart(text) {
  const body = canonicalBody(text, 'E_SIGNUP_SHAPE');
  if (!exact(body, ['proof', 'name', 'owner_email', 'runtime', 'introduced_by'])
      || !signedShape(body.proof, 'zipviz.signup.start', ['signup_id', 'public_key', 'audience', 'bound_digest'])
      || !UUID_V4.test(body.proof.signup_id) || !HEX32.test(body.proof.bound_digest)
      || typeof body.name !== 'string' || body.name.length > 254
      || !(body.introduced_by === null || (typeof body.introduced_by === 'string' && body.introduced_by.length <= 1024)))
    refuse(400, 'E_SIGNUP_SHAPE');
  if (typeof body.proof.public_key !== 'string' || !HEX32.test(body.proof.public_key)) refuse(400, 'E_KEY_INVALID');
  if (!SIGNUP_RUNTIME_VALUES.includes(body.runtime)) refuse(400, 'E_RUNTIME');
  normalizeSignupEmail(body.owner_email);
  return body;
}
export function parseSignupCancel(text) {
  const body = canonicalBody(text, 'E_SIGNUP_SHAPE');
  if (!signedShape(body, 'zipviz.signup.cancel', ['signup_id', 'audience', 'nonce'])
      || !UUID_V4.test(body.signup_id) || !UUID_V4.test(body.nonce)) refuse(400, 'E_SIGNUP_SHAPE');
  return body;
}
export function parseIntroPolicy(text) {
  const body = canonicalBody(text, 'E_POLICY_SHAPE');
  if (!signedShape(body, 'zipviz.intro_policy.read', ['domain', 'incarnation', 'audience'])
      || typeof body.domain !== 'string' || !DOMAIN.test(body.domain)
      || typeof body.incarnation !== 'string' || !INCARNATION.test(body.incarnation)) refuse(400, 'E_POLICY_SHAPE');
  return body;
}
export const parsePolicyRequest = parseIntroPolicy;
function validateIntro(body) {
  if (!signedShape(body, 'zipviz.intro', ['id', 'introducer', 'introducer_incarnation', 'audience', 'expires_at_ms'])
      || !UUID_V4.test(body.id) || typeof body.introducer !== 'string' || !DOMAIN.test(body.introducer)
      || typeof body.introducer_incarnation !== 'string' || !INCARNATION.test(body.introducer_incarnation)
      || !milliseconds(body.expires_at_ms) || body.expires_at_ms <= body.issued_at_ms
      || body.expires_at_ms - body.issued_at_ms > 259200000) refuse(422, 'E_INTRO_INVALID');
  return body;
}
export function parseIntroToken(token) {
  if (typeof token !== 'string' || token.length > 1024 || !token.startsWith('zvintro1.')) refuse(422, 'E_INTRO_INVALID');
  const bytes = base64UrlDecode(token.slice(9));
  const text = bytes && decodeUtf8(bytes); const body = text === null ? null : parseCanonicalJson(text);
  return validateIntro(body);
}
export function signupSigningBytes(object, domain) {
  const { signature: _signature, ...unsigned } = object;
  return concatBytes(utf8(domain), 0, utf8(canonicalizeJson(unsigned)));
}
export async function signupRequestDigest(text) { return toHex(await sha256(utf8(text))); }
export async function signupSubjectId(domain, incarnation) {
  if (typeof domain !== 'string' || !DOMAIN.test(domain)
      || typeof incarnation !== 'string' || !INCARNATION.test(incarnation)) throw new TypeError('invalid subject identity');
  const tuple = canonicalizeJson({ registry_origin: 'https://api.zipviz.ai', domain, incarnation });
  return `sub1_${base64UrlEncode(await sha256(concatBytes(utf8('ZipViz subject-id v1'), 0, utf8(tuple))))}`;
}
export async function signupKeyId(publicKey) {
  if (typeof publicKey !== 'string' || !HEX32.test(publicKey)) refuse(403, 'E_SIGNUP_PROOF');
  return `sha256:${toHex(await sha256(fromHex(publicKey)))}`;
}
export async function signupBoundDigest({ owner_email, runtime, introduced_by }) {
  return signupRequestDigest(canonicalizeJson({ introduced_by, owner_email: normalizeSignupEmail(owner_email), runtime }));
}
async function signatureValid(body, publicKey, domain) {
  try {
    if (!signatureShape(body.signature) || body.signature.key_id !== await signupKeyId(publicKey)) return false;
    const key = await crypto.subtle.importKey('raw', fromHex(publicKey), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, base64UrlDecode(body.signature.value_base64url), signupSigningBytes(body, domain));
  } catch { return false; }
}
function audienceMatches(body, audience) {
  if (typeof audience !== 'string' || audience.length === 0 || body.audience !== audience) refuse(401, 'E_SIGNUP_AUD');
}
export function assertSignupFresh(issuedAt, now) {
  if (!milliseconds(issuedAt) || !milliseconds(now) || Math.abs(now - issuedAt) > SIGNUP_FRESHNESS_MS) refuse(401, 'E_STALE');
}
export async function verifySignupStart(body, audience) {
  audienceMatches(body.proof, audience);
  if (!await signatureValid(body.proof, body.proof.public_key, SIGNUP_DOMAINS.start)
      || body.proof.bound_digest !== await signupBoundDigest(body)) refuse(403, 'E_SIGNUP_PROOF');
  return body;
}
export async function verifySignupCancel(body, publicKey, audience) {
  audienceMatches(body, audience);
  if (!await signatureValid(body, publicKey, SIGNUP_DOMAINS.cancel)) refuse(403, 'E_SIGNUP_PROOF');
  return body;
}
export async function verifyIntroPolicy(body, publicKey, audience) {
  audienceMatches(body, audience);
  if (!await signatureValid(body, publicKey, SIGNUP_DOMAINS.policy)) refuse(403, 'E_POLICY_PROOF');
  return body;
}
export async function verifyIntroToken(token, authority, now, audience) {
  const intro = typeof token === 'string' ? parseIntroToken(token) : validateIntro(token);
  // The caller supplies a coherent primary read. These captured values must
  // still be rechecked by the admission INSERT, not only here.
  const incarnation = authority?.identity_incarnation ?? authority?.incarnation;
  const revision = authority?.identity_revision ?? authority?.revision;
  if (!authority || authority.domain !== intro.introducer || incarnation !== intro.introducer_incarnation
      || !Number.isSafeInteger(revision) || revision < 0 || !milliseconds(now)
      || intro.issued_at_ms > now + 60000 || intro.expires_at_ms <= now
      || typeof audience !== 'string' || intro.audience !== audience
      || !await signatureValid(intro, authority.public_key, SIGNUP_DOMAINS.intro)) refuse(422, 'E_INTRO_INVALID');
  return { intro, authority: { domain: authority.domain, public_key: authority.public_key, incarnation, revision } };
}
