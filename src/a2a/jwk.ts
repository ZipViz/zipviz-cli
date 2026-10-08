import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64urlnopad } from "@scure/base";
import { canonicalizeJson } from "./jcs.js";
import { KeyError } from "./reasons.js";
import type { JsonObject, JsonValue } from "./schema.js";

type JwkMetadata = { kid?: string; alg?: string; use?: string };
export type OkpPublicJwk = JwkMetadata & { kty: "OKP"; crv: "Ed25519"; x: string };
export type EcPublicJwk = JwkMetadata & { kty: "EC"; crv: "P-256"; x: string; y: string };
export type PublicJwk = OkpPublicJwk | EcPublicJwk;
export type OkpPrivateJwk = OkpPublicJwk & { d: string };
export type EcPrivateJwk = EcPublicJwk & { d: string };
export type PrivateJwk = OkpPrivateJwk | EcPrivateJwk;

const PRIVATE_PARAMETERS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function invalid(): never {
  throw new KeyError("KEY_INVALID");
}

function decode(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return invalid();
  try {
    const decoded = base64urlnopad.decode(value);
    if (base64urlnopad.encode(decoded) !== value) return invalid();
    return decoded;
  } catch {
    return invalid();
  }
}

function metadata(value: Record<string, unknown>): JwkMetadata {
  const result: JwkMetadata = {};
  for (const key of ["kid", "alg", "use"] as const) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      if (typeof value[key] !== "string") return invalid();
      result[key] = value[key];
    }
  }
  return result;
}

function assertPublicKey(value: PublicJwk): void {
  const x = decode(value.x);
  if (x.length !== 32) return invalid();
  if (value.kty === "OKP") {
    const point = ed25519.Point.fromBytes(x, false);
    point.assertValidity();
    if (point.isSmallOrder()) return invalid();
    return;
  }
  const y = decode(value.y);
  if (y.length !== 32) return invalid();
  const point = new Uint8Array(65);
  point[0] = 4;
  point.set(x, 1);
  point.set(y, 33);
  p256.Point.fromBytes(point).assertValidity();
}

export function parsePublicJwk(value: unknown): PublicJwk {
  if (!isPlainObject(value)) return invalid();
  if (PRIVATE_PARAMETERS.some((parameter) => Object.prototype.hasOwnProperty.call(value, parameter))) return invalid();
  const extra = metadata(value);
  let result: PublicJwk;
  if (value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string") {
    result = { kty: "OKP", crv: "Ed25519", x: value.x, ...extra };
  } else if (value.kty === "EC" && value.crv === "P-256" &&
    typeof value.x === "string" && typeof value.y === "string") {
    result = { kty: "EC", crv: "P-256", x: value.x, y: value.y, ...extra };
  } else {
    return invalid();
  }
  try {
    assertPublicKey(result);
  } catch (error) {
    if (error instanceof KeyError) throw error;
    return invalid();
  }
  return result;
}

export function parseJwks(value: unknown): PublicJwk[] {
  if (!isPlainObject(value) || !Array.isArray(value.keys)) throw new KeyError("JWKS_INVALID");
  if (value.keys.length > 32) throw new KeyError("JWKS_INVALID");
  return value.keys.map((key) => parsePublicJwk(key));
}

export function jwkThumbprint(jwk: PublicJwk): string {
  const members: JsonObject = jwk.kty === "OKP"
    ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return base64urlnopad.encode(sha256(new TextEncoder().encode(canonicalizeJson(members))));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a[index]! ^ b[index]!;
  return difference === 0;
}

function privateBytes(value: unknown): Uint8Array {
  const bytes = decode(value);
  if (bytes.length !== 32) return invalid();
  return bytes;
}

export function publicJwkFromPrivate(value: PrivateJwk): PublicJwk {
  if (!isPlainObject(value)) return invalid();
  const secret = privateBytes(value.d);
  let publicKey: Uint8Array;
  let expected: PublicJwk;
  try {
    if (value.kty === "OKP" && value.crv === "Ed25519" && typeof value.x === "string") {
      publicKey = ed25519.getPublicKey(secret);
      expected = parsePublicJwk({ kty: "OKP", crv: "Ed25519", x: value.x, ...metadata(value) });
      if (!bytesEqual(publicKey, decode(expected.x))) return invalid();
      return expected;
    }
    if (value.kty === "EC" && value.crv === "P-256" &&
      typeof value.x === "string" && typeof value.y === "string") {
      publicKey = p256.getPublicKey(secret, false);
      expected = parsePublicJwk({ kty: "EC", crv: "P-256", x: value.x, y: value.y, ...metadata(value) });
      if (expected.kty !== "EC") return invalid();
      if (!bytesEqual(publicKey.subarray(1, 33), decode(expected.x)) ||
        !bytesEqual(publicKey.subarray(33, 65), decode(expected.y))) return invalid();
      return expected;
    }
  } catch (error) {
    if (error instanceof KeyError) throw error;
    return invalid();
  }
  return invalid();
}

export function jwkToJson(jwk: PublicJwk): JsonValue {
  return { ...jwk };
}
