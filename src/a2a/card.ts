import { base64urlnopad } from "@scure/base";
import {
  jwkThumbprint,
  parsePublicJwk,
  publicJwkFromPrivate,
  type PrivateJwk,
  type PublicJwk,
} from "./jwk.js";
import { signJws, verifyJws, type JwsAlgorithm } from "./jws.js";
import { CardError, REASON_MESSAGES, type CardReason, type SigReason } from "./reasons.js";
import { canonicalizeCard, parseCardJson, type JsonObject, type JsonValue } from "./schema.js";

export type SignatureResult = {
  index: number;
  valid: boolean;
  reason?: SigReason;
  message?: string;
  warnings?: SignatureWarning[];
  alg?: string;
  kid?: string;
  jku?: string;
  key_thumbprint?: string;
  unprotected_ignored?: string[];
};

export type SignatureWarning = {
  code: "SIG_TYP_UNEXPECTED";
  message: string;
};

export type CardWarning = {
  code: "CARD_SIGNATURE_FAILED_VERIFICATION";
  reason: SigReason | "KEY_JKU_HOST_NOT_ALLOWED";
  message: string;
  signature_index: number;
};

export type CardSignatureJson = {
  protected: string;
  signature: string;
  header?: JsonObject;
};
export type SignedCard = JsonObject & { signatures: CardSignatureJson[] };

export type CardVerification = {
  valid: boolean;
  valid_signatures: number;
  reason?: CardReason;
  message?: string;
  pointer?: string;
  uncovered: string[];
  signatures: SignatureResult[];
  warnings?: CardWarning[];
};

export type ReadSignature = {
  index: number;
  alg?: string;
  kid?: string;
  jku?: string;
  typ?: unknown;
  x5u?: string;
  reason?: SigReason;
  warnings?: SignatureWarning[];
  unprotected_ignored?: string[];
};

type WarningSignature = Omit<SignatureResult, "reason"> & {
  reason?: SigReason | "KEY_JKU_HOST_NOT_ALLOWED";
};

export const WARNING_EXEMPT_REASONS = new Set(["SIG_KEY_NOT_FOUND", "KEY_JKU_HOST_NOT_ALLOWED"]);

export function cardWarnings(signatures: WarningSignature[]): CardWarning[] {
  if (!signatures.some((signature) => signature.valid)) return [];
  const warnings: CardWarning[] = [];
  for (const signature of signatures) {
    if (signature.valid) continue;
    const reason = signature.reason ?? "SIG_MALFORMED";
    if (WARNING_EXEMPT_REASONS.has(reason)) continue;
    const identity = signature.kid === undefined ? "" : ` claiming key ${signature.kid}`;
    warnings.push({
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason,
      message: `signature ${signature.index + 1}${identity} failed verification: ${reason}`,
      signature_index: signature.index,
    });
  }
  return warnings;
}

type ParsedSignature = {
  index: number;
  protectedHeader: Record<string, unknown>;
  protectedText: string;
  signature: Uint8Array;
  alg: JwsAlgorithm;
  kid: string;
  typ?: unknown;
  jku?: string;
  x5u?: string;
  warnings: SignatureWarning[];
  unprotectedIgnored: string[];
};

const HEADER_KEYS_TO_REPORT = new Set(["alg", "kid", "jku", "crit", "b64", "x5u", "x5c", "jwk"]);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function plainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function signatureError(reason: SigReason): never {
  throw Object.assign(new Error(REASON_MESSAGES[reason]), { reason });
}

function decodeBase64Url(value: string): Uint8Array {
  try {
    const decoded = base64urlnopad.decode(value);
    if (base64urlnopad.encode(decoded) !== value) signatureError("SIG_ENCODING_INVALID");
    return decoded;
  } catch (error) {
    if (typeof error === "object" && error !== null && "reason" in error) throw error;
    return signatureError("SIG_ENCODING_INVALID");
  }
}

function validJku(value: unknown): value is string {
  if (typeof value !== "string" || value !== value.trim() || !/^https:\/\//i.test(value)) return false;
  try {
    const url = new URL(value);
    const authority = value.match(/^https:\/\/([^/?#]*)/i)?.[1] ?? "";
    return url.protocol === "https:" && url.username === "" && url.password === "" &&
      !authority.includes("@") && !value.includes("#") && url.hash === "" && url.hostname !== "";
  } catch {
    return false;
  }
}

function readProtectedHeader(text: string): Record<string, unknown> {
  const bytes = decodeBase64Url(text);
  let decoded: string;
  try {
    decoded = decoder.decode(bytes);
  } catch {
    return signatureError("SIG_ENCODING_INVALID");
  }
  const parsed = parseCardJson(decoded);
  if (!parsed.ok) return signatureError("SIG_HEADER_INVALID");
  return parsed.card;
}

function typWarning(value: unknown): SignatureWarning | undefined {
  if (value === undefined || (typeof value === "string" && value.toUpperCase() === "JOSE")) return undefined;
  const displayed = (JSON.stringify(value) ?? "undefined").slice(0, 64);
  return { code: "SIG_TYP_UNEXPECTED", message: `typ ${displayed} is not JOSE` };
}

function parsedHeader(header: Record<string, unknown>, signature: unknown): {
  alg: JwsAlgorithm;
  kid: string;
  typ?: unknown;
  jku?: string;
  x5u?: string;
  warnings: SignatureWarning[];
  ignored: string[];
} {
  if (Object.prototype.hasOwnProperty.call(header, "crit") ||
    Object.prototype.hasOwnProperty.call(header, "b64")) signatureError("SIG_CRIT_UNSUPPORTED");
  if (typeof header.alg !== "string") signatureError("SIG_HEADER_INVALID");
  if (header.alg === "none") signatureError("SIG_ALG_NONE");
  if (header.alg !== "EdDSA" && header.alg !== "ES256") signatureError("SIG_ALG_UNSUPPORTED");
  if (typeof header.kid !== "string" || header.kid.length === 0 || header.kid.length > 256) {
    signatureError("SIG_KID_MISSING");
  }
  if (Object.prototype.hasOwnProperty.call(header, "jku") && !validJku(header.jku)) {
    signatureError("SIG_JKU_INVALID");
  }
  const protectedHeader = header;
  const unprotected = plainObject(signature) && plainObject(signature.header) ? signature.header : {};
  const ignored = [...HEADER_KEYS_TO_REPORT].filter((key) =>
    Object.prototype.hasOwnProperty.call(unprotected, key)
  ).sort();
  return {
    alg: header.alg,
    kid: header.kid,
    ...(header.typ === undefined ? {} : { typ: header.typ }),
    ...(typeof header.jku === "string" ? { jku: header.jku } : {}),
    ...(typeof protectedHeader.x5u === "string" ? { x5u: protectedHeader.x5u } : {}),
    warnings: (warning => warning ? [warning] : [])(typWarning(header.typ)),
    ignored,
  };
}

function parseSignature(value: unknown, index: number): ParsedSignature {
  if (!plainObject(value)) return signatureError("SIG_MALFORMED");
  const allowed = new Set(["protected", "signature", "header"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) ||
    typeof value.protected !== "string" || typeof value.signature !== "string") {
    return signatureError("SIG_MALFORMED");
  }
  if (value.header !== undefined && value.header !== null && !plainObject(value.header)) {
    return signatureError("SIG_MALFORMED");
  }
  const header = readProtectedHeader(value.protected);
  const fields = parsedHeader(header, value);
  const signature = decodeBase64Url(value.signature);
  if (signature.length !== 64) return signatureError("SIG_MALFORMED");
  return {
    index,
    protectedHeader: header,
    protectedText: value.protected,
    signature,
    alg: fields.alg,
    kid: fields.kid,
    ...(fields.typ === undefined ? {} : { typ: fields.typ }),
    ...(fields.jku === undefined ? {} : { jku: fields.jku }),
    ...(fields.x5u === undefined ? {} : { x5u: fields.x5u }),
    warnings: fields.warnings,
    unprotectedIgnored: fields.ignored,
  };
}

function getSignatureArray(card: JsonObject): JsonValue[] | undefined {
  const value = card.signatures;
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) throw new CardError("CARD_SCHEMA_INVALID", "signatures must be an array", "/signatures");
  return value;
}

function errorReason(error: unknown): SigReason {
  if (typeof error === "object" && error !== null && "reason" in error) {
    const reason = (error as { reason?: unknown }).reason;
    if (typeof reason === "string") return reason as SigReason;
  }
  return "SIG_MALFORMED";
}

function resolveSignature(
  parsed: ParsedSignature,
  keys: PublicJwk[],
  signingInput: Uint8Array,
): SignatureResult {
  const matching: Array<{ key: PublicJwk; thumbprint: string }> = [];
  let sameKid = false;
  for (const input of keys) {
    let key: PublicJwk;
    try {
      key = parsePublicJwk(input);
    } catch {
      continue;
    }
    const thumbprint = jwkThumbprint(key);
    if (key.kid !== parsed.kid && thumbprint !== parsed.kid) continue;
    sameKid = true;
    const keyAlg = key.kty === "OKP" ? "EdDSA" : "ES256";
    if (keyAlg !== parsed.alg || (key.alg !== undefined && key.alg !== parsed.alg) ||
      (key.use !== undefined && key.use !== "sig")) continue;
    matching.push({ key, thumbprint });
  }
  const common = {
    index: parsed.index,
    alg: parsed.alg,
    kid: parsed.kid,
    ...(parsed.jku === undefined ? {} : { jku: parsed.jku }),
    ...(parsed.warnings.length === 0 ? {} : { warnings: parsed.warnings }),
    ...(parsed.unprotectedIgnored.length === 0 ? {} : { unprotected_ignored: parsed.unprotectedIgnored }),
  };
  if (matching.length === 0) {
    const reason: SigReason = sameKid ? "SIG_KEY_ALG_MISMATCH" : "SIG_KEY_NOT_FOUND";
    return { ...common, valid: false, reason, message: REASON_MESSAGES[reason] };
  }
  for (const candidate of matching) {
    if (verifyJws(parsed.alg, signingInput, parsed.signature, candidate.key)) {
      return { ...common, valid: true, key_thumbprint: candidate.thumbprint };
    }
  }
  return { ...common, valid: false, reason: "SIG_INVALID", message: REASON_MESSAGES.SIG_INVALID };
}

function cardFailure(error: unknown): CardVerification {
  if (error instanceof CardError) {
    return {
      valid: false,
      reason: error.reason,
      message: error.message,
      ...(error.pointer === undefined ? {} : { pointer: error.pointer }),
      valid_signatures: 0,
      uncovered: [],
      signatures: [],
    };
  }
  return {
    valid: false,
    reason: "CARD_SCHEMA_INVALID",
    message: REASON_MESSAGES.CARD_SCHEMA_INVALID,
    valid_signatures: 0,
    uncovered: [],
    signatures: [],
  };
}

export function signCard(
  card: JsonObject,
  privateKey: PrivateJwk,
  options: { kid?: string; jku?: string; append?: boolean },
): SignedCard {
  const canonical = canonicalizeCard(card);
  if (canonical.uncovered.length > 0) {
    throw new CardError("CARD_UNCOVERED_FIELDS", `${REASON_MESSAGES.CARD_UNCOVERED_FIELDS}: ${canonical.uncovered.join(", ")}`);
  }
  const signatures = getSignatureArray(card);
  if (signatures && signatures.length > 0 && !options.append) throw new CardError("CARD_ALREADY_SIGNED");
  if (signatures && signatures.length > 0 && signatures.length >= 16) {
    throw new CardError("CARD_TOO_MANY_SIGNATURES");
  }
  const publicKey = publicJwkFromPrivate(privateKey);
  const alg: JwsAlgorithm = publicKey.kty === "OKP" ? "EdDSA" : "ES256";
  const kid = options.kid ?? jwkThumbprint(publicKey);
  if (kid.length === 0 || kid.length > 256) throw new CardError("CARD_SCHEMA_INVALID", "kid must be 1 to 256 characters");
  if (options.jku !== undefined && !validJku(options.jku)) {
    throw new CardError("CARD_SCHEMA_INVALID", REASON_MESSAGES.SIG_JKU_INVALID);
  }
  const header = { alg, typ: "JOSE", kid, ...(options.jku ? { jku: options.jku } : {}) };
  const protectedText = base64urlnopad.encode(encoder.encode(JSON.stringify(header)));
  const payload = encoder.encode(canonical.canonical);
  const signingInput = encoder.encode(`${protectedText}.${base64urlnopad.encode(payload)}`);
  const signature = signJws(alg, signingInput, privateKey);
  const newSignature: JsonObject = {
    protected: protectedText,
    signature: base64urlnopad.encode(signature),
  };
  const result: SignedCard = {
    ...card,
    signatures: [...(options.append ? signatures ?? [] : []), newSignature] as CardSignatureJson[],
  };
  return result;
}

export function readSignatures(card: JsonObject): ReadSignature[] {
  if (!Array.isArray(card.signatures)) return [];
  return card.signatures.map((entry, index) => {
    if (!plainObject(entry) || typeof entry.protected !== "string") {
      return { index, reason: "SIG_MALFORMED" };
    }
    try {
      const header = readProtectedHeader(entry.protected);
      const parsed = parsedHeader(header, entry);
      return {
        index,
        alg: parsed.alg,
        kid: parsed.kid,
        ...(parsed.typ === undefined ? {} : { typ: parsed.typ }),
        ...(parsed.jku === undefined ? {} : { jku: parsed.jku }),
        ...(parsed.x5u === undefined ? {} : { x5u: parsed.x5u }),
        ...(parsed.warnings.length === 0 ? {} : { warnings: parsed.warnings }),
        ...(parsed.ignored.length === 0 ? {} : { unprotected_ignored: parsed.ignored }),
      };
    } catch (error) {
      const reason = errorReason(error);
      const partial: ReadSignature = { index, reason };
      try {
        const header = readProtectedHeader(entry.protected);
        if (typeof header.alg === "string") partial.alg = header.alg;
        if (typeof header.kid === "string") partial.kid = header.kid;
        if (typeof header.jku === "string") partial.jku = header.jku;
        if (header.typ !== undefined) partial.typ = header.typ;
        if (typeof header.x5u === "string") partial.x5u = header.x5u;
        const warning = typWarning(header.typ);
        if (warning) partial.warnings = [warning];
        if (plainObject(entry.header)) {
          const ignored = [...HEADER_KEYS_TO_REPORT].filter((key) =>
            Object.prototype.hasOwnProperty.call(entry.header, key)
          ).sort();
          if (ignored.length > 0) partial.unprotected_ignored = ignored;
        }
      } catch {
        return partial;
      }
      return partial;
    }
  });
}

export function verifyCard(card: JsonObject, options: { keys: PublicJwk[]; requireAll?: boolean }): CardVerification {
  let canonical: ReturnType<typeof canonicalizeCard>;
  let signatures: JsonValue[] | undefined;
  try {
    canonical = canonicalizeCard(card);
    signatures = getSignatureArray(card);
  } catch (error) {
    return cardFailure(error);
  }
  if (!signatures || signatures.length === 0) {
    return {
      valid: false,
      valid_signatures: 0,
      reason: "CARD_UNSIGNED",
      message: REASON_MESSAGES.CARD_UNSIGNED,
      uncovered: canonical.uncovered,
      signatures: [],
    };
  }
  if (signatures.length > 16) {
    return {
      valid: false,
      valid_signatures: 0,
      reason: "CARD_TOO_MANY_SIGNATURES",
      message: REASON_MESSAGES.CARD_TOO_MANY_SIGNATURES,
      uncovered: canonical.uncovered,
      signatures: [],
    };
  }
  const payload = encoder.encode(canonical.canonical);
  const results: SignatureResult[] = signatures.map((entry, index) => {
    try {
      const parsed = parseSignature(entry, index);
      const signingInput = encoder.encode(`${parsed.protectedText}.${base64urlnopad.encode(payload)}`);
      return resolveSignature(parsed, options.keys, signingInput);
    } catch (error) {
      const reason = errorReason(error);
      const base: SignatureResult = {
        index,
        valid: false,
        reason,
        message: typeof error === "object" && error !== null && "message" in error &&
          typeof (error as { message?: unknown }).message === "string"
          ? (error as { message: string }).message
          : REASON_MESSAGES[reason],
      };
      if (plainObject(entry) && typeof entry.protected === "string") {
        try {
          const header = readProtectedHeader(entry.protected);
          if (typeof header.alg === "string") base.alg = header.alg;
          if (typeof header.kid === "string") base.kid = header.kid;
          if (typeof header.jku === "string") base.jku = header.jku;
          const warning = typWarning(header.typ);
          if (warning) base.warnings = [warning];
          if (plainObject(entry.header)) {
            const ignored = [...HEADER_KEYS_TO_REPORT].filter((key) =>
              Object.prototype.hasOwnProperty.call(entry.header, key)
            ).sort();
            if (ignored.length > 0) base.unprotected_ignored = ignored;
          }
        } catch {
          return base;
        }
      }
      return base;
    }
  });
  const valid_signatures = results.filter((result) => result.valid).length;
  const warnings = cardWarnings(results);
  const warningFields = warnings.length === 0 ? {} : { warnings };
  const valid = options.requireAll === true
    ? results.every((result) => result.valid)
    : valid_signatures >= 1;
  if (!valid) {
    return {
      valid: false,
      valid_signatures,
      reason: "CARD_SIGNATURES_INVALID",
      message: REASON_MESSAGES.CARD_SIGNATURES_INVALID,
      uncovered: canonical.uncovered,
      signatures: results,
      ...warningFields,
    };
  }
  return { valid: true, valid_signatures, uncovered: canonical.uncovered, signatures: results, ...warningFields };
}

export { parseCardJson };
