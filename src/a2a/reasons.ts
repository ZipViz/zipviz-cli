export const CARD_REASONS = [
  "CARD_NOT_JSON",
  "CARD_NOT_OBJECT",
  "CARD_DUPLICATE_KEY",
  "CARD_SCHEMA_INVALID",
  "CARD_MISSING_REQUIRED",
  "CARD_TOO_DEEP",
  "CARD_TOO_MANY_SIGNATURES",
  "CARD_SIGNATURES_INVALID",
  "CARD_UNSIGNED",
  "CARD_UNCOVERED_FIELDS",
  "CARD_ALREADY_SIGNED",
] as const;

export const SIG_REASONS = [
  "SIG_MALFORMED",
  "SIG_ENCODING_INVALID",
  "SIG_HEADER_INVALID",
  "SIG_ALG_NONE",
  "SIG_ALG_UNSUPPORTED",
  "SIG_CRIT_UNSUPPORTED",
  "SIG_KID_MISSING",
  "SIG_JKU_INVALID",
  "SIG_KEY_NOT_FOUND",
  "SIG_KEY_ALG_MISMATCH",
  "SIG_INVALID",
] as const;

export const KEY_REASONS = ["KEY_INVALID", "JWKS_INVALID"] as const;

export type CardReason = (typeof CARD_REASONS)[number];
export type SigReason = (typeof SIG_REASONS)[number];
export type KeyReason = (typeof KEY_REASONS)[number];

export const REASON_MESSAGES: Record<CardReason | SigReason | KeyReason, string> = {
  CARD_NOT_JSON: "input is not valid JSON",
  CARD_NOT_OBJECT: "Agent Card must be a JSON object",
  CARD_DUPLICATE_KEY: "JSON contains a duplicate object member",
  CARD_SCHEMA_INVALID: "Agent Card does not match the A2A v1.0 schema",
  CARD_MISSING_REQUIRED: "required Agent Card field is missing",
  CARD_TOO_DEEP: "Agent Card nesting exceeds 128 levels",
  CARD_TOO_MANY_SIGNATURES: "Agent Card has more than 16 signatures",
  CARD_SIGNATURES_INVALID: "one or more Agent Card signatures are invalid",
  CARD_UNSIGNED: "Agent Card has no signatures",
  CARD_UNCOVERED_FIELDS: "Agent Card contains fields not covered by the A2A v1.0 schema",
  CARD_ALREADY_SIGNED: "Agent Card already has signatures; use --append to add another",
  SIG_MALFORMED: "signature object is malformed",
  SIG_ENCODING_INVALID: "signature contains invalid base64url or UTF-8",
  SIG_HEADER_INVALID: "protected header is not a JSON object",
  SIG_ALG_NONE: "the none signature algorithm is not supported",
  SIG_ALG_UNSUPPORTED: "signature algorithm is not supported",
  SIG_CRIT_UNSUPPORTED: "critical or unencoded-payload header parameters are not supported",
  SIG_KID_MISSING: "protected header kid is missing or invalid",
  SIG_JKU_INVALID: "protected header jku must be an HTTPS URL without userinfo or fragment",
  SIG_KEY_NOT_FOUND: "no public key matches the protected header kid",
  SIG_KEY_ALG_MISMATCH: "public key is not compatible with the protected header alg",
  SIG_INVALID: "signature does not match the card",
  KEY_INVALID: "public or private JWK is invalid",
  JWKS_INVALID: "JWKS must contain at most 32 public keys",
};

export class CardError extends Error {
  constructor(
    readonly reason: CardReason,
    message: string = REASON_MESSAGES[reason],
    readonly pointer?: string,
  ) {
    super(message);
    this.name = "CardError";
  }
}

export class KeyError extends Error {
  constructor(
    readonly reason: KeyReason,
    message: string = REASON_MESSAGES[reason],
  ) {
    super(message);
    this.name = "KeyError";
  }
}
