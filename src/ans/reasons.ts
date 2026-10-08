export const ANS_REASONS = [
  "ANS_NAME_INVALID",
  "ANS_INPUT_INVALID",
  "ANS_KEY_INVALID",
  "ANS_CERT_INVALID",
  "ANS_CERT_UNTRUSTED",
  "ANS_CERT_EXPIRED",
  "ANS_CERT_NOT_YET_VALID",
  "ANS_NAME_UNBOUND",
  "ANS_EVENT_MISMATCH",
  "ANS_FINGERPRINT_MISMATCH",
  "ANS_PROOF_INVALID",
  "ANS_SIG_MALFORMED",
  "ANS_SIGNATURE_INVALID",
  "ANS_REVOKED",
  "ANS_EXPIRED",
  "ANS_REVOCATION_NOT_CHECKED",
] as const;

export type AnsReason = (typeof ANS_REASONS)[number];

export class AnsError extends Error {
  constructor(
    readonly reason: AnsReason,
    message: string,
  ) {
    super(message);
    this.name = "AnsError";
  }
}
