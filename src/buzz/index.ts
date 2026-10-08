import type { BuzzVerification } from "./reasons.js";
import { verifyNostrEvent } from "./event.js";
import { verifyOwnerAuthForInput } from "./auth.js";

export type { AuthReason, Clause, EventReason, BuzzVerification } from "./reasons.js";
export type { NostrEvent } from "./event.js";
export { authMessageHash, authPreimage, parseConditions } from "./auth.js";
export { computeEventId } from "./event.js";
export { npubEncode } from "./npub.js";

export function verifyBuzzEvent(input: unknown): BuzzVerification {
  const checked = verifyNostrEvent(input);
  const record = typeof input === "object" && input !== null && !Array.isArray(input)
    ? input as Record<string, unknown>
    : undefined;
  const tags = Array.isArray(record?.tags)
    ? record.tags.filter((tag: unknown): tag is string[] => Array.isArray(tag) && tag[0] === "auth")
    : [];
  const auth = verifyOwnerAuthForInput(checked.signedEvent, tags, checked.result.valid);
  return {
    ok: checked.result.valid && (!auth.present || auth.valid),
    event: checked.result,
    owner_auth: auth,
  };
}
