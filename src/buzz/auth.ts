import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { BuzzVerification, AuthReason, Clause } from "./reasons.js";
import type { NostrEvent } from "./event.js";
import { npubEncode } from "./npub.js";

const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

type ParsedClause = Omit<Clause, "satisfied">;
type ConditionsResult =
  | { ok: true; clauses: ParsedClause[] }
  | { ok: false; reason: AuthReason; message: string };

export function authPreimage(agentPubkeyHex: string, conditions: string): string {
  return `nostr:agent-auth:${agentPubkeyHex}:${conditions}`;
}

export function authMessageHash(agentPubkeyHex: string, conditions: string): Uint8Array {
  return sha256(utf8ToBytes(authPreimage(agentPubkeyHex, conditions)));
}

export function parseConditions(conditions: string): ConditionsResult {
  if (conditions === "") return { ok: true, clauses: [] };
  if (!/^[\x21-\x7e]+$/.test(conditions)) {
    return { ok: false, reason: "AUTH_CONDITIONS_MALFORMED", message: "conditions must be printable ASCII without whitespace" };
  }

  const parts = conditions.split("&");
  if (parts.some((part) => part.length === 0)) {
    return { ok: false, reason: "AUTH_CONDITIONS_MALFORMED", message: "conditions contain an empty clause" };
  }

  const clauses: ParsedClause[] = [];
  for (const part of parts) {
    let field: ParsedClause["field"];
    let op: ParsedClause["op"];
    let decimal: string;
    if (part.startsWith("kind=")) {
      field = "kind";
      op = "=";
      decimal = part.slice("kind=".length);
    } else if (part.startsWith("created_at<")) {
      field = "created_at";
      op = "<";
      decimal = part.slice("created_at<".length);
    } else if (part.startsWith("created_at>")) {
      field = "created_at";
      op = ">";
      decimal = part.slice("created_at>".length);
    } else {
      return { ok: false, reason: "AUTH_CONDITION_UNSUPPORTED", message: "conditions contain an unsupported clause" };
    }

    if (!DECIMAL.test(decimal)) {
      return { ok: false, reason: "AUTH_CONDITION_BAD_DECIMAL", message: "condition values must be canonical decimal integers" };
    }

    const maxText = field === "kind" ? "65535" : "4294967295";
    if (decimal.length > maxText.length || (decimal.length === maxText.length && BigInt(decimal) > BigInt(maxText))) {
      return { ok: false, reason: "AUTH_CONDITION_OUT_OF_RANGE", message: "condition value is outside its allowed range" };
    }
    clauses.push({ clause: part, field, op, value: Number(decimal) });
  }

  return { ok: true, clauses };
}

function authFailure(reason: AuthReason, message: string): BuzzVerification["owner_auth"] {
  return { present: true, valid: false, reason, message };
}

function ownerLifts(pubkey: string): boolean {
  try {
    schnorr.utils.lift_x(BigInt(`0x${pubkey}`));
    return true;
  } catch {
    return false;
  }
}

function isClauseSatisfied(clause: ParsedClause, event: NostrEvent): boolean {
  if (clause.field === "kind") return event.kind === clause.value;
  if (clause.op === "<") return event.created_at < clause.value;
  return event.created_at > clause.value;
}

export function verifyOwnerAuth(event: NostrEvent, authTags: string[][]): BuzzVerification["owner_auth"] {
  if (authTags.length === 0) return { present: false, valid: false };
  if (authTags.length > 1) return authFailure("AUTH_MULTIPLE_TAGS", "event contains multiple auth tags");

  const tag = authTags[0]!;
  if (tag.length !== 4) return authFailure("AUTH_TAG_ELEMENT_COUNT", "auth tag must contain exactly four elements");

  const ownerPubkey = tag[1]!;
  if (!HEX_32.test(ownerPubkey)) {
    return authFailure("AUTH_OWNER_PUBKEY_FORMAT", "owner public key must be 64 lowercase hexadecimal characters");
  }
  if (ownerPubkey === event.pubkey) return authFailure("AUTH_SELF_ATTESTATION", "owner and agent public keys must differ");
  if (!ownerLifts(ownerPubkey)) {
    return authFailure("AUTH_OWNER_PUBKEY_NOT_ON_CURVE", "owner public key does not lift to a secp256k1 point");
  }

  const conditions = tag[2]!;
  const parsed = parseConditions(conditions);
  if (!parsed.ok) return authFailure(parsed.reason, parsed.message);

  const signature = tag[3]!;
  if (!HEX_64.test(signature)) {
    return authFailure("AUTH_SIG_FORMAT", "auth signature must be 128 lowercase hexadecimal characters");
  }
  let signatureValid = false;
  try {
    signatureValid = schnorr.verify(
      hexToBytes(signature),
      authMessageHash(event.pubkey, conditions),
      hexToBytes(ownerPubkey),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return authFailure("AUTH_SIG_INVALID", "owner authorisation signature is invalid");

  const clauses = parsed.clauses.map((clause) => ({ ...clause, satisfied: isClauseSatisfied(clause, event) }));
  const failed = clauses.filter((clause) => !clause.satisfied);
  if (failed.length > 0) {
    const details = failed.map((clause) => clause.clause.slice(0, 64)).join(", ").slice(0, 256);
    return authFailure("AUTH_CONDITION_UNMET", `event does not satisfy: ${details}`);
  }

  return {
    present: true,
    valid: true,
    owner_pubkey: ownerPubkey,
    owner_npub: npubEncode(ownerPubkey),
    conditions,
    clauses: clauses as Clause[],
  };
}

export function verifyOwnerAuthForInput(
  event: NostrEvent | undefined,
  tags: string[][],
  eventValid: boolean,
): BuzzVerification["owner_auth"] {
  const authTags = tags.filter((tag) => tag[0] === "auth");
  if (authTags.length === 0) return { present: false, valid: false };
  if (!eventValid || event === undefined) {
    return authFailure("AUTH_EVENT_INVALID", "owner authorisation was not checked because the event is invalid");
  }
  return verifyOwnerAuth(event, authTags);
}
