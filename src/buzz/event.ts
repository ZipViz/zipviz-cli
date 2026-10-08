import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { BuzzVerification, EventReason } from "./reasons.js";
import { npubEncode } from "./npub.js";

const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;

export type NostrEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

type EventCheck = {
  result: BuzzVerification["event"];
  signedEvent?: NostrEvent;
};

export function computeEventId(event: NostrEvent): string {
  // Deliberately match nostr-tools IDs: JSON.stringify escapes other control chars as \u00XX, unlike NIP-01's verbatim rule.
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

function eventFailure(
  reason: EventReason,
  message: string,
  fields: Partial<BuzzVerification["event"]> = {},
): EventCheck {
  return {
    result: {
      valid: false,
      id: fields.id ?? null,
      agent_pubkey: fields.agent_pubkey ?? null,
      agent_npub: fields.agent_npub ?? null,
      kind: fields.kind ?? null,
      created_at: fields.created_at ?? null,
      reason,
      message,
    },
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasWellFormedUtf16(value: string): boolean {
  return !/[\uD800-\uDFFF]/u.test(value);
}

function liftX(pubkeyHex: string): boolean {
  try {
    schnorr.utils.lift_x(BigInt(`0x${pubkeyHex}`));
    return true;
  } catch {
    return false;
  }
}

export function verifyNostrEvent(value: unknown): EventCheck {
  if (!isPlainObject(value)) return eventFailure("EVENT_BAD_ID", "event is not a JSON object");

  const id = value.id;
  if (typeof id !== "string" || !HEX_32.test(id)) {
    return eventFailure("EVENT_BAD_ID", "event id must be 64 lowercase hexadecimal characters");
  }

  const pubkey = value.pubkey;
  if (typeof pubkey !== "string" || !HEX_32.test(pubkey)) {
    return eventFailure("EVENT_BAD_PUBKEY", "event public key must be 64 lowercase hexadecimal characters", { id });
  }

  const createdAt = value.created_at;
  if (typeof createdAt !== "number" || !Number.isSafeInteger(createdAt) || createdAt < 0) {
    return eventFailure("EVENT_BAD_CREATED_AT", "created_at must be a non-negative safe integer", { id, agent_pubkey: pubkey });
  }

  const kind = value.kind;
  if (typeof kind !== "number" || !Number.isInteger(kind) || kind < 0 || kind > 65535) {
    return eventFailure("EVENT_BAD_KIND", "kind must be an integer from 0 through 65535", { id, agent_pubkey: pubkey, created_at: createdAt });
  }

  const tags = value.tags;
  if (!Array.isArray(tags) || !tags.every((tag) =>
    Array.isArray(tag) && tag.every((element) => typeof element === "string"))) {
    return eventFailure("EVENT_BAD_TAGS", "tags must be arrays of strings", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }

  const content = value.content;
  if (typeof content !== "string") {
    return eventFailure("EVENT_BAD_CONTENT", "content must be a string", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }

  const sig = value.sig;
  if (typeof sig !== "string" || !HEX_64.test(sig)) {
    return eventFailure("EVENT_BAD_SIG", "signature must be 128 lowercase hexadecimal characters", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }

  if (!tags.every((tag) => tag.every(hasWellFormedUtf16))) {
    return eventFailure("EVENT_BAD_TAGS", "tag values must contain well-formed UTF-16", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }
  if (!hasWellFormedUtf16(content)) {
    return eventFailure("EVENT_BAD_CONTENT", "content must contain well-formed UTF-16", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }

  if (!liftX(pubkey)) {
    return eventFailure("EVENT_PUBKEY_NOT_ON_CURVE", "event public key does not lift to a secp256k1 point", {
      id, agent_pubkey: pubkey, kind, created_at: createdAt,
    });
  }

  const agentNpub = npubEncode(pubkey);
  const event: NostrEvent = { pubkey, created_at: createdAt, kind, tags, content };
  if (computeEventId(event) !== id) {
    return eventFailure("EVENT_ID_MISMATCH", "event id does not match its signed fields", {
      id, agent_pubkey: pubkey, agent_npub: agentNpub, kind, created_at: createdAt,
    });
  }

  let validSignature = false;
  try {
    validSignature = schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey));
  } catch {
    validSignature = false;
  }
  if (!validSignature) {
    return eventFailure("EVENT_SIG_INVALID", "event signature is invalid", {
      id, agent_pubkey: pubkey, agent_npub: agentNpub, kind, created_at: createdAt,
    });
  }

  return {
    result: { valid: true, id, agent_pubkey: pubkey, agent_npub: agentNpub, kind, created_at: createdAt },
    signedEvent: event,
  };
}
