import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const OWNER_SECRET = "0000000000000000000000000000000000000000000000000000000000000001";
export const AGENT_SECRET = "0000000000000000000000000000000000000000000000000000000000000002";
export const OWNER_PUBKEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
export const AGENT_PUBKEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

export type TestEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

export function signEvent(
  secretHex = AGENT_SECRET,
  fields: Partial<Pick<TestEvent, "created_at" | "kind" | "tags" | "content">> = {},
): TestEvent {
  const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(secretHex)));
  const event = {
    pubkey,
    created_at: fields.created_at ?? 1713956400,
    kind: fields.kind ?? 1,
    tags: fields.tags ?? [],
    content: fields.content ?? "test event",
  };
  const id = bytesToHex(sha256(utf8ToBytes(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))));
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), hexToBytes(secretHex)));
  return { id, ...event, sig };
}

export function authTag(
  ownerSecretHex = OWNER_SECRET,
  agentPubkeyHex = AGENT_PUBKEY,
  conditions = "",
): string[] {
  const ownerPubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(ownerSecretHex)));
  const preimage = `nostr:agent-auth:${agentPubkeyHex}:${conditions}`;
  const message = sha256(utf8ToBytes(preimage));
  return ["auth", ownerPubkey, conditions, bytesToHex(schnorr.sign(message, hexToBytes(ownerSecretHex)))];
}

export function withAuth(event: TestEvent, tag: string[] = authTag(OWNER_SECRET, event.pubkey)): TestEvent {
  return signEvent(AGENT_SECRET, {
    created_at: event.created_at,
    kind: event.kind,
    tags: [...event.tags, tag],
    content: event.content,
  });
}
