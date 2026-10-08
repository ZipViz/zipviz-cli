import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { leafHash } from "./merkle.js";

const encoder = new TextEncoder();

/** LeafHash(E) = SHA-256(0x00 || JCS(E)). See merkle.ts for the citation chain. */
export function eventLeafHash(event: JsonValue): Uint8Array {
  return leafHash(encoder.encode(canonicalizeJson(event)));
}
