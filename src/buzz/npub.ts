import { bech32 } from "@scure/base";
import { hexToBytes } from "@noble/hashes/utils.js";

export function npubEncode(pubkeyHex: string): string {
  return bech32.encode("npub", bech32.toWords(hexToBytes(pubkeyHex)));
}
