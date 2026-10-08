import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { linkStatement, PROVISIONAL_LINK_EVENT_KIND } from "../src/link/index.js";
import { signEvent, type TestEvent } from "./buzz-helpers.js";

export const DOMAIN = "link.z.viz";
export const ISSUED_AT = 1713956400;

/** Keys are generated here, never read from a fixture. */
export type LinkKeys = {
  edPublic: string;
  signEd: (message: string) => string;
  nostrSecret: string;
  nostrPubkey: string;
};

export function makeKeys(): LinkKeys {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const nostrSecret = bytesToHex(schnorr.utils.randomSecretKey());
  const der = publicKey.export({ format: "der", type: "spki" });
  return {
    edPublic: der.subarray(der.length - 32).toString("hex"),
    signEd: (message) => nodeSign(null, Buffer.from(message, "utf8"), privateKey).toString("hex"),
    nostrSecret,
    nostrPubkey: bytesToHex(schnorr.getPublicKey(hexToBytes(nostrSecret))),
  };
}

export type LinkDoc = Record<string, unknown>;

export function linkEvent(keys: LinkKeys, statement: string, domain = DOMAIN, createdAt = ISSUED_AT): TestEvent {
  return signEvent(keys.nostrSecret, {
    created_at: createdAt,
    kind: PROVISIONAL_LINK_EVENT_KIND,
    tags: [["viz", domain]],
    content: statement,
  });
}

/** A complete, valid link document for both keys. */
export function makeLink(
  keys: LinkKeys,
  options: { domain?: string; issuedAt?: number } = {},
): { doc: LinkDoc; statement: string; event: TestEvent } {
  const domain = options.domain ?? DOMAIN;
  const issuedAt = options.issuedAt ?? ISSUED_AT;
  const statement = linkStatement({
    domain,
    ed25519Pubkey: keys.edPublic,
    nostrPubkey: keys.nostrPubkey,
    issuedAt,
  });
  const event = linkEvent(keys, statement, domain);
  return {
    statement,
    event,
    doc: {
      v: 1,
      domain,
      ed25519_pubkey: keys.edPublic,
      nostr_pubkey: keys.nostrPubkey,
      issued_at: issuedAt,
      statement,
      ed25519_sig: keys.signEd(statement),
      nostr_event: event,
    },
  };
}
