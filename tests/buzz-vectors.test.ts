import { readFileSync } from "node:fs";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import {
  authMessageHash,
  authPreimage,
  npubEncode,
  verifyBuzzEvent,
} from "../src/buzz/index.js";
import { AGENT_PUBKEY, AGENT_SECRET, OWNER_PUBKEY, OWNER_SECRET } from "./buzz-helpers.js";

const vectorLines = readFileSync(new URL("./fixtures/nip-oa/test-vectors.txt", import.meta.url), "utf8")
  .trim().split("\n");
const vectors = Object.fromEntries(vectorLines.map((line) => {
  const index = line.indexOf("=");
  return [line.slice(0, index), line.slice(index + 1)];
}));
const signedEvent = JSON.parse(readFileSync(new URL("./fixtures/nip-oa/signed-event.json", import.meta.url), "utf8")) as unknown;

describe("NIP-OA published test vector", () => {
  it("matches the exact preimage and message digest", () => {
    expect(authPreimage(AGENT_PUBKEY, vectors.conditions!)).toBe(vectors.preimage);
    expect(bytesToHex(authMessageHash(AGENT_PUBKEY, vectors.conditions!))).toBe(vectors["sha256(preimage)"]);
    expect(bytesToHex(utf8ToBytes(JSON.stringify(JSON.parse(vectors.tag!))))).toBe(vectors["tag-bytes-hex"]);
  });

  it("verifies the published owner signature and public keys", () => {
    const tag = JSON.parse(vectors.tag!) as string[];
    expect(bytesToHex(schnorr.getPublicKey(hexToBytes(OWNER_SECRET)))).toBe(OWNER_PUBKEY);
    expect(bytesToHex(schnorr.getPublicKey(hexToBytes(AGENT_SECRET)))).toBe(AGENT_PUBKEY);
    expect(schnorr.verify(hexToBytes(vectors.auth_sig!), authMessageHash(AGENT_PUBKEY, vectors.conditions!), hexToBytes(OWNER_PUBKEY))).toBe(true);
    expect(tag[1]).toBe(OWNER_PUBKEY);
    expect(npubEncode("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"))
      .toBe("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg");
  });

  it("verifies the published signed event and exposes valid owner authorisation", () => {
    const result = verifyBuzzEvent(signedEvent);
    expect(result.ok).toBe(true);
    expect(result.event).toMatchObject({
      valid: true,
      id: "d892a65e7677e0554ebb70ee16deeb6a0727dba46450fb4bc001291d7bff971b",
      agent_pubkey: AGENT_PUBKEY,
      kind: 1,
      created_at: 1713956400,
    });
    expect(result.owner_auth).toMatchObject({
      present: true,
      valid: true,
      owner_pubkey: OWNER_PUBKEY,
      conditions: "kind=1&created_at<1713957000",
      clauses: [
        { clause: "kind=1", field: "kind", op: "=", value: 1, satisfied: true },
        { clause: "created_at<1713957000", field: "created_at", op: "<", value: 1713957000, satisfied: true },
      ],
    });
  });
});
