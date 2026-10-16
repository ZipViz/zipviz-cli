import { describe, expect, it } from "vitest";
import { signCard, verifyCard, type JsonObject, type PrivateJwk, type PublicJwk } from "../src/a2a/index.js";
import { verifyIdentityLink } from "../src/link/index.js";
import { generateKeyPairSync } from "node:crypto";
import { makeKeys, makeLink } from "./link-helpers.js";

// Regression tests for two verification hardening fixes: strict Ed25519 link verification, and complete map canonicalization.

describe("identity-link Ed25519 verification is strict (no small-order or non-canonical keys)", () => {
  // The identity point and a non-canonical small-order encoding, each with the signature R = identity, S = 0. Under the
  // ZIP-215 default this verifies for any statement without any private key; strict verification must refuse it.
  const SMALL_ORDER_KEYS = ["01" + "00".repeat(31), "ec" + "ff".repeat(30) + "7f"];
  const FIXED_SIG = "01" + "00".repeat(31) + "00".repeat(32);

  it.each(SMALL_ORDER_KEYS)("refuses the link for small-order key %s with a fixed signature", (edPublic) => {
    const keys = { ...makeKeys(), edPublic, signEd: () => FIXED_SIG };
    const { doc } = makeLink(keys);
    const result = verifyIdentityLink(doc);
    expect(result.ed25519.valid).toBe(false);
    expect(result.ok).toBe(false);
  });

  it("still verifies a normal link signed by a real Ed25519 key", () => {
    const result = verifyIdentityLink(makeLink(makeKeys()).doc);
    expect(result.ed25519.valid).toBe(true);
    expect(result.ok).toBe(true);
  });
});

describe("canonicalization keeps every own map key, including __proto__", () => {
  const pair = generateKeyPairSync("ed25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" }) as PrivateJwk;
  const publicJwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "test-key" } as PublicJwk;
  const card = (scopesJson: string): JsonObject => JSON.parse(`{
    "name": "Example", "description": "Card",
    "supportedInterfaces": [{ "url": "https://agent.example/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }],
    "version": "1", "capabilities": {}, "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"], "skills": [],
    "securitySchemes": { "oauth": { "oauth2SecurityScheme": { "flows": { "clientCredentials": {
      "tokenUrl": "https://agent.example/token", "scopes": ${scopesJson} } } } } }
  }`) as JsonObject;
  const signed = signCard(card(`{ "read": "Read" }`), privateJwk, { kid: "test-key" });
  const withScopes = (scopesJson: string): JsonObject =>
    JSON.parse(JSON.stringify(signed).replace(`"scopes":{"read":"Read"}`, `"scopes":${scopesJson}`)) as JsonObject;

  it("the untouched signed card verifies", () => {
    expect(verifyCard(signed, { keys: [publicJwk] }).valid).toBe(true);
  });

  it("adding an ordinary scope breaks the signature", () => {
    expect(verifyCard(withScopes(`{"read":"Read","write":"Write"}`), { keys: [publicJwk] }).valid).toBe(false);
  });

  it("adding a __proto__ scope also breaks the signature (it is covered, not silently dropped)", () => {
    const tampered = withScopes(`{"read":"Read","__proto__":"Injected"}`);
    type Scoped = { securitySchemes: { oauth: { oauth2SecurityScheme: { flows: { clientCredentials: { scopes: object } } } } } };
    const scopes = (tampered as unknown as Scoped).securitySchemes.oauth.oauth2SecurityScheme.flows.clientCredentials.scopes;
    expect(Object.prototype.hasOwnProperty.call(scopes, "__proto__")).toBe(true);
    expect(verifyCard(tampered, { keys: [publicJwk] }).valid).toBe(false);
  });

  it("a card that really declares a __proto__ scope signs and verifies with that scope covered", () => {
    const own = signCard(card(`{ "read": "Read", "__proto__": "Declared" }`), privateJwk, { kid: "test-key" });
    expect(verifyCard(own, { keys: [publicJwk] }).valid).toBe(true);
    const changed = JSON.parse(JSON.stringify(own).replace(`"__proto__":"Declared"`, `"__proto__":"Changed"`)) as JsonObject;
    expect(verifyCard(changed, { keys: [publicJwk] }).valid).toBe(false);
  });
});
