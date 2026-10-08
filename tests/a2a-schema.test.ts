import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AGENT_CARD_SCHEMA, canonicalizeCard, parseCardJson, type JsonObject } from "../src/a2a/index.js";

const proto = readFileSync(path.join(import.meta.dirname, "fixtures", "a2a", "a2a.proto"), "utf8");
const messageNames = [
  "AgentCard",
  "AgentInterface",
  "AgentProvider",
  "AgentCapabilities",
  "AgentExtension",
  "AgentSkill",
  "AgentCardSignature",
  "SecurityRequirement",
  "StringList",
  "SecurityScheme",
  "APIKeySecurityScheme",
  "HTTPAuthSecurityScheme",
  "OAuth2SecurityScheme",
  "OpenIdConnectSecurityScheme",
  "MutualTlsSecurityScheme",
  "OAuthFlows",
  "AuthorizationCodeOAuthFlow",
  "ClientCredentialsOAuthFlow",
  "ImplicitOAuthFlow",
  "PasswordOAuthFlow",
  "DeviceCodeOAuthFlow",
] as const;

type ProtoField = { name: string; type: string; label: string; required: boolean; oneof: string | null };

function parseMessage(name: string): ProtoField[] {
  const block = proto.match(new RegExp(`^message ${name} \\{([\\s\\S]*?)^\\}`, "m"))?.[1];
  if (block === undefined) throw new Error(`proto message missing: ${name}`);
  let oneof: string | null = null;
  const fields: ProtoField[] = [];
  for (const sourceLine of block.split("\n")) {
    const line = sourceLine.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    const group = line.match(/^oneof (\w+) \{$/);
    if (group) {
      oneof = group[1]!;
      continue;
    }
    if (line === "}") {
      oneof = null;
      continue;
    }
    const field = line.match(/^(optional |repeated )?(map<[^>]+>|[\w.]+) (\w+) = \d+(.*);$/);
    if (!field) continue;
    fields.push({
      name: field[3]!.replace(/_([a-z])/g, (_match, char: string) => char.toUpperCase()),
      type: field[2]!,
      label: field[1]?.trim() ?? "singular",
      required: /\(google\.api\.field_behavior\) = REQUIRED/.test(field[4]!),
      oneof,
    });
  }
  return fields;
}

const completeCard = (): JsonObject => ({
  name: "Example",
  description: "",
  supportedInterfaces: [{ url: "https://agent.example/rpc", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
  version: "1",
  capabilities: {},
  defaultInputModes: [],
  defaultOutputModes: [],
  skills: [],
});

describe("A2A schema table and ProtoJSON field presence", () => {
  it("matches every vendored AgentCard-subtree proto field and oneof", () => {
    const actual = Object.fromEntries(messageNames.map((name) => [
      name,
      AGENT_CARD_SCHEMA[name].fields.map((field) => ({
        name: field.name,
        type: field.protoType,
        label: field.label,
        required: field.required,
        oneof: field.oneof ?? null,
      })),
    ]));
    const expected = Object.fromEntries(messageNames.map((name) => [name, parseMessage(name)]));
    expect(actual).toEqual(expected);
  });

  it("omits implicit defaults, preserves present optional values, and keeps required empty arrays", () => {
    const card = completeCard();
    card.provider = { url: "https://provider.example", organization: "Example" };
    card.capabilities = { streaming: false, pushNotifications: false, extensions: [], extendedAgentCard: false };
    card.documentationUrl = "";
    card.iconUrl = null;
    const normalized = canonicalizeCard(card);
    expect(normalized.canonical).toContain('"capabilities":{"extendedAgentCard":false,"pushNotifications":false,"streaming":false}');
    expect(normalized.canonical).toContain('"defaultInputModes":[]');
    expect(normalized.canonical).toContain('"documentationUrl":""');
    expect(normalized.canonical).not.toContain('"extensions"');
    expect(normalized.canonical).not.toContain('"iconUrl"');
  });

  it("rejects missing and null required fields with their JSON pointer", () => {
    const missing = completeCard();
    delete missing.supportedInterfaces;
    expect(() => canonicalizeCard(missing)).toThrow(expect.objectContaining({
      reason: "CARD_MISSING_REQUIRED",
      pointer: "/supportedInterfaces",
    }));
    const nullField = completeCard();
    nullField.description = null;
    expect(() => canonicalizeCard(nullField)).toThrow(expect.objectContaining({
      reason: "CARD_MISSING_REQUIRED",
      pointer: "/description",
    }));
  });

  it("rejects card content deeper than the canonicalization limit", () => {
    let nested: JsonObject = { leaf: true };
    for (let index = 0; index < 130; index++) nested = { nested };
    const card = completeCard();
    card.capabilities = { extensions: [{ params: nested }] };
    expect(() => canonicalizeCard(card)).toThrow(expect.objectContaining({ reason: "CARD_TOO_DEEP" }));
  });

  it("validates JSON types and enforces the oneof cardinality while retaining an empty selected member", () => {
    const wrong = completeCard();
    wrong.name = 4;
    expect(() => canonicalizeCard(wrong)).toThrow(expect.objectContaining({
      reason: "CARD_SCHEMA_INVALID",
      pointer: "/name",
    }));

    const emptyMember = completeCard();
    emptyMember.securitySchemes = { mtls: { mtlsSecurityScheme: {} } };
    expect(canonicalizeCard(emptyMember).canonical).toContain('"mtlsSecurityScheme":{}');

    const none = completeCard();
    none.securitySchemes = { bad: {} };
    expect(() => canonicalizeCard(none)).toThrow(expect.objectContaining({ reason: "CARD_SCHEMA_INVALID" }));
    const two = completeCard();
    two.securitySchemes = { bad: { mtlsSecurityScheme: {}, apiKeySecurityScheme: { location: "header", name: "x" } } };
    expect(() => canonicalizeCard(two)).toThrow(expect.objectContaining({ reason: "CARD_SCHEMA_INVALID" }));
  });

  it("keeps map entries and normalizes Struct values verbatim", () => {
    const card = completeCard();
    card.securitySchemes = { empty: { mtlsSecurityScheme: {} } };
    card.capabilities = {
      extensions: [{ uri: "urn:test", params: { empty: [], zero: 0, nested: { enabled: false } } }],
    };
    card.skills = [{
      id: "skill",
      name: "Skill",
      description: "Desc",
      tags: [],
    }];
    const normalized = canonicalizeCard(card).canonical;
    expect(normalized).toContain('"securitySchemes":{"empty":{"mtlsSecurityScheme":{}}}');
    expect(normalized).toContain('"params":{"empty":[],"nested":{"enabled":false},"zero":0}');
  });

  it("reports uncovered top-level, snake_case, nested, and legacy fields in sorted pointers", () => {
    const card = completeCard();
    card.url = "https://legacy.example";
    card.default_input_modes = ["text/plain"];
    card.skills = [{ id: "s", name: "S", description: "D", tags: [], unexpected: true }];
    expect(canonicalizeCard(card).uncovered).toEqual([
      "/default_input_modes",
      "/skills/0/unexpected",
      "/url",
    ]);
  });

  it("excludes signatures from canonical content and is independent of member order", () => {
    const first = completeCard();
    first.signatures = [{ protected: "ignored", signature: "ignored" }];
    const second = { ...completeCard(), version: "1", capabilities: {} };
    expect(canonicalizeCard(first).canonical).toBe(canonicalizeCard(second).canonical);
    const original = completeCard();
    const reordered = Object.fromEntries(Object.entries(original).reverse()) as JsonObject;
    expect(canonicalizeCard(reordered).canonical).toBe(canonicalizeCard(completeCard()).canonical);
  });

  it("normalizes the 8.4.1 example and reports the 8.5 sample's proto mismatch", () => {
    const example = completeCard();
    example.name = "Example Agent";
    example.capabilities = { streaming: false, pushNotifications: false, extensions: [] };
    expect(canonicalizeCard(example).canonical).toBe(
      '{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":[],"defaultOutputModes":[],"description":"","name":"Example Agent","skills":[],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://agent.example/rpc"}],"version":"1"}',
    );
    const sample = JSON.parse(readFileSync(path.join(import.meta.dirname, "fixtures", "a2a", "sample-card.json"), "utf8")) as JsonObject;
    expect(canonicalizeCard(sample).uncovered).toEqual(["/security"]);
    const protoSample = JSON.parse(
      readFileSync(path.join(import.meta.dirname, "fixtures", "a2a", "sample-card-proto.json"), "utf8"),
    ) as JsonObject;
    expect(canonicalizeCard(protoSample).uncovered).toEqual([]);
  });
});

describe("parseCardJson duplicate-member detection", () => {
  it("rejects duplicate keys including escaped-key collisions at any object depth", () => {
    for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"x":1,"x":2}}']) {
      expect(parseCardJson(text)).toMatchObject({ ok: false, reason: "CARD_DUPLICATE_KEY" });
    }
  });

  it("does not mistake braces or quotes inside strings for object structure", () => {
    expect(parseCardJson('{"name":"a } and \\" quote {","description":"ok"}')).toMatchObject({ ok: true });
    expect(parseCardJson("{")).toMatchObject({ ok: false, reason: "CARD_NOT_JSON" });
    expect(parseCardJson("[]")).toMatchObject({ ok: false, reason: "CARD_NOT_OBJECT" });
  });
});
