import { canonicalizeJson } from "./jcs.js";
import { CardError } from "./reasons.js";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

type SchemaName =
  | "AgentCard"
  | "AgentInterface"
  | "AgentProvider"
  | "AgentCapabilities"
  | "AgentExtension"
  | "AgentSkill"
  | "AgentCardSignature"
  | "SecurityRequirement"
  | "StringList"
  | "SecurityScheme"
  | "APIKeySecurityScheme"
  | "HTTPAuthSecurityScheme"
  | "OAuth2SecurityScheme"
  | "OpenIdConnectSecurityScheme"
  | "MutualTlsSecurityScheme"
  | "OAuthFlows"
  | "AuthorizationCodeOAuthFlow"
  | "ClientCredentialsOAuthFlow"
  | "ImplicitOAuthFlow"
  | "PasswordOAuthFlow"
  | "DeviceCodeOAuthFlow";

type ValueKind = "string" | "bool" | "message" | "struct" | "repeated" | "map";
type FieldSpec = {
  name: string;
  protoType: string;
  label: "singular" | "optional" | "repeated";
  required: boolean;
  oneof?: string;
  kind: ValueKind;
  child?: SchemaName;
  elementKind?: "string" | "message";
  elementChild?: SchemaName;
  mapValueKind?: "string" | "message";
  mapValueChild?: SchemaName;
};
type MessageSpec = { fields: readonly FieldSpec[]; requiredOneofs?: readonly string[] };

const scalar = (
  name: string,
  protoType: string,
  options: Partial<Pick<FieldSpec, "label" | "required" | "oneof">> = {},
): FieldSpec => ({
  name,
  protoType,
  label: options.label ?? "singular",
  required: options.required ?? false,
  kind: protoType === "bool" ? "bool" : "string",
  ...(options.oneof === undefined ? {} : { oneof: options.oneof }),
});

const message = (
  name: string,
  protoType: string,
  child: SchemaName,
  options: Partial<Pick<FieldSpec, "required" | "oneof">> = {},
): FieldSpec => ({
  name,
  protoType,
  label: "singular",
  required: options.required ?? false,
  kind: "message",
  child,
  ...(options.oneof === undefined ? {} : { oneof: options.oneof }),
});

const repeated = (
  name: string,
  protoType: string,
  elementKind: "string" | "message",
  options: { required?: boolean; elementChild?: SchemaName } = {},
): FieldSpec => ({
  name,
  protoType,
  label: "repeated",
  required: options.required ?? false,
  kind: "repeated",
  elementKind,
  ...(options.elementChild === undefined ? {} : { elementChild: options.elementChild }),
});

const map = (
  name: string,
  protoType: string,
  mapValueKind: "string" | "message",
  options: { mapValueChild?: SchemaName; required?: boolean } = {},
): FieldSpec => ({
  name,
  protoType,
  label: "singular",
  required: options.required ?? false,
  kind: "map",
  mapValueKind,
  ...(options.mapValueChild === undefined ? {} : { mapValueChild: options.mapValueChild }),
});

const struct = (name: string): FieldSpec => ({
  name,
  protoType: "google.protobuf.Struct",
  label: "singular",
  required: false,
  kind: "struct",
});

export const AGENT_CARD_SCHEMA: Record<SchemaName, MessageSpec> = {
  AgentCard: {
    fields: [
      scalar("name", "string", { required: true }),
      scalar("description", "string", { required: true }),
      repeated("supportedInterfaces", "AgentInterface", "message", { required: true, elementChild: "AgentInterface" }),
      message("provider", "AgentProvider", "AgentProvider"),
      scalar("version", "string", { required: true }),
      scalar("documentationUrl", "string", { label: "optional" }),
      message("capabilities", "AgentCapabilities", "AgentCapabilities", { required: true }),
      map("securitySchemes", "map<string, SecurityScheme>", "message", { mapValueChild: "SecurityScheme" }),
      repeated("securityRequirements", "SecurityRequirement", "message", {
        elementChild: "SecurityRequirement",
      }),
      repeated("defaultInputModes", "string", "string", { required: true }),
      repeated("defaultOutputModes", "string", "string", { required: true }),
      repeated("skills", "AgentSkill", "message", { required: true, elementChild: "AgentSkill" }),
      repeated("signatures", "AgentCardSignature", "message", { elementChild: "AgentCardSignature" }),
      scalar("iconUrl", "string", { label: "optional" }),
    ],
  },
  AgentInterface: {
    fields: [
      scalar("url", "string", { required: true }),
      scalar("protocolBinding", "string", { required: true }),
      scalar("tenant", "string"),
      scalar("protocolVersion", "string", { required: true }),
    ],
  },
  AgentProvider: {
    fields: [
      scalar("url", "string", { required: true }),
      scalar("organization", "string", { required: true }),
    ],
  },
  AgentCapabilities: {
    fields: [
      scalar("streaming", "bool", { label: "optional" }),
      scalar("pushNotifications", "bool", { label: "optional" }),
      repeated("extensions", "AgentExtension", "message", { elementChild: "AgentExtension" }),
      scalar("extendedAgentCard", "bool", { label: "optional" }),
    ],
  },
  AgentExtension: {
    fields: [
      scalar("uri", "string"),
      scalar("description", "string"),
      scalar("required", "bool"),
      struct("params"),
    ],
  },
  AgentSkill: {
    fields: [
      scalar("id", "string", { required: true }),
      scalar("name", "string", { required: true }),
      scalar("description", "string", { required: true }),
      repeated("tags", "string", "string", { required: true }),
      repeated("examples", "string", "string"),
      repeated("inputModes", "string", "string"),
      repeated("outputModes", "string", "string"),
      repeated("securityRequirements", "SecurityRequirement", "message", { elementChild: "SecurityRequirement" }),
    ],
  },
  AgentCardSignature: {
    fields: [
      scalar("protected", "string", { required: true }),
      scalar("signature", "string", { required: true }),
      struct("header"),
    ],
  },
  SecurityRequirement: {
    fields: [map("schemes", "map<string, StringList>", "message", { mapValueChild: "StringList" })],
  },
  StringList: {
    fields: [repeated("list", "string", "string")],
  },
  SecurityScheme: {
    requiredOneofs: ["scheme"],
    fields: [
      message("apiKeySecurityScheme", "APIKeySecurityScheme", "APIKeySecurityScheme", { oneof: "scheme" }),
      message("httpAuthSecurityScheme", "HTTPAuthSecurityScheme", "HTTPAuthSecurityScheme", { oneof: "scheme" }),
      message("oauth2SecurityScheme", "OAuth2SecurityScheme", "OAuth2SecurityScheme", { oneof: "scheme" }),
      message(
        "openIdConnectSecurityScheme",
        "OpenIdConnectSecurityScheme",
        "OpenIdConnectSecurityScheme",
        { oneof: "scheme" },
      ),
      message("mtlsSecurityScheme", "MutualTlsSecurityScheme", "MutualTlsSecurityScheme", { oneof: "scheme" }),
    ],
  },
  APIKeySecurityScheme: {
    fields: [
      scalar("description", "string"),
      scalar("location", "string", { required: true }),
      scalar("name", "string", { required: true }),
    ],
  },
  HTTPAuthSecurityScheme: {
    fields: [
      scalar("description", "string"),
      scalar("scheme", "string", { required: true }),
      scalar("bearerFormat", "string"),
    ],
  },
  OAuth2SecurityScheme: {
    fields: [
      scalar("description", "string"),
      message("flows", "OAuthFlows", "OAuthFlows", { required: true }),
      scalar("oauth2MetadataUrl", "string"),
    ],
  },
  OpenIdConnectSecurityScheme: {
    fields: [
      scalar("description", "string"),
      scalar("openIdConnectUrl", "string", { required: true }),
    ],
  },
  MutualTlsSecurityScheme: {
    fields: [scalar("description", "string")],
  },
  OAuthFlows: {
    requiredOneofs: ["flow"],
    fields: [
      message("authorizationCode", "AuthorizationCodeOAuthFlow", "AuthorizationCodeOAuthFlow", { oneof: "flow" }),
      message("clientCredentials", "ClientCredentialsOAuthFlow", "ClientCredentialsOAuthFlow", { oneof: "flow" }),
      message("implicit", "ImplicitOAuthFlow", "ImplicitOAuthFlow", { oneof: "flow" }),
      message("password", "PasswordOAuthFlow", "PasswordOAuthFlow", { oneof: "flow" }),
      message("deviceCode", "DeviceCodeOAuthFlow", "DeviceCodeOAuthFlow", { oneof: "flow" }),
    ],
  },
  AuthorizationCodeOAuthFlow: {
    fields: [
      scalar("authorizationUrl", "string", { required: true }),
      scalar("tokenUrl", "string", { required: true }),
      scalar("refreshUrl", "string"),
      map("scopes", "map<string, string>", "string", { required: true }),
      scalar("pkceRequired", "bool"),
    ],
  },
  ClientCredentialsOAuthFlow: {
    fields: [
      scalar("tokenUrl", "string", { required: true }),
      scalar("refreshUrl", "string"),
      map("scopes", "map<string, string>", "string", { required: true }),
    ],
  },
  ImplicitOAuthFlow: {
    fields: [
      scalar("authorizationUrl", "string"),
      scalar("refreshUrl", "string"),
      map("scopes", "map<string, string>", "string"),
    ],
  },
  PasswordOAuthFlow: {
    fields: [
      scalar("tokenUrl", "string"),
      scalar("refreshUrl", "string"),
      map("scopes", "map<string, string>", "string"),
    ],
  },
  DeviceCodeOAuthFlow: {
    fields: [
      scalar("deviceAuthorizationUrl", "string", { required: true }),
      scalar("tokenUrl", "string", { required: true }),
      scalar("refreshUrl", "string"),
      map("scopes", "map<string, string>", "string", { required: true }),
    ],
  },
};

const SCHEMA_DEPTH_LIMIT = 128;
const hasOwn = (value: object, key: string): boolean => Object.prototype.hasOwnProperty.call(value, key);
const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const pointerPart = (part: string): string => part.replace(/~/g, "~0").replace(/\//g, "~1");
const childPointer = (pointer: string, part: string): string => `${pointer}/${pointerPart(part)}`;

function invalid(pointer: string): never {
  throw new CardError("CARD_SCHEMA_INVALID", undefined, pointer || undefined);
}

function missing(pointer: string): never {
  throw new CardError("CARD_MISSING_REQUIRED", undefined, pointer || undefined);
}

function normalizeScalar(value: unknown, field: FieldSpec, pointer: string, forcePresence: boolean): JsonValue {
  const valid = field.kind === "bool" ? typeof value === "boolean" : typeof value === "string";
  if (!valid) return invalid(pointer);
  if (!forcePresence && !field.required && field.label !== "optional") {
    if ((field.kind === "bool" && value === false) || (field.kind === "string" && value === "")) return undefined as never;
  }
  return value as string | boolean;
}

function normalizeValue(
  value: unknown,
  field: FieldSpec,
  pointer: string,
  uncovered: string[],
  depth: number,
  forcePresence = false,
): JsonValue | undefined {
  if (depth > SCHEMA_DEPTH_LIMIT) throw new CardError("CARD_TOO_DEEP", undefined, pointer || undefined);
  if (field.kind === "string" || field.kind === "bool") {
    return normalizeScalar(value, field, pointer, forcePresence);
  }
  if (field.kind === "struct") {
    if (!isPlainObject(value)) return invalid(pointer);
    return value as JsonObject;
  }
  if (field.kind === "message") {
    if (!field.child) return invalid(pointer);
    return normalizeMessage(field.child, value, pointer, uncovered, depth + 1);
  }
  if (field.kind === "repeated") {
    if (!Array.isArray(value)) return invalid(pointer);
    if (value.length === 0 && !field.required) return undefined;
    const items: JsonValue[] = [];
    for (let index = 0; index < value.length; index++) {
      const item = value[index];
      const itemPointer = childPointer(pointer, String(index));
      if (field.elementKind === "string") {
        if (typeof item !== "string") return invalid(itemPointer);
        items.push(item);
      } else {
        if (!field.elementChild) return invalid(itemPointer);
        items.push(normalizeMessage(field.elementChild, item, itemPointer, uncovered, depth + 1));
      }
    }
    return items;
  }
  if (field.kind === "map") {
    if (!isPlainObject(value)) return invalid(pointer);
    const entries = Object.entries(value);
    if (entries.length === 0 && !field.required) return undefined;
    const result: JsonObject = {};
    // Every own key is defined as an own property, so a "__proto__" key is kept and covered instead of hitting the setter.
    const put = (key: string, item: JsonValue) =>
      Object.defineProperty(result, key, { value: item, enumerable: true, writable: true, configurable: true });
    for (const [key, item] of entries) {
      const itemPointer = childPointer(pointer, key);
      if (field.mapValueKind === "string") {
        if (typeof item !== "string") return invalid(itemPointer);
        put(key, item);
      } else {
        if (!field.mapValueChild) return invalid(itemPointer);
        put(key, normalizeMessage(field.mapValueChild, item, itemPointer, uncovered, depth + 1));
      }
    }
    return result;
  }
  return invalid(pointer);
}

function normalizeMessage(
  name: SchemaName,
  value: unknown,
  pointer: string,
  uncovered: string[],
  depth: number,
): JsonObject {
  if (depth > SCHEMA_DEPTH_LIMIT) throw new CardError("CARD_TOO_DEEP", undefined, pointer || undefined);
  if (!isPlainObject(value)) return invalid(pointer);
  const spec = AGENT_CARD_SCHEMA[name];
  const known = new Set(spec.fields.map((field) => field.name));

  for (const group of spec.requiredOneofs ?? []) {
    const selected = spec.fields.filter((field) => field.oneof === group && hasOwn(value, field.name) && value[field.name] !== null);
    if (selected.length !== 1) invalid(pointer);
  }

  const result: JsonObject = {};
  for (const field of spec.fields) {
    if (name === "AgentCard" && field.name === "signatures") continue;
    const exists = hasOwn(value, field.name);
    const fieldPointer = childPointer(pointer, field.name);
    const item = value[field.name];
    if (field.required && (!exists || item === null)) missing(fieldPointer);
    if (!exists || item === null) continue;
    const normalized = normalizeValue(item, field, fieldPointer, uncovered, depth + 1, field.oneof !== undefined);
    if (normalized !== undefined) result[field.name] = normalized;
  }

  for (const key of Object.keys(value)) {
    if (known.has(key)) continue;
    uncovered.push(childPointer(pointer, key));
  }
  return result;
}

export function canonicalizeCard(card: JsonObject): { canonical: string; uncovered: string[] } {
  const uncovered: string[] = [];
  const normalized = normalizeMessage("AgentCard", card, "", uncovered, 0);
  let canonical: string;
  try {
    canonical = canonicalizeJson(normalized);
  } catch (error) {
    if (error instanceof RangeError) throw new CardError("CARD_TOO_DEEP");
    throw new CardError("CARD_SCHEMA_INVALID", error instanceof Error ? error.message : undefined);
  }
  return { canonical, uncovered: [...new Set(uncovered)].sort() };
}

export type CardParse =
  | { ok: true; card: JsonObject }
  | { ok: false; reason: "CARD_NOT_JSON" | "CARD_NOT_OBJECT" | "CARD_DUPLICATE_KEY"; message: string };

function stringEnd(text: string, start: number): number {
  let index = start + 1;
  while (index < text.length) {
    const character = text[index]!;
    if (character === "\\") index += 2;
    else if (character === "\"") return index + 1;
    else index++;
  }
  return text.length;
}

function hasDuplicateMembers(text: string): boolean {
  const stack: Array<{ kind: "object" | "array"; expectKey: boolean; keys: Set<string> }> = [];
  for (let index = 0; index < text.length; index++) {
    const character = text[index]!;
    if (character === "\"") {
      const end = stringEnd(text, index);
      const frame = stack[stack.length - 1];
      if (frame?.kind === "object" && frame.expectKey) {
        const key = JSON.parse(text.slice(index, end)) as string;
        if (frame.keys.has(key)) return true;
        frame.keys.add(key);
        frame.expectKey = false;
      }
      index = end - 1;
    } else if (character === "{") {
      stack.push({ kind: "object", expectKey: true, keys: new Set<string>() });
    } else if (character === "[") {
      stack.push({ kind: "array", expectKey: false, keys: new Set<string>() });
    } else if (character === "}") {
      stack.pop();
    } else if (character === "]") {
      stack.pop();
    } else if (character === ",") {
      const frame = stack[stack.length - 1];
      if (frame?.kind === "object") frame.expectKey = true;
    }
  }
  return false;
}

export function parseCardJson(text: string): CardParse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { ok: false, reason: "CARD_NOT_JSON", message: "input is not valid JSON" };
  }
  if (!isPlainObject(parsed)) {
    return { ok: false, reason: "CARD_NOT_OBJECT", message: "Agent Card must be a JSON object" };
  }
  if (hasDuplicateMembers(text)) {
    return { ok: false, reason: "CARD_DUPLICATE_KEY", message: "JSON contains a duplicate object member" };
  }
  return { ok: true, card: parsed as JsonObject };
}
