import type { JsonValue } from "./schema.js";
export type { JsonValue } from "./schema.js";

const MAX_DEPTH = 128;

function assertWellFormedString(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("string contains a lone surrogate");
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("string contains a lone surrogate");
    }
  }
}

function encodeString(value: string): string {
  assertWellFormedString(value);
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("value is not JSON");
  return encoded;
}

function serialize(value: unknown, depth: number, stack: Set<object>): string {
  if (depth > MAX_DEPTH) throw new RangeError("JSON nesting exceeds 128 levels");
  if (value === null) return "null";
  if (typeof value === "string") return encodeString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("number is not finite");
    const encoded = JSON.stringify(Object.is(value, -0) ? 0 : value);
    if (encoded === undefined) throw new TypeError("number is not JSON");
    return encoded;
  }
  if (typeof value !== "object") throw new TypeError("value is not JSON");
  if (stack.has(value)) throw new TypeError("cyclic values are not JSON");
  if (Object.getOwnPropertySymbols(value).length > 0) throw new TypeError("symbol keys are not JSON");

  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Object.keys(value);
      if (ownKeys.length !== value.length || ownKeys.some((key, index) => key !== String(index))) {
        throw new TypeError("array properties are not JSON");
      }
      const items: string[] = [];
      for (let index = 0; index < value.length; index++) {
        items.push(serialize(value[index], depth + 1, stack));
      }
      return `[${items.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("value is not a plain object");
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort();
    const members: string[] = [];
    for (const key of keys) {
      const item = object[key];
      members.push(`${encodeString(key)}:${serialize(item, depth + 1, stack)}`);
    }
    return `{${members.join(",")}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalizeJson(value: JsonValue): string {
  return serialize(value, 0, new Set<object>());
}
