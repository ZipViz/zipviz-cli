import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalizeJson, type JsonValue } from "../src/a2a/jcs.js";

const vectorRoot = path.join(import.meta.dirname, "fixtures", "jcs");

describe("RFC 8785 canonicalizeJson", () => {
  it("matches every vendored cyberphone input/output vector", () => {
    const inputs = readdirSync(path.join(vectorRoot, "input")).filter((name) => name.endsWith(".json")).sort();
    expect(inputs).toHaveLength(6);
    for (const name of inputs) {
      const input = JSON.parse(readFileSync(path.join(vectorRoot, "input", name), "utf8")) as JsonValue;
      const expected = readFileSync(path.join(vectorRoot, "output", name), "utf8");
      expect(canonicalizeJson(input), name).toBe(expected);
    }
  });

  it("serializes every RFC 8785 Appendix B number vector", () => {
    const cases = [
      ["0000000000000000", "0"],
      ["8000000000000000", "0"],
      ["0000000000000001", "5e-324"],
      ["8000000000000001", "-5e-324"],
      ["7fefffffffffffff", "1.7976931348623157e+308"],
      ["ffefffffffffffff", "-1.7976931348623157e+308"],
      ["4340000000000000", "9007199254740992"],
      ["c340000000000000", "-9007199254740992"],
      ["4430000000000000", "295147905179352830000"],
      ["44b52d02c7e14af5", "9.999999999999997e+22"],
      ["44b52d02c7e14af6", "1e+23"],
      ["44b52d02c7e14af7", "1.0000000000000001e+23"],
      ["444b1ae4d6e2ef4e", "999999999999999700000"],
      ["444b1ae4d6e2ef4f", "999999999999999900000"],
      ["444b1ae4d6e2ef50", "1e+21"],
      ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
      ["3eb0c6f7a0b5ed8d", "0.000001"],
      ["41b3de4355555553", "333333333.3333332"],
      ["41b3de4355555554", "333333333.33333325"],
      ["41b3de4355555555", "333333333.3333333"],
      ["41b3de4355555556", "333333333.3333334"],
      ["41b3de4355555557", "333333333.33333343"],
      ["becbf647612f3696", "-0.0000033333333333333333"],
    ] as const;
    const bytes = new ArrayBuffer(8);
    const view = new DataView(bytes);
    for (const [hex, expected] of cases) {
      view.setBigUint64(0, BigInt(`0x${hex}`));
      const number = view.getFloat64(0);
      expect(canonicalizeJson(number), hex).toBe(expected);
    }
  });

  it("sorts keys by UTF-16 code units and emits strict JSON string escapes", () => {
    expect(canonicalizeJson({ "\u{1f600}": 1, "\ufb33": 2 })).toBe('{"😀":1,"דּ":2}');
    expect(canonicalizeJson("\b\t\n\f\r\"\\\u0000\u001f/")).toBe('"\\b\\t\\n\\f\\r\\"\\\\\\u0000\\u001f/"');
  });

  it("rejects lone surrogates and nesting deeper than 128", () => {
    expect(() => canonicalizeJson("\ud800")).toThrow();
    let nested: JsonValue = 0;
    for (let i = 0; i < 129; i++) nested = [nested];
    expect(() => canonicalizeJson(nested)).toThrow();
  });

  it("normalizes negative zero and rejects non-finite numbers", () => {
    expect(canonicalizeJson(-0)).toBe("0");
    expect(() => canonicalizeJson(Number.NaN)).toThrow();
    expect(() => canonicalizeJson(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => canonicalizeJson(Number.NEGATIVE_INFINITY)).toThrow();
  });

  it.each([
    ["undefined", undefined],
    ["bigint", 1n],
    ["function", () => 1],
    ["Date", new Date(0)],
    ["Map", new Map()],
  ])("rejects %s values", (_label, value) => {
    expect(() => canonicalizeJson(value as unknown as JsonValue)).toThrow();
  });
});
