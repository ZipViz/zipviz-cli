import { describe, expect, it } from "vitest";
import { parseAnsName } from "../src/ans/name.js";
import { AnsError } from "../src/ans/reasons.js";

function hostOfLength(target: number): string {
  const labels: string[] = [];
  let used = 0;
  while (used < target) {
    const dot = labels.length === 0 ? 0 : 1;
    const size = Math.min(63, target - used - dot);
    labels.push("a".repeat(size));
    used += dot + size;
  }
  return labels.join(".");
}

describe("draft-narajala-courtney-ansv2-01 ANSName", () => {
  it("parses the section 5.1 and appendix examples", () => {
    expect(parseAnsName("ans://v1.0.0.sentiment-analyzer.example.com")).toMatchObject({
      name: "ans://v1.0.0.sentiment-analyzer.example.com",
      version: "1.0.0",
      host: "sentiment-analyzer.example.com",
    });
    expect(parseAnsName("ANS://v1.5.0.Support.Example.COM").name).toBe("ans://v1.5.0.support.example.com");
    expect(parseAnsName("ans://v0.0.0.example.com").version).toBe("0.0.0");
    expect(parseAnsName("ans://v1.2.3.4.example.com").host).toBe("4.example.com");
  });

  it("accepts a 237 octet host and a 400 octet name, and rejects one past each limit", () => {
    const host = hostOfLength(237);
    expect(host.length).toBe(237);
    expect(parseAnsName(`ans://v1.0.0.${host}`).host).toBe(host);
    expect(() => parseAnsName(`ans://v1.0.0.${hostOfLength(238)}`)).toThrow(AnsError);

    const version = `1.0.${"1".repeat(377)}`;
    const atLimit = `ans://v${version}.example.com`;
    expect(atLimit.length).toBe(400);
    expect(parseAnsName(atLimit).version).toBe(version);
    expect(() => parseAnsName(`${atLimit}1`)).toThrow(expect.objectContaining({ reason: "ANS_NAME_INVALID" }));
  });

  it.each([
    "ans://1.0.0.example.com",
    "ans://v01.0.0.example.com",
    "ans://v1.0.example.com",
    "ans://v1.0.0.example",
    "ans://v1.0.0.example.com.",
    "ans://v1.0.0.192.0.2.1",
    "ans://v1.0.0.bad_label.example.com",
    "ans://v1.0.0.example.com/path",
    " ans://v1.0.0.example.com",
    `ans://v1.0.0.${"a".repeat(64)}.example.com`,
  ])("rejects %s", (name) => {
    expect(() => parseAnsName(name)).toThrow(expect.objectContaining({ reason: "ANS_NAME_INVALID" }));
  });
});
