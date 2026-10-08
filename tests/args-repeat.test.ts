import { describe, expect, it } from "vitest";
import { flagValue, flagValues, parseArgs } from "../src/args.js";

describe("repeatable value flags", () => {
  it("collects repeatable values in order without changing single-valued flags", () => {
    const parsed = parseArgs(
      ["--allow-host", "one.example", "--key", "first.pem", "--allow-host=two.example", "--key", "last.pem"],
      { value: ["allow-host", "key"], repeat: ["allow-host"] },
    );
    expect(parsed.flags.get("allow-host")).toEqual(["one.example", "two.example"]);
    expect(flagValues(parsed, "allow-host")).toEqual(["one.example", "two.example"]);
    expect(flagValue(parsed, "key")).toBe("last.pem");
  });

  it("returns an empty list for a repeatable value flag that was not supplied", () => {
    const parsed = parseArgs([], { repeat: ["allow-host"] });
    expect(flagValues(parsed, "allow-host")).toEqual([]);
  });
});
