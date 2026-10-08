import { CliError } from "../src/errors.js";
import { Output } from "../src/output.js";
import { escapeTerminal } from "../src/terminal.js";
import { describe, expect, it, vi } from "vitest";

const { checkMock } = vi.hoisted(() => ({ checkMock: vi.fn() }));

vi.mock("../src/check.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/check.js")>();
  return { ...actual, check: checkMock };
});

import { run, type Deps } from "../src/main.js";

describe("escapeTerminal", () => {
  it.each([
    ["\u0000", "\\x00"],
    ["\u001f", "\\x1f"],
    ["\u0020", "\u0020"],
    ["\u007f", "\\x7f"],
    ["\u0080", "\\x80"],
    ["\u009f", "\\x9f"],
    ["\u00a0", "\u00a0"],
    ["\u061c", "\\u061c"],
    ["\u200d", "\u200d"],
    ["\u200e", "\\u200e"],
    ["\u200f", "\\u200f"],
    ["\u061b", "\u061b"],
    ["\u2028", "\\u2028"],
    ["\u2029", "\\u2029"],
    ["\u202a", "\\u202a"],
    ["\u202e", "\\u202e"],
    ["\u2066", "\\u2066"],
    ["\u2069", "\\u2069"],
    ["\u2065", "\u2065"],
  ])("escapes %j as %j", (input, expected) => {
    expect(escapeTerminal(input)).toBe(expected);
  });

  it("preserves ordinary Unicode and backslashes", () => {
    const text = "Agent 漢字 🙂 \\\\ remains readable";
    expect(escapeTerminal(text)).toBe(text);
  });
});

describe("human Output.failure", () => {
  it("escapes untrusted fetch/JWKS error text while leaving JSON values and usage intact", () => {
    const raw = "JWKS fetch failed: \u001b[2J\u009b\u202e\nresult: valid";
    const stdout: string[] = [];
    const stderr: string[] = [];
    const failure = new CliError("FETCH_FAILED", raw, 9);

    expect(new Output(false, (text) => stdout.push(text), (text) => stderr.push(text)).failure("check --card", failure))
      .toBe(9);
    expect(stdout).toEqual([]);
    expect(stderr.join("")).toContain("JWKS fetch failed: \\x1b[2J\\x9b\\u202e\\x0aresult: valid");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => stderr.join("").includes(control))).toBe(false);
    expect(stderr.join("").split("\n")).toHaveLength(2);

    const jsonOut: string[] = [];
    new Output(true, (text) => jsonOut.push(text), () => undefined).failure("check --card", failure);
    expect(JSON.parse(jsonOut.join("")).error.message).toBe(raw);

    const usageOut: string[] = [];
    new Output(false, () => undefined, (text) => usageOut.push(text)).failure(
      "zipviz",
      new CliError("E_USAGE", "invalid option", 2),
      "usage:\n  zipviz check <file>",
    );
    expect(usageOut.join("")).toContain("\n\nusage:\n  zipviz check <file>\n");
  });
});

describe("main check output boundary", () => {
  it("escapes human Buzz lines and leaves JSON data untouched", async () => {
    const raw = "kind=1\u001b[2J\u009b\u202e\nresult: valid";
    const result = () => ({
      ok: false,
      data: { owner_auth: { conditions: raw } },
      lines: [`conditions: ${raw}`],
      exitCode: 5,
    });
    checkMock.mockResolvedValueOnce(result()).mockResolvedValueOnce(result());
    const stdout: string[] = [];
    const stderr: string[] = [];
    const deps: Deps = {
      fetch: async () => { throw new Error("unexpected fetch"); },
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text),
      zipvizHome: "/unused",
    };

    expect(await run(["check", "event.json"], deps)).toBe(5);
    expect(stdout.join("")).toContain("conditions: kind=1\\x1b[2J\\x9b\\u202e\\x0aresult: valid");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => stdout.join("").includes(control))).toBe(false);
    expect(stdout.join("").split("\n")).toHaveLength(2);

    stdout.length = 0;
    expect(await run(["check", "event.json", "--json"], deps)).toBe(5);
    expect(JSON.parse(stdout.join("")).owner_auth.conditions).toBe(raw);
    expect(stderr).toEqual([]);
  });
});
