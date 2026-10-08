import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { run, type Deps } from "../src/main.js";
import { npubEncode } from "../src/buzz/index.js";
import { AGENT_PUBKEY, AGENT_SECRET, OWNER_PUBKEY, OWNER_SECRET, authTag, signEvent } from "./buzz-helpers.js";

const fixturePath = new URL("./fixtures/nip-oa/signed-event.json", import.meta.url);
const signedEvent = JSON.parse(readFileSync(fixturePath, "utf8")) as Record<string, unknown>;
const tempDirs: string[] = [];
const outputHistory: string[] = [];

function setup(stdin: string | Uint8Array = "") {
  const home = mkdtempSync(path.join(tmpdir(), "zipviz-check-test-"));
  tempDirs.push(home);
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: async () => { throw new Error("unexpected fetch"); },
    stdout: (value) => { stdout.push(value); outputHistory.push(value); },
    stderr: (value) => { stderr.push(value); outputHistory.push(value); },
    zipvizHome: home,
    readStdin: async () => typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin,
  };
  return {
    deps,
    run: (args: string[]) => run(args, deps),
    stdout,
    stderr,
    write: (name: string, value: string | Uint8Array) => {
      const file = path.join(home, name);
      writeFileSync(file, value);
      return file;
    },
  };
}

afterEach(() => {
  for (const directory of tempDirs.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("zipviz check human output", () => {
  it("shows agent authorship separately from verified owner authorisation", async () => {
    const cli = setup();
    const file = cli.write("event.json", JSON.stringify(signedEvent));
    expect(await cli.run(["check", file])).toBe(0);
    expect(cli.stdout.join("")).toBe([
      `signed by agent ${npubEncode(AGENT_PUBKEY)}`,
      "event id d892a65e7677e0554ebb70ee16deeb6a0727dba46450fb4bc001291d7bff971b (kind 1, created_at 1713956400)",
      `authorised by owner ${npubEncode(OWNER_PUBKEY)}`,
      "conditions: kind=1&created_at<1713957000",
      "",
    ].join("\n"));
    expect(cli.stdout[0]).not.toContain(npubEncode(OWNER_PUBKEY));
    expect(cli.stdout.join("")).not.toContain(AGENT_SECRET);
    expect(cli.stdout.join("")).not.toContain(OWNER_SECRET);
  });

  it("does not show an owner for invalid authorisation", async () => {
    const cli = setup();
    const invalid = signEvent(AGENT_SECRET, {
      created_at: signedEvent.created_at as number,
      kind: signedEvent.kind as number,
      tags: [["auth", "A".repeat(64), "kind=1", "0".repeat(128)]],
      content: signedEvent.content as string,
    });
    const file = cli.write("invalid.json", JSON.stringify(invalid));
    expect(await cli.run(["check", file])).toBe(5);
    expect(cli.stdout.join("")).not.toContain(npubEncode(OWNER_PUBKEY));
    expect(cli.stdout.join("")).toContain("owner authorisation: invalid: AUTH_OWNER_PUBKEY_FORMAT");
  });

  it("uses event-invalid and no-auth display rules", async () => {
    const cli = setup();
    const invalidFile = cli.write("bad-event.json", JSON.stringify({ ...signedEvent, id: "0".repeat(64) }));
    const noAuthFile = cli.write("no-auth.json", JSON.stringify(signEvent(AGENT_SECRET, {
      created_at: signedEvent.created_at as number,
      kind: signedEvent.kind as number,
      tags: [],
      content: signedEvent.content as string,
    })));
    expect(await cli.run(["check", invalidFile])).toBe(4);
    expect(cli.stdout.join("")).toContain("event invalid: EVENT_ID_MISMATCH");
    expect(cli.stdout.join("")).toContain("owner authorisation: not checked (event invalid)");
    expect(await cli.run(["check", noAuthFile])).toBe(0);
    expect(cli.stdout.slice(-2).join("")).toContain("owner authorisation: none");
  });

  it("rejects terminal controls in signed NIP-OA conditions without leaking them", async () => {
    const cli = setup();
    const conditions = "kind=1\u001b[2J\u009b\u202e\nresult: valid";
    const event = signEvent(AGENT_SECRET, {
      created_at: signedEvent.created_at as number,
      kind: signedEvent.kind as number,
      tags: [authTag(OWNER_SECRET, AGENT_PUBKEY, conditions)],
      content: signedEvent.content as string,
    });
    const file = cli.write("terminal-conditions.json", JSON.stringify(event));

    expect(await cli.run(["check", file])).toBe(5);
    expect(cli.stdout.join("")).toContain("AUTH_CONDITIONS_MALFORMED");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => cli.stdout.join("").includes(control))).toBe(false);
    expect(cli.stdout.join("")).not.toContain("\nresult: valid");

    cli.stdout.length = 0;
    expect(await cli.run(["check", file, "--json"])).toBe(5);
    expect(JSON.parse(cli.stdout.join("")).owner_auth).toMatchObject({
      present: true,
      valid: false,
      reason: "AUTH_CONDITIONS_MALFORMED",
    });
  });
});

describe("zipviz check JSON and input handling", () => {
  it("emits the exact verification shape with --json", async () => {
    const cli = setup();
    const file = cli.write("event.json", JSON.stringify(signedEvent));
    expect(await cli.run(["check", file, "--json"])).toBe(0);
    expect(JSON.parse(cli.stdout.join(""))).toEqual({
      ok: true,
      command: "check",
      event: {
        valid: true,
        id: "d892a65e7677e0554ebb70ee16deeb6a0727dba46450fb4bc001291d7bff971b",
        agent_pubkey: AGENT_PUBKEY,
        agent_npub: npubEncode(AGENT_PUBKEY),
        kind: 1,
        created_at: 1713956400,
      },
      owner_auth: {
        present: true,
        valid: true,
        owner_pubkey: OWNER_PUBKEY,
        owner_npub: npubEncode(OWNER_PUBKEY),
        conditions: "kind=1&created_at<1713957000",
        clauses: [
          { clause: "kind=1", field: "kind", op: "=", value: 1, satisfied: true },
          { clause: "created_at<1713957000", field: "created_at", op: "<", value: 1713957000, satisfied: true },
        ],
      },
    });
  });

  it("reads a JSON event from stdin when the path is -", async () => {
    const cli = setup(JSON.stringify(signedEvent));
    expect(await cli.run(["check", "-"])).toBe(0);
    expect(cli.stdout.join("")).toContain(`signed by agent ${npubEncode(AGENT_PUBKEY)}`);
  });

  it("uses exit codes 4 and 5 for invalid event and invalid authorisation", async () => {
    const cli = setup();
    const invalidEvent = cli.write("invalid-event.json", JSON.stringify({ ...signedEvent, sig: "0".repeat(128) }));
    const invalidAuth = cli.write("invalid-auth.json", JSON.stringify(signEvent(AGENT_SECRET, {
      created_at: signedEvent.created_at as number,
      kind: signedEvent.kind as number,
      tags: [["auth", OWNER_PUBKEY, "kind=2", (signedEvent.tags as string[][])[0]![3]!]],
      content: signedEvent.content as string,
    })));
    expect(await cli.run(["check", invalidEvent])).toBe(4);
    expect(await cli.run(["check", invalidAuth])).toBe(5);
  });

  it.each([
    { label: "missing argument", args: ["check"], code: 2 },
    { label: "multiple arguments", args: ["check", "-", "-"], code: 2 },
  ])("returns usage exit code 2 for $label", async ({ args, code }) => {
    const cli = setup(JSON.stringify(signedEvent));
    expect(await cli.run(args)).toBe(code);
  });

  it("maps missing files and directories to E_INPUT_UNREADABLE and exit 6", async () => {
    const cli = setup();
    expect(await cli.run(["check", path.join(cli.deps.zipvizHome, "absent.json"), "--json"])).toBe(6);
    expect(JSON.parse(cli.stdout.join(""))).toMatchObject({ ok: false, command: "check", error: { code: "E_INPUT_UNREADABLE" } });
    cli.stdout.length = 0;
    expect(await cli.run(["check", cli.deps.zipvizHome, "--json"])).toBe(6);
    expect(JSON.parse(cli.stdout.join(""))).toMatchObject({ ok: false, command: "check", error: { code: "E_INPUT_UNREADABLE" } });
  });

  it("rejects oversized, invalid UTF-8, non-JSON, and non-object input", async () => {
    const cli = setup();
    const large = cli.write("large.json", " ".repeat(1024 * 1024 + 1));
    const invalidUtf8 = cli.write("utf8.json", new Uint8Array([0xff, 0xfe]));
    const notJson = cli.write("not-json.json", "{");
    const array = cli.write("array.json", "[]");
    const string = cli.write("string.json", '"x"');
    const expected = [
      [large, "E_INPUT_TOO_LARGE"],
      [invalidUtf8, "E_INPUT_NOT_UTF8"],
      [notJson, "E_INPUT_NOT_JSON"],
      [array, "E_INPUT_NOT_OBJECT"],
      [string, "E_INPUT_NOT_OBJECT"],
    ] as const;
    for (const [file, code] of expected) {
      cli.stdout.length = 0;
      expect(await cli.run(["check", file, "--json"])).toBe(6);
      const result = JSON.parse(cli.stdout.join(""));
      expect(result).toMatchObject({ error: { code } });
      if (code === "E_INPUT_TOO_LARGE") {
        expect(result.error.message).toBe("input exceeds the 1 MiB limit");
      }
    }
  });

  it("caps stdin and rejects malformed stdin JSON", async () => {
    const oversized = setup(" ".repeat(1024 * 1024 + 1));
    expect(await oversized.run(["check", "-", "--json"])).toBe(6);
    expect(JSON.parse(oversized.stdout.join(""))).toMatchObject({
      error: { code: "E_INPUT_TOO_LARGE", message: "input exceeds the 1 MiB limit" },
    });
    const malformed = setup("{");
    expect(await malformed.run(["check", "-"])).toBe(6);
  });

  it("rejects invalid UTF-8 stdin with E_INPUT_NOT_UTF8 and exit 6", async () => {
    const cli = setup(new Uint8Array([0xff, 0xfe]));
    expect(await cli.run(["check", "-", "--json"])).toBe(6);
    expect(JSON.parse(cli.stdout.join(""))).toMatchObject({
      ok: false,
      command: "check",
      error: { code: "E_INPUT_NOT_UTF8" },
    });
  });

  it("never prints private test keys across CLI runs", async () => {
    expect(outputHistory.join("")).not.toContain(AGENT_SECRET);
    expect(outputHistory.join("")).not.toContain(OWNER_SECRET);
  });
});
