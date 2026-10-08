import { execFileSync } from "node:child_process";
import {
  chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, symlinkSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { makeHarness, type Harness } from "./harness.js";

let h: Harness;
afterEach(() => h.cleanup());

const keysDir = () => path.join(h.home, ".zipviz", "keys");

type KeyFile = { key_id: string; path: string; safe: boolean; error: { code: string; message: string } | null };

/** Run backup in both modes and return the parsed JSON plus human text. */
async function both() {
  const json = await h.cliJson("backup");
  const human = await h.cli("backup");
  expect(json.code).toBe(0);
  expect(human.code).toBe(0);
  return { body: json.body, out: human.out };
}

/** No chmod of any kind may be suggested: chmod follows symlinks and touches special files. */
function expectChmodWithheld(body: Record<string, unknown>, out: string) {
  const restore = body.restore_steps as string[];
  expect(restore.join("\n")).not.toMatch(/chmod\s+[0-7]/);
  expect(restore.join("\n")).toMatch(/permission step withheld/);
  expect(out).not.toMatch(/chmod\s+[0-7]/);
  expect(out).toMatch(/permission step withheld/);
  expect(out).not.toContain("*.key");
  // The no-overwrite restore guidance stays.
  expect(restore.join("\n")).toMatch(/-xpkf .*never overwrite an existing key file/);
}

describe("zipviz backup: unsafe key entries", () => {
  it("reports a symlinked *.key entry as unsafe, not as a key, and withholds chmod; the target is untouched", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const outside = path.join(h.home, "outside.txt");
    writeFileSync(outside, "not a key\n", { mode: 0o644 });
    symlinkSync(outside, path.join(keysDir(), "default.key"));
    const { body, out } = await both();
    const files = body.key_files as KeyFile[];
    expect(files.find((k) => k.key_id === "default")).toMatchObject({
      safe: false, error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/symlink/) },
    });
    expect(files.find((k) => k.key_id === "sophie.z.viz")).toMatchObject({ safe: true, error: null });
    expect(body.key_store_error).toMatchObject({ code: "E_KEY_UNSAFE", message: expect.stringMatching(/1 of 2/) });
    expect(out).toMatch(/NOT CHECKED SAFE/);
    expect(out).toContain(`UNSAFE entry ${path.join(keysDir(), "default.key")}`);
    expect(out).not.toContain(`key file     ${path.join(keysDir(), "default.key")}`);
    expectChmodWithheld(body, out);
    expect(lstatSync(outside).mode & 0o777).toBe(0o644);
    expect(readFileSync(outside, "utf8")).toBe("not a key\n");
  });

  it("withholds chmod when keys/ itself is a symlink, and leaves the target dir untouched", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const real = path.join(h.home, "elsewhere");
    renameSync(keysDir(), real);
    chmodSync(real, 0o755);
    symlinkSync(real, keysDir());
    const { body, out } = await both();
    expect(body.key_store_error).toMatchObject({ code: "E_KEY_UNSAFE" });
    expect(body.key_files).toEqual([]);
    expectChmodWithheld(body, out);
    expect(lstatSync(real).mode & 0o777).toBe(0o755);
  });

  it("reports a fifo named default.key as not a regular file and never opens it", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    execFileSync("mkfifo", ["-m", "600", path.join(keysDir(), "default.key")]);
    const { body, out } = await both();
    expect((body.key_files as KeyFile[]).find((k) => k.key_id === "default")).toMatchObject({
      safe: false, error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/not a regular file/) },
    });
    expect(body.key_store_error).toMatchObject({ code: "E_KEY_UNSAFE" });
    expect(out).toMatch(/UNSAFE entry .*default\.key: key default is not a regular file/);
    expectChmodWithheld(body, out);
  });

  it("reports a directory named like a key as not a regular file", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    mkdirSync(path.join(keysDir(), "default.key"), { mode: 0o700 });
    const { body, out } = await both();
    expect((body.key_files as KeyFile[]).find((k) => k.key_id === "default")).toMatchObject({ safe: false });
    expectChmodWithheld(body, out);
  });

  it("reports a group/world-readable key file as unsafe without changing its mode", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const file = path.join(keysDir(), "sophie.z.viz.key");
    chmodSync(file, 0o644);
    const { body, out } = await both();
    expect(body.key_files).toEqual([{
      key_id: "sophie.z.viz",
      path: file,
      safe: false,
      error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/readable by group or others/) },
    }]);
    expect(body.key_store_error).toMatchObject({ code: "E_KEY_UNSAFE", message: expect.stringMatching(/1 of 1/) });
    expectChmodWithheld(body, out);
    expect(lstatSync(file).mode & 0o777).toBe(0o644);
  });

  it("for a verified store gives per-file, symlink-checked chmod steps and no glob", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    await h.cli("keygen");
    const { body, out } = await both();
    expect(body.key_store_error).toBeNull();
    expect((body.key_files as KeyFile[]).every((k) => k.safe && k.error === null)).toBe(true);
    const restore = (body.restore_steps as string[]).join("\n");
    expect(restore).not.toContain("*");
    expect(restore).not.toMatch(/withheld/);
    for (const id of ["default", "sophie.z.viz"]) {
      const p = path.join(keysDir(), `${id}.key`);
      expect(restore).toContain(`[ -f ${p} ] && [ ! -L ${p} ] && chmod 600 ${p}`);
    }
    expect(restore).toContain(`[ -d ${keysDir()} ] && [ ! -L ${keysDir()} ] && chmod 700 ${keysDir()}`);
    // Every chmod in the guidance is guarded by a not-a-symlink test.
    for (const line of restore.split("\n").filter((l) => /chmod/.test(l))) expect(line).toMatch(/\[ ! -L /);
    expect(out).not.toContain("*.key");
  });
});
