import { chmodSync, lstatSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { makeHarness, type Harness } from "./harness.js";

let h: Harness;
afterEach(() => {
  // Restore owner access so the harness can clean up the temp home.
  try {
    chmodSync(path.join(h.home, ".zipviz", "keys", "sophie.z.viz.key"), 0o600);
  } catch {
    // ignore
  }
  h.cleanup();
});

type KeyFile = { key_id: string; path: string; safe: boolean; error: { code: string; message: string } | null };

const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

describe.skipIf(isRoot)("zipviz backup: key files the owner cannot read", () => {
  for (const mode of [0o000, 0o100]) {
    const label = mode.toString(8).padStart(3, "0");
    it(`classifies a mode ${label} key file as unreadable and withholds every chmod step`, async () => {
      h = makeHarness();
      await h.cli("keygen", "--name", "sophie");
      await h.cli("keygen");
      const file = path.join(h.home, ".zipviz", "keys", "sophie.z.viz.key");
      chmodSync(file, mode);

      const json = await h.cliJson("backup");
      const human = await h.cli("backup");
      expect(json.code).toBe(0);
      expect(human.code).toBe(0);
      const body = json.body;
      const out = human.out;

      const files = body.key_files as KeyFile[];
      expect(files.find((k) => k.key_id === "sophie.z.viz")).toEqual({
        key_id: "sophie.z.viz",
        path: file,
        safe: false,
        error: { code: "E_KEY_UNREADABLE", message: expect.stringMatching(/EACCES/) },
      });
      expect(files.find((k) => k.key_id === "default")).toMatchObject({ safe: true, error: null });
      expect(body.key_store_error).toMatchObject({
        code: "E_KEY_UNREADABLE", message: expect.stringMatching(/1 of 2/),
      });

      const restore = (body.restore_steps as string[]).join("\n");
      expect(restore).not.toMatch(/chmod\s+[0-7]/);
      expect(restore).toMatch(/permission step withheld/);
      expect(restore).toMatch(/-xpkf .*never overwrite an existing key file/);

      expect(out).toMatch(/NOT CHECKED SAFE/);
      expect(out).toContain(`UNSAFE entry ${file}: `);
      expect(out).not.toContain(`key file     ${file}`);
      expect(out).not.toMatch(/chmod\s+[0-7]/);
      expect(out).toMatch(/permission step withheld/);

      // Metadata-only: the file's mode is untouched.
      expect(lstatSync(file).mode & 0o777).toBe(mode);
    });
  }

  it("still verifies an owner-readable 0600 key and offers guarded per-file steps", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const file = path.join(h.home, ".zipviz", "keys", "sophie.z.viz.key");
    const { body } = await h.cliJson("backup");
    expect(body.key_store_error).toBeNull();
    expect((body.key_files as KeyFile[])[0]).toMatchObject({ safe: true, error: null });
    expect((body.restore_steps as string[]).join("\n"))
      .toContain(`[ -f ${file} ] && [ ! -L ${file} ] && chmod 600 ${file}`);
  });
});
