import { generateKeyPairSync } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { shellQuote } from "../src/backup.js";
import { run, type Deps } from "../src/main.js";
import { makeHarness, type Harness } from "./harness.js";

let h: Harness;
afterEach(() => h.cleanup());

const keysDir = () => path.join(h.home, ".zipviz", "keys");

function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string) => {
    const st = lstatSync(p);
    out[path.relative(root, p) || "."] = `${st.mode.toString(8)} ${st.size} ${st.mtimeMs}`;
    if (st.isDirectory() && (st.mode & 0o500) === 0o500) for (const n of readdirSync(p)) walk(path.join(p, n));
  };
  walk(root);
  return out;
}

describe("zipviz backup", () => {
  it("prints the key paths and backup/restore steps with a stable JSON shape and exit 0", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    await h.cli("keygen");
    const { code, body } = await h.cliJson("backup");
    expect(code).toBe(0);
    expect(Object.keys(body)).toEqual([
      "ok", "command", "zipviz_home", "keys_dir", "key_files", "key_store_error", "format",
      "backup_steps", "restore_steps", "rules", "read_key_material",
    ]);
    expect(body).toMatchObject({
      ok: true,
      command: "backup",
      zipviz_home: path.join(h.home, ".zipviz"),
      keys_dir: keysDir(),
      key_files: [
        { key_id: "default", path: path.join(keysDir(), "default.key") },
        { key_id: "sophie.z.viz", path: path.join(keysDir(), "sophie.z.viz.key") },
      ],
      key_store_error: null,
      read_key_material: false,
    });
    const steps = [...(body.backup_steps as string[]), ...(body.restore_steps as string[])].join("\n");
    expect(steps).toContain(`tar -C ${path.join(h.home, ".zipviz")} -cpf`);
    expect(steps).toMatch(/-xpkf .*never overwrite an existing key file/);
    expect(String((body.format as Record<string, string>).store)).toMatch(/Ed25519.*PKCS#8 PEM/);
    expect(String((body.format as Record<string, string>).other)).toMatch(/P-256/);
    expect((body.rules as string[]).join(" ")).toMatch(/cannot recover, rotate or revoke/);

    const human = await h.cli("backup");
    expect(human.code).toBe(0);
    expect(human.out).toContain(`key file     ${path.join(keysDir(), "sophie.z.viz.key")}`);
    expect(human.out).toContain("it did not touch your keys");
  });

  it("never reads key bytes: unreadable and canary key files are listed by name only and left untouched", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const canary = "-----BEGIN PRIVATE KEY-----\nQ0FOQVJZLWJhY2t1cC1tdXN0LW5vdC1yZWFk\n-----END PRIVATE KEY-----\n";
    writeFileSync(path.join(keysDir(), "default.key"), canary, { mode: 0o600 });
    chmodSync(path.join(keysDir(), "sophie.z.viz.key"), 0o000);
    const before = snapshot(h.home);
    const human = await h.cli("backup");
    const json = await h.cliJson("backup");
    expect(human.code).toBe(0);
    expect(json.code).toBe(0);
    expect(snapshot(h.home)).toEqual(before);
    chmodSync(path.join(keysDir(), "sophie.z.viz.key"), 0o600);
    const pem = readFileSync(path.join(keysDir(), "sophie.z.viz.key"), "utf8");
    const all = human.out + human.err + JSON.stringify(json.body);
    expect(all).not.toMatch(/PRIVATE KEY|Q0FOQVJZ/);
    expect(all).not.toContain(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""));
    expect(h.registry.requests).toHaveLength(0);
  });

  it("still gives guidance when the store is missing or unsafe, and does not create or fix it", async () => {
    h = makeHarness();
    const missing = await h.cliJson("backup");
    expect(missing.code).toBe(0);
    expect(missing.body).toMatchObject({ key_files: [], key_store_error: null });
    expect(() => lstatSync(path.join(h.home, ".zipviz"))).toThrow();

    await h.cli("keygen", "--name", "sophie");
    chmodSync(keysDir(), 0o755);
    const unsafe = await h.cliJson("backup");
    expect(unsafe.code).toBe(0);
    expect(unsafe.body.key_store_error).toMatchObject({ code: "E_KEY_UNSAFE" });
    expect((await h.cli("backup")).out).toMatch(/NOT CHECKED SAFE: .*run: zipviz doctor/);
    expect(lstatSync(keysDir()).mode & 0o777).toBe(0o755);
  });

  it("quotes a home path with spaces or quotes in copy-paste commands", async () => {
    h = makeHarness();
    const home = path.join(h.home, "it's a dir");
    mkdirSync(home);
    const out: string[] = [];
    const deps: Deps = {
      fetch: async () => { throw new Error("backup must not use the network"); },
      stdout: (s) => out.push(s), stderr: (s) => out.push(s), zipvizHome: home,
    };
    expect(await run(["backup", "--json"], deps)).toBe(0);
    const body = JSON.parse(out.join(""));
    expect(body.backup_steps[0]).toContain(`tar -C ${shellQuote(home)} -cpf`);
    expect(shellQuote(home)).toBe(`'${h.home}/it'\\''s a dir'`);
    expect(shellQuote("/home/u/.zipviz")).toBe("/home/u/.zipviz");
  });

  it("leaves Ed25519 store keys and P-256 card keys elsewhere byte-identical", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    const p256 = path.join(h.home, "card.pem");
    writeFileSync(p256, generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey
      .export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
    const ed = path.join(keysDir(), "sophie.z.viz.key");
    const before = [readFileSync(ed), readFileSync(p256)];
    await h.cli("backup");
    await h.cli("backup", "--json");
    expect([readFileSync(ed), readFileSync(p256)]).toEqual(before);
  });

  it("rejects positional arguments", async () => {
    h = makeHarness();
    expect((await h.cli("backup", "now")).code).toBe(2);
  });
});
