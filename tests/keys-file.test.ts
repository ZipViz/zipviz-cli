import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readPrivateKeyFile } from "../src/keys.js";

const dirs: string[] = [];
function tempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "zipviz-key-file-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("readPrivateKeyFile", () => {
  it("loads Ed25519 and P-256 PKCS#8 PEM private keys", async () => {
    for (const kind of ["ed25519", "ec"] as const) {
      const dir = tempDir();
      const pair = kind === "ec"
        ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
        : generateKeyPairSync("ed25519");
      const file = path.join(dir, `${kind}.pem`);
      writeFileSync(file, pair.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
      const key = await readPrivateKeyFile(file);
      expect(key.asymmetricKeyType).toBe(kind === "ec" ? "ec" : "ed25519");
    }
  });

  it("preserves missing, unsafe, symlink and invalid-key error distinctions", async () => {
    const dir = tempDir();
    await expect(readPrivateKeyFile(path.join(dir, "missing.pem"))).rejects.toMatchObject({
      code: "E_NO_KEY",
      message: `no key file at ${path.join(dir, "missing.pem")}`,
    });
    const badMode = path.join(dir, "bad-mode.pem");
    writeFileSync(badMode, "not a key", { mode: 0o644 });
    chmodSync(badMode, 0o644);
    await expect(readPrivateKeyFile(badMode)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    const linked = path.join(dir, "linked.pem");
    symlinkSync(badMode, linked);
    await expect(readPrivateKeyFile(linked)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    const invalid = path.join(dir, "invalid.pem");
    writeFileSync(invalid, "not a key", { mode: 0o600 });
    await expect(readPrivateKeyFile(invalid)).rejects.toMatchObject({ code: "E_KEY_INVALID" });
  });

  it("rejects key files larger than 64 KiB before parsing", async () => {
    const dir = tempDir();
    const file = path.join(dir, "large.pem");
    writeFileSync(file, Buffer.alloc(65 * 1024), { mode: 0o600 });
    await expect(readPrivateKeyFile(file)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
  });
});
