import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const check = process.argv.includes("--check");
if (process.argv.slice(2).some(argument => argument !== "--check")) throw new Error("only --check is supported");
const temporary = mkdtempSync(path.join(tmpdir(), "zipviz-signup-fixture-"));
try {
  const tsc = path.join(root, "node_modules/typescript/bin/tsc");
  const result = spawnSync(process.execPath, [tsc, "-p", "scripts/tsconfig.signup-fixture.json", "--outDir", temporary], { cwd: root, stdio: "inherit" });
  if (result.status !== 0) throw new Error("signup fixture compilation failed");
  // Keep API fixture source byte-identical. Only the typed fake is transpiled;
  // these codec helpers and their test-only type bridges are copied verbatim.
  const helperFiles = ["bytes.js", "bytes.d.ts", "jcs.js", "jcs.d.ts", "signup-codec.js", "signup-codec.d.ts"];
  for (const file of helperFiles) {
    mkdirSync(path.join(temporary, "src"), { recursive: true });
    copyFileSync(path.join(root, "test-vectors/signup-api/src", file), path.join(temporary, "src", file));
  }
  const files = [...helperFiles.map(file => `src/${file}`), "tests/support/signup-fake.js", "tests/support/signup-fake.d.ts"];
  for (const file of files) {
    const generated = path.join(temporary, file);
    const destination = path.join(root, "tests/fixtures/signup-api", file);
    if (check) {
      if (!readFileSync(generated).equals(readFileSync(destination))) throw new Error(`generated signup fixture differs: ${file}`);
    } else {
      mkdirSync(path.dirname(destination), { recursive: true });
      copyFileSync(generated, destination);
    }
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
