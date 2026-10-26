import { fork } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

/** Compile the actual store source into a disposable child-process fixture. */
export function prepareStoreProcesses(directory: string, storePath: string, className: string, home: string) {
  for (const file of [storePath, "src/keys.ts", "src/errors.ts", "src/viz.ts", "src/a2a/jcs.ts"]) {
    const source = readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");
    const target = path.join(directory, file.replace(/\.ts$/, ".js"));
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.ESNext } }).outputText);
  }
  writeFileSync(path.join(directory, "package.json"), '{"type":"module"}');
  const worker = path.join(directory, "worker.mjs");
  writeFileSync(worker, `
    const { [process.argv[3]]: Store } = await import(process.argv[2]);
    const store = new Store(process.argv[4]);
    process.once("message", async ({ operation, args }) => {
      try { await store[operation](...args); process.send({ ok: true }); }
      catch (error) { process.send({ ok: false, code: error.code }); }
      process.disconnect();
    });
    process.send({ ready: true });
  `);
  return async (operations: Array<{ operation: string; args: unknown[] }>): Promise<Array<{ ok: boolean; code?: string }>> => {
    const children = operations.map(() => {
      const child = fork(worker, [path.join(directory, storePath.replace(/\.ts$/, ".js")), className, home], {
        env: { PATH: process.env.PATH, HOME: directory, TMPDIR: directory }, stdio: ["ignore", "pipe", "pipe", "ipc"],
      });
      const ready = new Promise<void>((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", code => { if (code !== 0) reject(new Error("store worker failed before ready")); });
        child.once("message", () => resolve());
      });
      const result = ready.then(() => new Promise<{ ok: boolean; code?: string }>((resolve, reject) => {
        let body: { ok: boolean; code?: string } | undefined;
        child.once("error", reject);
        child.once("message", message => { body = message as typeof body; });
        child.once("exit", code => code === 0 && body ? resolve(body) : reject(new Error("store worker did not finish")));
      }));
      return { child, ready, result };
    });
    // All processes have imported production code before any mutation is released.
    await Promise.all(children.map(child => child.ready));
    children.forEach((child, index) => child.child.send(operations[index]!));
    return Promise.all(children.map(child => child.result));
  };
}
