import { generateKeyPairSync } from "node:crypto";
import dns from "node:dns";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { run, type Deps } from "../src/main.js";
import { AGENT_PUBKEY, OWNER_PUBKEY } from "./buzz-helpers.js";

const signedEvent = readFileSync(new URL("./fixtures/nip-oa/signed-event.json", import.meta.url), "utf8");
const event = JSON.parse(signedEvent) as Record<string, unknown>;
const mocks: Array<ReturnType<typeof vi.spyOn>> = [];
const importPattern = /\b(?:from\s*|import\s*\()\s*["'](?:node:)?(?:net|http|https|tls|dns|dgram|http2|undici|child_process|worker_threads)(?:\/|["'])/;
const requirePattern = /\brequire\s*\(\s*["'](?:node:)?(?:net|http|https|tls|dns|dgram|http2|undici|child_process|worker_threads)(?:\/|["'])/;

function block<T extends object, K extends keyof T>(target: T, key: K) {
  const spy = vi.spyOn(target, key as never).mockImplementation((() => {
    throw new Error("network access attempted");
  }) as never);
  mocks.push(spy);
}

afterEach(() => {
  for (const mock of mocks.splice(0)) mock.mockRestore();
  vi.restoreAllMocks();
});

describe("check remains offline", () => {
  it("does not call network-capable APIs for valid, invalid, stdin, human, or JSON checks", async () => {
    block(globalThis, "fetch");
    block(net, "connect");
    block(net, "createConnection");
    block(net.Socket.prototype, "connect");
    block(tls, "connect");
    block(http, "request");
    block(http, "get");
    block(https, "request");
    block(https, "get");
    block(dns, "lookup");
    block(dns.promises, "lookup");
    const stdout: string[] = [];
    const deps: Deps = {
      fetch: async () => { throw new Error("deps.fetch called"); },
      stdout: (text) => stdout.push(text),
      stderr: () => undefined,
      zipvizHome: "/unused",
      readStdin: async () => new TextEncoder().encode(signedEvent),
    };
    await expect(run(["check", "tests/fixtures/nip-oa/signed-event.json"], deps)).resolves.toBe(0);
    await expect(run(["check", "tests/fixtures/nip-oa/signed-event.json", "--json"], deps)).resolves.toBe(0);
    await expect(run(["check", "-"], deps)).resolves.toBe(0);
    const invalid = { ...event, id: "0".repeat(64) };
    deps.readStdin = async () => new TextEncoder().encode(JSON.stringify(invalid));
    await expect(run(["check", "-", "--json"], deps)).resolves.toBe(4);
    expect(stdout.join("")).toContain(AGENT_PUBKEY);
    expect(stdout.join("")).toContain(OWNER_PUBKEY);
    for (const mock of mocks) expect(mock).not.toHaveBeenCalled();
  });

  it("contains no network imports or calls, and the verifier remains pure", () => {
    const buzzRoot = new URL("../src/buzz/", import.meta.url);
    const buzzFiles = readdirSync(buzzRoot).filter((name) => name.endsWith(".ts"));
    const sources = [
      ...buzzFiles.map((name) => [new URL(name, buzzRoot), `src/buzz/${name}`] as const),
      [new URL("../src/check.ts", import.meta.url), "src/check.ts"] as const,
    ];
    expect("// network over https docs").not.toMatch(importPattern);
    expect("// network over https docs").not.toMatch(requirePattern);
    expect('import x from "node:net"').toMatch(importPattern);
    expect('require("https")').toMatch(requirePattern);

    for (const [file, name] of sources) {
      const source = readFileSync(file, "utf8");
      expect(source, name).not.toMatch(importPattern);
      expect(source, name).not.toMatch(requirePattern);
      expect(source, name).not.toMatch(/\bfetch\s*\(/);
      expect(source, name).not.toMatch(/\bWebSocket\b/);
      if (name.startsWith("src/buzz/")) {
        expect(source, name).not.toMatch(/\b(?:from\s*|import\s*\()\s*["']node:/);
        expect(source, name).not.toMatch(/\b(?:Date|process)\b/);
      }
    }
    expect(sources.length).toBeGreaterThan(1);
  });
});

describe("signed-card operations remain offline", () => {
  it("runs card sign and verify with every network-capable API blocked", async () => {
    block(globalThis, "fetch");
    block(net, "connect");
    block(net, "createConnection");
    block(net.Socket.prototype, "connect");
    block(tls, "connect");
    block(http, "request");
    block(http, "get");
    block(https, "request");
    block(https, "get");
    block(dns, "lookup");
    block(dns.promises, "lookup");

    const dir = mkdtempSync(path.join(tmpdir(), "zipviz-a2a-offline-"));
    try {
      const pair = generateKeyPairSync("ed25519");
      const privatePath = path.join(dir, "private.pem");
      const cardPath = path.join(dir, "card.json");
      const signedPath = path.join(dir, "signed.json");
      const jwksPath = path.join(dir, "jwks.json");
      writeFileSync(privatePath, pair.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
      writeFileSync(cardPath, JSON.stringify({
        name: "Example",
        description: "Offline",
        supportedInterfaces: [{ url: "https://agent.example/rpc", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
        version: "1",
        capabilities: {},
        defaultInputModes: [],
        defaultOutputModes: [],
        skills: [],
      }));
      const publicJwk = pair.publicKey.export({ format: "jwk" });
      writeFileSync(jwksPath, JSON.stringify({ keys: [{ ...publicJwk, kid: "offline", alg: "EdDSA", use: "sig" }] }));

      const stdout: string[] = [];
      const deps: Deps = {
        fetch: async () => { throw new Error("unexpected fetch"); },
        stdout: (text) => stdout.push(text),
        stderr: () => undefined,
        zipvizHome: path.join(dir, "home"),
      };
      await expect(run(["card", "sign", cardPath, "--key", privatePath, "--kid", "offline"], deps)).resolves.toBe(0);
      writeFileSync(signedPath, stdout.join(""));
      await expect(run(["card", "verify", signedPath, "--jwks", jwksPath], deps)).resolves.toBe(0);
      for (const mock of mocks) expect(mock).not.toHaveBeenCalled();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps network imports isolated to src/net/fetch.ts and A2A modules pure", () => {
    const sourceRoot = new URL("../src/", import.meta.url);
    const forbidden = /\b(?:from\s*|import\s*\()\s*["'](?:node:)?(?:net|http|https|tls|dns|dgram|http2|undici)(?:\/|["'])/;
    function files(directory: URL, prefix: string): Array<[URL, string]> {
      return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        const url = new URL(entry.name, directory);
        const name = `${prefix}${entry.name}`;
        return entry.isDirectory() ? files(new URL(`${entry.name}/`, directory), `${name}/`)
          : entry.name.endsWith(".ts") ? [[url, name]] as Array<[URL, string]>
            : [];
      });
    }
    for (const [url, name] of files(sourceRoot, "src/")) {
      const source = readFileSync(url, "utf8");
      if (name === "src/net/fetch.ts") continue;
      expect(source, name).not.toMatch(forbidden);
      if (name.startsWith("src/a2a/")) {
        expect(source, name).not.toMatch(/\bnode:/);
        expect(source, name).not.toMatch(/\bfetch\s*\(/);
      }
      if (name.startsWith("src/buzz/") || name === "src/check.ts") {
        expect(source, name).not.toMatch(forbidden);
        expect(source, name).not.toMatch(/\bfetch\s*\(/);
      }
    }
  });
});
