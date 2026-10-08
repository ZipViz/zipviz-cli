import { createPrivateKey, createPublicKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { inviteDomain as inv } from "../src/viz.js";
import { makeHarness, spkiToHex, type Harness } from "./harness.js";
import { run, type Deps } from "../src/main.js";
import { isPublicAddress, type NetDeps } from "../src/net/fetch.js";

let h: Harness;
afterEach(() => h.cleanup());

/** Every encoding of the private key that must never leave the key file. */
function secretForms(pem: string): string[] {
  const jwk = createPrivateKey(pem).export({ format: "jwk" });
  const seed = Buffer.from(jwk.d!, "base64url");
  const der = createPrivateKey(pem).export({ format: "der", type: "pkcs8" });
  const pemBody = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  return [
    pem.trim(),
    pemBody,
    jwk.d!,
    seed.toString("hex"),
    seed.toString("base64"),
    der.toString("hex"),
    der.toString("base64"),
  ];
}

describe("private key never leaves the key file", () => {
  it("is absent from stdout, stderr, --json output and every request across all commands", async () => {
    h = makeHarness();
    const owner = "stu.smc.viz";
    await h.cli("keygen", "--name", owner);
    const ownerPem = readFileSync(path.join(h.home, ".zipviz", "keys", `${owner}.key`), "utf8");
    h.registry.addAgent(owner, spkiToHex(ownerPem));
    h.registry.issuers.add(owner);

    const runs: Array<string[]> = [
      ["keygen"],
      ["keygen", "--name", "sophie"],
      ["keygen", "--name", "sophie"],
      ["keygen", "--name", "sophie", "--force"],
      ["whoami"],
      ["invite", "create", owner],
      ["invite", "create", owner, "--execute"],
      ["invite", "create", owner, "--aud", "api.zipviz.ai"],
      ["invite", "create", owner, "--aud", "wrong.example", "--execute"],
    ];
    for (const argv of runs) {
      await h.cli(...argv);
      await h.cli(...argv, "--json");
    }
    const issued = JSON.parse((await h.cli("invite", "create", owner, "--execute", "--json")).out);
    await h.cli("invite", "revoke", owner, "--invite-id", issued.invite_id, "--execute");
    await h.cli("invite", "revoke", owner, "--invite-id", issued.invite_id, "--execute", "--json");
    await h.cli("redeem", issued.code, "--name", "sophie", "--json");
    await h.cli("redeem", h.registry.mintCode(owner), "--name", "sophie");
    await h.cli("redeem", h.registry.mintCode(owner), "--name", "zed", "--json");
    h.registry.invitesEnabled = false;
    await h.cli("redeem", h.registry.mintCode(owner), "--name", "zed");
    for (const name of [inv("sophie"), owner, inv("nobody")]) {
      await h.cli("verify", name);
      await h.cli("verify", name, "--json");
    }
    await h.cli("whoami");
    await h.cli("whoami", "--json");
    await h.cli("--help");

    const keyFiles = readdirSync(path.join(h.home, ".zipviz", "keys")).filter((f) => f.endsWith(".key"));
    expect(keyFiles.length).toBeGreaterThanOrEqual(3);
    const secrets = keyFiles.flatMap((f) =>
      secretForms(readFileSync(path.join(h.home, ".zipviz", "keys", f), "utf8"))
    );
    const haystack = [
      ...h.stdout,
      ...h.stderr,
      ...h.registry.requests.flatMap((r) => [r.url, r.body ?? "", JSON.stringify(r.headers)]),
    ].join("\n");

    expect(h.registry.requests.length).toBeGreaterThan(10);
    expect(haystack).not.toMatch(/PRIVATE KEY/);
    for (const s of secrets) expect(haystack.includes(s)).toBe(false);
  });

  it("keeps card command output, JSON, errors and request metadata free of private key material", async () => {
    h = makeHarness();
    const dir = mkdtempSync(path.join(tmpdir(), "zipviz-card-no-leak-"));
    let server: https.Server | undefined;
    try {
      const keygen = await h.cli("keygen", "--name", "card-owner");
      expect(keygen.code).toBe(0);
      const keyPath = path.join(h.home, ".zipviz", "keys", "card-owner.z.viz.key");
      const privatePem = readFileSync(keyPath, "utf8");
      const privateKey = createPrivateKey(privatePem);
      const secretValues = secretForms(privatePem);
      const publicJwk = { ...createPublicKey(privateKey).export({ format: "jwk" }), kid: "card-owner", alg: "EdDSA", use: "sig" };
      const cardPath = path.join(dir, "card.json");
      const signedPath = path.join(dir, "signed.json");
      const jwksPath = path.join(dir, "jwks.json");
      const card = {
        name: "Example",
        description: "No leak",
        supportedInterfaces: [{ url: "https://card.test/rpc", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
        version: "1",
        capabilities: {},
        defaultInputModes: [],
        defaultOutputModes: [],
        skills: [],
      };
      writeFileSync(cardPath, JSON.stringify(card));
      const stdout: string[] = [];
      const stderr: string[] = [];
      const requests: Array<{ url: string; headers: http.IncomingHttpHeaders }> = [];
      const jwks = { keys: [publicJwk] };
      const certificateDir = path.join(dir, "certificate");
      const keyCert = path.join(certificateDir, "key.pem");
      const cert = path.join(certificateDir, "cert.pem");
      mkdirSync(certificateDir);
      execFileSync("openssl", [
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
        "-subj", "/CN=card.test", "-addext", "subjectAltName=DNS:card.test",
        "-keyout", keyCert, "-out", cert,
      ], { stdio: "ignore" });
      const certificate = readFileSync(cert, "utf8");
      server = https.createServer({ key: readFileSync(keyCert), cert: certificate }, (req, res) => {
        requests.push({ url: req.url ?? "/", headers: req.headers });
        if (req.url === "/jwks.json") {
          res.writeHead(200, { "content-type": "application/jwk-set+json" }).end(JSON.stringify(jwks));
        } else {
          res.writeHead(200, { "content-type": "application/a2a+json" }).end(JSON.stringify(signedCard));
        }
      });
      await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
      const port = (server.address() as net.AddressInfo).port;
      const deps: Deps = {
        fetch: async () => { throw new Error("unexpected registry fetch"); },
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text),
        zipvizHome: h.home,
        net: {
          resolve: async () => ["127.0.0.1"],
          isAllowedAddress: (ip) => ip === "127.0.0.1" || isPublicAddress(ip),
          ca: certificate,
          httpsPort: port,
          timeoutMs: 1000,
        } satisfies NetDeps,
      };
      const invoke = async (...args: string[]) => run(args, deps);

      expect(await invoke("card", "sign", cardPath, "--key", keyPath, "--kid", "card-owner", "--jku", "https://card.test/jwks.json")).toBe(0);
      const signedCard = JSON.parse(stdout.at(-1)!) as Record<string, unknown>;
      writeFileSync(signedPath, JSON.stringify(signedCard));
      expect(await invoke("card", "sign", cardPath, "--key", keyPath, "--kid", "card-owner", "--jku", "https://card.test/jwks.json", "--json")).toBe(0);
      expect(await invoke("card", "jwks", "--key", keyPath, "--kid", "card-owner")).toBe(0);
      writeFileSync(jwksPath, stdout.at(-1)!);
      expect(await invoke("card", "jwks", "--key", keyPath, "--kid", "card-owner", "--json")).toBe(0);
      expect(await invoke("card", "verify", signedPath, "--jwks", jwksPath)).toBe(0);
      expect(await invoke("card", "verify", signedPath, "--jwks", jwksPath, "--json")).toBe(0);
      expect(await invoke("check", "--card", "card.test")).toBe(0);
      expect(await invoke("check", "--card", "card.test", "--json")).toBe(0);

      const captured = [
        ...stdout,
        ...stderr,
        ...requests.flatMap((request) => [request.url, JSON.stringify(request.headers)]),
      ].join("\n");
      expect(requests.some((request) => request.url === "/.well-known/agent-card.json")).toBe(true);
      expect(requests.some((request) => request.url === "/jwks.json")).toBe(true);
      expect(captured).not.toMatch(/PRIVATE KEY/);
      for (const secret of secretValues) expect(captured.includes(secret)).toBe(false);
    } finally {
      if (server?.listening) await new Promise<void>((resolve) => server!.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
