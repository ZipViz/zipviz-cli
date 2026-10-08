import { execFileSync } from "node:child_process";
import { base64urlnopad } from "@scure/base";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { ANS_BINDING_CHECKED_EXIT, ANS_BINDING_CHECKED_LINE } from "../src/ans/command.js";
import { run, type Deps } from "../src/main.js";
import { isPublicAddress, type NetDeps } from "../src/net/fetch.js";
import { buildAnsEvidence, type BuiltAns } from "./ans-build.js";
import type { AnsEvidence } from "../src/ans/verify.js";

const encoder = new TextEncoder();

function bundleBody(evidence: AnsEvidence, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    identityChainPem: evidence.identityChainPem,
    badge: evidence.badge,
    ...extra,
  };
}

function pinned(dir: string, built: BuiltAns): string[] {
  return [
    "--ca", write(dir, "ca.pem", built.evidence.trustAnchorPem),
    "--ra-jwk", write(dir, "ra.json", JSON.stringify(built.evidence.raKey)),
    "--kms-jwk", write(dir, "kms.json", JSON.stringify(built.evidence.kmsKey)),
  ];
}

const tempDirs: string[] = [];

function directory(): string {
  const created = mkdtempSync(path.join(tmpdir(), "zipviz-ans-cli-"));
  tempDirs.push(created);
  return created;
}

function write(dir: string, name: string, value: string): string {
  const file = path.join(dir, name);
  writeFileSync(file, value);
  return file;
}

function cli(args: string[], extra: Partial<Deps> = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: async () => { throw new Error("unexpected registry fetch"); },
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
    zipvizHome: directory(),
    readStdin: async () => new Uint8Array(),
    ...extra,
  };
  return run(args, deps).then((code) => ({ code, stdout: stdout.join(""), stderr: stderr.join("") }));
}

describe("zipviz check --ans", () => {
  const built = buildAnsEvidence();

  function bundle(value: unknown = bundleBody(built.evidence)): string {
    return write(directory(), "bundle.json", JSON.stringify(value));
  }

  it("does not let a bundle pass on keys it carries", async () => {
    const selfVouching = bundle({
      identityChainPem: built.evidence.identityChainPem,
      trustAnchorPem: built.evidence.trustAnchorPem,
      badge: built.evidence.badge,
      raKey: built.evidence.raKey,
      kmsKey: built.evidence.kmsKey,
    });
    const alone = await cli(["check", "--ans", built.name, "--bundle", selfVouching]);
    expect(alone.code).toBe(2);
    expect(`${alone.stdout}${alone.stderr}`.toLowerCase()).not.toMatch(/\bverified\b/);

    const rejected = await cli(["check", "--ans", built.name, "--bundle", selfVouching, ...pinned(directory(), built)]);
    expect(rejected.code).toBe(6);
    expect(rejected.stderr).toContain("trustAnchorPem");
    expect(rejected.stdout.toLowerCase()).not.toMatch(/\bverified\b/);
  });

  it("requires pinned trust anchors and does not call an unsigned status verified", async () => {
    const file = bundle();
    const human = await cli(["check", "--ans", built.name, "--bundle", file, ...pinned(directory(), built)]);
    expect(human.code).toBe(ANS_BINDING_CHECKED_EXIT);
    expect(human.stdout).toContain(ANS_BINDING_CHECKED_LINE);
    expect(human.stdout).toContain("live_log: not proved");
    expect(human.stdout).toContain("pinned CA SHA256:");
    expect(human.stdout).toContain("neither value is signed");
    expect(human.stdout).not.toContain(built.raPrivate.d);
    expect(human.stderr).toBe("");

    const json = await cli(["check", "--json", "--ans", built.name, "--bundle", file, ...pinned(directory(), built)]);
    const body = JSON.parse(json.stdout) as { ok: boolean; valid: boolean; scope: { live_log: string } };
    expect(body).toMatchObject({
      ok: false,
      command: "check",
      draft: "draft-narajala-courtney-ansv2-01",
      valid: false,
      binding_checked: true,
      reason: "ANS_REVOCATION_NOT_CHECKED",
      scope: {
        revocation: "not checked",
        live_log: "not proved",
        reputation: "not checked",
        behaviour: "not checked",
      },
    });
    expect(body).not.toHaveProperty("score");
    expect(json.stdout).not.toContain(built.raPrivate.d);
  });

  it("does not report a REVOKED badge flipped to ACTIVE as verified", async () => {
    const revoked = buildAnsEvidence({ status: "REVOKED", eventType: "AGENT_REGISTERED" });
    const body = bundleBody(revoked.evidence) as { badge: { status: string } };
    body.badge.status = "ACTIVE";
    const file = bundle(body);
    const human = await cli(["check", "--ans", revoked.name, "--bundle", file, ...pinned(directory(), revoked)]);
    expect(human.code).toBe(ANS_BINDING_CHECKED_EXIT);
    expect(human.stdout).toContain(ANS_BINDING_CHECKED_LINE);
    expect(human.stdout).toContain("live_log: not proved");
    const json = await cli(["--json", "check", "--ans", revoked.name, "--bundle", file, ...pinned(directory(), revoked)]);
    expect(JSON.parse(json.stdout)).toMatchObject({
      ok: false,
      valid: false,
      binding_checked: true,
      reason: "ANS_REVOCATION_NOT_CHECKED",
      scope: { revocation: "not checked", live_log: "not proved" },
      transparency_log: { valid: true, status: "ACTIVE", event_type: "AGENT_REGISTERED" },
    });
  });

  it("reads a bundle from stdin and rejects a score field, duplicate keys, and a bad proof", async () => {
    const text = JSON.stringify(bundleBody(built.evidence));
    const stdin = await cli(["check", "--ans", built.name, "--bundle", "-", ...pinned(directory(), built)], {
      readStdin: async () => encoder.encode(text),
    });
    expect(stdin.code).toBe(ANS_BINDING_CHECKED_EXIT);
    expect(stdin.stdout).toContain(ANS_BINDING_CHECKED_LINE);

    const scored = await cli(["check", "--ans", built.name, "--bundle", bundle(bundleBody(built.evidence, { score: 99 })), ...pinned(directory(), built)]);
    expect(scored.code).toBe(6);
    expect(scored.stderr).toContain("score");

    const duplicate = await cli(["check", "--ans", built.name, "--bundle", bundleText('{"identityChainPem":"a","identityChainPem":"b","badge":{}}'), ...pinned(directory(), built)]);
    expect(duplicate.code).toBe(6);

    const tampered = structuredClone(bundleBody(built.evidence)) as AnsLike;
    tampered.badge.inclusionProof.path[0] = "00".repeat(32);
    const failed = await cli(["--json", "check", "--ans", built.name, "--bundle", bundle(tampered), ...pinned(directory(), built)]);
    expect(failed.code).toBe(7);
    const failedBody = JSON.parse(failed.stdout) as { binding_checked: boolean; transparency_log?: { valid: boolean } };
    expect(failedBody).toMatchObject({ ok: false, command: "check", reason: "ANS_PROOF_INVALID", binding_checked: false });
    expect(failedBody.transparency_log?.valid).not.toBe(true);
    expect(failed.stdout).not.toContain(ANS_BINDING_CHECKED_LINE);
  });

  it("rejects a forged registration authority signature", async () => {
    const body = structuredClone(bundleBody(built.evidence)) as { badge: { signature: string } };
    const [protectedPart, signaturePart] = body.badge.signature.split("..");
    const bytes = base64urlnopad.decode(signaturePart!);
    bytes[0] = bytes[0]! ^ 0xff;
    body.badge.signature = `${protectedPart}..${base64urlnopad.encode(bytes)}`;
    const result = await cli(["--json", "check", "--ans", built.name, "--bundle", bundle(body), ...pinned(directory(), built)]);
    expect(result.code).toBe(7);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: false,
      valid: false,
      binding_checked: false,
      reason: "ANS_SIGNATURE_INVALID",
    });
    expect(result.stdout).not.toContain(ANS_BINDING_CHECKED_LINE);
  });

  it("reports a truncated JWK as a key error", async () => {
    const dir = directory();
    const result = await cli([
      "--json", "check", "--ans", built.name, "--bundle", bundle(),
      "--ca", write(dir, "ca.pem", built.evidence.trustAnchorPem),
      "--ra-jwk", write(dir, "ra.json", "{\"abc"),
      "--kms-jwk", write(dir, "kms.json", JSON.stringify(built.evidence.kmsKey)),
    ]);
    expect(result.code).toBe(7);
    expect(JSON.parse(result.stdout)).toMatchObject({
      ok: false,
      error: { code: "ANS_KEY_INVALID" },
    });
    const bundleJson = await cli([
      "--json", "check", "--ans", built.name, "--bundle", bundleText("{\"abc"),
      ...pinned(directory(), built),
    ]);
    expect(bundleJson.code).toBe(6);
    expect(JSON.parse(bundleJson.stdout).error.code).toBe("E_INPUT_NOT_JSON");
  });

  it("reports usage errors without calling the Buzz checker or the registry", async () => {
    expect((await cli(["check", "--ans", "not-a-name", "--bundle", "missing.json"])).code).toBe(2);
    expect((await cli(["check", "--ans", built.name])).code).toBe(2);
    expect((await cli(["check", "--bundle", "x.json"])).code).toBe(2);
    expect((await cli(["check", "--ans", built.name, "--card", "example.com", "--bundle", "x.json"])).code).toBe(2);
    for (const args of [
      ["check", "--card", "example.com", "--ans", built.name],
      ["check", "--card", "example.com", "--ca", "ca.pem"],
      ["check", "--card", "example.com", "--bundle", "bundle.json"],
      ["check", "--card", "example.com", "--badge", "badge.json"],
      ["check", "--card", "example.com", "--badge-url", "https://example.com/badge"],
      ["check", "--card", "example.com", "--ra-jwk", "ra.json"],
      ["check", "--card", "example.com", "--kms-jwk", "kms.json"],
      ["check", "--card", "example.com", "--cert", "cert.pem"],
    ]) {
      const mixed = await cli(args);
      expect(mixed.code, args.join(" ")).toBe(2);
      expect(mixed.stderr).toContain("--card cannot be combined with ANS options");
    }
    expect((await cli(["check", "event.json", "--ans", built.name, "--bundle", "x.json"])).code).toBe(2);
    const help = await cli(["--help"]);
    expect(help.stdout).toContain("--ans");
    expect(help.stdout).toContain("--badge-url");
  });

  it("refuses private, loopback, and link-local badge URLs before connecting", async () => {
    const dir = directory();
    const cert = write(dir, "cert.pem", built.evidence.identityChainPem);
    const ca = write(dir, "ca.pem", built.evidence.trustAnchorPem);
    const ra = write(dir, "ra.json", JSON.stringify(built.evidence.raKey));
    const kms = write(dir, "kms.json", JSON.stringify(built.evidence.kmsKey));
    const args = ["--json", "check", "--ans", built.name, "--cert", cert, "--ca", ca, "--ra-jwk", ra, "--kms-jwk", kms];
    for (const url of ["https://10.0.0.1/v1/agents/x", "https://127.0.0.1/badge", "https://169.254.169.254/latest", "https://[::1]/badge"]) {
      const refused = await cli([...args, "--badge-url", url]);
      expect(refused.code, url).toBe(9);
      expect(JSON.parse(refused.stdout).error.code).toBe("FETCH_ADDRESS_REFUSED");
    }
    expect((await cli([...args, "--badge-url", "https://user:pass@example.com/badge"])).code).toBe(9);
    expect(JSON.parse((await cli([...args, "--badge-url", "http://example.com/badge"])).stdout).error.code).toBe("FETCH_NOT_HTTPS");
  });
});

type AnsLike = BuiltAns["evidence"] & { badge: { inclusionProof: { path: string[] } } };

function bundleText(text: string): string {
  return write(directory(), "bundle.json", text);
}

describe("zipviz check --ans badge lookup", () => {
  let server: https.Server | undefined;
  let port = 0;
  let certificate = "";
  const requests: string[] = [];
  const built = buildAnsEvidence();

  function start(): Promise<void> {
    const dir = directory();
    const key = path.join(dir, "server.key");
    const cert = path.join(dir, "server.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
      "-subj", "/CN=badge.test", "-addext", "subjectAltName=DNS:badge.test",
      "-keyout", key, "-out", cert,
    ], { stdio: "pipe" });
    certificate = readFileSync(cert, "utf8");
    const listening = https.createServer({ key: readFileSync(key), cert: certificate }, (req, res) => {
      requests.push(req.url ?? "/");
      if (req.url === "/redirect") {
        res.writeHead(302, { location: "https://10.0.0.1/stolen" }).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(built.evidence.badge));
    });
    server = listening;
    return new Promise((resolve) => listening.listen(0, "127.0.0.1", () => {
      port = (listening.address() as net.AddressInfo).port;
      resolve();
    }));
  }

  afterAll(async () => {
    for (const created of tempDirs.splice(0)) rmSync(created, { recursive: true, force: true });
    const listening = server;
    if (listening) await new Promise<void>((resolve) => listening.close(() => resolve()));
  });

  it("fetches a badge over the read-only client and refuses a private redirect", async () => {
    await start();
    const dir = directory();
    const netDeps: NetDeps = {
      resolve: async () => ["127.0.0.1"],
      isAllowedAddress: (ip) => ip === "127.0.0.1" || isPublicAddress(ip),
      ca: certificate,
      httpsPort: port,
      timeoutMs: 1000,
    };
    const args = [
      "--json", "check", "--ans", built.name,
      "--cert", write(dir, "cert.pem", built.evidence.identityChainPem),
      "--ca", write(dir, "ca.pem", built.evidence.trustAnchorPem),
      "--ra-jwk", write(dir, "ra.json", JSON.stringify(built.evidence.raKey)),
      "--kms-jwk", write(dir, "kms.json", JSON.stringify(built.evidence.kmsKey)),
    ];
    const ok = await cli([...args, "--badge-url", "https://badge.test/v1/agents/example"], { net: netDeps });
    expect(ok.code).toBe(ANS_BINDING_CHECKED_EXIT);
    expect(JSON.parse(ok.stdout)).toMatchObject({
      ok: false,
      valid: false,
      binding_checked: true,
      reason: "ANS_REVOCATION_NOT_CHECKED",
      badge_url: "https://badge.test/v1/agents/example",
      scope: { revocation: "not checked", live_log: "not proved" },
      transparency_log: { valid: true },
    });
    expect(requests).toEqual(["/v1/agents/example"]);

    const redirected = await cli([...args, "--badge-url", "https://badge.test/redirect"], { net: netDeps });
    expect(redirected.code).toBe(9);
    expect(JSON.parse(redirected.stdout).error.code).toBe("FETCH_ADDRESS_REFUSED");
    expect(requests).toEqual(["/v1/agents/example", "/redirect"]);
  });
});
