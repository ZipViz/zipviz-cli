import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import https from "node:https";
import net from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { base64urlnopad } from "@scure/base";
import { run, type Deps } from "../src/main.js";
import type { JsonObject, PrivateJwk, PublicJwk } from "../src/a2a/index.js";
import { canonicalizeCard, signCard } from "../src/a2a/index.js";
import { isPublicAddress, type NetDeps } from "../src/net/fetch.js";

const card = (): JsonObject => ({
  name: "Example",
  description: "Card",
  supportedInterfaces: [{ url: "https://card.test/rpc", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
  version: "1",
  capabilities: {},
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [],
});

let root: string;
let certificate: string;
let port: number;
let server: https.Server;
let remoteCard: JsonObject;
let servedJwks: unknown = { keys: [] };
let cardRedirect = false;
const requests: Array<{ host: string | undefined; url: string | undefined }> = [];

function writeJson(name: string, value: unknown): string {
  const file = path.join(root, name);
  writeFileSync(file, JSON.stringify(value, null, 2), { mode: 0o600 });
  return file;
}

function netDeps(): NetDeps {
  return {
    resolve: async () => ["127.0.0.1"],
    isAllowedAddress: (ip) => ip === "127.0.0.1" || isPublicAddress(ip),
    ca: certificate,
    httpsPort: port,
    timeoutMs: 1000,
  };
}

function cli(args: string[], options: { stdin?: string; net?: NetDeps } = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: async () => { throw new Error("unexpected registry fetch"); },
    stdout: (text) => stdout.push(text),
    stderr: (text) => stderr.push(text),
    zipvizHome: path.join(root, "home"),
    readStdin: async () => new TextEncoder().encode(options.stdin ?? ""),
    ...(options.net ? { net: options.net } : {}),
  };
  return run(args, deps).then((code) => ({ code, out: stdout.join(""), err: stderr.join("") }));
}

function keyPair(kind: "ed25519" | "p256" = "ed25519") {
  const pair = kind === "p256"
    ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    : generateKeyPairSync("ed25519");
  const privatePem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const privateFile = path.join(root, `${kind}.key`);
  writeFileSync(privateFile, privatePem, { mode: 0o600 });
  const privateJwk = pair.privateKey.export({ format: "jwk" }) as PrivateJwk;
  const publicJwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "cli-key" } as PublicJwk;
  return { pair, privateFile, privatePem: String(privatePem), privateJwk, publicJwk };
}

function withProtectedHeader(
  signed: JsonObject,
  key: ReturnType<typeof keyPair>,
  header: Record<string, unknown>,
): JsonObject {
  const signatures = signed.signatures as Array<{ protected: string; signature: string; header?: JsonObject }>;
  const original = signatures[0]!;
  const protectedText = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(header)));
  const payload = base64urlnopad.encode(new TextEncoder().encode(canonicalizeCard(signed).canonical));
  const signingInput = `${protectedText}.${payload}`;
  const signature = cryptoSign(null, Buffer.from(signingInput), key.pair.privateKey);
  return {
    ...signed,
    signatures: [{
      ...original,
      protected: protectedText,
      signature: base64urlnopad.encode(signature),
      header: { alg: "HS256", kid: "untrusted" },
    }],
  };
}

beforeAll(async () => {
  root = mkdtempSync(path.join(tmpdir(), "zipviz-card-cli-"));
  const certDir = path.join(root, "cert");
  mkdirSync(certDir);
  const keyFile = path.join(certDir, "key.pem");
  const certFile = path.join(certDir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
    "-subj", "/CN=card.test", "-addext", "subjectAltName=DNS:card.test,DNS:evil.test,DNS:other.test",
    "-keyout", keyFile, "-out", certFile,
  ], { stdio: "ignore" });
  certificate = readFileSync(certFile, "utf8");
  remoteCard = card();
  server = https.createServer({ key: readFileSync(keyFile), cert: certificate }, (req, res) => {
    requests.push({ host: req.headers.host, url: req.url });
    if (req.url === "/redirect-private") {
      res.writeHead(302, { location: "https://10.0.0.1/.well-known/agent-card.json" }).end();
    } else if (req.url === "/.well-known/agent-card.json" && cardRedirect) {
      res.writeHead(302, { location: "/redirect-private" }).end();
    } else if (req.url === "/.well-known/agent-card.json") {
      res.writeHead(200, { "content-type": "application/a2a+json" }).end(JSON.stringify(remoteCard));
    } else if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "content-type": "application/jwk-set+json" }).end(JSON.stringify(servedJwks));
    } else if (req.url === "/evil-jwks.json") {
      res.writeHead(200, { "content-type": "application/jwk-set+json" }).end(JSON.stringify(servedJwks));
    } else {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as net.AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(root, { recursive: true, force: true });
});

describe("card sign, jwks, and verify CLI", () => {
  it.each(["ed25519", "p256"] as const)("signs, publishes public JWKS, and verifies %s offline", async (kind) => {
    const keys = keyPair(kind);
    const input = writeJson("card.json", card());
    const jwksPath = writeJson("jwks.json", { keys: [{ ...keys.publicJwk, use: "sig" }] });
    const signed = await cli(["card", "sign", input, "--key", keys.privateFile, "--kid", "cli-key"]);
    expect(signed.code).toBe(0);
    const signedCard = JSON.parse(signed.out) as JsonObject;
    expect(signedCard.signatures).toHaveLength(1);
    const jwks = await cli(["card", "jwks", "--key", keys.privateFile, "--kid", "cli-key"]);
    expect(jwks.code).toBe(0);
    expect(JSON.parse(jwks.out)).toEqual({ keys: [{ ...keys.publicJwk, alg: kind === "p256" ? "ES256" : "EdDSA", use: "sig" }] });
    const signedPath = writeJson("signed.json", signedCard);
    const verified = await cli(["card", "verify", signedPath, "--jwks", jwksPath]);
    expect(verified.code).toBe(0);
    expect(verified.out).toContain("valid");
    const machine = await cli(["card", "verify", signedPath, "--jwks", jwksPath, "--json"]);
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out)).toMatchObject({ ok: true, command: "card verify", valid: true });
  });

  it("verifies rotated cards with only the new JWKS key unless --require-all is used", async () => {
    const oldKey = keyPair();
    const newKey = keyPair();
    const first = signCard(card(), oldKey.privateJwk, { kid: "old-key" });
    const rotated = signCard(first, newKey.privateJwk, { kid: "new-key", append: true });
    const cardPath = writeJson("rotated-card.json", rotated);
    const jwksPath = writeJson("new-only-jwks.json", {
      keys: [{ ...newKey.publicJwk, kid: "new-key" }],
    });
    const args = ["card", "verify", cardPath, "--jwks", jwksPath];

    const verified = await cli(args);
    expect(verified.code).toBe(0);
    expect(verified.out).toContain(
      "signature 1: signature claiming key old-key (EdDSA) not checked: SIG_KEY_NOT_FOUND",
    );
    expect(verified.out).toContain("result: valid (1 of 2 signatures verified)");
    const machine = await cli([...args, "--json"]);
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out)).toMatchObject({
      ok: true,
      command: "card verify",
      valid: true,
      require_all: false,
      valid_signatures: 1,
      signatures: [{ valid: false, reason: "SIG_KEY_NOT_FOUND" }, { valid: true }],
    });

    const strict = await cli([...args, "--require-all"]);
    expect(strict.code).toBe(7);
    expect(strict.out).toContain("result: invalid");
    const strictMachine = await cli([...args, "--require-all", "--json"]);
    expect(strictMachine.code).toBe(7);
    expect(JSON.parse(strictMachine.out)).toMatchObject({
      ok: false,
      valid: false,
      require_all: true,
      valid_signatures: 1,
      reason: "CARD_SIGNATURES_INVALID",
    });

    const strictUncovered = writeJson("rotated-uncovered-card.json", {
      ...rotated,
      extension: "not covered",
    });
    const uncoveredDefault = await cli(["card", "verify", strictUncovered, "--jwks", jwksPath]);
    expect(uncoveredDefault.code).toBe(8);
    expect(uncoveredDefault.out).toContain("not covered by any signature: /extension");
    expect(uncoveredDefault.out).toContain(
      "result: 1 of 2 signatures verified, but 1 field not covered by any signature",
    );
    const uncoveredStrict = await cli(["card", "verify", strictUncovered, "--jwks", jwksPath, "--require-all"]);
    expect(uncoveredStrict.code).toBe(7);
  });

  it("warns about forged signatures without warning for an unchecked signature", async () => {
    const validKey = keyPair();
    const forgedKey = keyPair();
    const first = signCard(card(), validKey.privateJwk, { kid: "valid-key" });
    const appended = signCard(first, forgedKey.privateJwk, { kid: "forged-key", append: true });
    const entries = appended.signatures as Array<{ protected: string; signature: string }>;
    const mixed = {
      ...appended,
      signatures: [
        entries[0]!,
        { ...entries[1]!, signature: base64urlnopad.encode(new Uint8Array(64)) },
      ],
    };
    const mixedPath = writeJson("forged-signature-card.json", mixed);
    const bothKeysPath = writeJson("forged-signature-jwks.json", {
      keys: [
        { ...validKey.publicJwk, kid: "valid-key" },
        { ...forgedKey.publicJwk, kid: "forged-key" },
      ],
    });
    const warning = "warning: CARD_SIGNATURE_FAILED_VERIFICATION (signature 2 claiming key forged-key failed verification: SIG_INVALID)";

    const human = await cli(["card", "verify", mixedPath, "--jwks", bothKeysPath]);
    expect(human.code).toBe(0);
    expect(human.out).toContain(warning);
    expect(human.out.indexOf(warning)).toBeLessThan(human.out.indexOf("result: valid (1 of 2 signatures verified)"));
    const machine = await cli(["card", "verify", mixedPath, "--jwks", bothKeysPath, "--json"]);
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out).warnings).toEqual([{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason: "SIG_INVALID",
      message: "signature 2 claiming key forged-key failed verification: SIG_INVALID",
      signature_index: 1,
    }]);

    const strict = await cli(["card", "verify", mixedPath, "--jwks", bothKeysPath, "--require-all"]);
    expect(strict.code).toBe(7);
    expect(strict.out).toContain(warning);
    const strictMachine = await cli(["card", "verify", mixedPath, "--jwks", bothKeysPath, "--require-all", "--json"]);
    expect(strictMachine.code).toBe(7);
    expect(JSON.parse(strictMachine.out).warnings).toEqual(JSON.parse(machine.out).warnings);

    const missingCard = signCard(first, forgedKey.privateJwk, { kid: "missing-key", append: true });
    const missingPath = writeJson("missing-signature-key-card.json", missingCard);
    const oneKeyPath = writeJson("one-signature-key-jwks.json", {
      keys: [{ ...validKey.publicJwk, kid: "valid-key" }],
    });
    const unchecked = await cli(["card", "verify", missingPath, "--jwks", oneKeyPath]);
    expect(unchecked.code).toBe(0);
    expect(unchecked.out).not.toContain("CARD_SIGNATURE_FAILED_VERIFICATION");
    const uncheckedMachine = await cli(["card", "verify", missingPath, "--jwks", oneKeyPath, "--json"]);
    expect(uncheckedMachine.code).toBe(0);
    expect(JSON.parse(uncheckedMachine.out)).not.toHaveProperty("warnings");
  });

  it("warns for alg:none and bad base64url signatures alongside a valid signature", async () => {
    const keys = keyPair();
    const valid = signCard(card(), keys.privateJwk, { kid: "valid-key" });
    const validSignature = (valid.signatures as Array<{ protected: string; signature: string }>)[0]!;
    const encodeHeader = (value: unknown) => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(value)));
    const jwksPath = writeJson("warning-reasons-jwks.json", {
      keys: [{ ...keys.publicJwk, kid: "valid-key" }],
    });
    const cases = [
      {
        name: "alg-none",
        signature: { protected: encodeHeader({ alg: "none" }), signature: "" },
        reason: "SIG_ALG_NONE",
        message: "signature 2 failed verification: SIG_ALG_NONE",
      },
      {
        name: "bad-encoding",
        signature: { protected: encodeHeader({ alg: "EdDSA", kid: "bad-encoding" }), signature: "!" },
        reason: "SIG_ENCODING_INVALID",
        message: "signature 2 claiming key bad-encoding failed verification: SIG_ENCODING_INVALID",
      },
    ];

    for (const scenario of cases) {
      const inputPath = writeJson(`${scenario.name}-warning-card.json`, {
        ...valid,
        signatures: [validSignature, scenario.signature],
      });
      const warning = `warning: CARD_SIGNATURE_FAILED_VERIFICATION (${scenario.message})`;
      const human = await cli(["card", "verify", inputPath, "--jwks", jwksPath]);
      expect(human.code).toBe(0);
      expect(human.out).toContain(warning);

      const machine = await cli(["card", "verify", inputPath, "--jwks", jwksPath, "--json"]);
      expect(machine.code).toBe(0);
      expect(JSON.parse(machine.out).warnings).toEqual([{
        code: "CARD_SIGNATURE_FAILED_VERIFICATION",
        reason: scenario.reason,
        message: scenario.message,
        signature_index: 1,
      }]);
    }
  });

  it("warns for a rejected HS256 signature alongside a valid signature", async () => {
    const keys = keyPair();
    const valid = signCard(card(), keys.privateJwk, { kid: "valid-key" });
    const validSignature = (valid.signatures as Array<{ protected: string; signature: string }>)[0]!;
    const unsupportedSignature = {
      protected: base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({
        alg: "HS256",
        kid: "unsupported-key",
      }))),
      signature: "",
    };
    const inputPath = writeJson("unsupported-alg-card.json", {
      ...valid,
      signatures: [validSignature, unsupportedSignature],
    });
    const jwksPath = writeJson("unsupported-alg-jwks.json", {
      keys: [{ ...keys.publicJwk, kid: "valid-key" }],
    });
    const warning =
      "warning: CARD_SIGNATURE_FAILED_VERIFICATION (signature 2 claiming key unsupported-key failed verification: SIG_ALG_UNSUPPORTED)";

    const human = await cli(["card", "verify", inputPath, "--jwks", jwksPath]);
    expect(human.code).toBe(0);
    expect(human.out).toContain(warning);

    const machine = await cli(["card", "verify", inputPath, "--jwks", jwksPath, "--json"]);
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out).warnings).toEqual([{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason: "SIG_ALG_UNSUPPORTED",
      message: "signature 2 claiming key unsupported-key failed verification: SIG_ALG_UNSUPPORTED",
      signature_index: 1,
    }]);
  });

  it("escapes terminal controls in card output and preserves raw JSON values", async () => {
    const keys = keyPair();
    const rawKid = "kid\u001b[2J\u009b\u202e\nresult: valid";
    const signed = signCard(card(), keys.privateJwk, { kid: rawKid });
    const cardPath = writeJson("terminal-kid-card.json", signed);
    const jwksPath = writeJson("terminal-kid-jwks.json", {
      keys: [{ ...keys.publicJwk, kid: rawKid }],
    });

    const human = await cli(["card", "verify", cardPath, "--jwks", jwksPath]);
    expect(human.code).toBe(0);
    expect(human.out).toContain("key kid\\x1b[2J\\x9b\\u202e\\x0aresult: valid (EdDSA)");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => human.out.includes(control))).toBe(false);
    expect(human.out.split("\n").filter((line) => line === "result: valid")).toHaveLength(1);

    const machine = await cli(["card", "verify", cardPath, "--jwks", jwksPath, "--json"]);
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out).signatures[0].kid).toBe(rawKid);

    const rawField = "extension\u001bfield";
    const uncoveredPath = writeJson("terminal-field-card.json", {
      ...signCard(card(), keys.privateJwk, { kid: rawKid }),
      [rawField]: "uncovered",
    });
    const uncoveredHuman = await cli(["card", "verify", uncoveredPath, "--jwks", jwksPath]);
    expect(uncoveredHuman.code).toBe(8);
    expect(uncoveredHuman.out).toContain("not covered by any signature: /extension\\x1bfield");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => uncoveredHuman.out.includes(control))).toBe(false);
    const uncoveredMachine = await cli(["card", "verify", uncoveredPath, "--jwks", jwksPath, "--json"]);
    expect(uncoveredMachine.code).toBe(8);
    expect(JSON.parse(uncoveredMachine.out).uncovered).toEqual([`/${rawField}`]);
  });

  it("escapes terminal controls from a remote card and preserves raw JSON values", async () => {
    const keys = keyPair();
    const rawKid = "remote\u001b[2J\u009b\u202e\nresult: valid";
    remoteCard = signCard(card(), keys.privateJwk, { kid: rawKid });
    servedJwks = { keys: [{ ...keys.publicJwk, kid: rawKid }] };

    const human = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(human.code).toBe(0);
    expect(human.out).toContain("key remote\\x1b[2J\\x9b\\u202e\\x0aresult: valid (EdDSA)");
    expect(["\u001b", "\u009b", "\u202e"].some((control) => human.out.includes(control))).toBe(false);
    expect(human.out.split("\n").filter((line) => line === "result: valid")).toHaveLength(1);

    const machine = await cli(["check", "--card", "card.test", "--json"], { net: netDeps() });
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out).signatures[0].kid).toBe(rawKid);
  });

  it("prints typ warnings and ignored unprotected fields on valid, invalid, and unchecked signatures", async () => {
    const keys = keyPair();
    const jwksPath = writeJson("ignored-fields-jwks.json", { keys: [keys.publicJwk] });
    const emptyJwksPath = writeJson("empty-jwks.json", { keys: [] });
    const signed = signCard(card(), keys.privateJwk, { kid: "cli-key" });
    const header = JSON.parse(Buffer.from(
      (signed.signatures as Array<{ protected: string }>)[0]!.protected,
      "base64url",
    ).toString("utf8")) as Record<string, unknown>;
    const valid = withProtectedHeader(signed, keys, { ...header, typ: "JWT" });
    const validPath = writeJson("unexpected-typ.json", valid);
    const ignoredSuffix = "; ignored unprotected header fields: alg, kid (not trusted)";
    const warningSuffix = '; warning: SIG_TYP_UNEXPECTED (typ "JWT" is not JOSE)';

    const verified = await cli(["card", "verify", validPath, "--jwks", jwksPath]);
    expect(verified.code).toBe(0);
    expect(verified.out).toContain(
      `signature 1: card signed by key cli-key (EdDSA), valid; key from --jwks <file>${warningSuffix}${ignoredSuffix}`,
    );

    const tamperedPath = writeJson("tampered-unprotected.json", { ...valid, description: "tampered" });
    const tampered = await cli(["card", "verify", tamperedPath, "--jwks", jwksPath]);
    expect(tampered.code).toBe(7);
    expect(tampered.out).toContain(`signature 1: signature claiming key cli-key (EdDSA) is invalid: SIG_INVALID`);
    expect(tampered.out).toContain(`${warningSuffix}${ignoredSuffix}`);

    const unchecked = await cli(["card", "verify", validPath, "--jwks", emptyJwksPath]);
    expect(unchecked.code).toBe(7);
    expect(unchecked.out).toContain("signature 1: signature claiming key cli-key (EdDSA) not checked: SIG_KEY_NOT_FOUND");
    expect(unchecked.out).toContain(`${warningSuffix}${ignoredSuffix}`);
  });

  it("refuses uncovered cards, rejects already-signed input unless appending, and supports append", async () => {
    const keys = keyPair();
    const invalidPath = writeJson("legacy.json", { ...card(), url: "https://legacy.example" });
    expect((await cli(["card", "sign", invalidPath, "--key", keys.privateFile])).code).toBe(7);
    const input = writeJson("unsigned.json", card());
    const first = JSON.parse((await cli(["card", "sign", input, "--key", keys.privateFile])).out) as JsonObject;
    const signedPath = writeJson("one-signature.json", first);
    expect((await cli(["card", "sign", signedPath, "--key", keys.privateFile])).code).toBe(7);
    const appended = await cli(["card", "sign", signedPath, "--key", keys.privateFile, "--append"]);
    expect(appended.code).toBe(0);
    expect((JSON.parse(appended.out) as JsonObject).signatures).toHaveLength(2);
  });

  it("handles stdin, bounded input, and usage errors", async () => {
    const keys = keyPair();
    expect((await cli(["card", "sign", "-", "--key", keys.privateFile], { stdin: JSON.stringify(card()) })).code).toBe(0);
    expect((await cli(["card", "sign", path.join(root, "missing.json"), "--key", keys.privateFile])).code).toBe(6);
    expect((await cli(["card", "sign", "-", "--key", keys.privateFile], {
      stdin: "x".repeat(1024 * 1024 + 1),
    })).code).toBe(6);
    expect((await cli(["card", "sign", "-", "--key", keys.privateFile], { stdin: "[" })).code).toBe(7);
    expect((await cli(["card", "unknown", "-"])).code).toBe(2);
    expect((await cli(["card", "verify", "-", "--key", keys.privateFile, "--jwks", "also.json"])).code).toBe(2);
  });
});

describe("check --card remote verification", () => {
  it("fetches same-host JWKS and reports a valid card in human and JSON output", async () => {
    const keys = keyPair();
    const signed = signCard(card(), keys.privateJwk, {
      kid: "cli-key",
      jku: "https://card.test/.well-known/jwks.json",
    });
    remoteCard = signed;
    servedJwks = { keys: [keys.publicJwk] };
    requests.length = 0;
    const result = await cli(["check", "--card", "CARD.TEST"], { net: netDeps() });
    expect(result.code).toBe(0);
    expect(result.out).toContain("card: https://card.test/.well-known/agent-card.json");
    expect(result.out).toContain("signature 1:");
    expect(result.out).toContain("result: valid");
    expect(requests.map((request) => request.url)).toContain("/.well-known/jwks.json");
    const machine = await cli(["check", "--card", "card.test", "--json"], { net: netDeps() });
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out)).toMatchObject({
      ok: true,
      command: "check",
      card_url: "https://card.test/.well-known/agent-card.json",
      valid: true,
      signatures: [{ valid: true, key_source: "https://card.test/.well-known/jwks.json (same host as the card)" }],
    });
  });

  it("returns 7 for tampering and refuses cross-host jku without a network request", async () => {
    const keys = keyPair();
    servedJwks = { keys: [keys.publicJwk] };
    const signed = signCard(card(), keys.privateJwk, { kid: "cli-key", jku: "https://evil.test/evil-jwks.json" });
    remoteCard = { ...signed, description: "tampered" };
    requests.length = 0;
    const tampered = await cli(["check", "--card", "card.test", "--key", keys.privateFile], { net: netDeps() });
    expect(tampered.code).toBe(7);
    expect(tampered.out).toContain("SIG_INVALID");

    remoteCard = signed;
    requests.length = 0;
    const refused = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(refused.code).toBe(7);
    expect(refused.out).toContain("KEY_JKU_HOST_NOT_ALLOWED");
    expect(requests.some((request) => request.host?.startsWith("evil.test"))).toBe(false);
    const allowed = await cli(["check", "--card", "card.test", "--allow-jku-host", "other.test", "--allow-jku-host", "evil.test"], {
      net: netDeps(),
    });
    expect(allowed.code).toBe(0);
  });

  it("reports a missing remote key as not checked", async () => {
    const keys = keyPair();
    remoteCard = signCard(card(), keys.privateJwk, { kid: "absent-key" });
    servedJwks = { keys: [] };
    const result = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(result.code).toBe(7);
    expect(result.out).toContain(
      "signature 1: signature claiming key absent-key (EdDSA) not checked: SIG_KEY_NOT_FOUND (no public key matches the protected header kid)",
    );
  });

  it("computes forged-signature warnings from final remote key results", async () => {
    const validKey = keyPair();
    const forgedKey = keyPair();
    const first = signCard(card(), validKey.privateJwk, { kid: "valid-key" });
    const appended = signCard(first, forgedKey.privateJwk, { kid: "forged-key", append: true });
    const entries = appended.signatures as Array<{ protected: string; signature: string }>;
    remoteCard = {
      ...appended,
      signatures: [entries[0]!, { ...entries[1]!, signature: base64urlnopad.encode(new Uint8Array(64)) }],
    };
    servedJwks = {
      keys: [
        { ...validKey.publicJwk, kid: "valid-key" },
        { ...forgedKey.publicJwk, kid: "forged-key" },
      ],
    };

    const human = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(human.code).toBe(0);
    expect(human.out).toContain(
      "warning: CARD_SIGNATURE_FAILED_VERIFICATION (signature 2 claiming key forged-key failed verification: SIG_INVALID)",
    );
    const machine = await cli(["check", "--card", "card.test", "--json"], { net: netDeps() });
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out).warnings).toEqual([{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason: "SIG_INVALID",
      message: "signature 2 claiming key forged-key failed verification: SIG_INVALID",
      signature_index: 1,
    }]);
  });

  it("verifies a rotated card through same-host fallback JWKS unless --require-all is used", async () => {
    const oldKey = keyPair();
    const newKey = keyPair();
    const first = signCard(card(), oldKey.privateJwk, { kid: "old-key" });
    remoteCard = signCard(first, newKey.privateJwk, { kid: "new-key", append: true });
    servedJwks = { keys: [{ ...newKey.publicJwk, kid: "new-key" }] };
    requests.length = 0;

    const verified = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(verified.code).toBe(0);
    expect(verified.out).toContain("signature 1: signature claiming key old-key (EdDSA) not checked: SIG_KEY_NOT_FOUND");
    expect(verified.out).toContain("result: valid (1 of 2 signatures verified)");
    expect(requests.map((request) => request.url)).toContain("/.well-known/jwks.json");
    const machine = await cli(["check", "--card", "card.test", "--json"], { net: netDeps() });
    expect(machine.code).toBe(0);
    expect(JSON.parse(machine.out)).toMatchObject({
      valid: true,
      require_all: false,
      valid_signatures: 1,
      signatures: [
        { valid: false, reason: "SIG_KEY_NOT_FOUND" },
        { valid: true, key_source: "https://card.test/.well-known/jwks.json (same-host ZipViz fallback, not an A2A convention)" },
      ],
    });

    const strict = await cli(["check", "--card", "card.test", "--require-all"], { net: netDeps() });
    expect(strict.code).toBe(7);
    expect(strict.out).toContain("result: invalid");
    const strictMachine = await cli(["check", "--card", "card.test", "--require-all", "--json"], { net: netDeps() });
    expect(strictMachine.code).toBe(7);
    expect(JSON.parse(strictMachine.out)).toMatchObject({
      ok: false,
      require_all: true,
      valid_signatures: 1,
      reason: "CARD_SIGNATURES_INVALID",
    });
  });

  it("uses the reason message for malformed signature headers", async () => {
    const keys = keyPair();
    remoteCard = signCard(card(), keys.privateJwk, { kid: "cli-key" });
    const signatures = remoteCard.signatures as Array<{ protected: string; signature: string }>;
    const header = JSON.parse(Buffer.from(signatures[0]!.protected, "base64url").toString("utf8")) as Record<string, unknown>;
    delete header.kid;
    signatures[0]!.protected = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(header)));
    const result = await cli(["check", "--card", "card.test", "--key", keys.privateFile], { net: netDeps() });
    expect(result.code).toBe(7);
    expect(result.out).toContain("SIG_KID_MISSING (protected header kid is missing or invalid)");
  });

  it("does not treat a same-host URL on a different port as same-origin and never fetches x5u", async () => {
    const keys = keyPair();
    remoteCard = signCard(card(), keys.privateJwk, {
      kid: "cli-key",
      jku: `https://card.test:${port + 1}/.well-known/jwks.json`,
    });
    requests.length = 0;
    const sameHostDifferentPort = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(sameHostDifferentPort.code).toBe(7);
    expect(sameHostDifferentPort.out).toContain("KEY_JKU_HOST_NOT_ALLOWED");
    expect(requests.some((request) => request.url === "/.well-known/jwks.json")).toBe(false);

    remoteCard = signCard(card(), keys.privateJwk, {
      kid: "cli-key",
    });
    const signatures = remoteCard.signatures as Array<{ protected: string; signature: string }>;
    const x5uHeader = JSON.parse(Buffer.from(signatures[0]!.protected, "base64url").toString("utf8")) as Record<string, unknown>;
    x5uHeader.x5u = "https://evil.test/certificate";
    const protectedText = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(x5uHeader)));
    const payloadText = base64urlnopad.encode(new TextEncoder().encode(canonicalizeCard(remoteCard).canonical));
    const signature = cryptoSign(null, Buffer.from(`${protectedText}.${payloadText}`), keys.pair.privateKey);
    remoteCard.signatures = [{
      protected: protectedText,
      signature: base64urlnopad.encode(signature),
    }];
    servedJwks = { keys: [keys.publicJwk] };
    requests.length = 0;
    const x5u = await cli(["check", "--card", "card.test"], { net: netDeps() });
    expect(x5u.code).toBe(0);
    expect(x5u.out).toContain("KEY_X5U_NOT_SUPPORTED");
    expect(requests.some((request) => request.host?.startsWith("evil.test"))).toBe(false);
  });

  it("uses explicit key material, reports uncovered fields, and maps fetch failures to exit 9", async () => {
    const keys = keyPair();
    const jwks = writeJson("remote-jwks.json", { keys: [keys.publicJwk] });
    remoteCard = signCard(card(), keys.privateJwk, { kid: "cli-key" });
    const explicit = await cli(["check", "--card", "card.test", "--jwks", jwks], { net: netDeps() });
    expect(explicit.code).toBe(0);
    expect(explicit.out).toContain("--jwks");

    remoteCard = { ...remoteCard, legacy: true };
    const uncovered = await cli(["check", "--card", "card.test", "--jwks", jwks, "--json"], { net: netDeps() });
    expect(uncovered.code).toBe(8);
    expect(JSON.parse(uncovered.out)).toMatchObject({ ok: false, uncovered: ["/legacy"] });

    cardRedirect = true;
    const refused = await cli(["check", "--card", "card.test", "--jwks", jwks, "--json"], { net: netDeps() });
    cardRedirect = false;
    expect(refused.code).toBe(9);
    expect(JSON.parse(refused.out)).toMatchObject({ ok: false, error: { code: "FETCH_ADDRESS_REFUSED" } });
  });

  it("validates domain forms and option combinations", async () => {
    const badDomains = [
      "card",
      "card.test.",
      "card.test:443",
      "127.0.0.1",
      "::1",
      "127.1",
      "0x7f.1",
      "0177.0.0.1",
      "localhost",
      "bad_label.test",
      "cárd.test",
    ];
    for (const domain of badDomains) {
      expect((await cli(["check", "--card", domain], { net: netDeps() })).code, domain).toBe(2);
    }
    expect((await cli(["check", "--card", "card.test", "event.json"], { net: netDeps() })).code).toBe(2);
    expect((await cli(["check", "--jwks", "keys.json"])).code).toBe(2);
    expect((await cli(["check", "--allow-jku-host", "evil.test"])).code).toBe(2);
  });
});

describe("card commands do not disclose private key material", () => {
  it("keeps private PEM and JWK encodings out of all output and requests", async () => {
    const keys = keyPair();
    const input = writeJson("no-leak-card.json", card());
    const signatureOutput = await cli(["card", "sign", input, "--key", keys.privateFile, "--json"]);
    const jwksOutput = await cli(["card", "jwks", "--key", keys.privateFile, "--json"]);
    const signedFile = writeJson("no-leak-signed.json", JSON.parse(signatureOutput.out));
    const verified = await cli(["card", "verify", signedFile, "--jwks", writeJson("no-leak-jwks.json", { keys: [keys.publicJwk] }), "--json"]);
    const output = [signatureOutput.out, signatureOutput.err, jwksOutput.out, jwksOutput.err, verified.out, verified.err].join("\n");
    expect(output).not.toContain("PRIVATE KEY");
    expect(output).not.toContain(keys.privatePem.trim());
    expect(output).not.toContain(keys.privateJwk.d);
  });
});
