import { readFileSync, readdirSync, statSync, existsSync, writeFileSync, mkdirSync, chmodSync, chownSync, symlinkSync } from "node:fs";
import { createPrivateKey, generateKeyPairSync } from "node:crypto";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { INVITE_NAMESPACE, inviteDomain as inv } from "../src/viz.js";
import { makeHarness, spkiToHex, type Harness } from "./harness.js";

let h: Harness;
beforeEach(() => {
  h = makeHarness();
});
afterEach(() => h.cleanup());

const keysDir = () => path.join(h.home, ".zipviz", "keys");
const keyPath = (id: string) => path.join(keysDir(), `${id}.key`);
const localPub = (id: string) => spkiToHex(createPrivateKey(readFileSync(keyPath(id))));
/** The registry assigns the digits; the fake one counts up from 1000 per harness. */
const assigned = (chosen: string, digits = "1000") => inv(`${chosen}-${digits}`);

function installOwnerKey(domain: string): string {
  const { privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
  writeFileSync(keyPath(domain), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const pub = spkiToHex(privateKey);
  h.registry.addAgent(domain, pub);
  h.registry.issuers.add(domain);
  return pub;
}

describe("global options", () => {
  it("rejects non-https --api origins except http localhost", async () => {
    for (const bad of ["http://api.zipviz.ai", "ftp://x", "https://api.zipviz.ai/v1", "nope", "https://u:p@api.zipviz.ai"]) {
      const r = await h.cliJson("whoami", "--api", bad);
      expect(r.code).toBe(2);
      expect(r.body).toMatchObject({ ok: false, error: { code: "E_USAGE" } });
    }
    await h.cli("keygen");
    for (const good of ["https://api.zipviz.ai", "http://localhost:8787", "http://127.0.0.1:8787/"]) {
      expect((await h.cliJson("whoami", "--api", good)).code).toBe(0);
    }
  });

  it("accepts global options before the command", async () => {
    h.registry.addAgent("gary.yc.viz", "ab".repeat(32));
    const r = await h.cli("--api", "http://localhost:8787", "--json", "verify", "gary.yc.viz");
    expect(r.code).toBe(0);
    expect(h.registry.requests[0]!.url).toBe("http://localhost:8787/v1/agent/gary.yc.viz/card");
  });

  it("defaults to https://api.zipviz.ai", async () => {
    h.registry.addAgent("gary.yc.viz", "ab".repeat(32));
    await h.cli("verify", "gary.yc.viz");
    expect(h.registry.requests[0]!.url).toBe("https://api.zipviz.ai/v1/agent/gary.yc.viz/card");
  });

  it("prints usage and exits 2 for unknown commands and flags", async () => {
    expect((await h.cli("register", "x")).code).toBe(2);
    expect((await h.cli("keygen", "--bogus")).code).toBe(2);
    const help = await h.cli("--help");
    expect(help.code).toBe(0);
    expect(help.out).toContain("zipviz keygen");
    expect(help.out).toMatch(/register.*operator-gated/i);
    expect(help.out).not.toMatch(/mail ?guard|mailbox|relay/i);
  });

  it("mints invite names under z.viz and never shows the reserved zip namespace in help", async () => {
    expect(INVITE_NAMESPACE).toBe("z");
    expect(inv("sophie")).toBe("sophie.z.viz");
    const help = await h.cli("--help");
    expect(help.out).toContain(`<chosen name>-NNNN.${INVITE_NAMESPACE}.viz`);
    expect(help.out).not.toContain("zip.viz");
  });
});

describe("keygen", () => {
  it("writes an Ed25519 PKCS#8 key (dir 0700, file 0600) and prints only the public key", async () => {
    const r = await h.cliJson("keygen", "--name", "sophie");
    expect(r.code).toBe(0);
    const file = keyPath(inv("sophie"));
    expect(statSync(keysDir()).mode & 0o777).toBe(0o700);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(createPrivateKey(readFileSync(file)).asymmetricKeyType).toBe("ed25519");
    expect(r.body).toEqual({
      ok: true,
      command: "keygen",
      key_id: inv("sophie"),
      key_path: file,
      public_key: localPub(inv("sophie")),
    });
  });

  it("uses a default key id without --name and accepts a full .viz domain", async () => {
    expect((await h.cliJson("keygen")).body.key_id).toBe("default");
    expect((await h.cliJson("keygen", "--name", "stu.smc.viz")).body.key_id).toBe("stu.smc.viz");
    expect((await h.cliJson("keygen", "--name", "../etc")).code).toBe(2);
  });

  it("refuses to overwrite without --force, and replaces with --force", async () => {
    await h.cli("keygen", "--name", "sophie");
    const before = readFileSync(keyPath(inv("sophie")), "utf8");
    const again = await h.cliJson("keygen", "--name", "sophie");
    expect(again.code).toBe(1);
    expect(again.body).toMatchObject({ ok: false, error: { code: "E_KEY_EXISTS" } });
    expect(readFileSync(keyPath(inv("sophie")), "utf8")).toBe(before);
    const forced = await h.cliJson("keygen", "--name", "sophie", "--force");
    expect(forced.code).toBe(0);
    expect(readFileSync(keyPath(inv("sophie")), "utf8")).not.toBe(before);
    expect(statSync(keyPath(inv("sophie"))).mode & 0o777).toBe(0o600);
  });

  it("tightens an existing keys dir to 0700", async () => {
    mkdirSync(keysDir(), { recursive: true });
    chmodSync(keysDir(), 0o755);
    await h.cli("keygen");
    expect(statSync(keysDir()).mode & 0o777).toBe(0o700);
  });
});

describe("redeem", () => {
  it("redeems with the local public key and reports the assigned domain", async () => {
    await h.cli("keygen", "--name", "sophie");
    const code = h.registry.mintCode("stu.smc.viz");
    const r = await h.cliJson("redeem", code, "--name", "sophie");
    expect(r.code).toBe(0);
    expect(r.body).toMatchObject({
      ok: true,
      command: "redeem",
      domain: assigned("sophie"),
      name: "sophie-1000",
      public_key: localPub(assigned("sophie")),
    });
    const req = h.registry.requests.at(-1)!;
    expect(req.url).toBe("https://api.zipviz.ai/v1/agent-invites/redeem");
    expect(JSON.parse(req.body!)).toEqual({ code, name: "sophie", public_key: localPub(assigned("sophie")) });
    expect(JSON.stringify(r.body)).not.toContain(code);
  });

  it("uses and then renames the default key when no named key exists", async () => {
    const pub = (await h.cliJson("keygen")).body.public_key;
    const r = await h.cliJson("redeem", h.registry.mintCode("stu.smc.viz"), "--name", "sophie");
    expect(r.body).toMatchObject({ ok: true, domain: assigned("sophie"), public_key: pub });
    expect(existsSync(keyPath("default"))).toBe(false);
    expect(localPub(assigned("sophie"))).toBe(pub);
  });

  it("says plainly when invites are not enabled on the registry", async () => {
    await h.cli("keygen", "--name", "sophie");
    h.registry.invitesEnabled = false;
    const human = await h.cli("redeem", h.registry.mintCode("x.smc.viz"), "--name", "sophie");
    expect(human.code).toBe(1);
    expect(human.err).toContain("invites are not enabled on this registry");
    const r = await h.cliJson("redeem", h.registry.mintCode("x.smc.viz"), "--name", "sophie");
    expect(r.body).toEqual({
      ok: false,
      command: "redeem",
      error: { code: "E_INVITES_DISABLED", message: "invites are not enabled on this registry" },
    });
  });

  it("maps registry refusals to stable codes", async () => {
    await h.cli("keygen", "--name", "admin");
    await h.cli("keygen", "--name", "sophie");
    const bad = await h.cliJson("redeem", `zvi_${"x".repeat(43)}`, "--name", "sophie");
    expect(bad.body).toMatchObject({ ok: false, error: { code: "E_INVITE_INVALID", http_status: 404 } });
    const reserved = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "admin");
    expect(reserved.body).toMatchObject({ ok: false, error: { code: "E_NAME_RESERVED", http_status: 409 } });
    // E_DUPLICATE stays mapped for a registry that predates assigned digits.
    h.registry.predatesAssignedDigits = true;
    h.registry.addAgent(inv("sophie"), "cd".repeat(32));
    const dup = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    expect(dup.body).toMatchObject({ ok: false, error: { code: "E_DUPLICATE", http_status: 409 } });
  });

  it("maps E_NAME_EXHAUSTED to a plain retry message", async () => {
    await h.cli("keygen", "--name", "sophie");
    h.registry.assignDigits = () => "0007";
    h.registry.addAgent(assigned("sophie", "0007"), "cd".repeat(32));
    const r = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({
      ok: false,
      error: { code: "E_NAME_EXHAUSTED", message: "could not assign a name, please retry", http_status: 409 },
    });
  });

  it("validates code and name locally without calling the registry", async () => {
    await h.cli("keygen");
    expect((await h.cliJson("redeem", "not-a-code", "--name", "sophie")).body).toMatchObject({ error: { code: "E_INVITE_FORMAT" } });
    expect((await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "Bad_Name")).code).toBe(2);
    expect((await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"))).code).toBe(2);
    // The chosen part caps at 15 chars and may not already end in -NNNN.
    expect((await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "a".repeat(16))).code).toBe(2);
    expect((await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "a".repeat(15))).code).not.toBe(2);
    for (const lookalike of ["sophie-4821", "x-0000"]) {
      const r = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", lookalike);
      expect(r.code).toBe(2);
      expect(r.body).toMatchObject({ ok: false, error: { code: "E_USAGE" } });
    }
    // A longer digit run is not the assigned form, so it is still allowed.
    await h.cli("keygen");
    expect((await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie-48219")).code).not.toBe(2);
    expect(h.registry.requests.map((q) => JSON.parse(q.body!).name)).toEqual(["a".repeat(15), "sophie-48219"]);
  });

  it("fails clearly without a local key", async () => {
    const r = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_NO_KEY" } });
    expect(h.registry.requests).toHaveLength(0);
  });

  it("refuses a success response that does not echo the local public key", async () => {
    await h.cli("keygen", "--name", "sophie");
    const real = h.registry.fetch;
    h.registry.fetch = async (input, init) => {
      const res = await real(input, init);
      const body = await res.json();
      return new Response(JSON.stringify({ ...body, public_key: "ee".repeat(32) }), { status: res.status });
    };
    const r = await h.cliJson("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_UNEXPECTED_RESPONSE" } });
  });

  it("refuses a response domain that is not <chosen>-NNNN in the invite namespace", async () => {
    const bad = [
      inv("sophie"),                       // older bare domain
      inv("sophie-182"),                   // too few digits
      inv("sophie-18210"),                 // too many digits
      inv("evil-1000"),                    // another chosen part
      "sophie-1000.zip.viz",               // another namespace
      "sophie-1000.z.viz.evil.example",    // suffix smuggling
      "Sophie-1000.z.viz",                 // not the lowercase name that was sent
    ];
    for (const domain of bad) {
      const fresh = makeHarness();
      try {
        await fresh.cli("keygen", "--name", "sophie");
        const real = fresh.registry.fetch;
        fresh.registry.fetch = async (input, init) => {
          const res = await real(input, init);
          const body = await res.json() as Record<string, unknown>;
          return new Response(JSON.stringify({ ...body, domain, name: "sophie-1000" }), { status: res.status });
        };
        const r = await fresh.cliJson("redeem", fresh.registry.mintCode("a.smc.viz"), "--name", "sophie");
        expect(r.code, domain).toBe(1);
        expect(r.body, domain).toMatchObject({ ok: false, error: { code: "E_UNEXPECTED_RESPONSE" } });
        // Nothing is adopted: the key stays where keygen put it.
        expect(readdirSync(path.join(fresh.home, ".zipviz", "keys"))).toEqual([`${inv("sophie")}.key`]);
      } finally {
        fresh.cleanup();
      }
    }
  });
});

describe("verify", () => {
  it("resolves a registered name read-only", async () => {
    h.registry.addAgent("gary.yc.viz", "ab".repeat(32), {
      url: "https://gary.example",
      agent_conversations: { capability_uri: "urn:zipviz:agent-conversations:v3", envelope_version: "3" },
    });
    const r = await h.cliJson("verify", "Gary.YC.viz");
    expect(r.code).toBe(0);
    expect(r.body).toEqual({
      ok: true,
      command: "verify",
      name: "gary.yc.viz",
      registered: true,
      public_key: "ab".repeat(32),
      url: "https://gary.example",
      created: "2026-09-01T00:00:00.000Z",
      agent_conversations: { capability_uri: "urn:zipviz:agent-conversations:v3", envelope_version: "3" },
      local_key: false,
      signature_verified: null,
    });
    expect(h.registry.requests.every((q) => q.method === "GET")).toBe(true);
  });

  it("proves a local key with a fresh signature via POST /v1/verify", async () => {
    await h.cli("keygen", "--name", "sophie");
    await h.cli("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    const r = await h.cliJson("verify", assigned("sophie"));
    expect(r.body).toMatchObject({ ok: true, local_key: true, signature_verified: true });
    const v = h.registry.requests.at(-1)!;
    expect(v.url).toBe("https://api.zipviz.ai/v1/verify");
    expect(Object.keys(JSON.parse(v.body!)).sort()).toEqual(["from", "message", "signature", "timestamp"]);
  });

  it("exits 1 with E_NOT_REGISTERED for an unknown name, and 2 for an invalid one", async () => {
    const r = await h.cliJson("verify", inv("nobody"));
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_NOT_REGISTERED" } });
    expect((await h.cliJson("verify", "a/../b.viz")).code).toBe(2);
  });

  it("flags a card whose key does not match the local key", async () => {
    await h.cli("keygen", "--name", "sophie");
    h.registry.addAgent(inv("sophie"), "ab".repeat(32));
    const r = await h.cliJson("verify", inv("sophie"));
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_MISMATCH" } });
  });
});

describe("whoami", () => {
  it("lists local identities with registry status", async () => {
    await h.cli("keygen");
    await h.cli("keygen", "--name", "sophie");
    await h.cli("redeem", h.registry.mintCode("a.smc.viz"), "--name", "sophie");
    await h.cli("keygen", "--name", "zed");
    const r = await h.cliJson("whoami");
    expect(r.code).toBe(0);
    expect(r.body).toMatchObject({ ok: true, command: "whoami", api: "https://api.zipviz.ai" });
    const ids = r.body.identities as Array<Record<string, unknown>>;
    expect(ids.map((i) => i.key_id)).toEqual(["default", assigned("sophie"), inv("zed")]);
    expect(ids[0]).toMatchObject({ domain: null, registered: null, key_matches: null });
    expect(ids[1]).toMatchObject({ domain: assigned("sophie"), registered: true, key_matches: true });
    expect(ids[2]).toMatchObject({ domain: inv("zed"), registered: false, key_matches: null });
    expect(r.body.skipped).toEqual([]);
  });

  it("errors with E_NO_KEY when there are no local keys", async () => {
    expect((await h.cliJson("whoami")).body).toMatchObject({ ok: false, error: { code: "E_NO_KEY" } });
  });

  it("skips loose-permission key files instead of reading them", async () => {
    await h.cli("keygen", "--name", "sophie");
    chmodSync(keyPath(inv("sophie")), 0o644);
    const r = await h.cliJson("whoami");
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
  });

  it("reports an unsafe key and still lists the other keys", async () => {
    await h.cli("keygen", "--name", "bad");
    await h.cli("keygen", "--name", "good");
    chmodSync(keyPath(inv("bad")), 0o644);
    const r = await h.cliJson("whoami");
    expect(r.code).toBe(3);
    expect(r.body.skipped).toEqual([{ key_id: inv("bad"), code: "E_KEY_UNSAFE", message: expect.any(String) }]);
    const ids = r.body.identities as Array<Record<string, unknown>>;
    expect(ids.map((i) => i.key_id)).toEqual([inv("bad"), inv("good")]);
    expect(ids[0]).toMatchObject({ public_key: null, error: { code: "E_KEY_UNSAFE" } });
    expect(ids[1]).toMatchObject({ domain: inv("good"), registered: false });
    expect(h.registry.requests.map((q) => q.url)).toEqual([`https://api.zipviz.ai/v1/agent/${inv("good")}/card`]);
    const human = await h.cli("whoami");
    expect(human.code).toBe(3);
    const bad = inv("bad").replace(/\./g, "\\.");
    expect(human.out).toMatch(new RegExp(`${bad} .*unsafe|${bad} .*group or others`));
  });
});

describe("key storage hardening", () => {
  it("refuses a symlinked keys directory and leaves its target alone", async () => {
    const target = path.join(h.home, "elsewhere");
    mkdirSync(target, { mode: 0o755 });
    chmodSync(target, 0o755);
    mkdirSync(path.join(h.home, ".zipviz"), { mode: 0o700 });
    symlinkSync(target, keysDir());
    const r = await h.cliJson("keygen", "--name", "sophie");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
    expect(statSync(target).mode & 0o777).toBe(0o755);
    expect(existsSync(path.join(target, `${inv("sophie")}.key`))).toBe(false);
  });

  it("keygen refuses a symlinked ~/.zipviz before creating anything in its target", async () => {
    const target = path.join(h.home, "elsewhere");
    mkdirSync(target, { mode: 0o755 });
    chmodSync(target, 0o755);
    symlinkSync(target, path.join(h.home, ".zipviz"));
    const r = await h.cliJson("keygen", "--name", "sophie");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
    expect(existsSync(path.join(target, "keys"))).toBe(false);
    expect(statSync(target).mode & 0o777).toBe(0o755);
  });

  it("refuses to read keys through a symlinked keys directory", async () => {
    const real = path.join(h.home, "real-keys");
    mkdirSync(real, { mode: 0o700 });
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(path.join(real, `${inv("sophie")}.key`), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
    mkdirSync(path.join(h.home, ".zipviz"), { mode: 0o700 });
    symlinkSync(real, keysDir());
    expect((await h.cliJson("whoami")).body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
    expect((await h.cliJson("verify", inv("sophie"))).body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
    expect(h.registry.requests).toHaveLength(0);
  });

  it("refuses a symlinked key file", async () => {
    await h.cli("keygen", "--name", "real");
    symlinkSync(keyPath(inv("real")), keyPath(inv("link")));
    const r = await h.cliJson("invite", "create", inv("link"));
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/symlink.*ELOOP/) } });
  });

  it.skipIf(process.getuid?.() === 0)("reports the real open error (EACCES) for an unreadable key", async () => {
    await h.cli("keygen", "--name", "sophie");
    chmodSync(keyPath(inv("sophie")), 0o000);
    const r = await h.cliJson("invite", "create", inv("sophie"));
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNREADABLE", message: expect.stringMatching(/EACCES/) } });
  });

  it("verify of another agent's name never touches the local key store", async () => {
    const real = path.join(h.home, "real-keys");
    mkdirSync(real, { mode: 0o755 });
    mkdirSync(path.join(h.home, ".zipviz"), { mode: 0o700 });
    symlinkSync(real, keysDir());
    h.registry.addAgent("gary.yc.viz", "ab".repeat(32));
    const r = await h.cliJson("verify", "gary.yc.viz");
    expect(r.code).toBe(0);
    expect(r.body).toMatchObject({ ok: true, local_key: false, signature_verified: null });
  });

  it("refuses a keys directory readable by group or others", async () => {
    await h.cli("keygen", "--name", "sophie");
    chmodSync(keysDir(), 0o755);
    const r = await h.cliJson("whoami");
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/chmod 700/) } });
  });

  it("refuses a ~/.zipviz writable by group or others", async () => {
    await h.cli("keygen", "--name", "sophie");
    chmodSync(path.join(h.home, ".zipviz"), 0o770);
    const r = await h.cliJson("invite", "create", inv("sophie"));
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
  });

  it("refuses a keys path that is a regular file", async () => {
    mkdirSync(path.join(h.home, ".zipviz"), { mode: 0o700 });
    writeFileSync(keysDir(), "not a dir");
    expect((await h.cliJson("whoami")).body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE" } });
  });

  it.runIf(process.getuid?.() === 0)("refuses a keys directory owned by another user", async () => {
    await h.cli("keygen", "--name", "sophie");
    chownSync(keysDir(), 1234, 1234);
    const r = await h.cliJson("whoami");
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_UNSAFE", message: expect.stringMatching(/not owned/) } });
  });
});

describe("invite create|revoke", () => {
  it("--execute refuses registry origins other than the default or localhost", async () => {
    installOwnerKey("stu.smc.viz");
    for (const api of ["https://evil.example", "https://api.zipviz.ai.evil.example", "https://staging.zipviz.ai"]) {
      for (const args of [["create", "stu.smc.viz"], ["revoke", "stu.smc.viz", "--invite-id", "11b8aeb5-3233-493f-8a78-7d00be5373fe"]]) {
        const r = await h.cliJson("--api", api, "invite", ...args, "--execute");
        expect(r.code).toBe(2);
        expect(r.body).toMatchObject({ ok: false, error: { code: "E_API_NOT_ALLOWED" } });
      }
    }
    expect(h.registry.requests).toHaveLength(0);
    expect((await h.cliJson("--api", "https://evil.example", "invite", "create", "stu.smc.viz")).body).toMatchObject({ ok: true, dry_run: true });
    for (const api of ["http://localhost:8787", "http://127.0.0.1:8787", "https://api.zipviz.ai"]) {
      expect((await h.cliJson("--api", api, "invite", "create", "stu.smc.viz", "--execute")).body).toMatchObject({ ok: true, dry_run: false });
    }
  });

  it("dry-runs by default: signs locally and sends nothing", async () => {
    installOwnerKey("stu.smc.viz");
    const r = await h.cliJson("invite", "create", "stu.smc.viz");
    expect(r.code).toBe(0);
    expect(r.body).toEqual({ ok: true, command: "invite create", dry_run: true, aud: "api.zipviz.ai", issuer: "stu.smc.viz", ttl_seconds: 86400 });
    expect(h.registry.requests).toHaveLength(0);
  });

  it("--execute preflights the card key, then posts the signed envelope", async () => {
    installOwnerKey("stu.smc.viz");
    const r = await h.cliJson("invite", "create", "stu.smc.viz", "--ttl", "600", "--execute");
    expect(r.code).toBe(0);
    expect(r.body).toMatchObject({ ok: true, dry_run: false, issuer: "stu.smc.viz", namespace: INVITE_NAMESPACE, mints: `<name>.${INVITE_NAMESPACE}.viz` });
    expect(r.body.code).toMatch(/^zvi_[A-Za-z0-9_-]{43}$/);
    const [card, post] = h.registry.requests;
    expect(card!.url).toBe("https://api.zipviz.ai/v1/agent/stu.smc.viz/card");
    expect(post!.url).toBe("https://api.zipviz.ai/v1/agent-invites");
    const env = JSON.parse(post!.body!);
    expect(Object.keys(env)).toEqual(["v", "op", "aud", "issuer", "ttl_seconds", "timestamp", "nonce", "signature"]);
    expect(env).toMatchObject({ v: 1, op: "agent_invite.issue", aud: "api.zipviz.ai", issuer: "stu.smc.viz", ttl_seconds: 600 });

    const rv = await h.cliJson("invite", "revoke", "stu.smc.viz", "--invite-id", r.body.invite_id as string, "--execute");
    expect(rv.body).toMatchObject({ ok: true, command: "invite revoke", invite_id: r.body.invite_id });
    const revokeEnv = JSON.parse(h.registry.requests.at(-1)!.body!);
    expect(Object.keys(revokeEnv)).toEqual(["v", "op", "aud", "issuer", "invite_id", "timestamp", "nonce", "signature"]);
    expect(revokeEnv).toMatchObject({ op: "agent_invite.revoke", aud: "api.zipviz.ai" });
  });

  it("derives aud from the --api host (with port) and shows it in the dry run", async () => {
    installOwnerKey("stu.smc.viz");
    const cases: Array<[string, string]> = [
      ["https://api.zipviz.ai", "api.zipviz.ai"],
      ["http://127.0.0.1:8787", "127.0.0.1:8787"],
      ["http://localhost:8787", "localhost:8787"],
      ["https://staging.example:8443", "staging.example:8443"],
    ];
    for (const [api, aud] of cases) {
      const r = await h.cliJson("--api", api, "invite", "create", "stu.smc.viz");
      expect(r.body).toMatchObject({ ok: true, dry_run: true, aud });
    }
    const human = await h.cli("--api", "http://127.0.0.1:8787", "invite", "create", "stu.smc.viz");
    expect(human.out).toMatch(/aud 127\.0\.0\.1:8787/);
    expect(h.registry.requests).toHaveLength(0);
  });

  it("--aud overrides the derived audience and is signed into the envelope", async () => {
    installOwnerKey("stu.smc.viz");
    h.registry.audience = "zipviz-local";
    const r = await h.cliJson("--api", "http://127.0.0.1:8787", "invite", "create", "stu.smc.viz", "--aud", "zipviz-local", "--execute");
    expect(r.body).toMatchObject({ ok: true, dry_run: false, aud: "zipviz-local" });
    expect(JSON.parse(h.registry.requests.at(-1)!.body!).aud).toBe("zipviz-local");
    for (const bad of ["", "Has Space", "https://api.zipviz.ai", "a/b", "x".repeat(300)]) {
      expect((await h.cliJson("invite", "create", "stu.smc.viz", "--aud", bad)).code).toBe(2);
    }
  });

  it("hints that a registry rejecting the envelope shape may predate aud (E_INVITE_SHAPE)", async () => {
    installOwnerKey("stu.smc.viz");
    h.registry.predatesAudience = true;
    const hint = /invalid invite envelope.*registry may predate audience binding \(aud\)/;
    const c = await h.cliJson("invite", "create", "stu.smc.viz", "--execute");
    expect(c.code).toBe(1);
    expect(c.body).toMatchObject({ ok: false, error: { code: "E_INVITE_SHAPE", http_status: 400, message: expect.stringMatching(hint) } });
    const r = await h.cliJson("invite", "revoke", "stu.smc.viz", "--invite-id", "0fe4e558-e43c-4e46-b4ad-7cc15a61d1da", "--execute");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_INVITE_SHAPE", http_status: 400, message: expect.stringMatching(hint) } });
  });

  it("explains a registry audience mismatch (E_INVITE_AUD)", async () => {
    installOwnerKey("stu.smc.viz");
    h.registry.audience = "api.zipviz.ai";
    const r = await h.cliJson("--api", "http://127.0.0.1:8787", "invite", "create", "stu.smc.viz", "--execute");
    expect(r.code).toBe(1);
    expect(r.body).toMatchObject({
      ok: false,
      error: { code: "E_INVITE_AUD", http_status: 401, message: expect.stringMatching(/audience.*127\.0\.0\.1:8787.*--aud/) },
    });
  });

  it("refuses to send when the local key does not match the registered owner key", async () => {
    installOwnerKey("stu.smc.viz");
    h.registry.addAgent("stu.smc.viz", "ab".repeat(32));
    const r = await h.cliJson("invite", "create", "stu.smc.viz", "--execute");
    expect(r.body).toMatchObject({ ok: false, error: { code: "E_KEY_MISMATCH" } });
    expect(h.registry.requests.map((q) => q.method)).toEqual(["GET"]);
  });

  it("reports disabled invites plainly", async () => {
    installOwnerKey("stu.smc.viz");
    h.registry.invitesEnabled = false;
    const r = await h.cliJson("invite", "create", "stu.smc.viz", "--execute");
    expect(r.body).toEqual({
      ok: false,
      command: "invite create",
      error: { code: "E_INVITES_DISABLED", message: "invites are not enabled on this registry" },
    });
  });

  it("validates --ttl, --invite-id and the issuer domain", async () => {
    installOwnerKey("stu.smc.viz");
    expect((await h.cliJson("invite", "create", "stu.smc.viz", "--ttl", "10")).code).toBe(2);
    expect((await h.cliJson("invite", "revoke", "stu.smc.viz")).code).toBe(2);
    expect((await h.cliJson("invite", "revoke", "stu.smc.viz", "--invite-id", "x")).code).toBe(2);
    expect((await h.cliJson("invite", "revoke", "stu.smc.viz", "--invite-id", "00000000-0000-0000-0000-000000000000", "--ttl", "600")).code).toBe(2);
    expect((await h.cliJson("invite", "create", "not-a-domain")).code).toBe(2);
    expect((await h.cliJson("invite", "create", "nokey.smc.viz")).body).toMatchObject({ error: { code: "E_NO_KEY" } });
  });
});
