import { createPrivateKey } from "node:crypto";
import {
  chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync,
} from "node:fs";
import http from "node:http";
import type net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { clockCheck, DOCTOR_FAILED_EXIT, DOCTOR_UNKNOWN_EXIT } from "../src/doctor.js";
import { run, type Deps } from "../src/main.js";
import { makeHarness, type Harness } from "./harness.js";

const NOW = Date.parse("2026-10-07T12:00:00.000Z");
const httpDate = (ms: number) => new Date(ms).toUTCString();

type Reply = { status?: number; body?: unknown; date?: string | null; headers?: Record<string, string> } | "network-error";

type Call = { method: string; url: string; body: unknown };

/** Loosely typed view of the parsed --json output, for property assertions. */
type Check = { status: string; code: string | null; message: string; [k: string]: unknown } & {
  keys: Array<{ key_id: string; public_key: string | null; error: { code: string; message: string } | null }>;
  skew_ms: number | null;
  uncertainty_ms: number | null;
};
type CheckId = "key_store" | "registry" | "invites" | "clock";
type DoctorJson = Record<string, unknown> & { checks: Record<CheckId, Check>; summary: Record<string, number> };

let h: Harness | undefined;
afterEach(() => {
  h?.cleanup();
  h = undefined;
});

/** Run the CLI against the harness home with a scripted registry and a fixed local clock. */
function doctorRig(reply: Reply | ((url: string) => Reply), clock: () => number = () => NOW) {
  h ??= makeHarness();
  const calls: Call[] = [];
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: async (input, init) => {
      calls.push({ method: init?.method ?? "GET", url: String(input), body: init?.body ?? null });
      const r = typeof reply === "function" ? reply(String(input)) : reply;
      if (r === "network-error") throw new TypeError("fetch failed");
      const headers = new Headers({ "content-type": "application/json", ...(r.headers ?? {}) });
      const date = r.date === undefined ? httpDate(NOW) : r.date;
      if (date !== null) headers.set("date", date);
      return new Response(JSON.stringify(r.body ?? { status: "ok", timestamp: new Date(NOW).toISOString() }), {
        status: r.status ?? 200,
        headers,
      });
    },
    stdout: (s) => stdout.push(s),
    stderr: (s) => stderr.push(s),
    zipvizHome: path.join(h.home, ".zipviz"),
    now: clock,
  };
  const cli = async (...argv: string[]) => {
    const o = stdout.length;
    const e = stderr.length;
    const code = await run(argv, deps);
    return { code, out: stdout.slice(o).join(""), err: stderr.slice(e).join("") };
  };
  const json = async (...argv: string[]) => {
    const r = await cli(...argv, "--json");
    return { code: r.code, body: JSON.parse(r.out) as DoctorJson };
  };
  return { h, calls, stdout, stderr, cli, json };
}

const keysDir = () => path.join(h!.home, ".zipviz", "keys");

/** Every file and directory under root: type, mode, size, mtime and bytes. */
function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string) => {
    const st = lstatSync(p);
    const kind = st.isSymbolicLink() ? "link" : st.isDirectory() ? "dir" : "file";
    let content = "";
    if (kind === "file" && (st.mode & 0o400)) {
      try {
        content = readFileSync(p).toString("hex");
      } catch {
        content = "<unreadable>";
      }
    }
    out[path.relative(root, p) || "."] = `${kind} ${(st.mode & 0o7777).toString(8)} ${st.size} ${st.mtimeMs} ${content}`;
    if (kind === "dir" && (st.mode & 0o500) === 0o500) for (const n of readdirSync(p)) walk(path.join(p, n));
  };
  walk(root);
  return out;
}

function secretForms(pem: string): string[] {
  const jwk = createPrivateKey(pem).export({ format: "jwk" });
  const seed = Buffer.from(jwk.d!, "base64url");
  const der = createPrivateKey(pem).export({ format: "der", type: "pkcs8" });
  return [
    pem.trim(), pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), jwk.d!,
    seed.toString("hex"), seed.toString("base64"), der.toString("hex"), der.toString("base64"),
  ];
}

const CHECK_IDS: CheckId[] = ["key_store", "registry", "invites", "clock"];

describe("zipviz doctor: JSON shape and exit codes", () => {
  it("reports every check with a stable shape; invites stays unknown but is informational, so a healthy setup exits 0", async () => {
    const rig = doctorRig({});
    expect((await rig.h.cli("keygen", "--name", "sophie")).code).toBe(0);
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(0);
    expect(Object.keys(body)).toEqual(["ok", "command", "status", "api", "zipviz_home", "summary", "checks"]);
    expect(body).toMatchObject({
      ok: true, command: "doctor", status: "ok", api: "https://api.zipviz.ai",
      zipviz_home: path.join(rig.h.home, ".zipviz"),
      summary: { ok: 3, failed: 0, unknown: 1 },
    });
    expect(Object.keys(body.checks)).toEqual(CHECK_IDS);
    for (const id of CHECK_IDS) {
      expect(Object.keys(body.checks[id]).slice(0, 3)).toEqual(["status", "code", "message"]);
      expect(["ok", "failed", "unknown"]).toContain(body.checks[id].status);
      expect(body.checks[id].code === null).toBe(body.checks[id].status === "ok");
    }
    expect(body.checks.key_store).toMatchObject({ status: "ok", keys: [{ key_id: "sophie.z.viz", error: null }] });
    expect(body.checks.key_store!.keys[0]!.public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(body.checks.registry).toMatchObject({ status: "ok", http_status: 200, endpoint: "GET /v1/health" });
    expect(body.checks.invites).toEqual({
      status: "unknown", code: "DOCTOR_INVITES_NO_SIGNAL", message: expect.any(String), invites_enabled: null,
    });
    expect(body.checks.clock).toMatchObject({ status: "ok", window_ms: 300_000 });
  });

  it("prints one line per check and a result line; the unknown invites check is labelled informational", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "sophie");
    const r = await rig.cli("doctor");
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/^\[ok\] +key store /m);
    expect(r.out).toMatch(/^\[ok\] +registry /m);
    expect(r.out).toMatch(/^\[unknown\] +invites /m);
    expect(r.out).toMatch(/^\[ok\] +clock .*does not verify any signature/m);
    expect(r.out).toMatch(/^result: ok: 3 ok, 0 failed, 1 unknown \(invites is informational until the registry has a read-only signal\)$/m);
  });

  it("still exits 12 and says unknown is not healthy when a counted check is unknown", async () => {
    const rig = doctorRig("network-error");
    await rig.h.cli("keygen", "--name", "sophie");
    const r = await rig.cli("doctor");
    expect(r.code).toBe(DOCTOR_UNKNOWN_EXIT);
    expect(r.out).toMatch(/^result: unknown: 1 ok, 0 failed, 3 unknown \(unknown is not healthy/m);
  });

  it("exits 11 when any check failed, even if others are unknown, and reports ok:false", async () => {
    const rig = doctorRig("network-error");
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_FAILED_EXIT);
    expect(body.ok).toBe(false);
    expect(body.status).toBe("failed");
    expect(body.summary).toEqual({ ok: 0, failed: 1, unknown: 3 });
  });

  it("rejects positional arguments as a usage error and honours --api", async () => {
    const rig = doctorRig({});
    expect((await rig.cli("doctor", "extra")).code).toBe(2);
    const { body } = await rig.json("doctor", "--api", "http://127.0.0.1:8787");
    expect(body.api).toBe("http://127.0.0.1:8787");
    expect(rig.calls.at(-1)!.url).toBe("http://127.0.0.1:8787/v1/health");
  });

  it("is listed in --help with its exit codes, alongside backup", async () => {
    const rig = doctorRig({});
    const r = await rig.cli("--help");
    expect(r.out).toContain("zipviz doctor");
    expect(r.out).toContain("zipviz backup");
    expect(r.out).toMatch(/11 a check failed,\s+12 none failed but/);
  });
});

describe("zipviz doctor: key store", () => {
  it("diagnoses a missing ~/.zipviz without creating it, and still runs the remote checks", async () => {
    const rig = doctorRig({});
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_FAILED_EXIT);
    expect(body.checks.key_store).toMatchObject({ status: "failed", code: "DOCTOR_KEY_STORE_MISSING", keys: [] });
    expect(body.checks.registry.status).toBe("ok");
    expect(body.checks.clock.status).toBe("ok");
    expect(() => lstatSync(path.join(rig.h.home, ".zipviz"))).toThrow();
  });

  it("diagnoses a missing keys directory and an empty one separately", async () => {
    const rig = doctorRig({});
    mkdirSync(path.join(rig.h.home, ".zipviz"), { mode: 0o700 });
    expect((await rig.json("doctor")).body.checks.key_store.code).toBe("DOCTOR_KEY_STORE_MISSING");
    mkdirSync(keysDir(), { mode: 0o700 });
    expect((await rig.json("doctor")).body.checks.key_store.code).toBe("DOCTOR_NO_KEYS");
  });

  it("flags a permissive keys directory as unsafe and does not chmod it", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "sophie");
    chmodSync(keysDir(), 0o755);
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_FAILED_EXIT);
    expect(body.checks.key_store).toMatchObject({ status: "failed", code: "E_KEY_UNSAFE" });
    expect(body.checks.key_store.message).toMatch(/too permissive/);
    expect(lstatSync(keysDir()).mode & 0o777).toBe(0o755);
  });

  it("flags a group-writable ~/.zipviz as unsafe", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "sophie");
    chmodSync(path.join(rig.h.home, ".zipviz"), 0o770);
    const { body } = await rig.json("doctor");
    expect(body.checks.key_store).toMatchObject({ status: "failed", code: "E_KEY_UNSAFE" });
  });

  it("refuses a symlinked keys directory without following it", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "sophie");
    const elsewhere = path.join(rig.h.home, "elsewhere");
    renameSync(keysDir(), elsewhere);
    symlinkSync(elsewhere, keysDir());
    const { body } = await rig.json("doctor");
    expect(body.checks.key_store).toMatchObject({ status: "failed", code: "E_KEY_UNSAFE", keys: [] });
    expect(body.checks.key_store.message).toMatch(/not a symlink/);
  });

  it("reports each unsafe key file (symlink, group-readable) while still listing the safe ones", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "alpha");
    await rig.h.cli("keygen", "--name", "bravo");
    await rig.h.cli("keygen", "--name", "charlie");
    chmodSync(path.join(keysDir(), "bravo.z.viz.key"), 0o640);
    const target = path.join(rig.h.home, "outside.key");
    renameSync(path.join(keysDir(), "charlie.z.viz.key"), target);
    symlinkSync(target, path.join(keysDir(), "charlie.z.viz.key"));
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_FAILED_EXIT);
    const ks = body.checks.key_store;
    expect(ks).toMatchObject({ status: "failed", code: "E_KEY_UNSAFE", message: "2 of 3 key file(s) failed safety checks" });
    expect(ks.keys.map((k) => [k.key_id, k.error?.code ?? null])).toEqual([
      ["alpha.z.viz", null], ["bravo.z.viz", "E_KEY_UNSAFE"], ["charlie.z.viz", "E_KEY_UNSAFE"],
    ]);
    expect(ks.keys[1]!.public_key).toBeNull();
    expect(ks.keys[2]!.error!.message).toMatch(/symlink/);
    expect(lstatSync(path.join(keysDir(), "bravo.z.viz.key")).mode & 0o777).toBe(0o640);
    const human = await rig.cli("doctor");
    expect(human.out).toMatch(/bravo\.z\.viz {2}UNSAFE: .*must not be readable by group or others/);
  });

  it("never discloses private key material in any output or request", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "alpha");
    await rig.h.cli("keygen");
    await rig.h.cli("keygen", "--name", "bravo");
    chmodSync(path.join(keysDir(), "bravo.z.viz.key"), 0o644);
    const secrets = ["alpha.z.viz.key", "default.key", "bravo.z.viz.key"]
      .flatMap((f) => secretForms(readFileSync(path.join(keysDir(), f), "utf8")));
    await rig.cli("doctor");
    await rig.cli("doctor", "--json");
    await rig.cli("backup");
    await rig.cli("backup", "--json");
    chmodSync(keysDir(), 0o755);
    await rig.cli("doctor");
    await rig.cli("doctor", "--json");
    const haystack = [...rig.stdout, ...rig.stderr, ...rig.calls.map((c) => `${c.url} ${String(c.body)}`)].join("\n");
    expect(haystack).not.toMatch(/PRIVATE KEY/);
    for (const s of secrets) expect(haystack.includes(s)).toBe(false);
  });

  it("never looks outside the configured home", async () => {
    const rig = doctorRig({});
    const custom = mkdtempSync(path.join(tmpdir(), "zipviz-doctor-custom-"));
    try {
      const deps: Deps = {
        fetch: async () => new Response(JSON.stringify({ status: "ok" }), { headers: { date: httpDate(NOW) } }),
        stdout: (s) => rig.stdout.push(s), stderr: (s) => rig.stderr.push(s),
        zipvizHome: path.join(custom, "zv"), now: () => NOW,
      };
      await rig.h.cli("keygen", "--name", "sophie");
      await run(["doctor", "--json"], deps);
      const body = JSON.parse(rig.stdout.at(-1)!);
      expect(body.zipviz_home).toBe(path.join(custom, "zv"));
      expect(body.checks.key_store.code).toBe("DOCTOR_KEY_STORE_MISSING");
      expect(JSON.stringify(body)).not.toContain(rig.h.home);
    } finally {
      rmSync(custom, { recursive: true, force: true });
    }
  });
});

describe("zipviz doctor: read-only", () => {
  it("changes nothing on disk and sends exactly one GET /v1/health, even with invites off", async () => {
    const rig = doctorRig({});
    await rig.h.cli("keygen", "--name", "sophie");
    await rig.h.cli("keygen");
    chmodSync(path.join(keysDir(), "default.key"), 0o644);
    rig.h.registry.invitesEnabled = false;
    const before = snapshot(rig.h.home);
    await rig.cli("doctor");
    await rig.cli("doctor", "--json");
    expect(snapshot(rig.h.home)).toEqual(before);
    expect(rig.calls).toEqual([
      { method: "GET", url: "https://api.zipviz.ai/v1/health", body: null },
      { method: "GET", url: "https://api.zipviz.ai/v1/health", body: null },
    ]);
  });
});

describe("zipviz doctor: registry", () => {
  it("reports an unreachable registry as unknown (never ok), with clock unknown too", async () => {
    const rig = doctorRig("network-error");
    await rig.h.cli("keygen", "--name", "sophie");
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_UNKNOWN_EXIT);
    expect(body.checks.key_store.status).toBe("ok");
    expect(body.checks.registry).toMatchObject({ status: "unknown", code: "DOCTOR_REGISTRY_UNREACHABLE", http_status: null });
    expect(body.checks.clock).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_UNREACHABLE", skew_ms: null });
    expect(body.checks.invites.status).toBe("unknown");
  });

  it("fails on a registry 5xx and escapes registry-supplied text in human output", async () => {
    const rig = doctorRig({ status: 503, body: { error: "db\u001b[31m down", code: "E_NO_HYPERDRIVE\u001b]0;pwn\u0007" } });
    const { code, body } = await rig.json("doctor");
    expect(code).toBe(DOCTOR_FAILED_EXIT);
    expect(body.checks.registry).toMatchObject({
      status: "failed", code: "DOCTOR_REGISTRY_ERROR", http_status: 503, registry_message: "db\u001b[31m down",
    });
    const human = await rig.cli("doctor");
    expect(["\u001b", "\u0007"].some((control) => human.out.includes(control))).toBe(false);
    expect(human.out).toContain("E_NO_HYPERDRIVE\\x1b]0;pwn\\x07");
  });

  it("treats a 200 that is not a health response (older registry, service document) as unknown", async () => {
    const rig = doctorRig({ body: { service: "ZipViz Agent Registry", version: "2.3.0", endpoints: [] } });
    const { body } = await rig.json("doctor");
    expect(body.checks.registry).toMatchObject({ status: "unknown", code: "DOCTOR_REGISTRY_UNEXPECTED", http_status: 200 });
    expect(body.checks.clock.status).toBe("ok");
  });

  it("does not follow redirects", async () => {
    const rig = doctorRig({ status: 302, headers: { location: "https://elsewhere.example/v1/health" } });
    const { body } = await rig.json("doctor");
    expect(body.checks.registry).toMatchObject({ status: "unknown", http_status: 302 });
    expect(rig.calls).toHaveLength(1);
  });

  it("treats an oversized or non-JSON body as not healthy", async () => {
    const rig = doctorRig({ body: { status: "ok", pad: "x".repeat(20_000) } });
    expect((await rig.json("doctor")).body.checks.registry.status).toBe("unknown");
  });
});

describe("zipviz doctor: invites", () => {
  it("is unknown whether invites are on or off, and never probes the invite routes", async () => {
    for (const enabled of [true, false]) {
      const rig = doctorRig({});
      rig.h.registry.invitesEnabled = enabled;
      const { body } = await rig.json("doctor");
      expect(body.checks.invites).toMatchObject({ status: "unknown", invites_enabled: null });
      expect(rig.calls.every((c) => c.method === "GET" && !c.url.includes("agent-invites"))).toBe(true);
    }
  });
});

describe("zipviz doctor: clock skew", () => {
  const at = async (skewMs: number, opts: { date?: string | null; elapsed?: number } = {}) => {
    let t = NOW;
    const rig = doctorRig({ date: opts.date === undefined ? httpDate(NOW + skewMs) : opts.date }, () => {
      const v = t;
      t += opts.elapsed ?? 0;
      return v;
    });
    const r = await rig.json("doctor");
    return r.body.checks.clock;
  };

  it("is ok for small skew in either direction", async () => {
    expect(await at(0)).toMatchObject({ status: "ok", code: null });
    expect(await at(90_000)).toMatchObject({ status: "ok", skew_ms: expect.any(Number) });
    expect((await at(-90_000)).skew_ms).toBeLessThan(0);
  });

  it("fails beyond the ±5 minute window and says which way", async () => {
    const ahead = await at(-10 * 60_000);
    expect(ahead).toMatchObject({ status: "failed", code: "DOCTOR_CLOCK_SKEW" });
    expect(ahead.message).toMatch(/about 10m 0s ahead of the registry.*outside the ±5 minute/);
    const behind = await at(7 * 60_000);
    expect(behind.message).toMatch(/behind the registry.*outside/);
  });

  it("fails within one minute of the window edge (request time and drift)", async () => {
    const edge = await at(4 * 60_000 + 30_000);
    expect(edge).toMatchObject({ status: "failed", code: "DOCTOR_CLOCK_SKEW" });
    expect(edge.message).toMatch(/within 1 minute of the ±5 minute/);
  });

  it("is unknown when the Date header is missing or unparseable", async () => {
    expect(await at(0, { date: null })).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_NO_DATE", skew_ms: null });
    expect(await at(0, { date: "yesterday-ish" })).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_NO_DATE" });
  });

  it("is unknown when the request took too long to tell", async () => {
    // Server says +4m; the reply took 2 minutes, so the true skew could be anywhere from +2m to +4m.
    const slow = await at(4 * 60_000, { elapsed: 120_000 });
    expect(slow).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_AMBIGUOUS" });
    expect(slow.uncertainty_ms).toBeGreaterThan(60_000);
  });

  it("accounts for the one-second Date resolution and request timing in the bounds", () => {
    const c = clockCheck({ reached: true, status: 200, body: null, date: httpDate(NOW), sentAt: NOW - 200, receivedAt: NOW + 200 });
    expect(c.skew_ms).toBe(500);
    expect(c.uncertainty_ms).toBe(700);
    expect(c.message).toMatch(/does not verify any signature/);
  });
});

describe("zipviz doctor: real HTTP against a local registry", () => {
  it("reads the Date header from a live local server", async () => {
    h = makeHarness();
    const seen: string[] = [];
    const server = http.createServer((req, res) => {
      seen.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "application/json", date: httpDate(Date.now() - 8 * 60_000) });
      res.end(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const port = (server.address() as net.AddressInfo).port;
      await h.cli("keygen", "--name", "sophie");
      h.registry.fetch = (input, init) => fetch(input, init);
      const r = await h.cliJson("doctor", "--api", `http://127.0.0.1:${port}`);
      expect(r.code).toBe(DOCTOR_FAILED_EXIT);
      expect(r.body.checks).toMatchObject({
        key_store: { status: "ok" }, registry: { status: "ok" }, clock: { status: "failed", code: "DOCTOR_CLOCK_SKEW" },
      });
      expect(seen).toEqual(["GET /v1/health"]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("does not follow a real redirect, even to a healthy-looking endpoint", async () => {
    h = makeHarness();
    const seen: string[] = [];
    const server = http.createServer((req, res) => {
      seen.push(`${req.method} ${req.url}`);
      if (req.url === "/v1/health") res.writeHead(302, { location: "/elsewhere" }).end();
      else res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "ok" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const port = (server.address() as net.AddressInfo).port;
      h.registry.fetch = (input, init) => fetch(input, init);
      const r = await h.cliJson("doctor", "--api", `http://127.0.0.1:${port}`);
      expect((r.body.checks as Record<CheckId, Check>).registry).toMatchObject({ status: "unknown", http_status: 302 });
      expect(seen).toEqual(["GET /v1/health"]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
