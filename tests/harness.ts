import { createPublicKey, randomUUID, verify as edVerify } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { run, type Deps } from "../src/main.js";
import { INVITE_NAMESPACE } from "../src/viz.js";

export type RecordedRequest = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
};

type RegistryAgent = {
  public_key: string;
  url: string | null;
  created: string;
  agent_conversations?: { capability_uri: string; envelope_version: string };
};

const SERVICE_DOCUMENT = {
  service: "ZipViz Agent Registry",
  version: "2.3.0",
  endpoints: ["/v1/register", "/v1/agent/:domain", "/v1/verify"],
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export function spkiToHex(key: Parameters<typeof createPublicKey>[0]): string {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}

function rawKeyObject(hex: string) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

/** In-memory stand-in for the registry worker's public + invite routes. */
export class FakeRegistry {
  agents = new Map<string, RegistryAgent>();
  invitesEnabled = true;
  /** Mirrors AGENT_INVITE_AUDIENCE; null = accept the host the request was sent to. */
  audience: string | null = null;
  /** Older registry: exact-key envelope check, so any `aud` is an unknown key. */
  predatesAudience = false;
  issuers = new Set<string>();
  codes = new Map<string, { id: string; issuer: string; used: boolean; revoked: boolean }>();
  reserved = new Set(["admin", "root", "support", "z", "zip", "zipviz", "verify"]);
  /** The registry assigns the four digits. Sequential here so tests can predict them. */
  nextDigits = 1000;
  assignDigits = (): string => String(this.nextDigits++).padStart(4, "0");
  /** Older registry: mints the bare <name>.<ns>.viz and answers a clash with E_DUPLICATE. */
  predatesAssignedDigits = false;
  requests: RecordedRequest[] = [];

  addAgent(domain: string, publicKeyHex: string, extra: Partial<RegistryAgent> = {}) {
    this.agents.set(domain, {
      public_key: publicKeyHex,
      url: null,
      created: "2026-09-01T00:00:00.000Z",
      ...extra,
    });
  }

  mintCode(issuer: string): string {
    const code = `zvi_${randomUUID().replace(/-/g, "")}${"A".repeat(11)}`;
    this.codes.set(code, { id: randomUUID(), issuer, used: false, revoked: false });
    return code;
  }

  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    const body = typeof init?.body === "string" ? init.body : null;
    this.requests.push({ method, url: url.toString(), headers, body });
    const p = url.pathname;

    const card = p.match(/^\/v1\/agent\/([^/]+)\/card$/);
    if (method === "GET" && card) {
      const domain = decodeURIComponent(card[1]!);
      const a = this.agents.get(domain);
      if (!a) return json({ error: "Agent not found" }, 404);
      const out: Record<string, unknown> = {
        name: domain,
        description: "ExampleAgent verified identity",
        url: a.url,
        capabilities: [],
        authentication: { schemes: ["ed25519"] },
        public_key: a.public_key,
        protocols: ["a2a"],
        created: a.created,
      };
      if (a.agent_conversations) out.agent_conversations = a.agent_conversations;
      return json(out);
    }

    if (method === "POST" && p === "/v1/verify") {
      const b = JSON.parse(body ?? "{}");
      const a = this.agents.get(b.from);
      if (!a) return json({ verified: false, error: "agent not found", code: "E_AGENT_NOT_FOUND" }, 404);
      const payload = Buffer.from(JSON.stringify({ v: 1, from: b.from, message: b.message, timestamp: b.timestamp }));
      const ok = edVerify(null, payload, rawKeyObject(a.public_key), Buffer.from(b.signature, "base64"));
      return ok
        ? json({ verified: true, identity: b.from, signing_version: 1, freshness_checked: true, reputation: null, blue_tick: null })
        : json({ verified: false, error: "signature mismatch", code: "E_SIG_MISMATCH" });
    }

    if (method === "POST" && p.startsWith("/v1/agent-invites")) {
      if (!this.invitesEnabled) return json(SERVICE_DOCUMENT);
      const b = JSON.parse(body ?? "{}");
      if (p === "/v1/agent-invites/redeem") {
        const inv = this.codes.get(b.code);
        if (!inv || inv.used || inv.revoked) return json({ error: "invite code is invalid", code: "E_INVITE_INVALID" }, 404);
        if (typeof b.name !== "string" || b.name.length > 15 || /-[0-9]{4}$/.test(b.name)) {
          return json({ error: "invalid name", code: "E_NAME_FORMAT" }, 400);
        }
        if (this.reserved.has(b.name)) return json({ error: "name is reserved", code: "E_NAME_RESERVED" }, 409);
        if (this.predatesAssignedDigits) {
          // Older registry: mints the bare <name>.<ns>.viz and refuses a clash.
          const bare = `${b.name}.${INVITE_NAMESPACE}.viz`;
          if (this.agents.has(bare)) return json({ error: "agent already registered", code: "E_DUPLICATE" }, 409);
          inv.used = true;
          this.addAgent(bare, b.public_key);
          return json({ domain: bare, name: b.name, namespace: INVITE_NAMESPACE, public_key: b.public_key, status: "registered" }, 201);
        }
        let label: string | null = null;
        for (let attempt = 0; attempt < 5 && label === null; attempt += 1) {
          const candidate = `${b.name}-${this.assignDigits()}`;
          if (!this.agents.has(`${candidate}.${INVITE_NAMESPACE}.viz`)) label = candidate;
        }
        if (label === null) return json({ error: "could not assign a name", code: "E_NAME_EXHAUSTED" }, 409);
        const domain = `${label}.${INVITE_NAMESPACE}.viz`;
        inv.used = true;
        this.addAgent(domain, b.public_key);
        return json({ domain, name: label, namespace: INVITE_NAMESPACE, public_key: b.public_key, status: "registered" }, 201);
      }
      if (this.predatesAudience && "aud" in b) {
        return json({ error: "invalid invite envelope", code: "E_INVITE_SHAPE" }, 400);
      }
      if (typeof b.aud !== "string" || b.aud !== (this.audience ?? url.host)) {
        return json({ error: "invalid invite audience", code: "E_INVITE_AUD" }, 401);
      }
      const { signature, ...unsigned } = b;
      const issuer = this.agents.get(b.issuer);
      const sigOk = issuer
        && edVerify(null, Buffer.from(JSON.stringify(unsigned)), rawKeyObject(issuer.public_key), Buffer.from(signature, "hex"));
      if (p === "/v1/agent-invites") {
        if (!sigOk || !this.issuers.has(b.issuer)) return json({ error: "invite request not authorized", code: "E_INVITE_AUTH" }, 403);
        const code = this.mintCode(b.issuer);
        return json({
          code,
          invite_id: this.codes.get(code)!.id,
          namespace: INVITE_NAMESPACE,
          expires_at: new Date(Date.now() + b.ttl_seconds * 1000).toISOString(),
        }, 201);
      }
      if (p === "/v1/agent-invites/revoke") {
        if (!sigOk) return json({ error: "invite request not authorized", code: "E_INVITE_AUTH" }, 403);
        const entry = [...this.codes.values()].find((c) => c.id === b.invite_id && c.issuer === b.issuer);
        if (!entry) return json({ error: "invite not found", code: "E_INVITE_NOT_FOUND" }, 404);
        if (entry.used) return json({ error: "invite already used", code: "E_INVITE_USED" }, 409);
        entry.revoked = true;
        return json({ invite_id: b.invite_id, status: "revoked", revoked_at: new Date().toISOString() });
      }
    }
    return json(SERVICE_DOCUMENT);
  };
}

export type Harness = {
  home: string;
  registry: FakeRegistry;
  stdout: string[];
  stderr: string[];
  cli: (...argv: string[]) => Promise<{ code: number; out: string; err: string }>;
  cliJson: (...argv: string[]) => Promise<{ code: number; body: Record<string, unknown> }>;
  cleanup: () => void;
};

export function makeHarness(): Harness {
  const home = mkdtempSync(path.join(tmpdir(), "zipviz-cli-test-"));
  const registry = new FakeRegistry();
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: (input, init) => registry.fetch(input, init),
    stdout: (s) => stdout.push(s),
    stderr: (s) => stderr.push(s),
    zipvizHome: path.join(home, ".zipviz"),
  };
  const cli = async (...argv: string[]) => {
    const o = stdout.length;
    const e = stderr.length;
    const code = await run(argv, deps);
    return { code, out: stdout.slice(o).join(""), err: stderr.slice(e).join("") };
  };
  const cliJson = async (...argv: string[]) => {
    const r = await cli(...argv, "--json");
    return { code: r.code, body: JSON.parse(r.out) as Record<string, unknown> };
  };
  return { home, registry, stdout, stderr, cli, cliJson, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}
