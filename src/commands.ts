import { randomUUID } from "node:crypto";
import { Api, DEFAULT_API, disabledError, isInvitesDisabled, registryError } from "./api.js";
import { flagValue, type Parsed } from "./args.js";
import { CliError, usageError } from "./errors.js";
import { DEFAULT_KEY_ID, isValidKeyId, KeyStore, type LocalKey } from "./keys.js";
import type { Result } from "./output.js";
import {
  asciiLower, assignedInviteDomainRe, INVITE_ASSIGNED_SUFFIX_RE, INVITE_CHOSEN_NAME_MAX,
  INVITE_CODE_RE, INVITE_ID_RE, INVITE_LABEL_RE, INVITE_NAMESPACE, inviteDomain, inviteLabelOf,
  isValidVizAgentDomain, PUBLIC_KEY_HEX_RE,
} from "./viz.js";

export type Context = { api: Api; keys: KeyStore; parsed: Parsed };

/** whoami listed some keys but skipped at least one unsafe or unreadable key. */
const WHOAMI_PARTIAL_EXIT = 3;
const TTL_DEFAULT = 86_400;
const TTL_MIN = 300;
const TTL_MAX = 1_209_600;

function onlyPositional(p: Parsed, count: number, usage: string): string[] {
  if (p.positional.length !== count) throw usageError(`usage: ${usage}`);
  return p.positional;
}

/** `--name` for keygen: an invite label (→ <label>.<invite namespace>.viz) or a full .viz domain. */
function keyIdFromName(name: string | undefined): string {
  if (name === undefined) return DEFAULT_KEY_ID;
  const lower = asciiLower(name);
  if (INVITE_LABEL_RE.test(lower)) return inviteDomain(lower);
  if (isValidVizAgentDomain(lower)) return lower;
  throw usageError("--name must be a label (a-z, 0-9, '-', max 20) or a .viz domain");
}

function agentDomain(value: string): string {
  const lower = asciiLower(value);
  if (!isValidVizAgentDomain(lower)) throw usageError(`not a valid .viz agent name: ${value}`);
  return lower;
}

export async function keygen({ keys, parsed }: Context): Promise<Result> {
  onlyPositional(parsed, 0, "zipviz keygen [--name <label>] [--force]");
  const id = keyIdFromName(flagValue(parsed, "name"));
  const { path, publicKey } = await keys.generate(id, parsed.flags.has("force"));
  return {
    data: { key_id: id, key_path: path, public_key: publicKey },
    lines: [publicKey],
  };
}

export async function redeem({ api, keys, parsed }: Context): Promise<Result> {
  const [code] = onlyPositional(parsed, 1, "zipviz redeem <code> --name <chosen name>");
  const rawName = flagValue(parsed, "name");
  if (rawName === undefined) throw usageError("usage: zipviz redeem <code> --name <chosen name>");
  const name = asciiLower(rawName);
  // `--name` is the chosen part only; the registry appends the four digits.
  if (!INVITE_LABEL_RE.test(name) || name.length > INVITE_CHOSEN_NAME_MAX) {
    throw usageError(
      `--name must be a-z, 0-9 or '-', start with a letter or digit, max ${INVITE_CHOSEN_NAME_MAX}`
      + " (ZipViz appends -NNNN)",
    );
  }
  if (INVITE_ASSIGNED_SUFFIX_RE.test(name)) {
    throw usageError("--name must not end in a hyphen plus four digits: ZipViz assigns those");
  }
  if (!INVITE_CODE_RE.test(code!)) {
    throw new CliError("E_INVITE_FORMAT", "invite code must look like zvi_ followed by 43 characters");
  }
  // The key is chosen by local key id, never by a guess at the domain: the digits are
  // unknowable before the response, so nothing is predicted here.
  const namedKeyId = inviteDomain(name);
  const keyId = (await keys.exists(namedKeyId)) ? namedKeyId : DEFAULT_KEY_ID;
  if (!(await keys.exists(keyId))) {
    throw new CliError("E_NO_KEY", `no local key for ${name} (run: zipviz keygen --name ${name})`);
  }
  const key = await keys.load(keyId);

  const res = await api.post("/v1/agent-invites/redeem", { code, name, public_key: key.publicKey });
  if (isInvitesDisabled(res)) throw disabledError();
  if (res.status !== 201) {
    throw registryError(res, {
      E_INVITE_INVALID: "invite code is invalid, already used, revoked or expired",
      E_NAME_FORMAT: `the registry refused the name ${name}`,
      E_NAME_RESERVED: `${name} is reserved`,
      E_NAME_EXHAUSTED: "could not assign a name, please retry",
      // Kept for a registry that predates assigned digits and still mints <name>.<ns>.viz.
      E_DUPLICATE: `${namedKeyId} is already registered`,
      E_RATE_LIMITED: "too many attempts; try again later",
      E_AUTH_CONFIG: "invites are misconfigured on this registry",
    });
  }
  const b = res.body;
  const domain = typeof b?.domain === "string" ? b.domain : "";
  // Only the assigned form is accepted, so a registry answering with another name (or
  // the older bare domain) is refused rather than adopted.
  if (!assignedInviteDomainRe(name).test(domain) || b?.public_key !== key.publicKey) {
    throw new CliError(
      "E_UNEXPECTED_RESPONSE",
      `registry returned an unexpected redeem response (expected ${name}-NNNN.${INVITE_NAMESPACE}.viz)`,
      1,
      res.status,
    );
  }
  const label = inviteLabelOf(domain);
  const keyPath = keyId === domain ? key.path : await keys.adopt(keyId, domain);
  return {
    data: {
      domain,
      name: label,
      namespace: typeof b.namespace === "string" ? b.namespace : INVITE_NAMESPACE,
      public_key: key.publicKey,
      status: typeof b.status === "string" ? b.status : null,
      key_path: keyPath,
    },
    lines: [`registered ${domain}`, `public key ${key.publicKey}`, `key file   ${keyPath}`],
  };
}

/** Sign a fresh v1 /v1/verify envelope and ask the registry to check it. */
async function proveKey(api: Api, domain: string, key: LocalKey): Promise<boolean> {
  const message = `zipviz-cli key proof ${randomUUID()}`;
  const timestamp = new Date().toISOString();
  const signature = key.sign(JSON.stringify({ v: 1, from: domain, message, timestamp })).toString("base64");
  const res = await api.post("/v1/verify", { from: domain, message, timestamp, signature });
  return res.status === 200 && res.body?.verified === true;
}

async function localKeyFor(keys: KeyStore, domain: string): Promise<LocalKey | null> {
  return (await keys.exists(domain)) ? keys.load(domain) : null;
}

export async function verify({ api, keys, parsed }: Context): Promise<Result> {
  const [raw] = onlyPositional(parsed, 1, "zipviz verify <name>");
  const domain = agentDomain(raw!);
  const local = await localKeyFor(keys, domain);
  const card = await api.card(domain);
  if (!card) throw new CliError("E_NOT_REGISTERED", `${domain} is not registered`, 1, 404);
  const publicKey = typeof card.public_key === "string" ? card.public_key : null;
  if (!publicKey || !PUBLIC_KEY_HEX_RE.test(publicKey)) {
    throw new CliError("E_UNEXPECTED_RESPONSE", `registry card for ${domain} has no valid public key`);
  }
  let signatureVerified: boolean | null = null;
  if (local) {
    if (local.publicKey !== publicKey.toLowerCase()) {
      throw new CliError("E_KEY_MISMATCH", `local key for ${domain} does not match the registered key`);
    }
    signatureVerified = await proveKey(api, domain, local);
  }
  const conversations = card.agent_conversations ?? null;
  const lines = [
    `${domain} is registered`,
    `public key  ${publicKey}`,
    `created     ${String(card.created ?? "unknown")}`,
    `endpoint    ${typeof card.url === "string" ? card.url : "none"}`,
    `agent conversations ${conversations ? "declared" : "not declared"}`,
  ];
  if (signatureVerified !== null) {
    lines.push(`local key   ${signatureVerified ? "signature verified by registry" : "signature NOT verified"}`);
  }
  if (signatureVerified === false) {
    throw new CliError("E_SIG_MISMATCH", `registry did not verify a signature from the local key for ${domain}`);
  }
  return {
    data: {
      name: domain,
      registered: true,
      public_key: publicKey,
      url: typeof card.url === "string" ? card.url : null,
      created: card.created ?? null,
      agent_conversations: conversations,
      local_key: local !== null,
      signature_verified: signatureVerified,
    },
    lines,
  };
}

export async function whoami({ api, keys, parsed }: Context): Promise<Result> {
  onlyPositional(parsed, 0, "zipviz whoami");
  const ids = await keys.list();
  if (ids.length === 0) throw new CliError("E_NO_KEY", "no local keys (run: zipviz keygen --name <label>)");
  const identities = [];
  const lines = [`registry ${api.origin}`];
  let firstError: CliError | null = null;
  const skipped: Array<{ key_id: string; code: string; message: string }> = [];
  for (const id of ids) {
    let key: LocalKey;
    try {
      key = await keys.load(id);
    } catch (e) {
      if (!(e instanceof CliError)) throw e;
      firstError ??= e;
      skipped.push({ key_id: id, code: e.code, message: e.message });
      identities.push({
        key_id: id, domain: id === DEFAULT_KEY_ID ? null : id, public_key: null, registered: null, key_matches: null,
        error: { code: e.code, message: e.message },
      });
      lines.push(`${id}  (skipped: ${e.message})`);
      continue;
    }
    if (id === DEFAULT_KEY_ID) {
      identities.push({ key_id: id, domain: null, public_key: key.publicKey, registered: null, key_matches: null });
      lines.push(`${id}  ${key.publicKey}  (not bound to a name; redeem an invite to claim one)`);
      continue;
    }
    const card = await api.card(id);
    const matches = card ? String(card.public_key ?? "").toLowerCase() === key.publicKey : null;
    identities.push({ key_id: id, domain: id, public_key: key.publicKey, registered: card !== null, key_matches: matches });
    const status = card === null ? "not registered" : matches ? "registered, key matches" : "registered, KEY MISMATCH";
    lines.push(`${id}  ${key.publicKey}  (${status})`);
  }
  if (firstError && identities.every((i) => i.public_key === null)) throw firstError;
  return {
    data: { api: api.origin, identities, skipped },
    lines,
    exitCode: skipped.length > 0 ? WHOAMI_PARTIAL_EXIT : 0,
  };
}

function signedEnvelope(key: LocalKey, unsigned: Record<string, unknown>): Record<string, unknown> {
  return { ...unsigned, signature: key.sign(JSON.stringify(unsigned)).toString("hex") };
}

/** Lowercase host or host:port, as the registry's AGENT_INVITE_AUDIENCE. */
const AUD_RE = /^(?=.{1,253}(?::\d{1,5})?$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$/;

/** Defence in depth alongside `aud`: owner envelopes only go to the default registry or a local one. */
function isOwnerWriteOrigin(origin: string): boolean {
  const { hostname } = new URL(origin);
  return origin === DEFAULT_API || hostname === "localhost" || hostname === "127.0.0.1";
}

/** The registered card key must equal the local key before any owner write. */
async function preflightOwner(api: Api, issuer: string, key: LocalKey): Promise<void> {
  const card = await api.card(issuer);
  if (!card) throw new CliError("E_NOT_REGISTERED", `${issuer} is not registered`, 1, 404);
  if (String(card.public_key ?? "").toLowerCase() !== key.publicKey) {
    throw new CliError("E_KEY_MISMATCH", `local key for ${issuer} does not match its registered key`);
  }
}

export async function invite({ api, keys, parsed }: Context): Promise<Result> {
  const [sub, rawIssuer] = parsed.positional;
  if ((sub !== "create" && sub !== "revoke") || rawIssuer === undefined || parsed.positional.length !== 2) {
    throw usageError("usage: zipviz invite create <issuer> [--ttl <s>] [--execute] | invite revoke <issuer> --invite-id <uuid> [--execute]");
  }
  const issuer = agentDomain(rawIssuer);
  const execute = parsed.flags.has("execute");
  if (execute && !isOwnerWriteOrigin(api.origin)) {
    throw new CliError(
      "E_API_NOT_ALLOWED",
      `invite --execute only sends to ${DEFAULT_API} or http://localhost / http://127.0.0.1 (got ${api.origin})`,
      2,
    );
  }
  const audFlag = flagValue(parsed, "aud");
  if (audFlag !== undefined && !AUD_RE.test(audFlag)) {
    throw usageError("--aud must be a lowercase host or host:port, e.g. api.zipviz.ai or 127.0.0.1:8787");
  }
  const aud = audFlag ?? new URL(api.origin).host;
  const ttlRaw = flagValue(parsed, "ttl");
  const inviteId = flagValue(parsed, "invite-id");

  let unsigned: Record<string, unknown>;
  let summary: Record<string, unknown>;
  if (sub === "create") {
    if (inviteId !== undefined) throw usageError("--invite-id is only valid for revoke");
    const ttl = ttlRaw === undefined ? TTL_DEFAULT : Number(ttlRaw);
    if (!/^\d+$/.test(ttlRaw ?? String(TTL_DEFAULT)) || ttl < TTL_MIN || ttl > TTL_MAX) {
      throw usageError(`--ttl must be an integer between ${TTL_MIN} and ${TTL_MAX} seconds`);
    }
    summary = { aud, issuer, ttl_seconds: ttl };
    unsigned = { v: 1, op: "agent_invite.issue", aud, issuer, ttl_seconds: ttl };
  } else {
    if (ttlRaw !== undefined) throw usageError("--ttl is only valid for create");
    if (inviteId === undefined || !INVITE_ID_RE.test(inviteId)) throw usageError("--invite-id must be a lowercase UUID");
    summary = { aud, issuer, invite_id: inviteId };
    unsigned = { v: 1, op: "agent_invite.revoke", aud, issuer, invite_id: inviteId };
  }
  if (!isValidKeyId(issuer) || !(await keys.exists(issuer))) {
    throw new CliError("E_NO_KEY", `no local key for ${issuer}`);
  }
  const key = await keys.load(issuer);
  unsigned = { ...unsigned, timestamp: new Date().toISOString(), nonce: randomUUID() };
  const envelope = signedEnvelope(key, unsigned);

  if (!execute) {
    return {
      data: { dry_run: true, ...summary },
      lines: [
        `dry run: signed ${unsigned.op} for ${issuer} locally; nothing sent (add --execute to send)`,
        `aud ${aud}`,
      ],
    };
  }

  await preflightOwner(api, issuer, key);
  const res = await api.post(sub === "create" ? "/v1/agent-invites" : "/v1/agent-invites/revoke", envelope);
  if (isInvitesDisabled(res)) throw disabledError();
  if (res.status === 401 && res.body?.code === "E_INVITE_AUD") {
    throw new CliError(
      "E_INVITE_AUD",
      `registry rejected the invite audience ${aud}; pass --aud with the registry's configured audience (AGENT_INVITE_AUDIENCE)`,
      1,
      401,
    );
  }
  if (res.status === 400 && res.body?.code === "E_INVITE_SHAPE") {
    const base = registryError(res);
    throw new CliError(base.code, `${base.message} (registry may predate audience binding (aud))`, 1, 400);
  }
  const b = res.body;
  if (sub === "create") {
    if (res.status !== 201) throw registryError(res);
    if (!b || typeof b.code !== "string" || !INVITE_CODE_RE.test(b.code) || typeof b.invite_id !== "string") {
      throw new CliError("E_UNEXPECTED_RESPONSE", "registry returned an unexpected invite response", 1, res.status);
    }
    const namespace = typeof b.namespace === "string" ? b.namespace : INVITE_NAMESPACE;
    return {
      data: {
        dry_run: false, aud, issuer, code: b.code, invite_id: b.invite_id, namespace,
        mints: `<name>.${namespace}.viz`, expires_at: b.expires_at ?? null,
      },
      lines: [
        `invite code ${b.code}`,
        `invite id   ${b.invite_id}`,
        `mints       <name>.${namespace}.viz`,
        `expires     ${String(b.expires_at)}`,
        "share the code privately; it works once",
      ],
    };
  }
  if (res.status !== 200) throw registryError(res);
  if (!b || b.invite_id !== inviteId) {
    throw new CliError("E_UNEXPECTED_RESPONSE", "registry returned an unexpected revoke response", 1, res.status);
  }
  return {
    data: { dry_run: false, aud, issuer, invite_id: inviteId, status: b.status ?? "revoked", revoked_at: b.revoked_at ?? null },
    lines: [`revoked ${inviteId}`],
  };
}
