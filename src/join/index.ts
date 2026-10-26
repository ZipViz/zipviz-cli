import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { flagValue } from "../args.js";
import type { Context } from "../commands.js";
import { CliError, usageError } from "../errors.js";
import type { LocalKey } from "../keys.js";
import type { Deps } from "../main.js";
import type { Result } from "../output.js";
import { JoinClient, joinError, responseCode, type JoinResponse } from "./client.js";
import { buildCancel, buildStart, keyFingerprint, requestDigest, validatePoll, validateReceipt,
  type SignupPoll, type SignupRuntime, type StartReceipt } from "./codec.js";
import { PendingSignupStore, type PendingAttempt, type PendingSignupRecord } from "./store.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const unexpected = () => new CliError("E_UNEXPECTED_RESPONSE", "signup identity or response does not match; pending files are retained");
type Clock = { now: () => number; sleep: (ms: number) => Promise<void> };

function attempt(bytes: string): PendingAttempt {
  const body = JSON.parse(bytes) as { proof: { issued_at_ms: number } };
  return { request_b64url: Buffer.from(bytes).toString("base64url"), request_digest: requestDigest(bytes), issued_at_ms: body.proof.issued_at_ms };
}

/** Rebuild each retained request from the local key before trusting private disk state. */
function checkedAttempts(record: PendingSignupRecord, key: LocalKey): string[] {
  return record.attempts.map(entry => {
    const bytes = Buffer.from(entry.request_b64url, "base64url").toString("utf8");
    try {
      const b = JSON.parse(bytes) as { name: string; owner_email: string; runtime: SignupRuntime; introduced_by: string | null; proof: { signup_id: string; public_key: string; audience: string; issued_at_ms: number } };
      const rebuilt = buildStart(key, { signupId: record.signup_id, name: b.name, ownerEmail: b.owner_email,
        runtime: b.runtime, introducedBy: b.introduced_by, audience: record.audience, issuedAtMs: entry.issued_at_ms });
      if (rebuilt !== bytes || b.proof.signup_id !== record.signup_id || b.proof.public_key !== key.publicKey
          || b.proof.audience !== record.audience || requestDigest(bytes) !== entry.request_digest) throw unexpected();
      return bytes;
    } catch { throw new CliError("E_JOIN_PENDING_INVALID", "pending signup metadata is invalid; files are retained"); }
  });
}

/** Retry only an unchanged attempt after an uncertain transport outcome. */
async function sendStart(client: JoinClient, bytes: string, clock: Clock): Promise<JoinResponse> {
  for (let retry = 0; ; retry++) {
    try {
      const response = await client.request("/v1/signup/start", bytes);
      if (!(response.status === 503 && responseCode(response) === "E_SIGNUP_UNAVAILABLE") || retry === 2) return response;
    } catch (error) {
      if (!(error instanceof CliError) || error.code !== "E_NETWORK" || retry === 2) throw error;
    }
    await clock.sleep(1000 * 2 ** retry);
  }
}

async function recover(store: PendingSignupStore, client: JoinClient, record: PendingSignupRecord, key: LocalKey, clock: Clock): Promise<StartReceipt> {
  for (;;) {
    const bytes = checkedAttempts(record, key);
    const newest = bytes.length - 1;
    const response = await sendStart(client, bytes[newest]!, clock);
    if (response.status === 200 || response.status === 201) {
      const receipt = validateReceipt(response.body, record.signup_id);
      await store.saveReceipt(record.signup_id, { ...receipt });
      return receipt;
    }
    if (response.status === 401 && responseCode(response) === "E_STALE") {
      if (record.attempts.length >= 8) throw new CliError("E_JOIN_RETRY_LIMIT", "signup reached eight signed attempts; all pending files are retained");
      const first = JSON.parse(bytes[0]!) as { name: string; owner_email: string; runtime: SignupRuntime; introduced_by: string | null };
      const request = buildStart(key, { signupId: record.signup_id, name: first.name, ownerEmail: first.owner_email,
        runtime: first.runtime, introducedBy: first.introduced_by, audience: record.audience, issuedAtMs: clock.now() });
      record = await store.appendAttempt(record.signup_id, attempt(request));
      continue;
    }
    if (response.status === 409 && responseCode(response) === "E_SIGNUP_ID_CONFLICT") {
      const tried = new Set([bytes[newest]!]);
      for (;;) {
        // Another process may have appended while this request was in flight.
        // A foreign-row conclusion must account for every retained attempt.
        record = await store.read(record.signup_id);
        const retained = checkedAttempts(record, key);
        for (let index = retained.length - 1; index >= 0; index--) {
          const request = retained[index]!;
          if (tried.has(request)) continue;
          const replay = await sendStart(client, request, clock);
          if (replay.status === 200) {
            const receipt = validateReceipt(replay.body, record.signup_id);
            await store.saveReceipt(record.signup_id, { ...receipt });
            return receipt;
          }
          if (!(replay.status === 409 && responseCode(replay) === "E_SIGNUP_ID_CONFLICT")) throw joinError(replay);
          tried.add(request);
        }
        const current = await store.read(record.signup_id);
        if (current.attempts.length === record.attempts.length) throw unexpected();
        record = current;
      }
    }
    throw joinError(response);
  }
}

async function poll(client: JoinClient, id: string, wait: boolean, clock: Clock, initialDelay = 0): Promise<SignupPoll> {
  let pause = initialDelay;
  for (;;) {
    if (pause > 0) await clock.sleep(pause);
    const response = await client.request(`/v1/signup/${id}`);
    if (response.status === 429 && responseCode(response) === "E_SLOW_DOWN" && wait) {
      pause = Math.max(5000, response.retryAfterMs ?? 5000); continue;
    }
    if (response.status !== 200) throw joinError(response);
    const state = validatePoll(response.body, id, client.origin);
    if (!wait || state.state !== "pending") return state;
    pause = Math.max(5000, state.poll_interval_ms);
  }
}

function stateResult(state: SignupPoll): Result {
  const lines = [`signup ${state.signup_id}: ${state.state}`];
  if (state.state === "live") lines.push(`approved as ${state.domain}; run zipviz join adopt ${state.signup_id} to adopt the key`);
  return { data: { ...state }, lines };
}

export async function joinCommand({ api, parsed }: Context, deps: Deps): Promise<Result> {
  const positional = [...parsed.positional];
  const operation = positional.length === 0 ? "start" : positional.shift()!;
  const allowed = operation === "start" ? ["name", "owner-email", "runtime", "introduced-by", "aud", "resume", "wait"]
    : operation === "status" ? ["wait"] : operation === "cancel" || operation === "adopt" ? [] : null;
  if (!allowed || [...parsed.flags.keys()].some(flag => ![...allowed, "api", "json", "help"].includes(flag))) throw usageError("invalid join command or options (see --help)");
  const clock: Clock = { now: deps.now ?? Date.now, sleep: deps.sleep ?? (ms => delay(ms).then(() => undefined)) };
  const client = new JoinClient(api.origin, deps.fetch);
  const store = new PendingSignupStore(deps.zipvizHome);
  const wait = parsed.flags.has("wait");

  if (operation === "status") {
    const id = positional[0];
    if (positional.length !== 1 || !id || !UUID.test(id)) throw usageError("usage: zipviz join status <signup_id> [--wait]");
    // Status deliberately never opens, writes or checks the local store.
    return stateResult(await poll(client, id, wait, clock));
  }
  if (operation === "start") {
    if (positional.length) throw usageError("usage: zipviz join [start] --name <label> --owner-email <email> --runtime <runtime>");
    const resume = flagValue(parsed, "resume");
    let record: PendingSignupRecord; let key: LocalKey;
    if (resume !== undefined) {
      if (!UUID.test(resume) || ["name", "owner-email", "runtime", "introduced-by", "aud"].some(flag => parsed.flags.has(flag))) throw usageError("--resume takes only the retained signup id and optional --wait");
      record = await store.read(resume); key = await store.loadKey(resume);
      if (record.registry_origin !== api.origin) throw new CliError("E_JOIN_REGISTRY", "resume requires the original --api registry; pending files are retained", 2);
    } else {
      const name = flagValue(parsed, "name"); const email = flagValue(parsed, "owner-email"); const runtime = flagValue(parsed, "runtime");
      if (!name || !email || !runtime) throw usageError("join needs --name, --owner-email and --runtime");
      const audience = flagValue(parsed, "aud") ?? "api.zipviz.ai";
      if (!/^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$/.test(name) || /-\d{4}$/.test(name)) throw usageError("--name must be a lowercase chosen label, 1 to 15 characters, without -NNNN");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.trim().length > 254) throw usageError("--owner-email must be a valid email address");
      if (!["claude", "codex", "buzz", "openclaw", "hermes", "other"].includes(runtime)) throw usageError("invalid --runtime");
      if (!/^[a-z0-9][a-z0-9.:-]{0,252}$/.test(audience)) throw usageError("--aud must be the configured signup audience");
      const introducedBy = flagValue(parsed, "introduced-by") ?? null;
      if (introducedBy !== null && (introducedBy.length > 1024 || !/^zvintro1\.[A-Za-z0-9_-]+$/.test(introducedBy))) throw usageError("--introduced-by must be a ZipViz intro token");
      const availability = await client.request(`/v1/signup/availability?name=${encodeURIComponent(name)}`);
      if (availability.status !== 200) throw joinError(availability);
      if (availability.body?.valid !== true) throw joinError(availability);
      if (availability.body.name !== name || availability.body.code !== null || availability.body.example !== `${name}-NNNN.z.viz`) throw unexpected();
      const id = (deps.joinId ?? randomUUID)();
      if (!UUID.test(id)) throw unexpected();
      key = await store.generate(id);
      const bytes = buildStart(key, { signupId: id, name, ownerEmail: email, runtime: runtime as SignupRuntime,
        introducedBy, audience, issuedAtMs: clock.now() });
      record = await store.create(id, attempt(bytes), { registry_origin: api.origin, audience });
    }
    let receipt: StartReceipt;
    try { receipt = await recover(store, client, record, key, clock); }
    catch (error) {
      if (error instanceof CliError) throw new CliError(error.code, `${error.message}; resume: zipviz join start --resume ${record.signup_id}`, error.exitCode, error.httpStatus);
      throw error;
    }
    const fingerprint = keyFingerprint(key.publicKey);
    if (wait) deps.stderr(`approval link ${receipt.approval_url}\ncode ${receipt.user_code}\nkey fingerprint ${fingerprint}\nGive all three to your human. Waiting for their approval.\n`);
    let state: SignupPoll;
    try { state = await poll(client, record.signup_id, wait, clock, wait ? receipt.poll_interval_ms : 0); }
    catch (error) {
      const failed = error instanceof CliError ? error : new CliError("E_UNEXPECTED_RESPONSE", "could not confirm current signup state");
      const resumeCommand = `zipviz join start --resume ${record.signup_id}`;
      const statusCommand = `zipviz join status ${record.signup_id}`;
      return { ok: false, exitCode: 1, data: { signup_id: record.signup_id, receipt, key_fingerprint: fingerprint,
        current_state: null, receipt_is_historical: true, resume_command: resumeCommand, status_command: statusCommand,
        error: { code: failed.code, message: failed.message, ...(failed.httpStatus === undefined ? {} : { http_status: failed.httpStatus }) } },
      lines: ["Signup creation receipt saved; current state could not be confirmed.",
        `signup ${record.signup_id}`, `approval link ${receipt.approval_url}`, `code ${receipt.user_code}`,
        `key fingerprint ${fingerprint}`, "Give the approval link, code and key fingerprint to your human. Only they can approve.",
        "The saved receipt describes creation only; it does not establish current or live state.",
        `status: ${statusCommand}`, `resume: ${resumeCommand}`, `poll error: ${failed.code}`] };
    }
    return { data: { ...state, receipt, key_fingerprint: fingerprint }, lines: [
      `signup ${record.signup_id}: ${state.state}`, `approval link ${receipt.approval_url}`, `code ${receipt.user_code}`,
      `key fingerprint ${fingerprint}`, "Give the approval link, code and key fingerprint to your human. Only they can approve.",
      `resume: zipviz join start --resume ${record.signup_id}`, `status: zipviz join status ${record.signup_id}`,
      ...(state.state === "live" ? [`adopt: zipviz join adopt ${record.signup_id}`] : []),
    ] };
  }
  const id = positional[0];
  if (positional.length !== 1 || !id || !UUID.test(id)) throw usageError(`usage: zipviz join ${operation} <signup_id>`);
  const record = await store.read(id);
  if (record.registry_origin !== api.origin) throw new CliError("E_JOIN_REGISTRY", "use the signup's original --api registry", 2);
  const key = await store.loadKey(id); checkedAttempts(record, key);
  if (operation === "cancel") {
    const bytes = buildCancel(key, { signupId: id, audience: record.audience, nonce: randomUUID(), issuedAtMs: clock.now() });
    const response = await client.request(`/v1/signup/${id}/cancel`, bytes);
    if (response.status !== 200) throw joinError(response);
    if (response.body?.state !== "cancelled" || Object.keys(response.body).length !== 1) throw unexpected();
    return stateResult(await poll(client, id, false, clock));
  }
  // A recovered receipt is required: a foreign signup row cannot grant a local identity.
  validateReceipt(record.receipt, id);
  const state = await poll(client, id, false, clock);
  if (state.state !== "live" || state.public_key !== key.publicKey) throw unexpected();
  const response = await client.request(`/v1/agent/${encodeURIComponent(state.domain)}`);
  const current = response.body;
  if (response.status !== 200 || current?.domain !== state.domain || current.public_key !== key.publicKey
      || current.status !== "registered" || current.identity_status !== "active" || current.incarnation !== state.incarnation
      || !Number.isSafeInteger(current.revision) || (current.revision as number) < 0) throw unexpected();
  const keyPath = await store.adopt(id, state.domain, state.public_key);
  return { data: { signup_id: id, domain: state.domain, public_key: key.publicKey, incarnation: state.incarnation, key_path: keyPath },
    lines: [`adopted ${state.domain}`, `key file ${keyPath}`] };
}
