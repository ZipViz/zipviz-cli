import { randomUUID } from "node:crypto";
import { flagValue } from "../args.js";
import type { Context } from "../commands.js";
import { CliError, usageError } from "../errors.js";
import { JoinClient, type JoinResponse } from "../join/client.js";
import { requestDigest } from "../join/codec.js";
import type { Deps } from "../main.js";
import type { Result } from "../output.js";
import { isValidVizAgentDomain } from "../viz.js";
import { buildIntro, buildIntroPolicy, composeIntro, INTRO_DOMAIN_RE, validatePolicyResult } from "./codec.js";
import { IntroStore } from "./store.js";

const HEX32 = /^[0-9a-f]{64}$/;
const INCARNATION = /^[0-9a-f]{32}$/;
const unavailable = () => new CliError("E_INTRO_UNAVAILABLE", "an introduction is not currently allowed; no draft was transmitted");
const changed = () => new CliError("E_UNEXPECTED_RESPONSE", "current agent identity changed or could not be verified; no draft was transmitted");
interface Authority { domain: string; public_key: string; incarnation: string; revision: number }

function domainValue(value: string | undefined): string {
  if (!value || !INTRO_DOMAIN_RE.test(value) || !isValidVizAgentDomain(value)) throw usageError("intro requires a lowercase current .viz agent domain");
  return value;
}

function peerValue(value: string | undefined): string {
  if (!value || !value.trim() || Buffer.byteLength(value, "utf8") > 512
      || Buffer.from(value, "utf8").toString("utf8") !== value || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value)) {
    throw usageError("--peer must be an opaque reference of 1 to 512 UTF-8 bytes without control characters");
  }
  return value;
}

function currentAuthority(response: JoinResponse, domain: string, publicKey: string): Authority {
  const body = response.body;
  if (response.status !== 200 || body?.domain !== domain || body.status !== "registered" || body.identity_status !== "active"
      || typeof body.public_key !== "string" || !HEX32.test(body.public_key) || body.public_key !== publicKey
      || typeof body.incarnation !== "string" || !INCARNATION.test(body.incarnation)
      || !Number.isSafeInteger(body.revision) || (body.revision as number) < 0) throw changed();
  return { domain, public_key: body.public_key, incarnation: body.incarnation, revision: body.revision as number };
}

function currentCard(response: JoinResponse, domain: string, publicKey: string): Record<string, unknown> {
  if (response.status !== 200 || response.body?.name !== domain || response.body.public_key !== publicKey) throw changed();
  return response.body;
}

async function request(client: JoinClient, path: string, bytes?: string): Promise<JoinResponse> {
  try { return await client.request(path, bytes); }
  catch { throw unavailable(); }
}

function sameAuthority(before: Authority, after: Authority): boolean {
  return before.domain === after.domain && before.public_key === after.public_key
    && before.incarnation === after.incarnation && before.revision === after.revision;
}

/** Composes only. The sole POST is the contract's signed, read-only policy lookup. */
export async function introCommand({ api, keys, parsed }: Context, deps: Deps): Promise<Result> {
  const [operation, rawDomain] = parsed.positional;
  const allowed = operation === "create" ? ["peer", "existing-conversation", "peer-domain", "aud", "ttl"]
    : operation === "confirm-sent" ? ["peer", "confirmation", "confirmed-sent"] : null;
  if (parsed.positional.length !== 2 || !allowed
      || [...parsed.flags.keys()].some(flag => ![...allowed, "api", "json", "help"].includes(flag))) {
    throw usageError("usage: zipviz intro create|confirm-sent <domain> (see --help)");
  }
  const domain = domainValue(rawDomain);
  const peer = peerValue(flagValue(parsed, "peer"));
  const now = deps.now ?? Date.now;
  if (!Number.isSafeInteger(now()) || now() < 0) throw usageError("local clock must return nonnegative integer milliseconds");
  const store = new IntroStore(deps.zipvizHome);
  if (operation === "confirm-sent") {
    const confirmation = flagValue(parsed, "confirmation");
    if (!parsed.flags.has("confirmed-sent") || !confirmation) throw usageError("confirm-sent requires --confirmation and --confirmed-sent; it records your own statement that you sent the draft");
    const confirmed = await store.confirmSent(peer, confirmation, now(), domain);
    return { data: { ...confirmed, transmitted: false, confirmation_source: "caller" },
      lines: ["Recorded your confirmation that you sent the draft. ZipViz did not transmit or independently verify the message."] };
  }
  if (!parsed.flags.has("existing-conversation")) throw usageError("--existing-conversation is required: this is your statement, not something ZipViz can independently verify");
  const peerDomainFlag = flagValue(parsed, "peer-domain");
  const peerDomain = peerDomainFlag === undefined ? undefined : domainValue(peerDomainFlag);
  const audience = flagValue(parsed, "aud") ?? "api.zipviz.ai";
  if (!/^[a-z0-9][a-z0-9.:-]{0,252}$/.test(audience)) throw usageError("--aud must match the configured signup audience");
  const ttlText = flagValue(parsed, "ttl") ?? "259200";
  if (!/^[1-9][0-9]{0,5}$/.test(ttlText) || Number(ttlText) > 259200) throw usageError("--ttl must be 1 to 259200 seconds");
  const key = await keys.load(domain);
  const client = new JoinClient(api.origin, deps.fetch);
  const path = `/v1/agent/${encodeURIComponent(domain)}`;
  const authority = currentAuthority(await request(client, path), domain, key.publicKey);
  currentCard(await request(client, `${path}/card`), domain, key.publicKey);
  if (peerDomain !== undefined) {
    const peerResponse = await request(client, `/v1/agent/${encodeURIComponent(peerDomain)}`);
    if (peerResponse.status === 200 && peerResponse.body?.domain === peerDomain
        && (peerResponse.body.status === "registered" || peerResponse.body.status === "suspended")) {
      throw new CliError("E_INTRO_ALREADY_REGISTERED", "the supplied peer domain is already a ZipViz agent");
    }
    if (peerResponse.status !== 404 || (peerResponse.body?.code !== "E_AGENT_NOT_FOUND" && peerResponse.body?.error !== "Agent not found")) throw unavailable();
  }
  const policyBytes = buildIntroPolicy(key, { domain, incarnation: authority.incarnation, audience, issuedAtMs: now() });
  const response = await request(client, `${path}/intro-policy`, policyBytes);
  if (response.status !== 200) throw unavailable();
  validatePolicyResult(response.body, authority.incarnation, now());
  // Refuse a key/incarnation/revision change during the policy round trip.
  const after = currentAuthority(await request(client, path), domain, key.publicKey);
  if (!sameAuthority(authority, after)) throw changed();
  const card = currentCard(await request(client, `${path}/card`), domain, key.publicKey);
  validatePolicyResult(response.body, after.incarnation, now());
  await store.assertAvailable(peer, now());
  const issuedAtMs = now();
  validatePolicyResult(response.body, after.incarnation, issuedAtMs);
  const id = (deps.introId ?? randomUUID)();
  const expiresAtMs = issuedAtMs + Number(ttlText) * 1000;
  const token = buildIntro(key, { domain, incarnation: after.incarnation, audience, id, issuedAtMs, expiresAtMs });
  const draft = composeIntro(domain, card.owner, token);
  const confirmation = await store.makeConfirmation({ domain, peerRef: peer, draftId: id, issuedAtMs, expiresAtMs, tokenDigest: requestDigest(token) });
  const returnedAtMs = now();
  validatePolicyResult(response.body, after.incarnation, returnedAtMs);
  if (returnedAtMs >= expiresAtMs) throw unavailable();
  return { data: { compose_only: true, transmitted: false, domain, incarnation: after.incarnation,
    intro_token: token, draft, confirmation, expires_at_ms: expiresAtMs,
    existing_conversation: { caller_attested: true, independently_verified: false } },
  lines: ["Draft only. ZipViz did not transmit a message.", "Existing conversation: caller-attested, not independently verified.", draft,
    `Local confirmation receipt: ${confirmation}`,
    `After you send the draft, record it with: zipviz intro confirm-sent ${domain} --peer <same-reference> --confirmation <receipt> --confirmed-sent`] };
}
