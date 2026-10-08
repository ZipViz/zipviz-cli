import { createReadStream } from "node:fs";
import { flagValue, type Parsed } from "../args.js";
import { readLimited, MAX_INPUT_BYTES } from "../check.js";
import { CliError, usageError } from "../errors.js";
import { fetchJson, FetchError, type NetDeps } from "../net/fetch.js";
import type { Result } from "../output.js";
import { hasDuplicateMembers, isPlainObject } from "./json.js";
import { parseAnsName } from "./name.js";
import { AnsError } from "./reasons.js";
import { ANS_DRAFT, ANS_NOTE, verifyAnsBinding, type AnsEvidence, type AnsVerification } from "./verify.js";

export const ANS_USAGE = "usage: zipviz check --ans <ans-name> --ca <pem> --ra-jwk <file> --kms-jwk <file> (--bundle <file> | --cert <pem> (--badge <file> | --badge-url <https-url>))";

/** Every check passed except revocation, which this command does not perform. */
export const ANS_BINDING_CHECKED_EXIT = 10;

export const ANS_BINDING_CHECKED_LINE =
  "Checked: certificate and log entry match this name. Revocation: not checked.";

export type AnsCommandDeps = {
  readStdin?: () => Promise<Uint8Array>;
  net?: NetDeps;
};

const BUNDLE_FIELDS = new Set(["identityChainPem", "badge"]);

async function readBytes(filename: string, deps: AnsCommandDeps): Promise<Uint8Array> {
  if (filename === "-") {
    if (!deps.readStdin) throw new CliError("E_INPUT_UNREADABLE", "stdin could not be read", 6);
    let bytes: Uint8Array;
    try {
      bytes = await deps.readStdin();
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError("E_INPUT_UNREADABLE", "stdin could not be read", 6);
    }
    if (bytes.byteLength > MAX_INPUT_BYTES) throw new CliError("E_INPUT_TOO_LARGE", "input exceeds the 1 MiB limit", 6);
    return bytes;
  }
  try {
    return await readLimited(createReadStream(filename), MAX_INPUT_BYTES);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("E_INPUT_UNREADABLE", "input file could not be read", 6);
  }
}

async function readText(filename: string, deps: AnsCommandDeps): Promise<string> {
  const bytes = await readBytes(filename, deps);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CliError("E_INPUT_NOT_UTF8", "input is not valid UTF-8", 6);
  }
}

function parseJson(text: string, label: string): unknown {
  if (hasDuplicateMembers(text)) {
    throw new CliError("ANS_INPUT_INVALID", `${label} contains a duplicate JSON object member`, 6);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new CliError("E_INPUT_NOT_JSON", `${label} is not valid JSON`, 6);
  }
}

function parseKeyJson(text: string, role: string): unknown {
  try {
    if (hasDuplicateMembers(text)) {
      throw new CliError("ANS_KEY_INVALID", `${role} key contains a duplicate JSON member`, 7);
    }
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("ANS_KEY_INVALID", `${role} key file is not valid JSON`, 7);
  }
}

function bundleEvidence(value: unknown): { identityChainPem: string; badge: unknown } {
  if (!isPlainObject(value)) throw new CliError("ANS_INPUT_INVALID", "bundle must be a JSON object", 6);
  for (const key of Object.keys(value)) {
    if (!BUNDLE_FIELDS.has(key)) {
      throw new CliError("ANS_INPUT_INVALID", `bundle field ${key} is not accepted; pin trust with --ca, --ra-jwk, and --kms-jwk`, 6);
    }
  }
  if (typeof value.identityChainPem !== "string") {
    throw new CliError("ANS_INPUT_INVALID", "bundle identityChainPem must be a PEM string", 6);
  }
  if (value.badge === undefined) throw new CliError("ANS_INPUT_INVALID", "bundle must include badge", 6);
  return { identityChainPem: value.identityChainPem, badge: value.badge };
}

function pinLines(verification: AnsVerification): string[] {
  const pins = verification.pins;
  if (!pins) return [];
  const lines = [
    `pinned RA thumbprint ${pins.ra_jwk_thumbprint}`,
    `pinned KMS thumbprint ${pins.kms_jwk_thumbprint}`,
  ];
  if (pins.ca_sha256 !== undefined) lines.unshift(`pinned CA SHA256:${pins.ca_sha256}`);
  return lines;
}

function scopeLines(verification: AnsVerification): string[] {
  return [
    `revocation: ${verification.scope.revocation}`,
    `live_log: ${verification.scope.live_log}`,
  ];
}

function linesFor(verification: AnsVerification, fetched?: { badgeUrl: string; finalUrl: string }): string[] {
  const lines: string[] = [];
  if (fetched) {
    lines.push(`badge: ${fetched.badgeUrl}`);
    if (fetched.finalUrl !== fetched.badgeUrl) lines.push(`fetched from: ${fetched.finalUrl}`);
  }
  lines.push(verification.name);
  if (verification.reason === "ANS_REVOCATION_NOT_CHECKED") {
    const log = verification.transparency_log;
    lines.push(ANS_BINDING_CHECKED_LINE);
    lines.push(...pinLines(verification));
    lines.push(`identity certificate bound (SHA256:${verification.certificate?.fingerprint_sha256})`);
    if (log?.profile === "godaddy-live-v1") {
      lines.push(`transparency log inclusion checked (leaf ${log.leaf_index}, signed tree size ${log.tree_size})`);
      lines.push(`signed checkpoint checked (root, tree size, origin, timestamp; kid ${log.kms_kid})`);
      lines.push(`transparency log signature checked (kid ${log.ra_kid}, raid ${log.log_ra_id})`);
      lines.push(`log-authenticated producer header bound (kid ${log.producer_kid}, raId ${log.ra_id}); producer signature not independently checked`);
    } else {
      lines.push(`transparency log inclusion checked (asserted leaf ${log?.leaf_index}, asserted tree size ${log?.tree_size}; neither value is signed)`);
      lines.push(`signed tree head checked over the root hash only (kid ${log?.kms_kid})`);
      lines.push(`registration authority signature checked (kid ${log?.ra_kid}, raId ${log?.ra_id})`);
    }
    lines.push(`signed event ${log?.event_type}`);
    lines.push(`asserted status ${log?.status} (unsigned)`);
    lines.push(...scopeLines(verification));
    return lines;
  }
  if (!verification.valid) {
    lines.push(...pinLines(verification));
    lines.push(`ans invalid: ${verification.reason} (${verification.message})`);
    lines.push(...scopeLines(verification));
    return lines;
  }
  return lines;
}

function resultFor(verification: AnsVerification, fetched?: { badgeUrl: string; finalUrl: string }): Result {
  const data: Record<string, unknown> = {
    draft: ANS_DRAFT,
    name: verification.name,
    valid: verification.valid,
    scope: verification.scope,
    note: ANS_NOTE,
  };
  if (verification.version !== undefined) data.version = verification.version;
  if (verification.host !== undefined) data.host = verification.host;
  if (verification.reason !== undefined) data.reason = verification.reason;
  if (verification.message !== undefined) data.message = verification.message;
  if (verification.certificate !== undefined) data.certificate = verification.certificate;
  if (verification.transparency_log !== undefined) data.transparency_log = verification.transparency_log;
  if (verification.pins !== undefined) data.pins = verification.pins;
  if (fetched) {
    data.badge_url = fetched.badgeUrl;
    data.final_url = fetched.finalUrl;
  }
  const bindingChecked = verification.reason === "ANS_REVOCATION_NOT_CHECKED";
  data.binding_checked = bindingChecked;
  return {
    ok: verification.valid,
    exitCode: bindingChecked ? ANS_BINDING_CHECKED_EXIT : verification.valid ? 0 : 7,
    data,
    lines: linesFor(verification, fetched),
  };
}

export async function checkAns({ parsed }: { parsed: Parsed }, deps: AnsCommandDeps): Promise<Result> {
  if (parsed.positional.length !== 0) throw usageError(ANS_USAGE);
  const name = flagValue(parsed, "ans");
  if (name === undefined) throw usageError(ANS_USAGE);
  const bundlePath = flagValue(parsed, "bundle");
  const certPath = flagValue(parsed, "cert");
  const caPath = flagValue(parsed, "ca");
  const badgePath = flagValue(parsed, "badge");
  const badgeUrl = flagValue(parsed, "badge-url");
  const raPath = flagValue(parsed, "ra-jwk");
  const kmsPath = flagValue(parsed, "kms-jwk");
  if (caPath === undefined || raPath === undefined || kmsPath === undefined) throw usageError(ANS_USAGE);
  if (bundlePath !== undefined && (certPath !== undefined || badgePath !== undefined || badgeUrl !== undefined)) {
    throw usageError("--bundle cannot be combined with --cert, --badge, or --badge-url");
  }
  if (badgePath !== undefined && badgeUrl !== undefined) throw usageError("use only one of --badge or --badge-url");
  if (bundlePath === undefined && (certPath === undefined || (badgePath === undefined && badgeUrl === undefined))) {
    throw usageError(ANS_USAGE);
  }
  try {
    parseAnsName(name);
  } catch (error) {
    if (error instanceof AnsError) throw usageError(error.message);
    throw error;
  }

  const trustAnchorPem = await readText(caPath, deps);
  const raKey = parseKeyJson(await readText(raPath, deps), "registration authority");
  const kmsKey = parseKeyJson(await readText(kmsPath, deps), "KMS");
  let evidence: AnsEvidence;
  let fetched: { badgeUrl: string; finalUrl: string } | undefined;
  if (bundlePath !== undefined) {
    const bundled = bundleEvidence(parseJson(await readText(bundlePath, deps), "bundle"));
    evidence = { ...bundled, trustAnchorPem, raKey, kmsKey };
  } else {
    let badgeText: string;
    if (badgeUrl !== undefined) {
      try {
        const response = await fetchJson(badgeUrl, { accept: "application/json" }, deps.net);
        badgeText = response.text;
        fetched = { badgeUrl, finalUrl: response.finalUrl };
      } catch (error) {
        if (error instanceof FetchError) throw new CliError(error.code, error.message, 9);
        throw new CliError("FETCH_FAILED", "HTTPS request failed", 9);
      }
    } else {
      badgeText = await readText(badgePath!, deps);
    }
    evidence = {
      identityChainPem: await readText(certPath!, deps),
      trustAnchorPem,
      badge: parseJson(badgeText, "badge"),
      raKey,
      kmsKey,
    };
  }

  const verification = verifyAnsBinding(name, evidence);
  if (!verification.valid && verification.reason === "ANS_NAME_INVALID") throw usageError(verification.message ?? "invalid ANS name");
  return resultFor(verification, fetched);
}
