import { createReadStream } from "node:fs";
import {
  cardWarnings,
  jwkThumbprint,
  parseCardJson,
  parseJwks,
  publicJwkFromPrivate,
  readSignatures,
  REASON_MESSAGES,
  signCard,
  verifyCard,
  type JsonObject,
  type JsonValue,
  type PrivateJwk,
  type PublicJwk,
  type SignatureResult,
} from "./a2a/index.js";
import { flagValue, flagValues, type Parsed } from "./args.js";
import type { Context } from "./commands.js";
import { CliError, usageError } from "./errors.js";
import { readPrivateKeyFile } from "./keys.js";
import { fetchJson, FetchError, type NetDeps } from "./net/fetch.js";
import { readLimited, MAX_INPUT_BYTES } from "./check.js";
import type { Result } from "./output.js";

const CARD_NOTE =
  "a valid signature shows the card content was signed by the holder of the key; it does not prove who operates the agent or that the card's claims are true.";
const FETCH_ACCEPT = "application/json, application/a2a+json";
const JWKS_ACCEPT = "application/jwk-set+json, application/json";
const NOT_CHECKED_REASONS = new Set(["SIG_KEY_NOT_FOUND", "SIG_KEY_ALG_MISMATCH", "KEY_JKU_HOST_NOT_ALLOWED"]);

type CardDeps = { readStdin?: () => Promise<Uint8Array>; net?: NetDeps };
type CheckedSignature = Omit<SignatureResult, "reason"> & {
  reason?: SignatureResult["reason"] | "KEY_JKU_HOST_NOT_ALLOWED";
  key_source?: string;
};
type VerificationForOutput = Omit<ReturnType<typeof verifyCard>, "signatures"> & {
  signatures: CheckedSignature[];
};

function invalidCardResult(reason: string, message: string, fields: Record<string, unknown> = {}): Result {
  return {
    ok: false,
    data: { valid: false, reason, message, uncovered: [], signatures: [], ...fields },
    lines: [`card invalid: ${reason} (${message})`],
    exitCode: 7,
  };
}

async function localBytes(filename: string, deps: CardDeps): Promise<Uint8Array> {
  try {
    const bytes = filename === "-"
      ? await deps.readStdin?.()
      : await readLimited(createReadStream(filename), MAX_INPUT_BYTES);
    if (!bytes) throw new Error("missing input");
    if (bytes.byteLength > MAX_INPUT_BYTES) {
      throw new CliError("E_INPUT_TOO_LARGE", "input exceeds the 1 MiB limit", 6);
    }
    return bytes;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("E_INPUT_UNREADABLE", "input file or stdin could not be read", 6);
  }
}

async function localText(filename: string, deps: CardDeps): Promise<string> {
  const bytes = await localBytes(filename, deps);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CliError("E_INPUT_NOT_UTF8", "input is not valid UTF-8", 6);
  }
}

async function readCard(filename: string, deps: CardDeps): Promise<
  | { ok: true; card: JsonObject }
  | { ok: false; reason: string; message: string }
> {
  return parseCardJson(await localText(filename, deps));
}

function privateJwk(keyPath: string): Promise<PrivateJwk> {
  return readPrivateKeyFile(keyPath).then((key) => key.export({ format: "jwk" }) as PrivateJwk);
}

async function readJwksFile(filename: string, deps: CardDeps): Promise<PublicJwk[]> {
  const text = await localText(filename, deps);
  const parsed = parseCardJson(text);
  if (!parsed.ok) {
    throw new CliError("E_JWKS_INVALID", parsed.message, 6);
  }
  try {
    return parseJwks(parsed.card);
  } catch (error) {
    throw new CliError("E_JWKS_INVALID", error instanceof Error ? error.message : "JWKS is invalid", 6);
  }
}

function kidFor(publicKey: PublicJwk, kid: string | undefined): string {
  const selected = kid ?? jwkThumbprint(publicKey);
  if (selected.length === 0 || selected.length > 256) throw usageError("--kid must be 1 to 256 characters");
  return selected;
}

function publicJwks(privateKey: PrivateJwk, kid: string | undefined): { keys: PublicJwk[] } {
  const publicKey = publicJwkFromPrivate(privateKey);
  const alg = publicKey.kty === "OKP" ? "EdDSA" : "ES256";
  return { keys: [{ ...publicKey, kid: kidFor(publicKey, kid), alg, use: "sig" }] };
}

function publicKeysForCard(privateKey: PrivateJwk, card: JsonObject): PublicJwk[] {
  const publicKey = publicJwkFromPrivate(privateKey);
  const kids = readSignatures(card).flatMap((signature) => signature.kid ? [signature.kid] : []);
  const distinctKids = [...new Set(kids)];
  return distinctKids.length === 0
    ? [publicKey]
    : distinctKids.map((kid) => ({ ...publicKey, kid }));
}

function onlyFlags(parsed: Parsed, allowed: readonly string[]): void {
  const allowedSet = new Set(["api", "help", "json", ...allowed]);
  for (const key of parsed.flags.keys()) {
    if (!allowedSet.has(key)) throw usageError(`--${key} is not valid for this card command`);
  }
}

function cardInputError(reason: string, message: string): Result {
  return invalidCardResult(reason, message);
}

function signatureNotes(signature: CheckedSignature): string {
  const warnings = (signature.warnings ?? [])
    .map((warning) => `; warning: ${warning.code} (${warning.message})`)
    .join("");
  const ignored = signature.unprotected_ignored?.length
    ? `; ignored unprotected header fields: ${signature.unprotected_ignored.join(", ")} (not trusted)`
    : "";
  return `${warnings}${ignored}`;
}

function cardVerificationResult(
  verification: VerificationForOutput,
  fields: Record<string, unknown> = {},
  signatures: CheckedSignature[] = verification.signatures,
  requireAll = false,
): Result {
  if (verification.reason && verification.reason !== "CARD_SIGNATURES_INVALID") {
    const message = verification.message ?? verification.reason;
    const pointer = verification.pointer;
    const result = invalidCardResult(verification.reason, message, {
      ...fields,
      ...(pointer === undefined ? {} : { pointer }),
      valid_signatures: verification.valid_signatures,
      require_all: requireAll,
      uncovered: verification.uncovered,
      signatures,
    });
    if (pointer !== undefined) result.lines = [`card invalid: ${verification.reason} (${message} at ${pointer})`];
    return result;
  }
  const validSignatures = signatures.filter((signature) => signature.valid).length;
  const warnings = cardWarnings(signatures);
  const signatureValid = requireAll
    ? signatures.every((signature) => signature.valid)
    : signatures.some((signature) => signature.valid);
  const covered = verification.uncovered.length === 0;
  const valid = signatureValid && covered;
  const reason = !signatureValid
    ? "CARD_SIGNATURES_INVALID"
    : !covered
      ? "CARD_UNCOVERED_FIELDS"
      : undefined;
  const lines = signatures.map((signature) => {
    const prefix = `signature ${signature.index + 1}: `;
    const identity = signature.kid
      ? `key ${signature.kid}${signature.alg ? ` (${signature.alg})` : ""}`
      : "signature";
    if (!signature.valid) {
      if (NOT_CHECKED_REASONS.has(signature.reason ?? "")) {
        return `${prefix}signature claiming ${identity} not checked: ${signature.reason} (${signature.message ?? "key could not be resolved"})${signatureNotes(signature)}`;
      }
      return `${prefix}signature claiming ${identity} is invalid: ${signature.reason ?? "SIG_MALFORMED"} (${signature.message ?? "signature could not be verified"})${signatureNotes(signature)}`;
    }
    const source = signature.key_source ? `; key from ${signature.key_source}` : "";
    const warning = signature.message ? `; ${signature.message}` : "";
    return `${prefix}card signed by ${identity}, valid${source}${warning}${signatureNotes(signature)}`;
  });
  for (const pointer of verification.uncovered) lines.push(`not covered by any signature: ${pointer}`);
  for (const warning of warnings) {
    lines.push(`warning: ${warning.code} (${warning.message})`);
  }
  if (valid) {
    lines.push(validSignatures === signatures.length
      ? "result: valid"
      : `result: valid (${validSignatures} of ${signatures.length} signatures verified)`);
  }
  else if (signatureValid && !covered) {
    const signatureSummary = validSignatures === signatures.length
      ? "signatures valid"
      : `${validSignatures} of ${signatures.length} signatures verified`;
    lines.push(`result: ${signatureSummary}, but ${verification.uncovered.length} field${verification.uncovered.length === 1 ? "" : "s"} not covered by any signature`);
  } else {
    lines.push("result: invalid");
  }
  lines.push(`note: ${CARD_NOTE}`);
  return {
    ok: valid,
    data: {
      ...fields,
      valid,
      ...(reason === undefined ? {} : { reason }),
      valid_signatures: validSignatures,
      require_all: requireAll,
      uncovered: verification.uncovered,
      signatures,
      ...(warnings.length === 0 ? {} : { warnings }),
      note: CARD_NOTE,
    },
    lines,
    exitCode: valid ? 0 : signatureValid && !covered ? 8 : 7,
  };
}

function addX5uNote(signature: CheckedSignature, hasX5u: boolean): CheckedSignature {
  if (!hasX5u) return signature;
  const note = "KEY_X5U_NOT_SUPPORTED: x5u is never fetched";
  return { ...signature, message: signature.message ? `${signature.message}; ${note}` : note };
}

export async function cardCommand({ parsed }: Context, deps: CardDeps): Promise<Result> {
  const [subcommand, ...positionals] = parsed.positional;
  if (subcommand === "sign") {
    onlyFlags(parsed, ["key", "kid", "jku", "append"]);
    if (positionals.length !== 1) throw usageError("usage: zipviz card sign <card.json|-> --key <file> [--kid <kid>] [--jku <https-url>] [--append]");
    const keyPath = flagValue(parsed, "key");
    if (keyPath === undefined) throw usageError("card sign requires --key <file>");
    const privateKey = await privateJwk(keyPath);
    const input = await readCard(positionals[0]!, deps);
    if (!input.ok) return cardInputError(input.reason, input.message);
    try {
      const signed = signCard(input.card, privateKey, {
        ...(flagValue(parsed, "kid") === undefined ? {} : { kid: flagValue(parsed, "kid") }),
        ...(flagValue(parsed, "jku") === undefined ? {} : { jku: flagValue(parsed, "jku") }),
        append: parsed.flags.has("append"),
      });
      const publicKey = publicJwkFromPrivate(privateKey);
      const alg = publicKey.kty === "OKP" ? "EdDSA" : "ES256";
      const kid = flagValue(parsed, "kid") ?? jwkThumbprint(publicKey);
      return {
        data: { alg, kid, card: signed },
        lines: [],
        rawOutput: `${JSON.stringify(signed, null, 2)}\n`,
      };
    } catch (error) {
      if (error instanceof Error && "reason" in error) {
        const reason = String((error as { reason: unknown }).reason);
        return cardInputError(reason, error.message);
      }
      throw error;
    }
  }
  if (subcommand === "jwks") {
    onlyFlags(parsed, ["key", "kid"]);
    if (positionals.length !== 0) throw usageError("usage: zipviz card jwks --key <file> [--kid <kid>]");
    const keyPath = flagValue(parsed, "key");
    if (keyPath === undefined) throw usageError("card jwks requires --key <file>");
    const key = await privateJwk(keyPath);
    const jwks = publicJwks(key, flagValue(parsed, "kid"));
    return {
      data: jwks,
      lines: [],
      rawOutput: `${JSON.stringify(jwks)}\n`,
    };
  }
  if (subcommand === "verify") {
    onlyFlags(parsed, ["key", "jwks", "require-all"]);
    if (positionals.length !== 1) throw usageError("usage: zipviz card verify <card.json|-> (--key <file> | --jwks <file>) [--require-all]");
    const keyPath = flagValue(parsed, "key");
    const jwksPath = flagValue(parsed, "jwks");
    const requireAll = parsed.flags.has("require-all");
    if ((keyPath === undefined) === (jwksPath === undefined)) {
      throw usageError("card verify requires exactly one of --key or --jwks");
    }
    const input = await readCard(positionals[0]!, deps);
    if (!input.ok) {
      return invalidCardResult(input.reason, input.message, {
        require_all: requireAll,
        valid_signatures: 0,
      });
    }
    let keys: PublicJwk[];
    let keySource: string;
    if (keyPath !== undefined) {
      const privateKey = await privateJwk(keyPath);
      keys = publicKeysForCard(privateKey, input.card);
      keySource = "--key <file>";
    } else {
      keys = await readJwksFile(jwksPath!, deps);
      keySource = "--jwks <file>";
    }
    const verification = verifyCard(input.card, { keys, requireAll });
    const signatures = verification.signatures.map((signature) => ({
      ...signature,
      key_source: keySource,
      ...(signature.jku === undefined ? {} : {}),
    }));
    return cardVerificationResult(verification, {}, signatures, requireAll);
  }
  throw usageError("usage: zipviz card <sign|jwks|verify> ...");
}

function validCardDomain(domain: string): boolean {
  if (domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2 || labels.some((label) =>
    label.length < 1 || label.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  )) return false;
  if (/^\d+(?:\.\d+){3}$/.test(domain)) return false;
  try {
    return new URL(`https://${domain}`).hostname === domain;
  } catch {
    return false;
  }
}

function allowedJkuHost(value: string): string {
  if (value !== value.trim() || /[/?#@\\\s]/.test(value)) {
    throw usageError(`--allow-jku-host must be a hostname or host:port: ${value}`);
  }
  try {
    const url = new URL(`https://${value}`);
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash || url.hostname === "") {
      throw new Error("bad host");
    }
    return url.host.toLowerCase();
  } catch {
    throw usageError(`--allow-jku-host must be a hostname or host:port: ${value}`);
  }
}

function singleCardVerification(card: JsonObject, entry: unknown, keys: PublicJwk[], index: number): SignatureResult | undefined {
  const verification = verifyCard({ ...card, signatures: [entry as JsonValue] }, { keys });
  const signature = verification.signatures[0];
  return signature === undefined ? undefined : { ...signature, index };
}

function asFailedSignature(
  descriptor: ReturnType<typeof readSignatures>[number],
  reason: string,
  message: string,
): CheckedSignature {
  return {
    index: descriptor.index,
    valid: false,
    ...(descriptor.warnings === undefined ? {} : { warnings: descriptor.warnings }),
    ...(descriptor.unprotected_ignored === undefined ? {} : { unprotected_ignored: descriptor.unprotected_ignored }),
    ...(descriptor.alg === undefined ? {} : { alg: descriptor.alg }),
    ...(descriptor.kid === undefined ? {} : { kid: descriptor.kid }),
    ...(descriptor.jku === undefined ? {} : { jku: descriptor.jku }),
    reason: reason as CheckedSignature["reason"],
    message,
  };
}

function jkuSource(url: string, sameHost: boolean, isFallback: boolean): string {
  const label = isFallback
    ? "same-host ZipViz fallback, not an A2A convention"
    : sameHost
      ? "same host as the card"
      : "allowed by --allow-jku-host";
  return `${url} (${label})`;
}

async function remoteKeys(
  url: string,
  host: string,
  deps: CardDeps,
  cache: Map<string, Promise<{ keys: PublicJwk[]; source: string }>>,
  sameHost: boolean,
  isFallback: boolean,
): Promise<{ keys: PublicJwk[]; source: string }> {
  const normalized = new URL(url).href;
  let request = cache.get(normalized);
  if (request === undefined) {
    if (cache.size >= 4) {
      throw new FetchError("FETCH_FAILED", "maximum of 4 distinct JWKS URLs exceeded", normalized);
    }
    request = fetchJson(normalized, {
      accept: JWKS_ACCEPT,
      allowedHosts: (candidate) => candidate.toLowerCase() === host.toLowerCase(),
    }, deps.net).then((response) => {
      const parsed = parseCardJson(response.text);
      if (!parsed.ok) throw new FetchError("FETCH_FAILED", `JWKS is invalid: ${parsed.message}`, normalized);
      try {
        return {
          keys: parseJwks(parsed.card),
          source: jkuSource(normalized, sameHost, isFallback),
        };
      } catch (error) {
        throw new FetchError("FETCH_FAILED", `JWKS is invalid: ${error instanceof Error ? error.message : "invalid JSON"}`, normalized);
      }
    });
    cache.set(normalized, request);
  }
  return request;
}

export async function checkCard({ parsed }: Context, deps: CardDeps): Promise<Result> {
  if (parsed.positional.length !== 0) throw usageError("usage: zipviz check --card <domain> [--key <file> | --jwks <file>] [--allow-jku-host <host>]... [--require-all]");
  const suppliedDomain = flagValue(parsed, "card");
  const requireAll = parsed.flags.has("require-all");
  if (suppliedDomain === undefined || [...suppliedDomain].some((character) => character.charCodeAt(0) > 0x7f)) {
    throw usageError("--card must be an ASCII hostname with at least two valid labels, no port or trailing dot");
  }
  const domain = suppliedDomain.toLowerCase();
  if (!validCardDomain(domain)) {
    throw usageError("--card must be an ASCII hostname with at least two valid labels, no port or trailing dot");
  }
  const keyPath = flagValue(parsed, "key");
  const jwksPath = flagValue(parsed, "jwks");
  if (keyPath !== undefined && jwksPath !== undefined) throw usageError("use only one of --key or --jwks");
  const allowedHosts = new Set(flagValues(parsed, "allow-jku-host").map(allowedJkuHost));
  const cardUrl = `https://${domain}/.well-known/agent-card.json`;
  let fetched: Awaited<ReturnType<typeof fetchJson>>;
  try {
    fetched = await fetchJson(cardUrl, { accept: FETCH_ACCEPT }, deps.net);
  } catch (error) {
    if (error instanceof FetchError) throw new CliError(error.code, error.message, 9);
    throw new CliError("FETCH_FAILED", "HTTPS request failed", 9);
  }
  const parsedCard = parseCardJson(fetched.text);
  const responseFields = { card_url: cardUrl, final_url: fetched.finalUrl };
  if (!parsedCard.ok) {
    return invalidCardResult(parsedCard.reason, parsedCard.message, {
      ...responseFields,
      require_all: requireAll,
      valid_signatures: 0,
      uncovered: [],
      signatures: [],
      note: CARD_NOTE,
    });
  }
  const card = parsedCard.card;
  const baseline = verifyCard(card, { keys: [], requireAll });
  const redirectLines = fetched.finalUrl !== cardUrl ? [`fetched from: ${fetched.finalUrl}`] : [];
  const fields = { ...responseFields };
  if (baseline.reason && baseline.reason !== "CARD_SIGNATURES_INVALID") {
    const result = invalidCardResult(baseline.reason, baseline.message ?? baseline.reason, {
      ...fields,
      pointer: baseline.pointer,
      require_all: requireAll,
      valid_signatures: baseline.valid_signatures,
      uncovered: baseline.uncovered,
      signatures: baseline.signatures,
      note: CARD_NOTE,
    });
    result.lines.unshift(`card: ${cardUrl}`, ...redirectLines);
    return result;
  }
  const rawSignatures = Array.isArray(card.signatures) ? card.signatures : [];
  const descriptors = readSignatures(card);
  let explicitKeys: PublicJwk[] | undefined;
  let explicitSource: string | undefined;
  if (keyPath !== undefined) {
    explicitKeys = publicKeysForCard(await privateJwk(keyPath), card);
    explicitSource = "--key <file>";
  } else if (jwksPath !== undefined) {
    explicitKeys = await readJwksFile(jwksPath, deps);
    explicitSource = "--jwks <file>";
  }
  const cache = new Map<string, Promise<{ keys: PublicJwk[]; source: string }>>();
  const signatures: CheckedSignature[] = [];
  for (let index = 0; index < rawSignatures.length; index++) {
    const descriptor = descriptors[index] ?? { index, reason: "SIG_MALFORMED" as const };
    if (descriptor.reason) {
      signatures.push(asFailedSignature(descriptor, descriptor.reason, REASON_MESSAGES[descriptor.reason]));
      continue;
    }
    if (explicitKeys !== undefined) {
      const verified = singleCardVerification(card, rawSignatures[index], explicitKeys, index);
      signatures.push({
        ...addX5uNote(
          verified ?? asFailedSignature(descriptor, "SIG_MALFORMED", "signature is malformed"),
          descriptor.x5u !== undefined,
        ),
        key_source: explicitSource,
      });
      continue;
    }
    const jku = descriptor.jku;
    let keyUrl = `https://${domain}/.well-known/jwks.json`;
    let keyHost = domain;
    let sameHost = true;
    if (jku !== undefined) {
      const parsedJku = new URL(jku);
      keyHost = parsedJku.host.toLowerCase();
      sameHost = keyHost === domain;
      if (!sameHost && !allowedHosts.has(keyHost)) {
        signatures.push(asFailedSignature(
          descriptor,
          "KEY_JKU_HOST_NOT_ALLOWED",
          `jku ${jku} is on another host; pass --allow-jku-host ${keyHost} to allow it`,
        ));
        continue;
      }
      keyUrl = parsedJku.href;
    }
    let resolved: { keys: PublicJwk[]; source: string };
    try {
      resolved = await remoteKeys(keyUrl, keyHost, deps, cache, sameHost, jku === undefined);
    } catch (error) {
      const fetchCode = error instanceof FetchError ? error.code : "FETCH_FAILED";
      const message = error instanceof FetchError ? error.message : "JWKS fetch failed";
      signatures.push(asFailedSignature(descriptor, "SIG_KEY_NOT_FOUND", `${fetchCode}: ${message}`));
      continue;
    }
    const verified = singleCardVerification(card, rawSignatures[index], resolved.keys, index);
    signatures.push({
      ...addX5uNote(
        verified ?? asFailedSignature(descriptor, "SIG_MALFORMED", "signature is malformed"),
        descriptor.x5u !== undefined,
      ),
      key_source: resolved.source,
    });
  }
  const verification = {
    ...baseline,
    signatures,
  };
  const result = cardVerificationResult(verification, fields, signatures, requireAll);
  result.lines.unshift(`card: ${cardUrl}`, ...redirectLines);
  return result;
}
