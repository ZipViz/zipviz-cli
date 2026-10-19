import { lstat } from "node:fs/promises";
import path from "node:path";
import type { Api, ProbeResponse } from "./api.js";
import { usageError, CliError } from "./errors.js";
import type { LocalKey } from "./keys.js";
import type { Result } from "./output.js";
import type { Context } from "./commands.js";

/**
 * `zipviz doctor`: read-only diagnosis of the local key store and the registry.
 *
 * Every check reports `ok`, `failed` or `unknown`. `unknown` means the CLI could not
 * find out (unreachable registry, no signal, ambiguous timing) and is never shown as
 * `ok`. The invites check is informational: the registry has no read-only invite
 * signal, so it is always unknown and does not count toward the result or exit code.
 * Any other unknown does. Doctor never writes, chmods, generates keys, redeems,
 * registers or POSTs.
 */

export type CheckStatus = "ok" | "failed" | "unknown";

export type DoctorCheck = {
  status: CheckStatus;
  /** Stable reason code; null only when status is ok. */
  code: string | null;
  message: string;
  [detail: string]: unknown;
};

/** At least one check failed. */
export const DOCTOR_FAILED_EXIT = 11;
/** Nothing failed, but at least one check that counts is unknown. */
export const DOCTOR_UNKNOWN_EXIT = 12;
/** Checks reported in full but left out of the result and exit code. */
export const INFORMATIONAL_CHECKS: ReadonlySet<string> = new Set(["invites"]);

export const DOCTOR_TIMEOUT_MS = 5_000;
export const HEALTH_PATH = "/v1/health";
/** The registry rejects signed timestamps more than 5 minutes from its own clock. */
export const SIGNATURE_WINDOW_MS = 300_000;
/** Skew within this margin of the window is flagged: requests take time and clocks drift. */
export const SKEW_MARGIN_MS = 60_000;
const SKEW_LIMIT_MS = SIGNATURE_WINDOW_MS - SKEW_MARGIN_MS;
/** An HTTP Date header has one-second resolution. */
const DATE_RESOLUTION_MS = 1_000;
const REGISTRY_TEXT_MAX = 120;

/** Registry-supplied text: a bounded string, or null. Terminal escaping happens in main. */
function registryText(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return value.length > REGISTRY_TEXT_MAX ? `${value.slice(0, REGISTRY_TEXT_MAX)}…` : value;
}

const errnoCode = (e: unknown) => (e as NodeJS.ErrnoException).code ?? "unknown error";

/** lstat without following links: "absent", or the stat. Other errors are returned as codes. */
async function presence(p: string): Promise<"absent" | "present" | { error: string }> {
  try {
    await lstat(p);
    return "present";
  } catch (e) {
    return errnoCode(e) === "ENOENT" ? "absent" : { error: errnoCode(e) };
  }
}

export async function keyStoreCheck(keys: Context["keys"]): Promise<DoctorCheck> {
  const home = path.dirname(keys.dir);
  const base = { home, keys_dir: keys.dir };
  const missing = (where: string): DoctorCheck => ({
    status: "failed",
    code: "DOCTOR_KEY_STORE_MISSING",
    message: `${where} does not exist; no local identity yet (run: zipviz keygen --name <label>)`,
    ...base,
    keys: [],
  });
  for (const dir of [home, keys.dir]) {
    const p = await presence(dir);
    if (p === "absent") return missing(dir);
    if (p !== "present") {
      return {
        status: "failed", code: "E_KEY_UNREADABLE", message: `cannot inspect ${dir}: ${p.error}`, ...base, keys: [],
      };
    }
  }
  // KeyStore.list() applies the same directory checks as whoami/load: real directory
  // (no symlink), owned by this user, ~/.zipviz not group/world-writable, keys/ 0700.
  let ids: string[];
  try {
    ids = await keys.list();
  } catch (e) {
    if (!(e instanceof CliError)) throw e;
    return { status: "failed", code: e.code, message: e.message, ...base, keys: [] };
  }
  if (ids.length === 0) {
    return {
      status: "failed",
      code: "DOCTOR_NO_KEYS",
      message: `no key files in ${keys.dir} (run: zipviz keygen --name <label>)`,
      ...base,
      keys: [],
    };
  }
  const entries: Array<Record<string, unknown>> = [];
  let firstError: CliError | null = null;
  for (const id of ids) {
    let key: LocalKey;
    try {
      // load() opens with O_NOFOLLOW and checks regular file, owner, 0600, size and Ed25519.
      // Only the public key leaves LocalKey.
      key = await keys.load(id);
    } catch (e) {
      if (!(e instanceof CliError)) throw e;
      firstError ??= e;
      entries.push({ key_id: id, path: keys.pathFor(id), public_key: null, error: { code: e.code, message: e.message } });
      continue;
    }
    entries.push({ key_id: id, path: key.path, public_key: key.publicKey, error: null });
  }
  if (firstError) {
    const bad = entries.filter((k) => k.error !== null).length;
    return {
      status: "failed",
      code: firstError.code,
      message: `${bad} of ${entries.length} key file(s) failed safety checks`,
      ...base,
      keys: entries,
    };
  }
  return {
    status: "ok",
    code: null,
    message: `${entries.length} key file(s) in ${keys.dir}; directories and files pass ownership, symlink and permission checks`,
    ...base,
    keys: entries,
  };
}

export function registryCheck(api: Api, probe: ProbeResponse): DoctorCheck {
  const base = { api: api.origin, endpoint: `GET ${HEALTH_PATH}` };
  if (!probe.reached) {
    return {
      status: "unknown",
      code: "DOCTOR_REGISTRY_UNREACHABLE",
      message: `could not reach ${api.origin} within ${DOCTOR_TIMEOUT_MS / 1000} s (network, DNS, TLS or timeout)`,
      ...base,
      http_status: null,
    };
  }
  const b = probe.body;
  if (probe.status === 200 && b?.status === "ok") {
    return { status: "ok", code: null, message: `${api.origin} answered ${HEALTH_PATH} with status ok`, ...base, http_status: 200 };
  }
  const registryCode = registryText(b?.code);
  const registryMessage = registryText(b?.error);
  const extra = { ...base, http_status: probe.status, registry_code: registryCode, registry_message: registryMessage };
  if (probe.status >= 500) {
    return {
      status: "failed",
      code: "DOCTOR_REGISTRY_ERROR",
      message: `${api.origin} reports an error: HTTP ${probe.status}${registryCode ? ` ${registryCode}` : ""}`,
      ...extra,
    };
  }
  return {
    status: "unknown",
    code: "DOCTOR_REGISTRY_UNEXPECTED",
    message: `${api.origin} answered HTTP ${probe.status} without a recognizable health response`,
    ...extra,
  };
}

/**
 * The registry has no read-only invite signal. Its invite routes answer POST only;
 * every GET falls through to the default service document whether invites are on or
 * off, so `isInvitesDisabled` on a GET would report "disabled" falsely. Doctor never
 * POSTs, so this is always unknown; `redeem`/`invite` report E_INVITES_DISABLED.
 */
export function invitesCheck(): DoctorCheck {
  return {
    status: "unknown",
    code: "DOCTOR_INVITES_NO_SIGNAL",
    message: "the registry has no read-only invite signal; redeem reports E_INVITES_DISABLED if invites are off",
    invites_enabled: null,
  };
}

function formatDuration(ms: number): string {
  const s = Math.round(Math.abs(ms) / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}

/** IMF-fixdate / RFC 850 / asctime as accepted by Date.parse; null when unusable. */
function parseHttpDate(value: string | null): number | null {
  if (value === null || !/^[A-Za-z]{3}/.test(value.trim())) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : null;
}

/**
 * Skew = registry clock − local clock. The Date header is truncated to the second and
 * was generated somewhere between send and receive, so the true skew lies in
 * [date − receivedAt, date + 999 − sentAt]. Only a bound entirely inside or outside
 * the limit is reported as ok or failed; anything in between is unknown.
 */
export function clockCheck(probe: ProbeResponse): DoctorCheck {
  const base = { window_ms: SIGNATURE_WINDOW_MS, margin_ms: SKEW_MARGIN_MS };
  const unknown = (code: string, message: string): DoctorCheck => ({
    status: "unknown", code, message, ...base, skew_ms: null, uncertainty_ms: null, server_date: null,
  });
  if (!probe.reached) return unknown("DOCTOR_CLOCK_UNREACHABLE", "registry unreachable; clock skew not measured");
  const serverDate = parseHttpDate(probe.date);
  if (serverDate === null) {
    return unknown("DOCTOR_CLOCK_NO_DATE", "registry response had no usable Date header; clock skew not measured");
  }
  const low = serverDate - probe.receivedAt;
  const high = serverDate + DATE_RESOLUTION_MS - 1 - probe.sentAt;
  // The local clock moved backwards during the request (or the timings are garbage):
  // the interval is empty and no skew, sign or bound derived from it means anything.
  if (!(Number.isFinite(low) && Number.isFinite(high)) || probe.sentAt > probe.receivedAt || high < low) {
    return unknown(
      "DOCTOR_CLOCK_INVALID_INTERVAL",
      "local clock moved during the request (receive time before send time); timing unusable, clock skew not measured",
    );
  }
  const skew = Math.round((low + high) / 2);
  const uncertainty = Math.round((high - low) / 2);
  const details = { ...base, skew_ms: skew, uncertainty_ms: uncertainty, server_date: registryText(probe.date) };
  const direction = skew > 0 ? "behind" : "ahead of";
  const about = `local clock is about ${formatDuration(skew)} ${direction} the registry (±${formatDuration(Math.max(uncertainty, 1000))})`;
  const note = "skew only; this does not verify any signature";
  if (low >= -SKEW_LIMIT_MS && high <= SKEW_LIMIT_MS) {
    return { status: "ok", code: null, message: `${about}; inside the ±5 minute signature window (${note})`, ...details };
  }
  if (low > SKEW_LIMIT_MS || high < -SKEW_LIMIT_MS) {
    const beyond = low > SIGNATURE_WINDOW_MS || high < -SIGNATURE_WINDOW_MS;
    return {
      status: "failed",
      code: "DOCTOR_CLOCK_SKEW",
      message: `${about}; ${beyond ? "outside" : "within 1 minute of"} the ±5 minute signature window, signed requests may be rejected (sync your clock)`,
      ...details,
    };
  }
  return {
    ...details,
    status: "unknown",
    code: "DOCTOR_CLOCK_AMBIGUOUS",
    message: `${about}; the request took too long to tell whether that is inside the safe range`,
  };
}

const LABELS: Record<string, string> = {
  key_store: "key store",
  registry: "registry",
  invites: "invites",
  clock: "clock",
};

export async function doctor({ api, keys, parsed }: Context, deps: { now?: () => number }): Promise<Result> {
  if (parsed.positional.length !== 0) throw usageError("usage: zipviz doctor [--api <origin>] [--json]");
  const now = deps.now ?? Date.now;
  // Independent: the local check runs regardless of the network, and vice versa.
  const [keyStore, probe] = await Promise.all([
    keyStoreCheck(keys).catch((e: unknown): DoctorCheck => ({
      status: "unknown",
      code: e instanceof CliError ? e.code : "DOCTOR_INTERNAL",
      message: e instanceof CliError ? e.message : "key store check could not complete",
      home: path.dirname(keys.dir),
      keys_dir: keys.dir,
      keys: [],
    })),
    api.probe(HEALTH_PATH, DOCTOR_TIMEOUT_MS, now),
  ]);
  const checks: Record<string, DoctorCheck> = {
    key_store: keyStore,
    registry: registryCheck(api, probe),
    invites: invitesCheck(),
    clock: clockCheck(probe),
  };
  const all = Object.values(checks);
  const summary = {
    ok: all.filter((c) => c.status === "ok").length,
    failed: all.filter((c) => c.status === "failed").length,
    unknown: all.filter((c) => c.status === "unknown").length,
  };
  const counted = Object.entries(checks).filter(([id]) => !INFORMATIONAL_CHECKS.has(id)).map(([, c]) => c);
  const status: CheckStatus = counted.some((c) => c.status === "failed") ? "failed"
    : counted.some((c) => c.status === "unknown") ? "unknown" : "ok";
  const exitCode = status === "failed" ? DOCTOR_FAILED_EXIT : status === "unknown" ? DOCTOR_UNKNOWN_EXIT : 0;

  const lines = [`zipviz doctor: registry ${api.origin}, home ${path.dirname(keys.dir)} (read-only)`];
  for (const [id, check] of Object.entries(checks)) {
    lines.push(`${`[${check.status}]`.padEnd(10)}${LABELS[id]!.padEnd(11)}${check.message}`);
    if (id === "key_store") {
      for (const k of check.keys as Array<Record<string, unknown>>) {
        const err = k.error as { message: string } | null;
        lines.push(`${" ".repeat(21)}${String(k.key_id)}  ${err ? `UNSAFE: ${err.message}` : String(k.public_key)}`);
      }
    }
  }
  lines.push(
    `result: ${status}: ${summary.ok} ok, ${summary.failed} failed, ${summary.unknown} unknown`
    + (status === "unknown" ? " (unknown is not healthy: the CLI could not confirm it)"
      : checks.invites!.status === "unknown" ? " (invites is informational until the registry has a read-only signal)" : ""),
  );
  return {
    ok: status === "ok",
    exitCode,
    data: { status, api: api.origin, zipviz_home: path.dirname(keys.dir), summary, checks },
    lines,
  };
}
