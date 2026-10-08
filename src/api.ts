import { CliError, INVITES_DISABLED, usageError } from "./errors.js";

export const DEFAULT_API = "https://api.zipviz.ai";
const TIMEOUT_MS = 15_000;

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export type JsonResponse = { status: number; body: Record<string, unknown> | null };

/** Result of `Api.probe`; times are local epoch milliseconds. */
export type ProbeResponse =
  | (JsonResponse & { reached: true; date: string | null; sentAt: number; receivedAt: number })
  | { reached: false; sentAt: number; receivedAt: number };

const PROBE_MAX_BYTES = 16 * 1024;

/** Read at most `max` bytes of a response body; null if it is larger. */
async function readCapped(res: Response, max: number): Promise<string | null> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** https origin, or http on localhost/127.0.0.1 for local testing. */
export function parseApiOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw usageError("--api must be an https origin (or http://localhost / http://127.0.0.1)");
  }
  const local = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if ((url.protocol !== "https:" && !local) || url.pathname !== "/" || url.search || url.hash
      || url.username || url.password) {
    throw usageError("--api must be an https origin (or http://localhost / http://127.0.0.1)");
  }
  return url.origin;
}

export class Api {
  constructor(readonly origin: string, private readonly fetchFn: FetchFn) {}

  private async request(path: string, init: RequestInit): Promise<JsonResponse> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.origin}${path}`, {
        ...init,
        headers: { accept: "application/json", ...(init.body ? { "content-type": "application/json" } : {}) },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new CliError("E_NETWORK", `could not reach ${this.origin}`);
    }
    const text = await res.text().catch(() => "");
    let body: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    } catch {
      body = null;
    }
    return { status: res.status, body };
  }

  get(path: string): Promise<JsonResponse> {
    return this.request(path, { method: "GET" });
  }

  post(path: string, payload: unknown): Promise<JsonResponse> {
    return this.request(path, { method: "POST", body: JSON.stringify(payload) });
  }

  /**
   * One bounded diagnostic GET (used by `doctor`): never follows redirects, caps the
   * body, and records local send/receive times plus the `Date` header so callers can
   * estimate clock skew. Network failure is reported, not thrown.
   */
  async probe(path: string, timeoutMs: number, now: () => number = Date.now): Promise<ProbeResponse> {
    const sentAt = now();
    let res: Response;
    try {
      res = await this.fetchFn(`${this.origin}${path}`, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      return { reached: false, sentAt, receivedAt: now() };
    }
    const receivedAt = now();
    const date = res.headers.get("date");
    let body: Record<string, unknown> | null = null;
    try {
      const text = await readCapped(res, PROBE_MAX_BYTES);
      const parsed: unknown = text === null ? null : JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    } catch {
      body = null;
    }
    return { reached: true, status: res.status, body, date, sentAt, receivedAt };
  }

  /** GET /v1/agent/:domain/card; null when the registry has no such agent. */
  async card(domain: string): Promise<Record<string, unknown> | null> {
    const res = await this.get(`/v1/agent/${encodeURIComponent(domain)}/card`);
    if (res.status === 404) return null;
    if (res.status !== 200 || !res.body) {
      throw new CliError("E_REGISTRY", `registry card lookup returned HTTP ${res.status}`, 1, res.status);
    }
    return res.body;
  }
}

/**
 * With the invite flag off, the worker falls through to its default 200
 * service document for every invite route.
 */
export function isInvitesDisabled(res: JsonResponse): boolean {
  return res.status === 200 && typeof res.body?.service === "string" && Array.isArray(res.body?.endpoints);
}

export function disabledError(): CliError {
  return new CliError("E_INVITES_DISABLED", INVITES_DISABLED);
}

/** Turn a registry error body into a CliError with the registry's own code. */
export function registryError(res: JsonResponse, messages: Record<string, string> = {}): CliError {
  const code = typeof res.body?.code === "string" ? res.body.code : "E_REGISTRY";
  const fallback = typeof res.body?.error === "string" ? res.body.error : `registry returned HTTP ${res.status}`;
  return new CliError(code, messages[code] ?? fallback, 1, res.status);
}
