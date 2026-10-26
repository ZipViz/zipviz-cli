import { CliError } from "../errors.js";
import type { FetchFn } from "../api.js";

export interface JoinResponse { status: number; body: Record<string, unknown> | null; retryAfterMs: number | null }

/** A bounded, redirect-free transport: canonical start bytes must never be reserialized. */
export class JoinClient {
  constructor(readonly origin: string, private readonly fetch: FetchFn) {}

  async request(path: string, bytes?: string): Promise<JoinResponse> {
    let response: Response;
    try {
      response = await this.fetch(`${this.origin}${path}`, {
        method: bytes === undefined ? "GET" : "POST", body: bytes,
        headers: { accept: "application/json", ...(bytes === undefined ? {} : { "content-type": "application/json" }) },
        redirect: "error", signal: AbortSignal.timeout(15_000),
      });
    } catch { throw new CliError("E_NETWORK", "could not reach the signup registry; pending files are retained"); }
    let body: Record<string, unknown> | null = null;
    let text: string | null = null;
    try {
      const reader = response.body?.getReader();
      if (reader) {
        const chunks: Uint8Array[] = []; let length = 0;
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            length += value.byteLength;
            if (length > 16_384) { await reader.cancel().catch(() => undefined); chunks.length = 0; break; }
            chunks.push(value);
          }
        } finally { reader.releaseLock(); }
        if (length <= 16_384) text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
      }
    } catch { throw new CliError("E_NETWORK", "could not read the signup registry response; pending files are retained"); }
    try {
      const parsed: unknown = text === null ? null : JSON.parse(text);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    } catch { body = null; }
    const retry = response.headers.get("retry-after") ?? "";
    const retryAfterMs = /^\d{1,5}$/.test(retry) && Number(retry) >= 1 && Number(retry) <= 86400 ? Number(retry) * 1000 : null;
    return { status: response.status, body, retryAfterMs };
  }
}

const MESSAGES: Record<string, string> = {
  E_SIGNUP_SHAPE: "the registry refused the signup request shape",
  E_NAME_FORMAT: "the chosen name is invalid",
  E_KEY_INVALID: "the signup public key is invalid",
  E_RUNTIME: "the runtime must be claude, codex, buzz, openclaw, hermes or other",
  E_STALE: "the signup signature is stale; check the local clock",
  E_SIGNUP_AUD: "the signup audience does not match; check --aud",
  E_SIGNUP_PROOF: "the registry refused the signup proof",
  E_NAME_RESERVED: "the chosen name is reserved",
  E_NAME_EXHAUSTED: "the registry could not assign a name; pending files are retained",
  E_KEY_REGISTERED: "this key is already registered",
  E_KEY_PENDING: "this key already has a pending request; retain and resume that request",
  E_SIGNUP_ID_CONFLICT: "this signup id belongs to a different request",
  E_INTRO_INVALID: "the introduction is invalid",
  E_INTRO_USED: "the introduction was already used",
  E_INTRO_UNAVAILABLE: "the introducer does not currently allow introductions",
  E_RATE_LIMITED: "too many signup attempts; try again later",
  E_RATE_LIMIT_UNAVAILABLE: "signup rate limiting is unavailable; try again later",
  E_SIGNUP_BUSY: "signup capacity is temporarily exhausted",
  E_SIGNUP_UNAVAILABLE: "signup is temporarily unavailable; resume the same request later",
  E_SIGNUP_PAUSED: "signups are paused; pending files are retained",
  E_SIGNUP_NOT_FOUND: "the signup was not found; pending files are retained",
  E_SIGNUP_FINAL: "the signup is already final; check its status",
  E_REPLAY: "the cancellation nonce was already used; check signup status",
  E_SLOW_DOWN: "polling is rate limited; try again later",
  E_NOT_FOUND: "signup is not enabled on this registry",
  E_SIGNUP_DISABLED: "signup is not enabled on this registry",
};

export function responseCode(response: JoinResponse): string {
  if (response.status === 200 && typeof response.body?.service === "string" && Array.isArray(response.body.endpoints)) return "E_SIGNUP_DISABLED";
  const code = response.body?.code;
  return typeof code === "string" && Object.hasOwn(MESSAGES, code) ? code : "E_UNEXPECTED_RESPONSE";
}

export function joinError(response: JoinResponse): CliError {
  const code = responseCode(response);
  // Never echo an untrusted body: it may contain an email or request bytes.
  return new CliError(code, MESSAGES[code] ?? "the registry returned an unexpected signup response", 1, response.status);
}
