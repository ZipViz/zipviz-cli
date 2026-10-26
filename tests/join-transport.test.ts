import { describe, expect, it } from "vitest";
import { JoinClient, joinError, responseCode } from "../src/join/client.js";

const ORIGIN = "https://api.zipviz.ai";
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers });

describe("join bounded transport and private diagnostics", () => {
  it("sends canonical bytes unchanged, disables redirects and limits the request lifetime", async () => {
    const canonical = '{"introduced_by":null,"proof":{"issued_at_ms":1793000000000}}';
    const seen: Array<{ url: string; init: RequestInit | undefined }> = [];
    const client = new JoinClient(ORIGIN, async (url, init) => { seen.push({ url, init }); return json({ state: "pending" }, 201); });
    expect(await client.request("/v1/signup/start", canonical)).toMatchObject({ status: 201, body: { state: "pending" } });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(`${ORIGIN}/v1/signup/start`);
    expect(seen[0]!.init).toMatchObject({ method: "POST", body: canonical, redirect: "error", headers: { accept: "application/json", "content-type": "application/json" } });
    expect(seen[0]!.init!.signal).toBeInstanceOf(AbortSignal);
  });

  it("uses GET for a poll with no request body or content-type", async () => {
    let captured: RequestInit | undefined;
    const client = new JoinClient(ORIGIN, async (_url, init) => { captured = init; return json({}); });
    await client.request("/v1/signup/synthetic-id");
    expect(captured).toMatchObject({ method: "GET", headers: { accept: "application/json" }, redirect: "error" });
    expect(captured!.body).toBeUndefined();
    expect(new Headers(captured!.headers).has("content-type")).toBe(false);
  });

  it.each(["0", "86401", "-1", "1.5", "Thu, 01 Jan 1970 00:00:00 GMT", "1e3", "arbitrary"])("ignores invalid Retry-After %s", async retry => {
    const client = new JoinClient(ORIGIN, async () => json({ code: "E_SLOW_DOWN" }, 429, { "Retry-After": retry }));
    expect((await client.request("/v1/signup/synthetic-id")).retryAfterMs).toBeNull();
  });

  it.each([["1", 1000], ["86400", 86400000]])("keeps bounded integer Retry-After %s", async (retry, expected) => {
    const client = new JoinClient(ORIGIN, async () => json({ code: "E_SLOW_DOWN" }, 429, { "Retry-After": String(retry) }));
    expect((await client.request("/v1/signup/synthetic-id")).retryAfterMs).toBe(expected);
  });

  it("cancels an oversized response stream and returns no untrusted parsed body", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode("x".repeat(16385))); },
      cancel() { cancelled = true; },
    });
    const client = new JoinClient(ORIGIN, async () => new Response(stream));
    expect((await client.request("/v1/signup/synthetic-id")).body).toBeNull();
    expect(cancelled).toBe(true);
  });

  it.each(["not-json", "null", "[]", '"string"'])("refuses a non-object response body %s", async bytes => {
    const client = new JoinClient(ORIGIN, async () => new Response(bytes));
    expect((await client.request("/v1/signup/synthetic-id")).body).toBeNull();
  });

  it("does not expose transport exceptions containing owner email or request material", async () => {
    const client = new JoinClient(ORIGIN, async () => { throw new Error("fixture-owner@example.invalid PRIVATE KEY synthetic request bytes"); });
    await expect(client.request("/v1/signup/start", "synthetic request bytes")).rejects.toMatchObject({ code: "E_NETWORK", message: expect.not.stringMatching(/example\.invalid|PRIVATE KEY|request bytes/) });
  });

  it.each([
    "E_SIGNUP_SHAPE", "E_NAME_FORMAT", "E_KEY_INVALID", "E_RUNTIME", "E_STALE", "E_SIGNUP_AUD", "E_SIGNUP_PROOF",
    "E_NAME_RESERVED", "E_NAME_EXHAUSTED", "E_KEY_REGISTERED", "E_KEY_PENDING", "E_SIGNUP_ID_CONFLICT",
    "E_INTRO_INVALID", "E_INTRO_USED", "E_INTRO_UNAVAILABLE", "E_RATE_LIMITED", "E_RATE_LIMIT_UNAVAILABLE",
    "E_SIGNUP_BUSY", "E_SIGNUP_UNAVAILABLE", "E_SIGNUP_PAUSED", "E_SIGNUP_NOT_FOUND", "E_SIGNUP_FINAL", "E_REPLAY", "E_SLOW_DOWN",
  ])("maps %s to a stable local message without echoing private server text", code => {
    const response = { status: 400, retryAfterMs: null, body: { code, error: "fixture-owner@example.invalid PRIVATE KEY synthetic request bytes" } };
    const error = joinError(response);
    expect(error.code).toBe(code);
    expect(error.message).not.toMatch(/example\.invalid|PRIVATE KEY|synthetic request bytes/);
    expect(error.httpStatus).toBe(400);
  });

  it.each(["E_NOT_IN_CONTRACT", "arbitrary", "E_NAME_FORMAT\nprivate", null, 7])("sanitizes unknown error code %s", code => {
    const response = { status: 503, retryAfterMs: null, body: { code, error: "fixture-owner@example.invalid" } };
    expect(responseCode(response)).toBe("E_UNEXPECTED_RESPONSE");
    expect(joinError(response)).toMatchObject({ code: "E_UNEXPECTED_RESPONSE", message: expect.not.stringContaining("example.invalid") });
  });
});
