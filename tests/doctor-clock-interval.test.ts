import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { clockCheck, DOCTOR_UNKNOWN_EXIT } from "../src/doctor.js";
import { run, type Deps } from "../src/main.js";
import { makeHarness, type Harness } from "./harness.js";

const NOW = Date.parse("2026-10-07T12:00:00.000Z");
const httpDate = (ms: number) => new Date(ms).toUTCString();
const probe = (date: number, sentAt: number, receivedAt: number) =>
  ({ reached: true as const, status: 200, body: null, date: httpDate(date), sentAt, receivedAt });

let h: Harness | undefined;
afterEach(() => {
  h?.cleanup();
  h = undefined;
});

describe("clockCheck: inverted or empty timing interval", () => {
  it("is unknown (never ok, never negative skew) when the send time is after the receive time", () => {
    // Reviewer repro: sentAt = receivedAt + 10s, Date == receivedAt.
    const c = clockCheck(probe(NOW, NOW + 10_000, NOW));
    expect(c).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_INVALID_INTERVAL", skew_ms: null, uncertainty_ms: null });
    expect(c.message).toMatch(/local clock moved during the request/);
    expect(c.message).not.toMatch(/inside the ±5 minute/);
  });

  it("is unknown for a sub-second inversion too, even though the Date window would hide it", () => {
    const c = clockCheck(probe(NOW, NOW + 500, NOW));
    expect(c).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_INVALID_INTERVAL", skew_ms: null });
  });

  it("is unknown for an inversion far outside the window rather than a skew verdict", () => {
    const c = clockCheck(probe(NOW + 10 * 60_000, NOW + 30_000, NOW));
    expect(c).toMatchObject({ status: "unknown", code: "DOCTOR_CLOCK_INVALID_INTERVAL" });
  });

  it("still reports ordered timings normally (sentAt == receivedAt is ordered)", () => {
    expect(clockCheck(probe(NOW, NOW, NOW))).toMatchObject({ status: "ok", code: null });
    const c = clockCheck(probe(NOW, NOW - 200, NOW + 200));
    expect(c.skew_ms).toBe(500);
    expect(c.uncertainty_ms).toBe(700);
  });

  it("doctor --json and human output report the unusable interval as unknown, exit 12", async () => {
    h = makeHarness();
    await h.cli("keygen", "--name", "sophie");
    // The local clock steps back 10 s between send and receive.
    const times = [NOW + 10_000, NOW];
    const out: string[] = [];
    const deps: Deps = {
      fetch: async () => new Response(JSON.stringify({ status: "ok" }), {
        status: 200, headers: { "content-type": "application/json", date: httpDate(NOW) },
      }),
      stdout: (s) => out.push(s),
      stderr: (s) => out.push(s),
      zipvizHome: path.join(h.home, ".zipviz"),
      now: () => times.shift() ?? NOW,
    };
    expect(await run(["doctor", "--json"], deps)).toBe(DOCTOR_UNKNOWN_EXIT);
    const body = JSON.parse(out.join("")) as { checks: { clock: Record<string, unknown> } };
    expect(body.checks.clock).toMatchObject({
      status: "unknown", code: "DOCTOR_CLOCK_INVALID_INTERVAL", skew_ms: null, uncertainty_ms: null,
    });

    out.length = 0;
    times.push(NOW + 10_000, NOW);
    expect(await run(["doctor"], deps)).toBe(DOCTOR_UNKNOWN_EXIT);
    expect(out.join("")).toMatch(/\[unknown\]\s+clock\s+local clock moved during the request/);
  });
});
