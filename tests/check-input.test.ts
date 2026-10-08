import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { MAX_INPUT_BYTES, readLimited } from "../src/check.js";

describe("bounded stdin reading", () => {
  it("stops pulling stream chunks as soon as the byte limit is exceeded", async () => {
    let pulledAfterLimit = false;
    async function* chunks() {
      yield new Uint8Array(MAX_INPUT_BYTES);
      yield new Uint8Array([0x20]);
      pulledAfterLimit = true;
      throw new Error("stream was drained after exceeding its limit");
    }

    await expect(readLimited(Readable.from(chunks(), { highWaterMark: 0 }), MAX_INPUT_BYTES)).rejects.toMatchObject({
      code: "E_INPUT_TOO_LARGE",
      exitCode: 6,
    });
    expect(pulledAfterLimit).toBe(false);
  });

  it("terminates a never-ending source immediately after crossing the cap", async () => {
    let pulls = 0;
    let closed = false;
    async function* growingSource() {
      try {
        while (true) {
          pulls += 1;
          // Bound mutation runs: a missing cap fails before a third allocation.
          if (pulls > 2) throw new Error("safety guard: read continued past the cap");
          yield new Uint8Array(pulls === 1 ? MAX_INPUT_BYTES : 1);
        }
      } finally {
        closed = true;
      }
    }

    await expect(readLimited(growingSource(), MAX_INPUT_BYTES)).rejects.toMatchObject({
      code: "E_INPUT_TOO_LARGE",
      message: "input exceeds the 1 MiB limit",
      exitCode: 6,
    });
    expect(pulls).toBe(2);
    expect(closed).toBe(true);
  });

  it.each([
    [3, "3 byte"],
    [2 * 1024 * 1024, "2 MiB"],
  ])("formats the passed %i byte limit", async (limit, label) => {
    await expect(readLimited(Readable.from([new Uint8Array(limit + 1)]), limit))
      .rejects.toMatchObject({ message: `input exceeds the ${label} limit` });
  });

});
