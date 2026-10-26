import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalizeJson } from "../src/a2a/jcs.js";
import { PendingSignupStore, type PendingAttempt } from "../src/join/store.js";

const ID = "00000000-0000-4000-8000-000000000001";
const ORIGIN = { registry_origin: "https://signup.example", audience: "signup.example" };
const fixtures: string[] = [];

function fixture() {
  const parent = mkdtempSync(path.join(tmpdir(), "zipviz-synthetic-join-"));
  fixtures.push(parent);
  const home = path.join(parent, ".zipviz");
  return { parent, home, store: new PendingSignupStore(home) };
}

function attempt(issuedAt = 1793000000000, name = "synthetic"): PendingAttempt {
  const request = canonicalizeJson({
    name, owner_email: "synthetic@example.invalid", runtime: "codex", introduced_by: null,
    proof: { signup_id: ID, public_key: "ab".repeat(32), issued_at_ms: issuedAt, signature: { value_base64url: "A".repeat(86) } },
  });
  return {
    request_b64url: Buffer.from(request).toString("base64url"),
    request_digest: createHash("sha256").update(request).digest("hex"),
    issued_at_ms: issuedAt,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of fixtures.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("private pending signup store (disposable synthetic fixtures)", () => {
  it("creates 0700 directories and separate 0600 key/metadata, without exposing key bytes", async () => {
    const { store, home } = fixture();
    const key = await store.generate(ID);
    const first = attempt();
    await store.create(ID, first, ORIGIN);
    for (const dir of [home, path.join(home, "keys"), store.dir]) expect(statSync(dir).mode & 0o777).toBe(0o700);
    for (const file of [store.keyPathFor(ID), store.metadataPathFor(ID)]) expect(statSync(file).mode & 0o777).toBe(0o600);
    expect((await store.loadKey(ID)).publicKey).toBe(key.publicKey);
    expect(await store.read(ID)).toEqual({ schema_version: "1.0", signup_id: ID, ...ORIGIN, attempts: [first] });
    expect(JSON.stringify(key)).not.toContain("PRIVATE KEY");
    expect(readdirSync(store.dir).sort()).toEqual([`${ID}.json`, `${ID}.key`]);
  });

  it("keeps each exact attempt across append, receipt and restart", async () => {
    const { store, home } = fixture();
    const first = attempt();
    const second = attempt(first.issued_at_ms + 301000);
    await store.create(ID, first, ORIGIN);
    await store.appendAttempt(ID, second);
    const restarted = new PendingSignupStore(home);
    expect((await restarted.read(ID)).attempts).toEqual([first, second]);
    await restarted.saveReceipt(ID, { signup_id: ID, user_code: "BCDF-GHJK" });
    expect((await store.read(ID)).attempts).toEqual([first, second]);
    expect(statSync(store.metadataPathFor(ID)).mode & 0o777).toBe(0o600);
    await expect(store.appendAttempt(ID, attempt(second.issued_at_ms + 301000))).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    await expect(store.saveReceipt(ID, { signup_id: ID, user_code: "JKLM-NPQR" })).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    expect((await store.read(ID)).attempts).toEqual([first, second]);
  });

  it("stops at eight attempts with all bytes retained", async () => {
    const { store } = fixture();
    await store.create(ID, attempt(), ORIGIN);
    for (let i = 1; i < 8; i++) await store.appendAttempt(ID, attempt(1793000000000 + i * 301000));
    const before = readFileSync(store.metadataPathFor(ID));
    await expect(store.appendAttempt(ID, attempt(1793000000000 + 8 * 301000))).rejects.toMatchObject({ code: "E_JOIN_RETRY_LIMIT" });
    expect(readFileSync(store.metadataPathFor(ID))).toEqual(before);
  });

  it("refuses changed request fields, corrupt digests and noncanonical request bytes", async () => {
    const { store } = fixture();
    await store.create(ID, attempt(), ORIGIN);
    const before = readFileSync(store.metadataPathFor(ID));
    await expect(store.appendAttempt(ID, attempt(1793000301000, "changed"))).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    await expect(store.appendAttempt(ID, { ...attempt(1793000301000), request_digest: "00".repeat(32) })).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    const noncanonical = Buffer.from(Buffer.from(attempt(1793000301000).request_b64url, "base64url").toString("utf8") + " ");
    await expect(store.appendAttempt(ID, {
      request_b64url: noncanonical.toString("base64url"), request_digest: createHash("sha256").update(noncanonical).digest("hex"), issued_at_ms: 1793000301000,
    })).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    expect(readFileSync(store.metadataPathFor(ID))).toEqual(before);
  });

  it("rejects malformed UTF-8 even when decoding would create valid canonical JSON", async () => {
    const { store } = fixture();
    const first = attempt();
    const validText = Buffer.from(first.request_b64url, "base64url").toString("utf8");
    const invalidUtf8 = Buffer.from(validText.replace("synthetic@example.invalid", "\ufffd@example.invalid"));
    const marker = invalidUtf8.indexOf(Buffer.from("\ufffd"));
    const malformed = Buffer.concat([invalidUtf8.subarray(0, marker), Buffer.from([0xff]), invalidUtf8.subarray(marker + 3)]);
    await expect(store.create(ID, {
      request_b64url: malformed.toString("base64url"), request_digest: createHash("sha256").update(malformed).digest("hex"), issued_at_ms: first.issued_at_ms,
    }, ORIGIN)).rejects.toMatchObject({ code: "E_JOIN_PENDING_INVALID" });
    expect(existsSync(store.metadataPathFor(ID))).toBe(false);
  });

  it("uses no-clobber creation for both key and metadata", async () => {
    const { store } = fixture();
    await store.generate(ID);
    await store.create(ID, attempt(), ORIGIN);
    const key = readFileSync(store.keyPathFor(ID));
    const metadata = readFileSync(store.metadataPathFor(ID));
    await expect(store.generate(ID)).rejects.toMatchObject({ code: "E_KEY_EXISTS" });
    await expect(store.create(ID, attempt(), ORIGIN)).rejects.toMatchObject({ code: "E_JOIN_EXISTS" });
    expect(readFileSync(store.keyPathFor(ID))).toEqual(key);
    expect(readFileSync(store.metadataPathFor(ID))).toEqual(metadata);
  });

  it("refuses metadata and key symlinks without touching their targets", async () => {
    const { store, parent } = fixture();
    await store.create(ID, attempt(), ORIGIN);
    const external = path.join(parent, "synthetic-target");
    writeFileSync(external, "must remain unchanged", { mode: 0o600 });
    rmSync(store.metadataPathFor(ID));
    symlinkSync(external, store.metadataPathFor(ID));
    symlinkSync(external, store.keyPathFor(ID));
    await expect(store.read(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    await expect(store.loadKey(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    await expect(store.create(ID, attempt(), ORIGIN)).rejects.toMatchObject({ code: "E_JOIN_EXISTS" });
    await expect(store.generate(ID)).rejects.toMatchObject({ code: "E_KEY_EXISTS" });
    expect(readFileSync(external, "utf8")).toBe("must remain unchanged");
  });

  it("rejects symlinked directory levels and permissive existing directories", async () => {
    for (const level of ["home", "keys", "pending"] as const) {
      const { store, home, parent } = fixture();
      const external = path.join(parent, "synthetic-external");
      mkdirSync(external, { mode: 0o700 });
      const target = level === "home" ? home : level === "keys" ? path.join(home, "keys") : store.dir;
      mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      symlinkSync(external, target);
      await expect(store.generate(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
      expect(readdirSync(external)).toEqual([]);
    }
    for (const level of ["home", "keys", "pending"] as const) {
      const { store, home } = fixture();
      await store.create(ID, attempt(), ORIGIN);
      const target = level === "home" ? home : level === "keys" ? path.join(home, "keys") : store.dir;
      chmodSync(target, level === "home" ? 0o777 : 0o755);
      await expect(store.read(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
      await expect(store.generate(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    }
  });

  it("rejects permissive, foreign-owner and non-regular metadata", async () => {
    const { store } = fixture();
    await store.create(ID, attempt(), ORIGIN);
    chmodSync(store.metadataPathFor(ID), 0o644);
    await expect(store.read(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
    chmodSync(store.metadataPathFor(ID), 0o600);
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
      await expect(store.read(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
      vi.restoreAllMocks();
    }
    rmSync(store.metadataPathFor(ID));
    mkdirSync(store.metadataPathFor(ID), { mode: 0o700 });
    await expect(store.read(ID)).rejects.toMatchObject({ code: "E_KEY_UNSAFE" });
  });

  it("adopts by no-clobber link and unlink, deleting metadata only after successful move", async () => {
    const { store } = fixture();
    const local = await store.generate(ID);
    await store.create(ID, attempt(), ORIGIN);
    await store.saveReceipt(ID, { signup_id: ID });
    const inode = statSync(store.keyPathFor(ID)).ino;
    const destination = await store.adopt(ID, "synthetic-1234.z.viz");
    expect(statSync(destination).ino).toBe(inode);
    expect(statSync(destination).mode & 0o777).toBe(0o600);
    expect((await store.keys.load("synthetic-1234.z.viz")).publicKey).toBe(local.publicKey);
    expect(existsSync(store.keyPathFor(ID))).toBe(false);
    expect(existsSync(store.metadataPathFor(ID))).toBe(false);
  });

  it("keeps pending key and history when adoption would clobber a file or symlink", async () => {
    for (const symlink of [false, true]) {
      const { store, parent } = fixture();
      await store.generate(ID);
      await store.create(ID, attempt(), ORIGIN);
      await store.saveReceipt(ID, { signup_id: ID });
      const dst = store.keys.pathFor("synthetic-1234.z.viz");
      const target = path.join(parent, "synthetic-existing");
      writeFileSync(target, "existing synthetic file", { mode: 0o600 });
      if (symlink) symlinkSync(target, dst);
      else writeFileSync(dst, "existing synthetic key", { mode: 0o600 });
      const before = readFileSync(store.metadataPathFor(ID));
      await expect(store.adopt(ID, "synthetic-1234.z.viz")).rejects.toMatchObject({ code: "E_KEY_EXISTS" });
      expect(existsSync(store.keyPathFor(ID))).toBe(true);
      expect(readFileSync(store.metadataPathFor(ID))).toEqual(before);
      expect(readFileSync(target, "utf8")).toBe("existing synthetic file");
      expect(lstatSync(dst).isSymbolicLink()).toBe(symlink);
    }
  });

  it("retains key and metadata when the caller's checked public key no longer matches", async () => {
    const { store } = fixture();
    await store.generate(ID);
    await store.create(ID, attempt(), ORIGIN);
    await store.saveReceipt(ID, { signup_id: ID });
    await expect(store.adopt(ID, "synthetic-1234.z.viz", "00".repeat(32))).rejects.toMatchObject({ code: "E_UNEXPECTED_RESPONSE" });
    expect(existsSync(store.keyPathFor(ID))).toBe(true);
    expect(existsSync(store.metadataPathFor(ID))).toBe(true);
    expect(existsSync(store.keys.pathFor("synthetic-1234.z.viz"))).toBe(false);
  });

  it("refuses unsafe ids before creating files", async () => {
    const { store, home } = fixture();
    for (const id of ["../outside", "AAAAAAAA-0000-4000-8000-000000000001", "00000000-0000-0000-8000-000000000001", "default"]) {
      await expect(store.generate(id)).rejects.toMatchObject({ code: "E_USAGE" });
    }
    expect(existsSync(home)).toBe(false);
  });

  it("preserves all data on a live-process lock and recovers a dead-process lock", async () => {
    const { store } = fixture();
    await store.create(ID, attempt(), ORIGIN);
    const lock = path.join(store.dir, `.${ID}.lock`);
    writeFileSync(lock, String(process.pid), { mode: 0o600 });
    const before = readFileSync(store.metadataPathFor(ID));
    await expect(store.appendAttempt(ID, attempt(1793000301000))).rejects.toMatchObject({ code: "E_JOIN_BUSY" });
    expect(readFileSync(store.metadataPathFor(ID))).toEqual(before);
    rmSync(lock);
    writeFileSync(lock, "2147483647", { mode: 0o600 });
    await store.appendAttempt(ID, attempt(1793000301000));
    expect((await store.read(ID)).attempts).toHaveLength(2);
    expect(existsSync(lock)).toBe(false);
  });
});
