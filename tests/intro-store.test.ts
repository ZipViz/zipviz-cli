import { createHmac } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IntroStore } from "../src/intro/store.js";
import { prepareStoreProcesses } from "./support/store-process.js";

const NOW = 1793000000000;
const DAY = 86400000;
const DOMAIN = "synthetic-1234.z.viz";
const PEER = "synthetic-runtime-thread:opaque-reference";
const DRAFT = "00000000-0000-4000-8000-000000000002";
const fixtures: string[] = [];

function fixture() {
  const parent = mkdtempSync(path.join(tmpdir(), "zipviz-synthetic-intros-"));
  fixtures.push(parent);
  const home = path.join(parent, ".zipviz");
  return { parent, home, store: new IntroStore(home) };
}

async function confirmation(store: IntroStore, peerRef = PEER, issuedAtMs = NOW) {
  return store.makeConfirmation({ domain: DOMAIN, peerRef, draftId: DRAFT,
    issuedAtMs, expiresAtMs: issuedAtMs + 3 * DAY, tokenDigest: "ab".repeat(32) });
}

function sent(store: IntroStore): { schema_version: string; sent: Record<string, number> } {
  return JSON.parse(readFileSync(store.sentPath, "utf8")) as { schema_version: string; sent: Record<string, number> };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const folder of fixtures.splice(0)) rmSync(folder, { recursive: true, force: true });
});

describe("private intro dedupe (disposable synthetic fixtures)", () => {
  it("prepares private directories/secret without marking a peer sent or persisting its reference", async () => {
    const { home, store } = fixture();
    await store.assertAvailable(PEER, NOW);
    const receipt = await confirmation(store);
    expect(receipt).toMatch(/^zvic1\./);
    expect(existsSync(store.sentPath)).toBe(false);
    for (const dir of [home, store.dir]) expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(store.secretPath).mode & 0o777).toBe(0o600);
    for (const name of readdirSync(store.dir)) {
      const bytes = readFileSync(path.join(store.dir, name));
      expect(bytes.toString("utf8")).not.toContain(PEER);
      expect(bytes.toString("utf8")).not.toContain("zvintro1.");
    }
  });

  it("records only authenticated explicit confirmation and deduplicates after restart", async () => {
    const { home, store } = fixture();
    await store.assertAvailable(PEER, NOW);
    const receipt = await confirmation(store);
    await store.assertAvailable(PEER, NOW + 1);
    expect(existsSync(store.sentPath)).toBe(false);
    expect(await store.confirmSent(PEER, receipt, NOW + 2, DOMAIN)).toEqual({ domain: DOMAIN, draft_id: DRAFT, confirmed_at_ms: NOW + 2 });
    expect(statSync(store.sentPath).mode & 0o777).toBe(0o600);
    const record = sent(store);
    expect(record.schema_version).toBe("1.0");
    expect(Object.keys(record.sent)).toHaveLength(1);
    expect(Object.keys(record.sent)[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.keys(record.sent)[0]).toBe(createHmac("sha256", readFileSync(store.secretPath)).update(PEER, "utf8").digest("hex"));
    expect(Object.values(record.sent)).toEqual([NOW + 2]);
    const raw = readFileSync(store.sentPath, "utf8");
    expect(raw).not.toContain(PEER);
    expect(raw).not.toContain(receipt);
    expect(raw).not.toContain(DRAFT);
    expect(raw).not.toContain(DOMAIN);
    const restart = new IntroStore(home);
    await expect(restart.assertAvailable(PEER, NOW + 2 + 30 * DAY - 1)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    await restart.assertAvailable(PEER, NOW + 2 + 30 * DAY);
    expect(readFileSync(store.sentPath, "utf8")).toBe(raw);
  });

  it("retains earlier peer entries when another confirmation is added", async () => {
    const { store } = fixture();
    await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
    const before = sent(store).sent;
    const other = "synthetic-peer:second";
    await store.confirmSent(other, await confirmation(store, other), NOW + 1, DOMAIN);
    expect(sent(store).sent).toMatchObject(before);
    expect(Object.keys(sent(store).sent)).toHaveLength(2);
    await expect(store.assertAvailable(PEER, NOW + 2)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    await expect(store.assertAvailable(other, NOW + 2)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
  });

  it("rejects replay and preserves the original confirmation timestamp", async () => {
    const { store } = fixture();
    const receipt = await confirmation(store);
    await store.confirmSent(PEER, receipt, NOW, DOMAIN);
    const before = readFileSync(store.sentPath);
    await expect(store.confirmSent(PEER, receipt, NOW + 1, DOMAIN)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    expect(readFileSync(store.sentPath)).toEqual(before);
  });

  it("binds a confirmation to its peer, domain, canonical bytes and issued time", async () => {
    const { store } = fixture();
    const receipt = await confirmation(store);
    const tampered = `${receipt.slice(0, -1)}${receipt.endsWith("A") ? "B" : "A"}`;
    for (const [peer, candidate, now, domain] of [
      ["synthetic-other-peer", receipt, NOW, DOMAIN],
      [PEER, receipt, NOW, "synthetic-9999.z.viz"],
      [PEER, tampered, NOW, DOMAIN],
      [PEER, `${receipt}=`, NOW, DOMAIN],
      [PEER, receipt, NOW - 1, DOMAIN],
      [PEER, "not-a-confirmation", NOW, DOMAIN],
    ] as const) {
      await expect(store.confirmSent(peer, candidate, now, domain)).rejects.toMatchObject({ code: "E_INTRO_CONFIRMATION" });
      expect(existsSync(store.sentPath)).toBe(false);
    }
  });

  it("records a caller's late confirmation after intro expiry and starts dedupe at confirmation time", async () => {
    const { home, store } = fixture();
    const receipt = await confirmation(store);
    const confirmedAt = NOW + 4 * DAY;
    expect(await new IntroStore(home).confirmSent(PEER, receipt, confirmedAt, DOMAIN)).toEqual({
      domain: DOMAIN, draft_id: DRAFT, confirmed_at_ms: confirmedAt,
    });
    expect(Object.values(sent(store).sent)).toEqual([confirmedAt]);
    await expect(store.assertAvailable(PEER, confirmedAt + 30 * DAY - 1)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    await store.assertAvailable(PEER, confirmedAt + 30 * DAY);
  });

  it("refuses a confirmation produced by another local store without logging its private contents", async () => {
    const { store: first } = fixture();
    const { store: second } = fixture();
    const receipt = await confirmation(first);
    const error = await second.confirmSent(PEER, receipt, NOW, DOMAIN).then(() => null, cause => cause as Error & { code: string });
    expect(error).toMatchObject({ code: "E_INTRO_CONFIRMATION" });
    expect(error?.message).not.toContain(PEER);
    expect(error?.message).not.toContain(receipt);
    expect(existsSync(second.sentPath)).toBe(false);
  });

  it("rejects invalid peer/time/draft parameters without creating sent state", async () => {
    const { home, store } = fixture();
    for (const peer of ["", "line\nbreak", "\0", "x".repeat(1025)]) {
      await expect(store.assertAvailable(peer, NOW)).rejects.toMatchObject({ code: "E_USAGE" });
    }
    expect(existsSync(home)).toBe(false);
    for (const now of [-1, NaN, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(store.assertAvailable(PEER, now)).rejects.toMatchObject({ code: "E_USAGE" });
    }
    const base = { domain: DOMAIN, peerRef: PEER, draftId: DRAFT, issuedAtMs: NOW, expiresAtMs: NOW + DAY, tokenDigest: "ab".repeat(32) };
    for (const change of [{ domain: "../unsafe" }, { draftId: "not-a-uuid" }, { tokenDigest: "not-a-digest" }, { expiresAtMs: NOW }, { expiresAtMs: NOW + 3 * DAY + 1 }]) {
      await expect(store.makeConfirmation({ ...base, ...change })).rejects.toMatchObject({ code: "E_INTRO_CONFIRMATION" });
      expect(existsSync(store.sentPath)).toBe(false);
    }
  });

  it("refuses symlinked directory levels before touching an external target", async () => {
    for (const level of ["home", "intros"] as const) {
      const { parent, home, store } = fixture();
      const external = path.join(parent, "synthetic-external");
      mkdirSync(external, { mode: 0o700 });
      const target = level === "home" ? home : store.dir;
      mkdirSync(path.dirname(target), { mode: 0o700, recursive: true });
      symlinkSync(external, target);
      await expect(store.assertAvailable(PEER, NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_UNSAFE" });
      expect(readdirSync(external)).toEqual([]);
    }
  });

  it("refuses symlinked secret/sent files without reading or overwriting their target", async () => {
    for (const kind of ["secret", "sent"] as const) {
      const { parent, store } = fixture();
      await store.assertAvailable(PEER, NOW);
      const target = path.join(parent, "synthetic-external");
      writeFileSync(target, "synthetic marker remains", { mode: 0o600 });
      const filename = kind === "secret" ? store.secretPath : store.sentPath;
      rmSync(filename, { force: true });
      symlinkSync(target, filename);
      await expect(store.assertAvailable(PEER, NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_UNSAFE" });
      expect(readFileSync(target, "utf8")).toBe("synthetic marker remains");
    }
  });

  it("refuses permissive directories, secret and sent files", async () => {
    for (const kind of ["home", "intros", "secret", "sent"] as const) {
      const { home, store } = fixture();
      await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
      const target = kind === "home" ? home : kind === "intros" ? store.dir : kind === "secret" ? store.secretPath : store.sentPath;
      chmodSync(target, kind === "home" ? 0o777 : kind === "intros" ? 0o755 : 0o644);
      await expect(store.assertAvailable("synthetic-other", NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_UNSAFE" });
    }
  });

  it("refuses a foreign owner or nonregular secret/sent entry", async () => {
    const { store } = fixture();
    await store.assertAvailable(PEER, NOW);
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
      await expect(store.assertAvailable(PEER, NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_UNSAFE" });
      vi.restoreAllMocks();
    }
    for (const file of [store.secretPath, store.sentPath]) {
      rmSync(file, { force: true });
      mkdirSync(file, { mode: 0o700 });
      await expect(store.assertAvailable(PEER, NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_UNSAFE" });
      rmSync(file, { recursive: true });
      if (file === store.secretPath) await store.assertAvailable(PEER, NOW);
    }
  });

  it("does not replace a missing secret when sent state already exists", async () => {
    const { store } = fixture();
    await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
    const before = readFileSync(store.sentPath);
    rmSync(store.secretPath);
    await expect(store.assertAvailable("synthetic-other", NOW)).rejects.toMatchObject({ code: "E_INTRO_STORE_INVALID" });
    expect(existsSync(store.secretPath)).toBe(false);
    expect(readFileSync(store.sentPath)).toEqual(before);
  });

  it("fails closed on oversized, malformed UTF-8, unknown schema and corrupt sent state", async () => {
    for (const bytes of [
      Buffer.alloc(128 * 1024, 0x20),
      Buffer.from([0xff]),
      Buffer.from('{"schema_version":"2.0","sent":{}}'),
      Buffer.from('{"schema_version":"1.0","sent":{},"extra":true}'),
      Buffer.from('{"schema_version":"1.0","schema_version":"1.0","sent":{}}'),
      Buffer.from('{"schema_version":"1.0","sent":{"not-a-hash":1793000000000}}'),
      Buffer.from(`{"schema_version":"1.0","sent":{"${"ab".repeat(32)}":-1}}`),
    ]) {
      const { store } = fixture();
      await store.assertAvailable(PEER, NOW);
      writeFileSync(store.sentPath, bytes, { mode: 0o600 });
      await expect(store.assertAvailable(PEER, NOW)).rejects.toMatchObject({ code: expect.stringMatching(/^E_INTRO_STORE_(?:INVALID|UNSAFE)$/) });
      expect(readFileSync(store.sentPath).equals(bytes)).toBe(true);
    }
  });

  it("fails closed on live, dead and incomplete lock markers without modifying sent state", async () => {
    const { store } = fixture();
    const receipt = await confirmation(store);
    const lock = path.join(store.dir, ".lock");
    writeFileSync(lock, String(process.pid), { mode: 0o600 });
    await expect(store.confirmSent(PEER, receipt, NOW, DOMAIN)).rejects.toMatchObject({ code: "E_INTRO_BUSY" });
    expect(existsSync(store.sentPath)).toBe(false);
    for (const contents of ["2147483647", "", "not-a-pid"]) {
      writeFileSync(lock, contents, { mode: 0o600 });
      await expect(store.confirmSent(PEER, receipt, NOW, DOMAIN)).rejects.toMatchObject({ code: "E_INTRO_BUSY" });
      expect(readFileSync(lock, "utf8")).toBe(contents);
      expect(existsSync(store.sentPath)).toBe(false);
    }
  });

  it("preserves all confirmed entries when concurrent processes encounter the same dead-owner lock", async () => {
    const { parent, home, store } = fixture();
    await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
    const secondPeer = "synthetic-peer:already-confirmed";
    await store.confirmSent(secondPeer, await confirmation(store, secondPeer), NOW + 1, DOMAIN);
    const peers = ["synthetic-peer:new-a", "synthetic-peer:new-b", "synthetic-peer:new-c", "synthetic-peer:new-d"];
    const confirmations: string[] = [];
    for (const peer of peers) confirmations.push(await confirmation(store, peer));
    const lock = path.join(store.dir, ".lock");
    writeFileSync(lock, "2147483647", { mode: 0o600 });
    const before = readFileSync(store.sentPath);
    const secret = readFileSync(store.secretPath);
    const inode = lstatSync(lock).ino;
    const run = prepareStoreProcesses(path.join(parent, "workers"), "src/intro/store.ts", "IntroStore", home);
    const outcomes = await run(peers.map((peer, index) => ({ operation: "confirmSent", args: [peer, confirmations[index]!, NOW + 2, DOMAIN] })));
    expect(outcomes).toEqual(Array.from({ length: 4 }, () => ({ ok: false, code: "E_INTRO_BUSY" })));
    expect(readFileSync(store.sentPath)).toEqual(before);
    expect(readFileSync(store.secretPath)).toEqual(secret);
    expect(Object.keys(sent(store).sent)).toHaveLength(2);
    expect(lstatSync(lock).ino).toBe(inode);
    expect(readFileSync(lock, "utf8")).toBe("2147483647");
  });

  it("honors a shared recovery marker before lock acquisition without altering it or confirmed entries", async () => {
    const { store } = fixture();
    await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
    const before = readFileSync(store.sentPath);
    const recovery = path.join(store.dir, ".recovery");
    writeFileSync(recovery, "synthetic recovery guard", { mode: 0o600 });
    const inode = lstatSync(recovery).ino;
    await expect(store.assertAvailable("synthetic-peer:new", NOW + 1)).rejects.toMatchObject({ code: "E_INTRO_BUSY" });
    expect(readFileSync(store.sentPath)).toEqual(before);
    expect(readFileSync(recovery, "utf8")).toBe("synthetic recovery guard");
    expect(lstatSync(recovery).ino).toBe(inode);
    expect(existsSync(path.join(store.dir, ".lock"))).toBe(false);
  });

  it("honors a shared recovery marker that appears during lock publication", async () => {
    const { store } = fixture();
    await store.confirmSent(PEER, await confirmation(store), NOW, DOMAIN);
    const before = readFileSync(store.sentPath);
    const target = store as unknown as { createLock(file: string): Promise<FileHandle> };
    const original = target.createLock.bind(store);
    const recovery = path.join(store.dir, ".recovery");
    vi.spyOn(target, "createLock").mockImplementation(async file => {
      const handle = await original(file);
      writeFileSync(recovery, "synthetic concurrent recovery", { mode: 0o600 });
      return handle;
    });
    await expect(store.assertAvailable("synthetic-peer:new", NOW + 1)).rejects.toMatchObject({ code: "E_INTRO_BUSY" });
    expect(readFileSync(store.sentPath)).toEqual(before);
    expect(readFileSync(recovery, "utf8")).toBe("synthetic concurrent recovery");
    expect(existsSync(path.join(store.dir, ".lock"))).toBe(false);
  });

  it("serializes concurrent confirmations without losing either peer after the busy caller retries", async () => {
    const { home, store } = fixture();
    const otherPeer = "synthetic-peer:concurrent";
    const firstReceipt = await confirmation(store);
    const secondReceipt = await confirmation(store, otherPeer);
    const operations = [
      () => store.confirmSent(PEER, firstReceipt, NOW, DOMAIN),
      () => new IntroStore(home).confirmSent(otherPeer, secondReceipt, NOW, DOMAIN),
    ];
    const results = await Promise.allSettled(operations.map(operation => operation()));
    expect(results.some(result => result.status === "fulfilled")).toBe(true);
    for (const [index, result] of results.entries()) {
      if (result.status === "rejected") {
        expect(result.reason).toMatchObject({ code: "E_INTRO_BUSY" });
        await operations[index]!();
      }
    }
    expect(Object.keys(sent(store).sent)).toHaveLength(2);
    await expect(store.assertAvailable(PEER, NOW + 1)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    await expect(store.assertAvailable(otherPeer, NOW + 1)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    expect(readdirSync(store.dir).sort()).toEqual(["secret", "sent.json"]);
  });

  it("admits one concurrent same-peer confirmation and retains its original timestamp", async () => {
    const { home, store } = fixture();
    const receipt = await confirmation(store);
    const results = await Promise.allSettled([
      store.confirmSent(PEER, receipt, NOW, DOMAIN),
      new IntroStore(home).confirmSent(PEER, receipt, NOW + 1, DOMAIN),
    ]);
    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find(result => result.status === "rejected");
    expect(rejected).toBeDefined();
    if (rejected?.status === "rejected") expect(rejected.reason).toMatchObject({ code: expect.stringMatching(/^E_INTRO_(?:BUSY|DUPLICATE)$/) });
    const before = readFileSync(store.sentPath);
    await expect(store.confirmSent(PEER, receipt, NOW + 2, DOMAIN)).rejects.toMatchObject({ code: "E_INTRO_DUPLICATE" });
    expect(readFileSync(store.sentPath)).toEqual(before);
    expect(Object.keys(sent(store).sent)).toHaveLength(1);
  });
});
