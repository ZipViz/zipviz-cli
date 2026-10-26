import { createHash, createPrivateKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { link, lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";
import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { CliError } from "../errors.js";
import { KeyStore, LocalKey, readPrivateKeyFile } from "../keys.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 64 * 1024;
export const JOIN_ATTEMPT_CAP = 8;

export interface PendingAttempt {
  request_b64url: string;
  request_digest: string;
  issued_at_ms: number;
}

export interface PendingSignupRecord {
  schema_version: "1.0";
  signup_id: string;
  registry_origin: string;
  audience: string;
  attempts: PendingAttempt[];
  receipt?: Record<string, unknown>;
}

const unsafe = () => new CliError("E_KEY_UNSAFE", "pending signup store must contain private, user-owned regular files and real directories");
const invalid = () => new CliError("E_JOIN_PENDING_INVALID", "pending signup metadata is invalid; retained files were not changed");
const missing = () => new CliError("E_JOIN_NOT_FOUND", "no local pending signup with that id");
const obj = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const sameFile = (a: Stats, b: Stats) => a.dev === b.dev && a.ino === b.ino;

export function isSignupId(id: string): boolean {
  return UUID.test(id);
}

function checkId(id: string): void {
  if (!isSignupId(id)) throw new CliError("E_USAGE", "signup id must be a lowercase UUIDv4", 2);
}

function checkFile(st: Stats): void {
  if (!st.isFile() || (st.mode & 0o077) !== 0 || (st.mode & 0o400) === 0
    || (typeof process.getuid === "function" && st.uid !== process.getuid()) || st.size > MAX_BYTES) throw unsafe();
}

async function privateFile(file: string): Promise<FileHandle> {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw missing();
    if (code === "ELOOP" || code === "ENOTDIR") throw unsafe();
    throw new CliError("E_KEY_UNREADABLE", "cannot read local pending signup file");
  }
  try {
    checkFile(await handle.stat());
    return handle;
  } catch (e) {
    await handle.close();
    throw e;
  }
}

function requestIdentity(attempt: PendingAttempt, id: string): string {
  if (!obj(attempt) || Object.keys(attempt).sort().join() !== "issued_at_ms,request_b64url,request_digest"
    || typeof attempt.request_b64url !== "string" || !/^[A-Za-z0-9_-]+$/.test(attempt.request_b64url)
    || typeof attempt.request_digest !== "string" || !/^[0-9a-f]{64}$/.test(attempt.request_digest)
    || !Number.isSafeInteger(attempt.issued_at_ms) || attempt.issued_at_ms < 0) throw invalid();
  const bytes = Buffer.from(attempt.request_b64url, "base64url");
  const text = bytes.toString("utf8");
  if (bytes.length > 4096 || bytes.toString("base64url") !== attempt.request_b64url
    || !Buffer.from(text, "utf8").equals(bytes)
    || createHash("sha256").update(bytes).digest("hex") !== attempt.request_digest) throw invalid();
  let request: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!obj(parsed) || canonicalizeJson(parsed as JsonValue) !== text || !obj(parsed.proof)) throw invalid();
    request = parsed;
  } catch {
    throw invalid();
  }
  const proof = request.proof as Record<string, unknown>;
  if (proof.signup_id !== id || proof.issued_at_ms !== attempt.issued_at_ms) throw invalid();
  const stableProof = { ...proof };
  delete stableProof.issued_at_ms;
  delete stableProof.signature;
  return canonicalizeJson({ ...request, proof: stableProof } as JsonValue);
}

function validateRecord(value: unknown, id: string): PendingSignupRecord {
  if (!obj(value) || value.schema_version !== "1.0" || value.signup_id !== id
    || typeof value.registry_origin !== "string" || typeof value.audience !== "string"
    || value.registry_origin.length > 2048 || !value.registry_origin || !value.audience || value.audience.length > 255
    || Object.keys(value).some((k) => !["schema_version", "signup_id", "registry_origin", "audience", "attempts", "receipt"].includes(k))
    || !Array.isArray(value.attempts) || value.attempts.length < 1 || value.attempts.length > JOIN_ATTEMPT_CAP
    || (value.receipt !== undefined && !obj(value.receipt))) throw invalid();
  let identity: string | undefined;
  for (const attempt of value.attempts as PendingAttempt[]) {
    const next = requestIdentity(attempt, id);
    if (identity !== undefined && identity !== next) throw invalid();
    identity = next;
  }
  return value as unknown as PendingSignupRecord;
}

/** Private append-only retry history, separate from the ordinary domain-key store. */
export class PendingSignupStore {
  readonly dir: string;
  readonly keys: KeyStore;
  constructor(readonly zipvizHome: string) {
    this.keys = new KeyStore(zipvizHome);
    this.dir = path.join(this.keys.dir, "pending");
  }

  keyPathFor(id: string): string { checkId(id); return path.join(this.dir, `${id}.key`); }
  metadataPathFor(id: string): string { checkId(id); return path.join(this.dir, `${id}.json`); }

  private async directories(create: boolean): Promise<void> {
    for (const [dir, mask] of [[this.zipvizHome, 0o022], [this.keys.dir, 0o077], [this.dir, 0o077]] as const) {
      if (create) {
        try { await mkdir(dir, { mode: 0o700 }); }
        catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; }
      }
      let handle;
      try { handle = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); }
      catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code === "ENOENT") throw missing();
        if (code === "ELOOP" || code === "ENOTDIR") throw unsafe();
        throw new CliError("E_KEY_UNREADABLE", "cannot open pending signup directory");
      }
      try {
        const st = await handle.stat();
        if (!st.isDirectory() || (st.mode & mask) !== 0 || (typeof process.getuid === "function" && st.uid !== process.getuid())) throw unsafe();
      } finally { await handle.close(); }
    }
  }

  private async syncDir(dir = this.dir): Promise<void> {
    const handle = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  /** Lock only local mutations; a crash after append cannot leave a live-process lock. */
  private async locked<T>(id: string, fn: () => Promise<T>): Promise<T> {
    checkId(id);
    await this.directories(true);
    const lock = path.join(this.dir, `.${id}.lock`);
    let handle: FileHandle;
    try { handle = await open(lock, "wx", 0o600); }
    catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      const existing = await privateFile(lock);
      let st: Stats;
      let pid: number;
      try {
        st = await existing.stat();
        pid = Number((await existing.readFile("utf8")).trim());
      } finally { await existing.close(); }
      if (!Number.isSafeInteger(pid) || pid <= 0) throw unsafe();
      try { process.kill(pid, 0); throw new CliError("E_JOIN_BUSY", "another process is updating this pending signup"); }
      catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
      }
      if (!sameFile(st, await lstat(lock))) throw new CliError("E_JOIN_BUSY", "pending signup lock changed; retry");
      await unlink(lock);
      try { handle = await open(lock, "wx", 0o600); }
      catch { throw new CliError("E_JOIN_BUSY", "another process is updating this pending signup"); }
    }
    try {
      await handle.writeFile(String(process.pid));
      await handle.sync();
      return await fn();
    } finally {
      const st = await handle.stat();
      await handle.close();
      const current = await lstat(lock).catch(() => null);
      if (current && sameFile(st, current)) await unlink(lock);
    }
  }

  private async write(id: string, record: PendingSignupRecord, create: boolean): Promise<void> {
    validateRecord(record, id);
    const data = JSON.stringify(record);
    if (Buffer.byteLength(data) > MAX_BYTES) throw invalid();
    const target = this.metadataPathFor(id);
    if (!create) {
      const existing = await privateFile(target);
      await existing.close();
    }
    const tmp = path.join(this.dir, `.${id}.${randomUUID()}.tmp`);
    const handle = await open(tmp, "wx", 0o600);
    try { await handle.writeFile(data); await handle.sync(); }
    finally { await handle.close(); }
    try {
      if (create) { await link(tmp, target); await unlink(tmp); }
      else await rename(tmp, target);
      await this.syncDir();
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliError("E_JOIN_EXISTS", "pending signup metadata already exists");
      throw e;
    }
  }

  async generate(id: string): Promise<LocalKey> {
    return this.locked(id, async () => {
      const target = this.keyPathFor(id);
      const tmp = path.join(this.dir, `.${id}.${randomUUID()}.tmp`);
      const { privateKey } = generateKeyPairSync("ed25519");
      const handle = await open(tmp, "wx", 0o600);
      try { await handle.writeFile(privateKey.export({ format: "pem", type: "pkcs8" })); await handle.sync(); }
      finally { await handle.close(); }
      try { await link(tmp, target); await unlink(tmp); await this.syncDir(); }
      catch (e) {
        await unlink(tmp).catch(() => undefined);
        if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliError("E_KEY_EXISTS", "a pending key already exists for this signup");
        throw e;
      }
      return new LocalKey(id, target, privateKey);
    });
  }

  async loadKey(id: string): Promise<LocalKey> {
    checkId(id);
    await this.directories(false);
    const file = this.keyPathFor(id);
    const privateKey = await readPrivateKeyFile(file);
    if (privateKey.asymmetricKeyType !== "ed25519") throw new CliError("E_KEY_INVALID", "pending signup key must be Ed25519");
    return new LocalKey(id, file, privateKey);
  }

  async read(id: string): Promise<PendingSignupRecord> {
    checkId(id);
    await this.directories(false);
    const handle = await privateFile(this.metadataPathFor(id));
    try {
      const bytes = await handle.readFile();
      if (bytes.length > MAX_BYTES) throw unsafe();
      let parsed: unknown;
      try { parsed = JSON.parse(bytes.toString("utf8")); } catch { throw invalid(); }
      return validateRecord(parsed, id);
    } finally { await handle.close(); }
  }

  async create(id: string, attempt: PendingAttempt, context: { registry_origin: string; audience: string }): Promise<PendingSignupRecord> {
    return this.locked(id, async () => {
      const record: PendingSignupRecord = { schema_version: "1.0", signup_id: id, ...context, attempts: [attempt] };
      await this.write(id, record, true);
      return record;
    });
  }

  async appendAttempt(id: string, attempt: PendingAttempt): Promise<PendingSignupRecord> {
    return this.locked(id, async () => {
      const record = await this.read(id);
      if (record.receipt) throw invalid();
      if (record.attempts.length >= JOIN_ATTEMPT_CAP) throw new CliError("E_JOIN_RETRY_LIMIT", "join retry limit reached; all pending attempts were retained");
      const updated = { ...record, attempts: [...record.attempts, attempt] };
      await this.write(id, updated, false);
      return updated;
    });
  }

  async saveReceipt(id: string, receipt: Record<string, unknown>): Promise<PendingSignupRecord> {
    return this.locked(id, async () => {
      const record = await this.read(id);
      if (record.receipt && canonicalizeJson(record.receipt as JsonValue) !== canonicalizeJson(receipt as JsonValue)) throw invalid();
      const updated = { ...record, receipt };
      await this.write(id, updated, false);
      return updated;
    });
  }

  /** Called only after the join command has fenced current registry identity. */
  async adopt(id: string, domain: string, expectedPublicKey?: string): Promise<string> {
    if (!/^[a-z0-9-]{1,20}\.z\.viz$/.test(domain)) throw new CliError("E_UNEXPECTED_RESPONSE", "invalid approved domain; pending key retained");
    return this.locked(id, async () => {
      const src = this.keyPathFor(id);
      const dst = this.keys.pathFor(domain);
      const pinnedSource = await privateFile(src);
      let source: Stats;
      let local: LocalKey;
      try {
        source = await pinnedSource.stat();
        const pem = await pinnedSource.readFile();
        if (pem.length > MAX_BYTES) throw unsafe();
        try {
          if (!/^-----BEGIN PRIVATE KEY-----/.test(pem.toString("utf8").trimStart())) throw new Error("not PKCS#8");
          const key = createPrivateKey({ key: pem, format: "pem" });
          if (key.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
          local = new LocalKey(id, src, key);
        } catch { throw new CliError("E_KEY_INVALID", "pending signup key must be PKCS#8 Ed25519"); }
      } finally { await pinnedSource.close(); }
      if (expectedPublicKey !== undefined && local.publicKey !== expectedPublicKey) {
        throw new CliError("E_UNEXPECTED_RESPONSE", "pending key changed; retained for inspection");
      }
      const record = await this.read(id);
      if (!record.receipt) throw invalid();
      try { await link(src, dst); }
      catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliError("E_KEY_EXISTS", "the approved domain already has a local key; pending key retained");
        throw e;
      }
      const linked = await lstat(dst);
      if (!sameFile(source, linked) || !linked.isFile()) {
        await unlink(dst);
        throw unsafe();
      }
      await this.syncDir(this.keys.dir);
      if (!sameFile(source, await lstat(src))) throw unsafe();
      await unlink(src);
      await this.syncDir();
      const metadata = await privateFile(this.metadataPathFor(id));
      await metadata.close();
      await unlink(this.metadataPathFor(id));
      await this.syncDir();
      return dst;
    });
  }
}
