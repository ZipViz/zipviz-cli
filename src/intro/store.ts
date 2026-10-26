import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { link, lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";
import { canonicalizeJson, type JsonValue } from "../a2a/jcs.js";
import { CliError } from "../errors.js";
import { isValidVizAgentDomain } from "../viz.js";

export const INTRO_DEDUPE_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BYTES = 64 * 1024;
const MAX_LIFETIME_MS = 72 * 60 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const unsafe = () => new CliError("E_INTRO_STORE_UNSAFE", "intro store requires private, user-owned regular files and real directories");
const invalid = () => new CliError("E_INTRO_STORE_INVALID", "intro store metadata is invalid; existing data was retained");
const confirmationError = () => new CliError("E_INTRO_CONFIRMATION", "intro confirmation is invalid or dated in the future");
const duplicate = () => new CliError("E_INTRO_DUPLICATE", "an intro was already confirmed for this peer within 30 days");
const busy = () => new CliError("E_INTRO_BUSY", "intro store is locked or recovery is in progress; existing markers are not removed automatically");
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const sameFile = (a: Stats, b: Stats) => a.dev === b.dev && a.ino === b.ino;

interface SentFile { schema_version: "1.0"; sent: Record<string, number> }
interface Confirmation {
  schema_version: "1.0"; domain: string; peer_hmac: string; draft_id: string;
  issued_at_ms: number; expires_at_ms: number; token_digest: string;
}
export interface IntroConfirmationOptions {
  domain: string; peerRef: string; draftId: string; issuedAtMs: number;
  expiresAtMs: number; tokenDigest: string;
}
export interface IntroConfirmationResult { domain: string; draft_id: string; confirmed_at_ms: number }

function checkPeer(value: string): void {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value, "utf8") > 512
    || Array.from(value).some(character => {
      const code = character.codePointAt(0)!;
      return code <= 31 || (code >= 127 && code <= 159) || code === 0x2028 || code === 0x2029;
    })
    || Buffer.from(value, "utf8").toString("utf8") !== value) {
    throw new CliError("E_USAGE", "peer reference must be 1 to 512 UTF-8 bytes without control characters", 2);
  }
}

function checkNow(value: number): void {
  if (!integer(value)) throw new CliError("E_USAGE", "intro time must be a nonnegative safe integer", 2);
}

function checkFile(st: Stats): void {
  if (!st.isFile() || (st.mode & 0o077) !== 0 || (st.mode & 0o400) === 0
    || (typeof process.getuid === "function" && st.uid !== process.getuid()) || st.size > MAX_BYTES) throw unsafe();
}

/** Private local dedupe. Conversation context and sent confirmation remain caller attestations. */
export class IntroStore {
  readonly dir: string;
  readonly secretPath: string;
  readonly sentPath: string;
  constructor(readonly zipvizHome: string) {
    this.dir = path.join(zipvizHome, "intros");
    this.secretPath = path.join(this.dir, "secret");
    this.sentPath = path.join(this.dir, "sent.json");
  }

  private async directories(): Promise<void> {
    for (const [dir, mask] of [[this.zipvizHome, 0o022], [this.dir, 0o077]] as const) {
      let created = false;
      try { await mkdir(dir, { mode: 0o700 }); created = true; }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      let handle;
      try { handle = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); }
      catch (error) {
        if (["ELOOP", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code ?? "")) throw unsafe();
        throw new CliError("E_INTRO_STORE_UNREADABLE", "cannot open intro store directory");
      }
      try {
        const stat = await handle.stat();
        if (!stat.isDirectory() || (stat.mode & mask) !== 0
          || (typeof process.getuid === "function" && stat.uid !== process.getuid())) throw unsafe();
        if (created) await handle.sync();
      } finally { await handle.close(); }
      if (created) {
        const parent = await open(path.dirname(dir), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        try { await parent.sync(); } finally { await parent.close(); }
      }
    }
  }

  private async privateFile(file: string): Promise<FileHandle | null> {
    let handle;
    try { handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return null;
      if (code === "ELOOP" || code === "ENOTDIR") throw unsafe();
      throw new CliError("E_INTRO_STORE_UNREADABLE", "cannot read local intro store file");
    }
    try { checkFile(await handle.stat()); return handle; }
    catch (error) { await handle.close(); throw error; }
  }

  private async syncDir(): Promise<void> {
    const handle = await open(this.dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  /** Publish only a complete PID lock, so concurrent readers never see an empty lock. */
  private async createLock(lockPath: string): Promise<FileHandle> {
    const temporary = path.join(this.dir, `.${randomUUID()}.lock-tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(String(process.pid));
      await handle.sync();
      await link(temporary, lockPath);
      await unlink(temporary);
      return handle;
    } catch (error) {
      await handle.close();
      await unlink(temporary).catch(() => undefined);
      throw error;
    }
  }

  private async locked<T>(fn: () => Promise<T>): Promise<T> {
    await this.directories();
    const lockPath = path.join(this.dir, ".lock");
    // Shared-client recovery uses this marker. Ordinary mutations never remove it.
    const recoveryPath = path.join(this.dir, ".recovery");
    const recoveryPresent = () => lstat(recoveryPath).then(() => true).catch(error => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    });
    if (await recoveryPresent()) throw busy();
    let handle: FileHandle;
    try { handle = await this.createLock(lockPath); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      // Checking a stale inode/PID does not make pathname reclamation atomic.
      // Preserve it and all sent history; recovery requires separate exclusion.
      throw busy();
    }
    try {
      // A cooperating recovery guard may have appeared during lock publication.
      if (await recoveryPresent()) throw busy();
      return await fn();
    } finally {
      const stat = await handle.stat();
      await handle.close();
      const current = await lstat(lockPath).catch(() => null);
      if (current && sameFile(stat, current)) await unlink(lockPath);
    }
  }

  private async secret(): Promise<Buffer> {
    const existing = await this.privateFile(this.secretPath);
    if (existing) {
      try {
        const bytes = await existing.readFile();
        if (bytes.length !== 32) throw invalid();
        return bytes;
      } finally { await existing.close(); }
    }
    // Losing a secret must not silently reset established peer dedupe history.
    if (await lstat(this.sentPath).then(() => true).catch(error => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    })) throw invalid();
    const bytes = randomBytes(32);
    const temporary = path.join(this.dir, `.${randomUUID()}.tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    try {
      await link(temporary, this.secretPath);
      await unlink(temporary);
      await this.syncDir();
    } catch (error) { await unlink(temporary).catch(() => undefined); throw error; }
    return bytes;
  }

  private async sent(): Promise<SentFile> {
    const handle = await this.privateFile(this.sentPath);
    if (!handle) return { schema_version: "1.0", sent: Object.create(null) as Record<string, number> };
    try {
      const bytes = await handle.readFile();
      if (bytes.byteLength > MAX_BYTES) throw unsafe();
      const text = bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(bytes)) throw invalid();
      let value: unknown;
      try { value = JSON.parse(text); } catch { throw invalid(); }
      if (!object(value) || Object.keys(value).sort().join() !== "schema_version,sent"
        || value.schema_version !== "1.0" || !object(value.sent)) throw invalid();
      for (const [hash, at] of Object.entries(value.sent)) if (!HEX.test(hash) || !integer(at)) throw invalid();
      // Canonical storage rejects duplicate JSON keys rather than accepting their last value.
      if (canonicalizeJson(value as JsonValue) !== text) throw invalid();
      return value as unknown as SentFile;
    } finally { await handle.close(); }
  }

  private peerHmac(secret: Buffer, peerRef: string): string {
    return createHmac("sha256", secret).update(peerRef, "utf8").digest("hex");
  }

  private assertUnsent(file: SentFile, hash: string, now: number): void {
    const sentAt = file.sent[hash];
    if (sentAt !== undefined && (sentAt > now || now - sentAt < INTRO_DEDUPE_MS)) throw duplicate();
  }

  private async write(file: SentFile): Promise<void> {
    const bytes = canonicalizeJson(file as unknown as JsonValue);
    if (Buffer.byteLength(bytes) > MAX_BYTES) throw new CliError("E_INTRO_STORE_FULL", "intro store is full; existing history was retained");
    const existing = await this.privateFile(this.sentPath);
    const create = existing === null;
    if (existing) await existing.close();
    const temporary = path.join(this.dir, `.${randomUUID()}.tmp`);
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    try {
      if (create) { await link(temporary, this.sentPath); await unlink(temporary); }
      else await rename(temporary, this.sentPath);
      await this.syncDir();
    } catch (error) { await unlink(temporary).catch(() => undefined); throw error; }
  }

  async assertAvailable(peerRef: string, now: number): Promise<void> {
    checkPeer(peerRef); checkNow(now);
    await this.locked(async () => {
      const secret = await this.secret();
      this.assertUnsent(await this.sent(), this.peerHmac(secret, peerRef), now);
    });
  }

  async makeConfirmation(options: IntroConfirmationOptions): Promise<string> {
    checkPeer(options.peerRef); checkNow(options.issuedAtMs);
    if (!isValidVizAgentDomain(options.domain) || !UUID.test(options.draftId) || !HEX.test(options.tokenDigest)
      || !integer(options.expiresAtMs) || options.expiresAtMs <= options.issuedAtMs
      || options.expiresAtMs - options.issuedAtMs > MAX_LIFETIME_MS) throw confirmationError();
    return this.locked(async () => {
      const secret = await this.secret();
      const peerHash = this.peerHmac(secret, options.peerRef);
      this.assertUnsent(await this.sent(), peerHash, options.issuedAtMs);
      const body: Confirmation = {
        schema_version: "1.0", domain: options.domain, peer_hmac: peerHash, draft_id: options.draftId,
        issued_at_ms: options.issuedAtMs, expires_at_ms: options.expiresAtMs, token_digest: options.tokenDigest,
      };
      const payload = Buffer.from(canonicalizeJson(body as unknown as JsonValue)).toString("base64url");
      const mac = createHmac("sha256", secret).update(`ZipViz intro-confirmation v1\0${payload}`).digest("base64url");
      return `zvic1.${payload}.${mac}`;
    });
  }

  async confirmSent(peerRef: string, receipt: string, now: number, expectedDomain?: string): Promise<IntroConfirmationResult> {
    checkPeer(peerRef); checkNow(now);
    if (typeof receipt !== "string" || receipt.length > 2048) throw confirmationError();
    const match = /^zvic1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(receipt);
    if (!match) throw confirmationError();
    return this.locked(async () => {
      const secret = await this.secret();
      const payload = match[1]!; const encodedMac = match[2]!;
      const receivedMac = Buffer.from(encodedMac, "base64url");
      const expectedMac = createHmac("sha256", secret).update(`ZipViz intro-confirmation v1\0${payload}`).digest();
      if (receivedMac.toString("base64url") !== encodedMac || receivedMac.length !== expectedMac.length
        || !timingSafeEqual(receivedMac, expectedMac)) throw confirmationError();
      const bytes = Buffer.from(payload, "base64url");
      const text = bytes.toString("utf8");
      if (bytes.toString("base64url") !== payload || !Buffer.from(text).equals(bytes)) throw confirmationError();
      let body: unknown;
      try { body = JSON.parse(text); } catch { throw confirmationError(); }
      if (!object(body) || Object.keys(body).sort().join() !== "domain,draft_id,expires_at_ms,issued_at_ms,peer_hmac,schema_version,token_digest"
        || canonicalizeJson(body as JsonValue) !== text || body.schema_version !== "1.0"
        || typeof body.domain !== "string" || !isValidVizAgentDomain(body.domain)
        || (expectedDomain !== undefined && body.domain !== expectedDomain)
        || typeof body.draft_id !== "string" || !UUID.test(body.draft_id)
        || typeof body.token_digest !== "string" || !HEX.test(body.token_digest)
        || body.peer_hmac !== this.peerHmac(secret, peerRef)
        || !integer(body.issued_at_ms) || !integer(body.expires_at_ms)
        || body.issued_at_ms > now || body.expires_at_ms <= body.issued_at_ms
        || body.expires_at_ms - body.issued_at_ms > MAX_LIFETIME_MS) throw confirmationError();
      const file = await this.sent();
      const hash = body.peer_hmac as string;
      this.assertUnsent(file, hash, now);
      await this.write({ ...file, sent: { ...file.sent, [hash]: now } });
      return { domain: body.domain, draft_id: body.draft_id, confirmed_at_ms: now };
    });
  }
}
