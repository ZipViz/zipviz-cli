import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { CliError } from "./errors.js";
import { isValidVizAgentDomain } from "./viz.js";

export const DEFAULT_KEY_ID = "default";

/** Key ids are a full .viz domain or `default`; the id is the file stem. */
export function isValidKeyId(id: string): boolean {
  return id === DEFAULT_KEY_ID || isValidVizAgentDomain(id);
}

const unsafe = (message: string) => new CliError("E_KEY_UNSAFE", message);
const KEY_FILE_MAX_BYTES = 64 * 1024;

function unreadable(what: string, e: unknown): CliError {
  return new CliError("E_KEY_UNREADABLE", `cannot open ${what}: ${(e as NodeJS.ErrnoException).code ?? "unknown error"}`);
}

async function readPrivateKey(
  pathname: string,
  missing: () => CliError,
  label: string,
  allowP256 = true,
): Promise<KeyObject> {
  let handle;
  try {
    handle = await open(pathname, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw missing();
    if (code === "ELOOP") throw unsafe(`${label} is a symlink (ELOOP); refusing to follow it`);
    throw unreadable(label, e);
  }
  let pem: Buffer;
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new CliError("E_KEY_UNSAFE", `${label} is not a regular file`);
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
      throw new CliError("E_KEY_UNSAFE", `${label} is not owned by this user`);
    }
    if ((st.mode & 0o077) !== 0) {
      const hint = label.startsWith("key ") ? ` (chmod 600 ${pathname})` : "";
      throw new CliError("E_KEY_UNSAFE", `${label} must not be readable by group or others${hint}`);
    }
    if (st.size > KEY_FILE_MAX_BYTES) throw new CliError("E_KEY_UNSAFE", `${label} exceeds the 64 KiB limit`);
    pem = await handle.readFile();
    if (pem.byteLength > KEY_FILE_MAX_BYTES) throw new CliError("E_KEY_UNSAFE", `${label} exceeds the 64 KiB limit`);
  } finally {
    await handle.close();
  }
  let privateKey: KeyObject;
  try {
    if (!/^-----BEGIN PRIVATE KEY-----/.test(pem.toString("utf8").trimStart())) {
      throw new Error("not PKCS#8");
    }
    privateKey = createPrivateKey({ key: pem, format: "pem" });
  } catch {
    throw new CliError("E_KEY_INVALID", `${label} is not a valid PKCS#8 PEM key`);
  }
  const type = privateKey.asymmetricKeyType;
  const isP256 = type === "ec" && privateKey.asymmetricKeyDetails?.namedCurve === "prime256v1";
  if (type !== "ed25519" && !(allowP256 && isP256)) {
    throw new CliError("E_KEY_INVALID", allowP256
      ? `${label} is not Ed25519 or P-256`
      : `${label} is not Ed25519`);
  }
  return privateKey;
}

export async function readPrivateKeyFile(pathname: string): Promise<KeyObject> {
  return readPrivateKey(pathname, () => new CliError("E_NO_KEY", `no key file at ${pathname}`), pathname);
}

export class KeyStore {
  readonly dir: string;

  constructor(zipvizHome: string) {
    this.dir = path.join(zipvizHome, "keys");
  }

  pathFor(id: string): string {
    if (!isValidKeyId(id)) throw new CliError("E_USAGE", `invalid key id: ${id}`, 2);
    return path.join(this.dir, `${id}.key`);
  }

  private levels(): Array<[string, number]> {
    return [
      [path.dirname(this.dir), 0o022],
      [this.dir, 0o077],
    ];
  }

  /**
   * Check one directory on an O_DIRECTORY|O_NOFOLLOW handle: a real directory owned
   * by this user with none of `mask`'s permission bits. With `fix`, tighten it to
   * 0700 via the handle instead of checking the mode. Returns false if absent.
   */
  private async checkOne(dir: string, mask: number, fix: boolean): Promise<boolean> {
    let handle;
    try {
      handle = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return false;
      if (code === "ELOOP" || code === "ENOTDIR") throw unsafe(`${dir} must be a real directory, not a symlink`);
      throw unreadable(dir, e);
    }
    try {
      const st = await handle.stat();
      if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
        throw unsafe(`${dir} is not owned by this user`);
      }
      if (fix) await handle.chmod(0o700);
      else if ((st.mode & mask) !== 0) throw unsafe(`${dir} is too permissive (chmod 700 ${dir})`);
    } finally {
      await handle.close();
    }
    return true;
  }

  /** Check ~/.zipviz then ~/.zipviz/keys; false if either is absent. */
  private async checkDir(): Promise<boolean> {
    for (const [dir, mask] of this.levels()) {
      if (!(await this.checkOne(dir, mask, false))) return false;
    }
    return true;
  }

  /** Create ~/.zipviz then ~/.zipviz/keys one level at a time, checking each before descending. */
  private async ensureDir(): Promise<void> {
    for (const [dir] of this.levels()) {
      try {
        await mkdir(dir, { mode: 0o700 });
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      await this.checkOne(dir, 0, true);
    }
  }

  /** Whether a key file is present; reads nothing (load() does the safety checks). */
  async exists(id: string): Promise<boolean> {
    try {
      await lstat(this.pathFor(id));
      return true;
    } catch {
      return false;
    }
  }

  /** Generate an Ed25519 key; the PEM is written straight to a 0600 file. */
  async generate(id: string, force: boolean): Promise<{ path: string; publicKey: string }> {
    const file = this.pathFor(id);
    if (!force && (await this.exists(id))) {
      throw new CliError("E_KEY_EXISTS", `a key already exists at ${file} (use --force to replace it)`);
    }
    await this.ensureDir();
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" });
    const tmp = path.join(this.dir, `.${id}.${process.pid}.${Date.now()}.tmp`);
    const handle = await open(tmp, "wx", 0o600);
    try {
      await handle.writeFile(pem);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      if (force) {
        await rename(tmp, file);
      } else {
        // link() fails if the target exists, so a racing keygen cannot be clobbered.
        await link(tmp, file);
        await unlink(tmp);
      }
    } catch (e) {
      await unlink(tmp).catch(() => undefined);
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        throw new CliError("E_KEY_EXISTS", `a key already exists at ${file} (use --force to replace it)`);
      }
      throw e;
    }
    return { path: file, publicKey: publicKeyHex(privateKey) };
  }

  /** Load a key after checking it is a private, regular, user-owned file (checked on the open handle). */
  async load(id: string): Promise<LocalKey> {
    const file = this.pathFor(id);
    const missing = () => new CliError("E_NO_KEY", `no local key ${id} (run: zipviz keygen --name <label>)`);
    if (!(await this.checkDir())) throw missing();
    const privateKey = await readPrivateKey(file, missing, `key ${id}`, false);
    return new LocalKey(id, file, privateKey);
  }

  /** Rename a key to a new id, refusing to replace an existing key. */
  async adopt(from: string, to: string): Promise<string> {
    const src = this.pathFor(from);
    const dst = this.pathFor(to);
    await link(src, dst);
    await unlink(src);
    return dst;
  }

  /**
   * Metadata-only safety check of a listed key file, without opening it: the same
   * conventions load() enforces on its handle (regular file, not a symlink, owned by
   * this user, no group/other bits, owner-readable, at most 64 KiB), via lstat so nothing is followed.
   * Returns null when the entry passes, or the CliError load() would raise for it.
   * Point-in-time only: callers must not assume the entry stays this way.
   */
  async inspect(id: string): Promise<CliError | null> {
    const file = this.pathFor(id);
    const label = `key ${id}`;
    let st;
    try {
      st = await lstat(file);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        return new CliError("E_NO_KEY", `${label} disappeared while being checked`);
      }
      return unreadable(label, e);
    }
    if (st.isSymbolicLink()) return unsafe(`${label} is a symlink; refusing to follow it`);
    if (!st.isFile()) return unsafe(`${label} is not a regular file`);
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
      return unsafe(`${label} is not owned by this user`);
    }
    if ((st.mode & 0o077) !== 0) return unsafe(`${label} must not be readable by group or others`);
    // load() opens O_RDONLY, which fails with EACCES when the owner-read bit is unset
    // (e.g. mode 000 or 0100); classify it the same way without opening the file.
    if ((st.mode & 0o400) === 0) {
      return new CliError("E_KEY_UNREADABLE", `cannot open ${label}: EACCES (owner has no read permission)`);
    }
    if (st.size > KEY_FILE_MAX_BYTES) return unsafe(`${label} exceeds the 64 KiB limit`);
    return null;
  }

  async list(): Promise<string[]> {
    if (!(await this.checkDir())) return [];
    let names: string[];
    try {
      names = await readdir(this.dir);
    } catch {
      return [];
    }
    return names
      .filter((n) => n.endsWith(".key"))
      .map((n) => n.slice(0, -4))
      .filter(isValidKeyId)
      .sort();
  }
}

export function publicKeyHex(key: KeyObject): string {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}

/** Holds the private KeyObject privately; only signatures and the public key leave. */
export class LocalKey {
  readonly #privateKey: KeyObject;
  readonly publicKey: string;

  constructor(readonly id: string, readonly path: string, privateKey: KeyObject) {
    this.#privateKey = privateKey;
    this.publicKey = publicKeyHex(privateKey);
  }

  sign(payload: string): Buffer {
    return sign(null, Buffer.from(payload, "utf8"), this.#privateKey);
  }

  toJSON(): { id: string; public_key: string } {
    return { id: this.id, public_key: this.publicKey };
  }
}
