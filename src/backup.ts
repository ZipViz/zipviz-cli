import path from "node:path";
import { CliError, usageError } from "./errors.js";
import type { Result } from "./output.js";
import type { Context } from "./commands.js";

/**
 * `zipviz backup`: where the local keys live and how to back them up and restore them.
 *
 * Guidance only. It lists key file names (directory entries), lstats them, and never
 * opens, reads, copies, exports, uploads, moves, deletes or chmods a key file.
 */

/** POSIX single-quote a path for a copy-pasteable command. */
export function shellQuote(value: string): string {
  return /^[A-Za-z0-9_./~:@%+,=-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`;
}

/** Bound on how many listed entries are inspected. */
const MAX_KEY_ENTRIES = 256;

type KeyFileEntry = {
  key_id: string;
  path: string;
  /** Point-in-time metadata check only; never read as "will stay safe". */
  safe: boolean;
  error: { code: string; message: string } | null;
};

export async function backup({ keys, parsed }: Context): Promise<Result> {
  if (parsed.positional.length !== 0) throw usageError("usage: zipviz backup [--json]");
  const home = path.dirname(keys.dir);
  const archive = "zipviz-keys-backup.tar";

  // Names and metadata only: list() checks the directories (as whoami does) and reads the
  // entries; inspect() lstats each listed entry (no symlink is followed, no key file is
  // opened), so a symlink, fifo, directory, foreign or loosely permissioned entry is
  // reported as unsafe instead of being listed as a key.
  let keyIds: string[] = [];
  let storeError: { code: string; message: string } | null = null;
  try {
    keyIds = await keys.list();
  } catch (e) {
    if (!(e instanceof CliError)) throw e;
    storeError = { code: e.code, message: e.message };
  }
  const keyFiles: KeyFileEntry[] = [];
  for (const id of keyIds.slice(0, MAX_KEY_ENTRIES)) {
    const err = await keys.inspect(id);
    keyFiles.push({
      key_id: id,
      path: keys.pathFor(id),
      safe: err === null,
      error: err ? { code: err.code, message: err.message } : null,
    });
  }
  const unsafeFiles = keyFiles.filter((k) => !k.safe);
  if (!storeError && unsafeFiles.length > 0) {
    const first = unsafeFiles[0]!.error!;
    storeError = {
      code: first.code,
      message: `${unsafeFiles.length} of ${keyFiles.length} key file(s) failed safety checks (${first.message})`,
    };
  }
  if (!storeError && keyIds.length > MAX_KEY_ENTRIES) {
    storeError = {
      code: "E_KEY_UNSAFE",
      message: `${keys.dir} lists more than ${MAX_KEY_ENTRIES} key files; only the first ${MAX_KEY_ENTRIES} were checked`,
    };
  }
  const verified = storeError === null;

  const h = shellQuote(home);
  const dir = shellQuote(keys.dir);
  const backupSteps = [
    `umask 077 && tar -C ${h} -cpf ${archive} keys`,
    `encrypt ${archive} (for example: gpg --symmetric ${archive}), keep the encrypted copy offline or on media you control, then delete the plain ${archive}`,
  ];
  // Never a glob or a bare chmod: chmod follows symlinks. The steps are offered only once
  // every listed entry passed the checks above, and each one re-checks at restore time
  // that its target is a real directory / regular file and not a symlink.
  const permissionSteps = verified
    ? [
      `[ ! -L ${h} ] && [ -d ${dir} ] && [ ! -L ${dir} ] && chmod 700 ${dir}    # only if keys/ is a real directory, not a symlink`,
      ...keyFiles.map((k) => {
        const p = shellQuote(k.path);
        return `[ -f ${p} ] && [ ! -L ${p} ] && chmod 600 ${p}    # only if it is a regular file, not a symlink`;
      }),
    ]
    : [
      "permission step withheld: the key store did not pass safety checks, so no chmod is suggested "
      + "(chmod follows symlinks); run zipviz doctor, fix the store by hand, then run zipviz backup again",
    ];
  const restoreSteps = [
    `zipviz whoami    # first: note which keys this machine already has`,
    `decrypt the backup to ${archive}`,
    `mkdir -p -m 700 ${h} && tar -C ${h} -xpkf ${archive} keys    # -k: never overwrite an existing key file`,
    ...permissionSteps,
    `zipviz doctor && zipviz whoami    # the public key must still match the registry`,
  ];
  const rules = [
    "Copy the .key files byte for byte; do not convert or re-encode them (they are PKCS#8 PEM).",
    "Never paste a key file into chat, tickets, email, cloud notes or a repository, and never send it to ZipViz.",
    "The registry holds only your public key. This CLI cannot recover, rotate or revoke a lost key.",
    "zipviz keygen --force destroys the existing key; back up first.",
  ];
  const format = {
    store: "Ed25519 private keys, PKCS#8 PEM, one file per identity: <name>.key (or default.key before redeem)",
    other: "A2A card signing keys passed with --key may be Ed25519 or P-256 PKCS#8 PEM files elsewhere; back those up the same way",
  };

  const lines = [
    `zipviz home  ${home}`,
    `key folder   ${keys.dir}`,
    `format       ${format.store}`,
  ];
  if (storeError) lines.push(`key store    NOT CHECKED SAFE: ${storeError.message} (run: zipviz doctor)`);
  if (keyFiles.length === 0 && !storeError) lines.push("key files    none found yet");
  for (const k of keyFiles) {
    lines.push(k.safe ? `key file     ${k.path}` : `UNSAFE entry ${k.path}: ${k.error!.message}`);
  }
  lines.push(
    "",
    "Back up (this command only prints instructions; it did not touch your keys):",
    ...backupSteps.map((s, i) => `  ${i + 1}. ${s}`),
    "",
    "Restore:",
    ...restoreSteps.map((s, i) => `  ${i + 1}. ${s}`),
    "",
    ...rules.map((r) => `- ${r}`),
    `- ${format.other}.`,
  );
  return {
    data: {
      zipviz_home: home,
      keys_dir: keys.dir,
      key_files: keyFiles,
      key_store_error: storeError,
      format,
      backup_steps: backupSteps,
      restore_steps: restoreSteps,
      rules,
      read_key_material: false,
    },
    lines,
  };
}
