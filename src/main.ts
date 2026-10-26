import { homedir } from "node:os";
import path from "node:path";
import { Api, DEFAULT_API, parseApiOrigin, type FetchFn } from "./api.js";
import { flagValue, parseArgs, type FlagSpec } from "./args.js";
import * as commands from "./commands.js";
import { cardCommand, checkCard } from "./card.js";
import { CliError } from "./errors.js";
import { KeyStore } from "./keys.js";
import { Output, type Result, type Writer } from "./output.js";
import { escapeTerminal } from "./terminal.js";
import { checkAns } from "./ans/command.js";
import { check, MAX_INPUT_BYTES, readLimited } from "./check.js";
import { linkCommand } from "./link/index.js";
import { doctor } from "./doctor.js";
import { backup } from "./backup.js";
import type { NetDeps } from "./net/fetch.js";
import { INVITE_NAMESPACE } from "./viz.js";
import { VERSION } from "./version.js";
import { joinCommand } from "./join/index.js";

export { VERSION };

export type Deps = {
  fetch: FetchFn;
  stdout: Writer;
  stderr: Writer;
  /** Directory holding `keys/`; defaults to ~/.zipviz. */
  zipvizHome: string;
  readStdin?: () => Promise<Uint8Array>;
  net?: NetDeps;
  /** Local clock in epoch ms; `doctor` uses it to measure skew. Defaults to Date.now. */
  now?: () => number;
  /** Injectable scheduler and id source for deterministic synthetic join tests. */
  sleep?: (ms: number) => Promise<void>;
  joinId?: () => string;
};

export const USAGE = `zipviz ${VERSION} — local Ed25519 identity for the ZipViz .viz registry

usage:
  zipviz keygen [--name <label>] [--force]     create a local key; prints the public key only
  zipviz redeem <code> --name <chosen name>    claim <chosen name>-NNNN.${INVITE_NAMESPACE}.viz (ZipViz assigns the 4 digits)
  zipviz verify <name>                         look up a .viz name (and prove your local key, if you hold it)
  zipviz whoami                                local keys and their registry status
  zipviz join [start] --name <label> --owner-email <email> --runtime <runtime> [--introduced-by <token>] [--aud <audience>] [--wait]
  zipviz join start --resume <signup_id> [--wait]
  zipviz join status <signup_id> [--wait]        poll only; never moves or reads keys
  zipviz join cancel <signup_id>                withdraw a pending request with its local key
  zipviz join adopt <signup_id>                 explicitly adopt after checking current registry identity
  zipviz doctor                                read-only health check: key store safety, registry
                                               reachability, invite availability, clock skew
                                               exit 0 nothing failed or unknown, apart from the
                                               informational invites check; 11 a check failed;
                                               12 none failed but another check is unknown
  zipviz backup                                where your keys live and how to back up / restore them
                                               (prints guidance only; never reads or copies key bytes)
  zipviz check <file|->                       verify a Buzz/Nostr event offline (NIP-01 + NIP-OA owner auth)
  zipviz check --card <domain> [--key <file> | --jwks <file>] [--allow-jku-host <host>]... [--require-all]
                                               fetch and verify an A2A v1.0 signed Agent Card
  zipviz check --ans <ans-name> --ca <pem> --ra-jwk <file> --kms-jwk <file> (--bundle <file> | --cert <pem> (--badge <file> | --badge-url <https-url>))
                                               check an ANS name; trust anchors are the pinned files, not the bundle
  zipviz card sign <card.json|-> --key <file> [--kid <kid>] [--jku <https-url>] [--append]
  zipviz card jwks --key <file> [--kid <kid>]
  zipviz card verify <card.json|-> (--key <file> | --jwks <file>) [--require-all]
  zipviz link sign <domain> --nostr-pubkey <hex> [--issued-at <unix-seconds>]
  zipviz link verify <file|->                  verify a Buzz<->ZipViz identity link offline (both signatures)
  zipviz invite create <issuer> [--ttl <s>] [--aud <host>] [--execute]
  zipviz invite revoke <issuer> --invite-id <uuid> [--aud <host>] [--execute]
                                               owner-signed; dry run unless --execute;
                                               aud defaults to the --api host

global options:
  --api <origin>   registry origin (default ${DEFAULT_API}; https, or http://localhost / http://127.0.0.1)
  --json           machine-readable output on stdout (for agents and scripts; check the exit code too)
  --help           show this help

Keys live in ~/.zipviz/keys and never leave this machine.
There is no register command: direct registration is operator-gated, not self-serve.`;

type Command = { spec: FlagSpec; handler: (ctx: commands.Context, deps: Deps) => Promise<Result> };

const COMMANDS: Record<string, Command> = {
  keygen: { spec: { bool: ["force"], value: ["name"] }, handler: commands.keygen },
  redeem: { spec: { value: ["name"] }, handler: commands.redeem },
  verify: { spec: {}, handler: commands.verify },
  whoami: { spec: {}, handler: commands.whoami },
  doctor: { spec: {}, handler: doctor },
  backup: { spec: {}, handler: backup },
  check: {
    spec: {
      bool: ["require-all"],
      value: ["card", "key", "jwks", "ans", "bundle", "cert", "ca", "badge", "badge-url", "ra-jwk", "kms-jwk"],
      repeat: ["allow-jku-host"],
    },
    handler: check,
  },
  card: {
    spec: { bool: ["append", "require-all"], value: ["key", "kid", "jku", "jwks"] },
    handler: cardCommand,
  },
  invite: { spec: { bool: ["execute"], value: ["ttl", "invite-id", "aud"] }, handler: commands.invite },
  link: { spec: { value: ["nostr-pubkey", "issued-at"] }, handler: linkCommand },
  join: { spec: { bool: ["wait"], value: ["name", "owner-email", "runtime", "introduced-by", "aud", "resume"] }, handler: joinCommand },
};

export function defaultDeps(): Deps {
  return {
    fetch: (input, init) => fetch(input, init),
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    zipvizHome: path.join(homedir(), ".zipviz"),
    readStdin: () => readLimited(process.stdin, MAX_INPUT_BYTES),
  };
}

export async function run(argv: readonly string[], deps: Deps): Promise<number> {
  const json = argv.includes("--json");
  const out = new Output(json, deps.stdout, deps.stderr);
  const nameIndex = argv.findIndex((a, i) => !a.startsWith("-") && argv[i - 1] !== "--api");
  const name = nameIndex === -1 ? undefined : argv[nameIndex];
  let label = name ?? "zipviz";
  try {
    if (argv.includes("--version")) {
      return out.success("version", { data: { version: VERSION }, lines: [VERSION] });
    }
    const command = name === undefined ? undefined : COMMANDS[name];
    if (!command) {
      if (name === undefined && (argv.includes("--help") || argv.includes("-h"))) {
        return out.success("help", { data: { usage: USAGE }, lines: [USAGE] });
      }
      throw new CliError("E_USAGE", name ? `unknown command: ${name}` : "missing command", 2);
    }
    const rest = [...argv];
    rest.splice(nameIndex, 1);
    const parsed = parseArgs(rest, command.spec);
    if (name === "invite" && parsed.positional[0]) label = `invite ${parsed.positional[0]}`;
    if (name === "card" && parsed.positional[0]) label = `card ${parsed.positional[0]}`;
    if (name === "link" && parsed.positional[0]) label = `link ${parsed.positional[0]}`;
    if (name === "join") label = `join ${parsed.positional[0] ?? "start"}`;
    if (parsed.flags.has("help")) return out.success("help", { data: { usage: USAGE }, lines: [USAGE] });
    if (name === "check") {
      const cardOptions = ["key", "jwks", "allow-jku-host", "require-all"];
      const ansOptions = ["ans", "bundle", "cert", "ca", "badge", "badge-url", "ra-jwk", "kms-jwk"];
      // ANS options stay separate from --card.
      if (parsed.flags.has("card") && ansOptions.some((option) => parsed.flags.has(option))) {
        throw new CliError("E_USAGE", "--card cannot be combined with ANS options", 2);
      }
      if (parsed.flags.has("ans")) {
        if (cardOptions.some((option) => parsed.flags.has(option))) {
          throw new CliError("E_USAGE", "--ans cannot be combined with Agent Card options", 2);
        }
        const result = await checkAns({ parsed }, deps);
        if (!json) result.lines = result.lines.map(escapeTerminal);
        return out.success(label, result);
      }
      if (parsed.flags.has("card")) {
        const result = await checkCard(
          { api: new Api(DEFAULT_API, deps.fetch), keys: new KeyStore(deps.zipvizHome), parsed },
          deps,
        );
        if (!json) result.lines = result.lines.map(escapeTerminal);
        return out.success(label, result);
      }
      if (cardOptions.some((option) => parsed.flags.has(option))) {
        throw new CliError("E_USAGE", "--key, --jwks and --allow-jku-host require --card", 2);
      }
      if (ansOptions.some((option) => parsed.flags.has(option))) {
        throw new CliError("E_USAGE", "--bundle, --cert, --ca, --badge, --badge-url, --ra-jwk and --kms-jwk require --ans", 2);
      }
    }
    const apiFlag = flagValue(parsed, "api");
    const api = new Api(apiFlag === undefined ? DEFAULT_API : parseApiOrigin(apiFlag), deps.fetch);
    const result = await command.handler({ api, keys: new KeyStore(deps.zipvizHome), parsed }, deps);
    if (!json && (name === "check" || name === "card" || name === "link" || name === "doctor" || name === "backup" || name === "join")) {
      result.lines = result.lines.map(escapeTerminal);
    }
    return out.success(label, result);
  } catch (e) {
    const err = e instanceof CliError ? e : new CliError("E_INTERNAL", "unexpected error");
    return out.failure(label, err, USAGE);
  }
}
