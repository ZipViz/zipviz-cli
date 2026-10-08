import { flagValue } from "../args.js";
import { npubEncode } from "../buzz/index.js";
import { readJsonObject, type CheckDeps } from "../check.js";
import type { Context } from "../commands.js";
import { CliError, usageError } from "../errors.js";
import { DEFAULT_KEY_ID } from "../keys.js";
import type { Result } from "../output.js";
import { asciiLower, isValidVizAgentDomain } from "../viz.js";
import {
  LINK_DOC_VERSION, linkStatement, PROVISIONAL_LINK_EVENT_KIND, PUBKEY_HEX_RE, unsignedLinkEvent,
} from "./statement.js";
import { registryCaveat, verifyIdentityLink } from "./verify.js";

/** Exit code for a well-formed document whose link does not verify (matches `zipviz check`). */
const LINK_INVALID_EXIT = 4;
const SIGN_USAGE = "zipviz link sign <domain> --nostr-pubkey <hex> [--issued-at <unix-seconds>]";
const VERIFY_USAGE = "zipviz link verify <file|->";

function jsonLines(label: string, value: unknown): string[] {
  return [label, ...JSON.stringify(value, null, 2).split("\n")];
}

function parseIssuedAt(raw: string | undefined): number {
  if (raw === undefined) return Math.floor(Date.now() / 1000);
  if (!/^[0-9]{1,15}$/.test(raw)) throw usageError("--issued-at must be whole Unix seconds");
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) throw usageError("--issued-at must be whole Unix seconds");
  return value;
}

async function linkSign({ keys, parsed }: Context): Promise<Result> {
  if (parsed.positional.length !== 2) throw usageError(`usage: ${SIGN_USAGE}`);
  const domain = asciiLower(parsed.positional[1]!);
  if (!isValidVizAgentDomain(domain)) throw usageError(`not a valid .viz agent name: ${parsed.positional[1]}`);
  const rawNostr = flagValue(parsed, "nostr-pubkey");
  if (rawNostr === undefined) throw usageError(`usage: ${SIGN_USAGE}`);
  const nostrPubkey = asciiLower(rawNostr);
  if (!PUBKEY_HEX_RE.test(nostrPubkey)) {
    throw usageError("--nostr-pubkey must be 64 hexadecimal characters (the x-only key, not an npub)");
  }
  const issuedAt = parseIssuedAt(flagValue(parsed, "issued-at"));

  const keyId = (await keys.exists(domain)) ? domain : DEFAULT_KEY_ID;
  if (!(await keys.exists(keyId))) {
    throw new CliError("E_NO_KEY", `no local key for ${domain} (run: zipviz keygen --name ${domain})`);
  }
  const key = await keys.load(keyId);

  const fields = { domain, ed25519Pubkey: key.publicKey, nostrPubkey, issuedAt };
  const statement = linkStatement(fields);
  const signature = key.sign(statement).toString("hex");
  const event = unsignedLinkEvent(fields, statement);
  const npub = npubEncode(nostrPubkey);
  const document = {
    v: LINK_DOC_VERSION,
    domain,
    ed25519_pubkey: key.publicKey,
    nostr_pubkey: nostrPubkey,
    nostr_npub: npub,
    issued_at: issuedAt,
    statement,
    ed25519_sig: signature,
  };

  return {
    data: { key_id: keyId, link: document, nostr_event_template: event, provisional_kind: PROVISIONAL_LINK_EVENT_KIND },
    lines: [
      `statement          ${statement}`,
      `ed25519 pubkey     ${key.publicKey}`,
      `ed25519 signature  ${signature}`,
      `buzz agent         ${npub}`,
      "",
      ...jsonLines("link document (half-signed):", document),
      "",
      ...jsonLines("unsigned nostr event for your Buzz client to sign:", event),
      "",
      `kind ${PROVISIONAL_LINK_EVENT_KIND} is provisional: no NIP defines an identity-link kind yet.`,
      `next: sign that event, add it to the link document as "nostr_event", then run ${VERIFY_USAGE}.`,
      "this CLI never reads, accepts or holds a Nostr secret key (nsec).",
      `a verified link proves only that these two keys co-signed the statement; it does not prove the registry lists this ed25519 key for ${domain} (check with: zipviz verify ${domain}).`,
    ],
  };
}

async function linkVerify({ parsed }: Context, deps: CheckDeps): Promise<Result> {
  if (parsed.positional.length !== 2) throw usageError(`usage: ${VERIFY_USAGE}`);
  const verification = verifyIdentityLink(await readJsonObject(parsed.positional[1]!, deps));
  const { link, ed25519, nostr } = verification;

  const lines: string[] = [];
  if (verification.ok) {
    lines.push(
      `linked to Buzz agent ${link.nostr_npub}`,
      `zipviz agent ${link.domain} (ed25519 ${link.ed25519_pubkey})`,
      `both signatures verify: Ed25519 over the statement, nostr event ${nostr.event.id} (kind ${nostr.event.kind})`,
      `issued_at ${link.issued_at}`,
      "this proves both keys co-signed the statement, nothing more: neither identity authors the other's messages.",
      registryCaveat(link.domain),
    );
    if (nostr.kind_matches_provisional === false) {
      lines.push(`note: event kind ${nostr.event.kind} is not the provisional link kind ${PROVISIONAL_LINK_EVENT_KIND}.`);
    }
    if (nostr.created_at_matches_issued_at === false) {
      lines.push(`note: nostr event created_at ${nostr.event.created_at} differs from issued_at ${link.issued_at}; only issued_at is signed by both keys.`);
    }
  } else {
    lines.push(`link failed: ${link.reason}`, `${link.message}`);
    lines.push(`ed25519 side: ${ed25519.valid ? "ok" : (ed25519.reason ?? "not checked")}`);
    lines.push(`nostr side: ${nostr.valid ? "ok" : (nostr.reason ?? "not checked")}`);
    if (link.nostr_npub) lines.push(`claimed Buzz agent ${link.nostr_npub} is NOT linked.`);
    lines.push(registryCaveat(link.domain));
  }

  return {
    ok: verification.ok,
    data: verification,
    lines,
    exitCode: verification.ok ? 0 : LINK_INVALID_EXIT,
  };
}

export async function linkCommand(ctx: Context, deps: CheckDeps): Promise<Result> {
  const sub = ctx.parsed.positional[0];
  if (sub === "sign") return linkSign(ctx);
  if (sub === "verify") return linkVerify(ctx, deps);
  throw usageError(`usage: ${SIGN_USAGE} | ${VERIFY_USAGE}`);
}
