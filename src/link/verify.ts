import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { npubEncode, verifyBuzzEvent, type BuzzVerification } from "../buzz/index.js";
import { isValidVizAgentDomain } from "../viz.js";
import type { LinkReason, LinkSide, LinkVerification } from "./reasons.js";
import {
  ED25519_SIG_HEX_RE, hasLinkStatementShape, isIssuedAt, LINK_DOC_VERSION, LINK_STATEMENT_PREFIX, linkStatement,
  PROVISIONAL_LINK_EVENT_KIND, PUBKEY_HEX_RE, VIZ_TAG,
} from "./statement.js";

const NO_EVENT: BuzzVerification["event"] = {
  valid: false, id: null, agent_pubkey: null, agent_npub: null, kind: null, created_at: null,
};
const NO_OWNER_AUTH: BuzzVerification["owner_auth"] = { present: false, valid: false };

/**
 * The standing caveat on every offline link check: the Ed25519 key is whatever the document
 * says, so a verified link says nothing about who owns `<domain>` in the registry.
 */
export const REGISTRY_CAVEAT =
  "offline check: the ed25519 key was taken from this document and was NOT compared with the "
  + "key the registry lists for the domain; compare it with zipviz verify <name>";

/** The caveat with `<name>` filled in, when the document named a usable domain. */
export function registryCaveat(domain?: string | null): string {
  return domain ? REGISTRY_CAVEAT.replace("zipviz verify <name>", `zipviz verify ${domain}`) : REGISTRY_CAVEAT;
}

function fail(reason: LinkReason, message: string, fields: Partial<LinkVerification["link"]> = {}): LinkVerification {
  return {
    ok: false,
    link: {
      valid: false,
      registry_checked: false,
      caveat: REGISTRY_CAVEAT,
      domain: fields.domain ?? null,
      ed25519_pubkey: fields.ed25519_pubkey ?? null,
      nostr_pubkey: fields.nostr_pubkey ?? null,
      nostr_npub: fields.nostr_npub ?? null,
      issued_at: fields.issued_at ?? null,
      statement: fields.statement ?? null,
      reason,
      message,
    },
    ed25519: { valid: false },
    nostr: {
      valid: false, event: NO_EVENT, owner_auth: NO_OWNER_AUTH,
      kind_matches_provisional: null, created_at_matches_issued_at: null,
    },
  };
}

const side = (reason: LinkReason, message: string): LinkSide => ({ valid: false, reason, message });

function verifyEd25519(statement: string, pubkeyHex: string, signature: unknown): LinkSide {
  if (signature === undefined || signature === null) {
    return side("LINK_ED25519_SIG_MISSING", "one-sided link: no Ed25519 signature from the ZipViz key");
  }
  if (typeof signature !== "string" || !ED25519_SIG_HEX_RE.test(signature)) {
    return side("LINK_ED25519_SIG_FORMAT", "ed25519_sig must be 128 lowercase hexadecimal characters");
  }
  let valid = false;
  try {
    valid = ed25519.verify(hexToBytes(signature), utf8ToBytes(statement), hexToBytes(pubkeyHex));
  } catch {
    valid = false;
  }
  return valid
    ? { valid: true }
    : side("LINK_ED25519_SIG_INVALID", "Ed25519 signature does not verify over the statement bytes");
}

function vizTagValues(event: unknown): string[] {
  const tags = (event as { tags?: unknown }).tags;
  if (!Array.isArray(tags)) return [];
  return tags
    .filter((tag): tag is string[] => Array.isArray(tag) && tag[0] === VIZ_TAG)
    .map((tag) => (typeof tag[1] === "string" ? tag[1] : ""));
}

function verifyNostrSide(
  statement: string,
  domain: string,
  nostrPubkey: string,
  issuedAt: number,
  event: unknown,
): LinkVerification["nostr"] {
  if (event === undefined || event === null) {
    return {
      ...side("LINK_NOSTR_EVENT_MISSING", "one-sided link: no signed Nostr event from the Buzz key"),
      event: NO_EVENT, owner_auth: NO_OWNER_AUTH,
      kind_matches_provisional: null, created_at_matches_issued_at: null,
    };
  }
  const verification = verifyBuzzEvent(event);
  const kindMatches = verification.event.kind === null
    ? null
    : verification.event.kind === PROVISIONAL_LINK_EVENT_KIND;
  const base = {
    event: verification.event,
    owner_auth: verification.owner_auth,
    kind_matches_provisional: kindMatches,
    created_at_matches_issued_at: verification.event.created_at === null
      ? null
      : verification.event.created_at === issuedAt,
  };
  if (!verification.event.valid) {
    const reason = verification.event.reason ?? "EVENT_SIG_INVALID";
    return {
      ...side("LINK_NOSTR_EVENT_INVALID", `Nostr event does not verify: ${reason}`),
      ...base,
    };
  }
  if (verification.owner_auth.present && !verification.owner_auth.valid) {
    return {
      ...side("LINK_NOSTR_OWNER_AUTH_INVALID", "Nostr event carries an invalid NIP-OA owner authorisation"),
      ...base,
    };
  }
  const content = (event as { content?: unknown }).content;
  if (content !== statement) {
    return { ...side("LINK_CONTENT_MISMATCH", "Nostr event content is not the link statement"), ...base };
  }
  if (verification.event.agent_pubkey !== nostrPubkey) {
    return {
      ...side("LINK_EVENT_PUBKEY_MISMATCH", "Nostr event was signed by a key other than the one in the statement"),
      ...base,
    };
  }
  const vizTags = vizTagValues(event);
  if (vizTags.length === 0) {
    return { ...side("LINK_VIZ_TAG_MISSING", `Nostr event has no ["${VIZ_TAG}", "<domain>"] tag`), ...base };
  }
  if (!vizTags.every((value) => value === domain)) {
    return { ...side("LINK_VIZ_TAG_MISMATCH", `Nostr event viz tag does not name ${domain}`), ...base };
  }
  return { valid: true, ...base };
}

/**
 * Verify an identity-link document offline. Nothing here reads the network, the local clock or
 * any secret key, and neither key type is ever derived from or converted into the other.
 */
export function verifyIdentityLink(input: unknown): LinkVerification {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return fail("LINK_DOC_NOT_OBJECT", "link document must be a JSON object");
  }
  const doc = input as Record<string, unknown>;

  if (doc.v !== LINK_DOC_VERSION) {
    return fail(
      "LINK_VERSION_UNSUPPORTED",
      `unsupported link document version: v must be ${LINK_DOC_VERSION}`,
    );
  }
  const domain = doc.domain;
  if (!isValidVizAgentDomain(domain)) {
    return fail("LINK_DOMAIN_INVALID", "domain must be a .viz agent domain");
  }
  const edPubkey = doc.ed25519_pubkey;
  if (typeof edPubkey !== "string" || !PUBKEY_HEX_RE.test(edPubkey)) {
    return fail("LINK_ED25519_PUBKEY_FORMAT", "ed25519_pubkey must be 64 lowercase hexadecimal characters", { domain });
  }
  const nostrPubkey = doc.nostr_pubkey;
  if (typeof nostrPubkey !== "string" || !PUBKEY_HEX_RE.test(nostrPubkey)) {
    return fail("LINK_NOSTR_PUBKEY_FORMAT", "nostr_pubkey must be 64 lowercase hexadecimal characters", {
      domain, ed25519_pubkey: edPubkey,
    });
  }
  const npub = npubEncode(nostrPubkey);
  if (doc.nostr_npub !== undefined && doc.nostr_npub !== npub) {
    return fail("LINK_NPUB_MISMATCH", "nostr_npub is not the bech32 form of nostr_pubkey", {
      domain, ed25519_pubkey: edPubkey, nostr_pubkey: nostrPubkey, nostr_npub: npub,
    });
  }
  const issuedAt = doc.issued_at;
  if (!isIssuedAt(issuedAt)) {
    return fail("LINK_ISSUED_AT_INVALID", "issued_at must be a non-negative safe integer", {
      domain, ed25519_pubkey: edPubkey, nostr_pubkey: nostrPubkey,
    });
  }
  const known = {
    domain,
    ed25519_pubkey: edPubkey,
    nostr_pubkey: nostrPubkey,
    nostr_npub: npub,
    issued_at: issuedAt,
  };

  const statement = doc.statement;
  if (typeof statement !== "string") {
    return fail("LINK_STATEMENT_MISSING", "statement must be a string", known);
  }
  if (!hasLinkStatementShape(statement)) {
    return fail(
      "LINK_STATEMENT_MALFORMED",
      `statement must be ${LINK_STATEMENT_PREFIX}:<domain>:<ed25519-hex>:<nostr-hex>:<issued_at>`,
      known,
    );
  }
  const expected = linkStatement({
    domain, ed25519Pubkey: edPubkey, nostrPubkey, issuedAt,
  });
  if (statement !== expected) {
    return fail("LINK_STATEMENT_MISMATCH", "statement does not match the document's domain, keys and issued_at", {
      ...known, statement,
    });
  }

  const ed = verifyEd25519(statement, edPubkey, doc.ed25519_sig);
  const nostr = verifyNostrSide(statement, domain, nostrPubkey, issuedAt, doc.nostr_event);
  const valid = ed.valid && nostr.valid;
  const failure = ed.valid ? nostr : ed;
  return {
    ok: valid,
    link: {
      valid,
      registry_checked: false,
      caveat: REGISTRY_CAVEAT,
      ...known,
      statement,
      ...(valid ? {} : { reason: failure.reason, message: failure.message }),
    },
    ed25519: ed,
    nostr,
  };
}
