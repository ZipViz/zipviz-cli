/**
 * The identity-link statement both keys sign (see docs/design/buzz-identity-link.md).
 *
 *   zipviz:identity-link:v1:<viz-domain>:<ed25519-pubkey-hex>:<nostr-pubkey-hex>:<issued_at>
 *
 * The prefix is the domain separation: these bytes can never be a `/v1/verify` envelope
 * (JSON), a NIP-OA auth preimage (`nostr:agent-auth:…`) or a NIP-01 event id (a hash).
 */
export const LINK_STATEMENT_PREFIX = "zipviz:identity-link:v1";

/** The only link-document version this CLI understands; `v` is rejected if it is anything else. */
export const LINK_DOC_VERSION = 1;

/**
 * PROVISIONAL. Buzz has not chosen a kind for identity links and there is no NIP for this.
 * It sits in the parameterised-replaceable range (30000-39999) so one current link per pair
 * is possible later; a `d` tag would be needed for that and is deliberately not emitted yet.
 */
export const PROVISIONAL_LINK_EVENT_KIND = 30388;

/** Tag naming the ZipViz side on the Nostr event. */
export const VIZ_TAG = "viz";

export const PUBKEY_HEX_RE = /^[0-9a-f]{64}$/;
export const ED25519_SIG_HEX_RE = /^[0-9a-f]{128}$/;

export type LinkFields = {
  domain: string;
  ed25519Pubkey: string;
  nostrPubkey: string;
  issuedAt: number;
};

/** Exact UTF-8 bytes, no normalisation: the fields are joined with ':' verbatim. */
export function linkStatement(fields: LinkFields): string {
  return [
    LINK_STATEMENT_PREFIX,
    fields.domain,
    fields.ed25519Pubkey,
    fields.nostrPubkey,
    String(fields.issuedAt),
  ].join(":");
}

/** Whether a statement has the v1 prefix and the right number of fields. */
export function hasLinkStatementShape(statement: string): boolean {
  const parts = statement.split(":");
  return parts.length === 7 && parts.slice(0, 3).join(":") === LINK_STATEMENT_PREFIX;
}

export function isIssuedAt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

export type UnsignedLinkEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

/** The event template the Buzz client signs; the CLI never holds a Nostr secret key. */
export function unsignedLinkEvent(fields: LinkFields, statement: string): UnsignedLinkEvent {
  return {
    pubkey: fields.nostrPubkey,
    created_at: fields.issuedAt,
    kind: PROVISIONAL_LINK_EVENT_KIND,
    tags: [[VIZ_TAG, fields.domain]],
    content: statement,
  };
}
