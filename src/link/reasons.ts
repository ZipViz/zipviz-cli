import type { BuzzVerification } from "../buzz/index.js";

/** Stable reason codes for an offline identity-link check (same style as src/buzz/reasons.ts). */
export type LinkReason =
  | "LINK_DOC_NOT_OBJECT"
  | "LINK_VERSION_UNSUPPORTED"
  | "LINK_DOMAIN_INVALID"
  | "LINK_ED25519_PUBKEY_FORMAT"
  | "LINK_NOSTR_PUBKEY_FORMAT"
  | "LINK_NPUB_MISMATCH"
  | "LINK_ISSUED_AT_INVALID"
  | "LINK_STATEMENT_MISSING"
  | "LINK_STATEMENT_MALFORMED"
  | "LINK_STATEMENT_MISMATCH"
  | "LINK_ED25519_SIG_MISSING"
  | "LINK_ED25519_SIG_FORMAT"
  | "LINK_ED25519_SIG_INVALID"
  | "LINK_NOSTR_EVENT_MISSING"
  | "LINK_NOSTR_EVENT_INVALID"
  | "LINK_NOSTR_OWNER_AUTH_INVALID"
  | "LINK_CONTENT_MISMATCH"
  | "LINK_EVENT_PUBKEY_MISMATCH"
  | "LINK_VIZ_TAG_MISSING"
  | "LINK_VIZ_TAG_MISMATCH";

export type LinkSide = {
  valid: boolean;
  reason?: LinkReason;
  message?: string;
};

export type LinkVerification = {
  /** Both signatures verify and every cross-check holds. */
  ok: boolean;
  link: {
    valid: boolean;
    /**
     * Always false: this check is offline, so the Ed25519 key is taken from the document and is
     * never compared with the key the registry lists for `domain`. A valid link proves only
     * that the two keys in the statement co-signed it.
     */
    registry_checked: false;
    /** Human-readable form of the `registry_checked` caveat, always present. */
    caveat: string;
    domain: string | null;
    ed25519_pubkey: string | null;
    nostr_pubkey: string | null;
    nostr_npub: string | null;
    issued_at: number | null;
    statement: string | null;
    reason?: LinkReason;
    message?: string;
  };
  /** The ZipViz side: Ed25519 signature over the statement bytes. */
  ed25519: LinkSide;
  /** The Buzz side: the signed Nostr event, verified by verifyBuzzEvent unchanged. */
  nostr: LinkSide & {
    event: BuzzVerification["event"];
    owner_auth: BuzzVerification["owner_auth"];
    /** Provisional kind: a different kind is reported, not rejected. */
    kind_matches_provisional: boolean | null;
    /**
     * Whether the event's `created_at` equals the statement's `issued_at`. Reported, not
     * rejected: `issued_at` is inside the bytes both keys sign, while `created_at` is the
     * Buzz client's own publish time.
     */
    created_at_matches_issued_at: boolean | null;
  };
};
