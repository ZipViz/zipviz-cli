export type EventReason =
  | "EVENT_BAD_ID"
  | "EVENT_BAD_PUBKEY"
  | "EVENT_BAD_CREATED_AT"
  | "EVENT_BAD_KIND"
  | "EVENT_BAD_TAGS"
  | "EVENT_BAD_CONTENT"
  | "EVENT_BAD_SIG"
  | "EVENT_PUBKEY_NOT_ON_CURVE"
  | "EVENT_ID_MISMATCH"
  | "EVENT_SIG_INVALID";

export type AuthReason =
  | "AUTH_MULTIPLE_TAGS"
  | "AUTH_TAG_ELEMENT_COUNT"
  | "AUTH_OWNER_PUBKEY_FORMAT"
  | "AUTH_OWNER_PUBKEY_NOT_ON_CURVE"
  | "AUTH_SELF_ATTESTATION"
  | "AUTH_CONDITIONS_MALFORMED"
  | "AUTH_CONDITION_UNSUPPORTED"
  | "AUTH_CONDITION_BAD_DECIMAL"
  | "AUTH_CONDITION_OUT_OF_RANGE"
  | "AUTH_SIG_FORMAT"
  | "AUTH_SIG_INVALID"
  | "AUTH_CONDITION_UNMET"
  | "AUTH_EVENT_INVALID";

export type Clause = {
  clause: string;
  field: "kind" | "created_at";
  op: "=" | "<" | ">";
  value: number;
  satisfied: boolean;
};

export type BuzzVerification = {
  ok: boolean;
  event: {
    valid: boolean;
    id: string | null;
    agent_pubkey: string | null;
    agent_npub: string | null;
    kind: number | null;
    created_at: number | null;
    reason?: EventReason;
    message?: string;
  };
  owner_auth: {
    present: boolean;
    valid: boolean;
    owner_pubkey?: string;
    owner_npub?: string;
    conditions?: string;
    clauses?: Clause[];
    reason?: AuthReason;
    message?: string;
  };
};
