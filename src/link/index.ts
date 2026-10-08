export type { LinkReason, LinkSide, LinkVerification } from "./reasons.js";
export type { LinkFields, UnsignedLinkEvent } from "./statement.js";
export {
  ED25519_SIG_HEX_RE, hasLinkStatementShape, LINK_DOC_VERSION, LINK_STATEMENT_PREFIX, linkStatement,
  PROVISIONAL_LINK_EVENT_KIND, PUBKEY_HEX_RE, unsignedLinkEvent, VIZ_TAG,
} from "./statement.js";
export { REGISTRY_CAVEAT, registryCaveat, verifyIdentityLink } from "./verify.js";
export { linkCommand } from "./command.js";
