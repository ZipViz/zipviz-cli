import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { npubEncode, verifyBuzzEvent } from "../src/buzz/index.js";
import {
  LINK_DOC_VERSION, LINK_STATEMENT_PREFIX, linkStatement, PROVISIONAL_LINK_EVENT_KIND,
  verifyIdentityLink,
} from "../src/link/index.js";
import { authTag, signEvent } from "./buzz-helpers.js";
import { DOMAIN, ISSUED_AT, linkEvent, makeKeys, makeLink } from "./link-helpers.js";

const keys = makeKeys();
const other = makeKeys();

describe("identity link, positive vectors", () => {
  it("accepts a link both keys signed and reports both identities separately", () => {
    const { doc, statement, event } = makeLink(keys);
    const result = verifyIdentityLink(doc);
    expect(result.ok).toBe(true);
    expect(result.link).toMatchObject({
      valid: true,
      domain: DOMAIN,
      ed25519_pubkey: keys.edPublic,
      nostr_pubkey: keys.nostrPubkey,
      nostr_npub: npubEncode(keys.nostrPubkey),
      issued_at: ISSUED_AT,
      statement,
    });
    expect(result.link.reason).toBeUndefined();
    expect(result.ed25519.valid).toBe(true);
    expect(result.nostr.valid).toBe(true);
    expect(result.nostr.event.id).toBe(event.id);
    expect(result.nostr.kind_matches_provisional).toBe(true);
    expect(statement).toBe(`${LINK_STATEMENT_PREFIX}:${DOMAIN}:${keys.edPublic}:${keys.nostrPubkey}:${ISSUED_AT}`);
  });

  it("accepts a valid NIP-OA owner authorisation on the Buzz side", () => {
    const { doc, statement } = makeLink(keys);
    doc.nostr_event = signEvent(keys.nostrSecret, {
      created_at: ISSUED_AT,
      kind: PROVISIONAL_LINK_EVENT_KIND,
      tags: [["viz", DOMAIN], authTag(undefined, keys.nostrPubkey)],
      content: statement,
    });
    const result = verifyIdentityLink(doc);
    expect(result.ok).toBe(true);
    expect(result.nostr.owner_auth).toMatchObject({ present: true, valid: true });
  });

  it("reports a non-provisional kind without rejecting the link", () => {
    const { doc, statement } = makeLink(keys);
    doc.nostr_event = signEvent(keys.nostrSecret, {
      created_at: ISSUED_AT, kind: 1, tags: [["viz", DOMAIN]], content: statement,
    });
    const result = verifyIdentityLink(doc);
    expect(result.ok).toBe(true);
    expect(result.nostr.kind_matches_provisional).toBe(false);
  });

  it("never claims the registry was checked, on success or on failure", () => {
    const { doc } = makeLink(keys);
    const ok = verifyIdentityLink(doc);
    expect(ok.ok).toBe(true);
    expect(ok.link.registry_checked).toBe(false);
    expect(ok.link.caveat).toMatch(/NOT compared with the key the registry lists/);
    // A link signed by a throwaway Ed25519 key that names the same domain still verifies as a
    // pair of signatures, so the caveat is the only thing standing between it and a false claim.
    const impostor = verifyIdentityLink(makeLink(other).doc);
    expect(impostor.ok).toBe(true);
    expect(impostor.link.ed25519_pubkey).not.toBe(keys.edPublic);
    expect(impostor.link.registry_checked).toBe(false);
    expect(verifyIdentityLink({ ...doc, v: 99 }).link.registry_checked).toBe(false);
  });

  it("reports, without rejecting, an event created_at that differs from issued_at", () => {
    const { doc, statement } = makeLink(keys);
    expect(verifyIdentityLink(doc).nostr.created_at_matches_issued_at).toBe(true);
    const result = verifyIdentityLink({
      ...doc,
      nostr_event: linkEvent(keys, statement, DOMAIN, ISSUED_AT + 600),
    });
    expect(result.ok).toBe(true);
    expect(result.nostr.created_at_matches_issued_at).toBe(false);
    expect(result.nostr.event.created_at).toBe(ISSUED_AT + 600);
  });
});

const reasonOf = (doc: Record<string, unknown>) => verifyIdentityLink(doc).link.reason;

describe("identity link, one reject rule per test", () => {
  it("rejects a wrong Ed25519 signature", () => {
    const { doc } = makeLink(keys);
    doc.ed25519_sig = other.signEd(doc.statement as string);
    const result = verifyIdentityLink(doc);
    expect(result.ok).toBe(false);
    expect(result.link.reason).toBe("LINK_ED25519_SIG_INVALID");
    expect(result.nostr.valid).toBe(true);
  });

  it("rejects a wrong Nostr signature", () => {
    const { doc, event } = makeLink(keys);
    doc.nostr_event = { ...event, sig: `${event.sig.slice(0, -2)}${event.sig.endsWith("00") ? "11" : "00"}` };
    const result = verifyIdentityLink(doc);
    expect(result.ok).toBe(false);
    expect(result.link.reason).toBe("LINK_NOSTR_EVENT_INVALID");
    expect(result.ed25519.valid).toBe(true);
  });

  it("rejects a Nostr event whose content is not the statement", () => {
    const { doc } = makeLink(keys);
    doc.nostr_event = linkEvent(keys, "zipviz:identity-link:v1:not.the.statement");
    expect(reasonOf(doc)).toBe("LINK_CONTENT_MISMATCH");
  });

  it("rejects a Nostr event signed by a key other than the one named in the statement", () => {
    const { doc, statement } = makeLink(keys);
    doc.nostr_event = linkEvent(other, statement);
    expect(reasonOf(doc)).toBe("LINK_EVENT_PUBKEY_MISMATCH");
  });

  it("rejects a viz tag naming another domain", () => {
    const { doc, statement } = makeLink(keys);
    doc.nostr_event = signEvent(keys.nostrSecret, {
      created_at: ISSUED_AT, kind: PROVISIONAL_LINK_EVENT_KIND,
      tags: [["viz", "other.z.viz"]], content: statement,
    });
    expect(reasonOf(doc)).toBe("LINK_VIZ_TAG_MISMATCH");
  });

  it("rejects a Nostr event with no viz tag", () => {
    const { doc, statement } = makeLink(keys);
    doc.nostr_event = signEvent(keys.nostrSecret, {
      created_at: ISSUED_AT, kind: PROVISIONAL_LINK_EVENT_KIND, tags: [], content: statement,
    });
    expect(reasonOf(doc)).toBe("LINK_VIZ_TAG_MISSING");
  });

  it("rejects a document whose domain does not match the statement", () => {
    const { doc } = makeLink(keys);
    doc.domain = "other.z.viz";
    expect(reasonOf(doc)).toBe("LINK_STATEMENT_MISMATCH");
  });

  it("rejects a swapped key pair", () => {
    const statement = linkStatement({
      domain: DOMAIN, ed25519Pubkey: keys.nostrPubkey, nostrPubkey: keys.edPublic, issuedAt: ISSUED_AT,
    });
    const result = verifyIdentityLink({
      v: 1,
      domain: DOMAIN,
      ed25519_pubkey: keys.nostrPubkey,
      nostr_pubkey: keys.edPublic,
      issued_at: ISSUED_AT,
      statement,
      ed25519_sig: keys.signEd(statement),
      nostr_event: linkEvent(keys, statement),
    });
    expect(result.ok).toBe(false);
    expect(result.link.reason).toBe("LINK_ED25519_SIG_INVALID");
    expect(result.nostr.reason).toBe("LINK_EVENT_PUBKEY_MISMATCH");
  });

  it("rejects a one-sided link: no Nostr event", () => {
    const { doc } = makeLink(keys);
    delete doc.nostr_event;
    const result = verifyIdentityLink(doc);
    expect(result.link.reason).toBe("LINK_NOSTR_EVENT_MISSING");
    expect(result.ed25519.valid).toBe(true);
  });

  it("rejects a one-sided link: no Ed25519 signature", () => {
    const { doc } = makeLink(keys);
    delete doc.ed25519_sig;
    const result = verifyIdentityLink(doc);
    expect(result.link.reason).toBe("LINK_ED25519_SIG_MISSING");
    expect(result.nostr.valid).toBe(true);
  });

  it("rejects non-hex or wrong-length keys and signatures", () => {
    const { doc } = makeLink(keys);
    expect(reasonOf({ ...doc, ed25519_pubkey: keys.edPublic.toUpperCase() })).toBe("LINK_ED25519_PUBKEY_FORMAT");
    expect(reasonOf({ ...doc, ed25519_pubkey: keys.edPublic.slice(0, 63) })).toBe("LINK_ED25519_PUBKEY_FORMAT");
    expect(reasonOf({ ...doc, nostr_pubkey: `zz${keys.nostrPubkey.slice(2)}` })).toBe("LINK_NOSTR_PUBKEY_FORMAT");
    expect(reasonOf({ ...doc, nostr_pubkey: npubEncode(keys.nostrPubkey) })).toBe("LINK_NOSTR_PUBKEY_FORMAT");
    expect(reasonOf({ ...doc, ed25519_sig: (doc.ed25519_sig as string).slice(0, 126) })).toBe("LINK_ED25519_SIG_FORMAT");
  });

  it("rejects a malformed statement or a different prefix", () => {
    const { doc, statement } = makeLink(keys);
    expect(reasonOf({ ...doc, statement: "hello" })).toBe("LINK_STATEMENT_MALFORMED");
    expect(reasonOf({ ...doc, statement: statement.replace("v1", "v2") })).toBe("LINK_STATEMENT_MALFORMED");
    expect(reasonOf({ ...doc, statement: `${statement}:extra` })).toBe("LINK_STATEMENT_MALFORMED");
    expect(reasonOf({ ...doc, statement: 42 })).toBe("LINK_STATEMENT_MISSING");
  });

  it("rejects an invalid domain, issued_at or document shape", () => {
    const { doc } = makeLink(keys);
    expect(reasonOf({ ...doc, domain: "example.com" })).toBe("LINK_DOMAIN_INVALID");
    expect(reasonOf({ ...doc, issued_at: String(ISSUED_AT) })).toBe("LINK_ISSUED_AT_INVALID");
    expect(reasonOf({ ...doc, issued_at: -1 })).toBe("LINK_ISSUED_AT_INVALID");
    expect(verifyIdentityLink([]).link.reason).toBe("LINK_DOC_NOT_OBJECT");
    expect(verifyIdentityLink(null).link.reason).toBe("LINK_DOC_NOT_OBJECT");
  });

  it("rejects an invalid NIP-OA owner authorisation on the link event", () => {
    const { doc, statement, event } = makeLink(keys);
    doc.nostr_event = signEvent(keys.nostrSecret, {
      created_at: ISSUED_AT,
      kind: PROVISIONAL_LINK_EVENT_KIND,
      // The link event's own signature replayed as an owner-authorisation signature.
      tags: [["viz", DOMAIN], ["auth", other.nostrPubkey, "", event.sig]],
      content: statement,
    });
    expect(reasonOf(doc)).toBe("LINK_NOSTR_OWNER_AUTH_INVALID");
  });

  it("rejects a document version other than v1", () => {
    const { doc } = makeLink(keys);
    expect(LINK_DOC_VERSION).toBe(1);
    expect(reasonOf({ ...doc, v: 99 })).toBe("LINK_VERSION_UNSUPPORTED");
    expect(reasonOf({ ...doc, v: 2 })).toBe("LINK_VERSION_UNSUPPORTED");
    expect(reasonOf({ ...doc, v: "1" })).toBe("LINK_VERSION_UNSUPPORTED");
    const withoutVersion = { ...doc };
    delete withoutVersion.v;
    expect(reasonOf(withoutVersion)).toBe("LINK_VERSION_UNSUPPORTED");
  });

  it("rejects a nostr_npub that is not the bech32 form of nostr_pubkey", () => {
    const { doc } = makeLink(keys);
    expect(reasonOf({ ...doc, nostr_npub: npubEncode(other.nostrPubkey) })).toBe("LINK_NPUB_MISMATCH");
    expect(reasonOf({ ...doc, nostr_npub: "npub1notbech32" })).toBe("LINK_NPUB_MISMATCH");
    expect(reasonOf({ ...doc, nostr_npub: keys.nostrPubkey })).toBe("LINK_NPUB_MISMATCH");
    expect(reasonOf({ ...doc, nostr_npub: npubEncode(keys.nostrPubkey) })).toBeUndefined();
  });
});

describe("domain separation of the statement bytes", () => {
  it("does not let the Ed25519 link signature pass as a /v1/verify envelope signature", () => {
    const { doc, statement } = makeLink(keys);
    const envelope = JSON.stringify({ domain: DOMAIN, nonce: "0".repeat(32), issued_at: ISSUED_AT });
    const linkSignature = hexToBytes(doc.ed25519_sig as string);
    const pubkey = hexToBytes(keys.edPublic);
    expect(ed25519.verify(linkSignature, utf8ToBytes(statement), pubkey)).toBe(true);
    expect(ed25519.verify(linkSignature, utf8ToBytes(envelope), pubkey)).toBe(false);
    expect(statement.startsWith(LINK_STATEMENT_PREFIX)).toBe(true);
    expect(statement.startsWith("{")).toBe(false);
  });

  it("does not let an envelope signature pass as the Ed25519 link signature", () => {
    const { doc } = makeLink(keys);
    const envelope = JSON.stringify({ domain: DOMAIN, nonce: "0".repeat(32), issued_at: ISSUED_AT });
    expect(reasonOf({ ...doc, ed25519_sig: keys.signEd(envelope) })).toBe("LINK_ED25519_SIG_INVALID");
  });

  it("does not let the statement act as a NIP-OA auth preimage or a bare event id", () => {
    const { statement, event } = makeLink(keys);
    expect(statement.startsWith("nostr:agent-auth:")).toBe(false);
    expect(/^[0-9a-f]{64}$/.test(statement)).toBe(false);
    // The signed link event is still a valid NIP-01 event, but carries no owner authorisation.
    const buzz = verifyBuzzEvent(event);
    expect(buzz.event.valid).toBe(true);
    expect(buzz.owner_auth.present).toBe(false);
  });
});
