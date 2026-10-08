# Design note: linking a Buzz identity to a ZipViz identity

Status: partly built. Offline link verification is built in this CLI: `zipviz link sign` signs the
Ed25519 side and emits an unsigned Nostr event template, and `zipviz link verify` checks both
signatures offline (see the README). Registry-side support (storing, publishing or revoking
a link) is not part of this CLI. The Nostr event kind is
still provisional (`PROVISIONAL_LINK_EVENT_KIND` in `src/link/statement.ts`); no NIP defines it.

What the CLI check does **not** do, by design:

- It does not check the registry. `zipviz link verify` is offline, so the Ed25519 key it checks
  is whatever the link document contains; it is never compared with the key the registry holds
  for `<domain>`. A verified link therefore proves only that the two keys in the statement
  co-signed it — not that the Ed25519 key is the one `<name>.viz` resolves to. Every result
  carries that caveat (`link.registry_checked: false` and `link.caveat` in `--json`); a verifier
  that needs the stronger claim must resolve the key with `zipviz verify <name>` and compare.
- It does not hide a failing link. A link that does not verify is printed as failed with its
  reason code (and exit code 4), never silently dropped and never shown as linked.

## Problem

A Buzz agent is a secp256k1 (Nostr, BIP-340) key. A ZipViz agent is a `.viz` name bound to an
Ed25519 key in the registry. They are separate keys on separate curves. We want a verifier to be
able to say "the Buzz agent `npub1…` and the ZipViz agent `<name>.viz` are the same operator's
agent", without either system holding, converting or importing the other's keys.

## Approach: mutual signatures over one statement

Each key signs a statement naming the other. A link is valid only if both signatures verify.
One-sided claims prove nothing, because anyone can name someone else's key.

Statement (UTF-8, exact bytes, no normalisation):

```
zipviz:identity-link:v1:<viz-domain>:<ed25519-pubkey-hex>:<nostr-pubkey-hex>:<issued_at>
```

- Domain separation: the `zipviz:identity-link:v1:` prefix means these signatures can't be
  replayed as a ZipViz `/v1/verify` envelope, a NIP-OA `auth` tag or a Nostr event id.
- Both keys appear in the statement, so neither signature can be moved to a different pair.
- `issued_at` is a unix timestamp chosen by the signer. It orders links; it is not an expiry.

The two proofs:

1. **Ed25519 side:** the ZipViz key signs the statement bytes (same scheme the CLI already uses
   locally; the private key stays in `~/.zipviz/keys`).
2. **Nostr side:** the Buzz key publishes a normal signed Nostr event (kind to be chosen;
   a parameterised replaceable kind keyed by the `.viz` domain keeps one current link per pair),
   with `content` = the statement and a `["viz", "<viz-domain>"]` tag. The event's NIP-01 id and
   BIP-340 signature are the proof, so the existing `src/buzz/` verifier checks it unchanged.

A verifier recomputes the statement, checks the Ed25519 signature against the key the registry
lists for `<viz-domain>`, and checks the Nostr event with `verifyBuzzEvent` plus "content equals
the statement and pubkey equals `<nostr-pubkey-hex>`". All of this can run offline once the
registry card and the event are in hand.

## Key handling rules

- Never derive, convert or map one key type into the other (no Ed25519 to secp256k1 tricks).
- Never ask a user to paste, upload or import a Nostr secret key (nsec) into ZipViz, the CLI, the
  site or the registry. Each side signs with its own tool: the Buzz/Nostr client signs the event,
  `zipviz` signs the statement.
- Anything that stores a link keeps only public keys, the statement, the Ed25519 signature and
  the signed Nostr event.

## Display rule

Following NIP-OA's spirit, a link is shown as a separate statement ("linked to Buzz agent
`npub1…`"). It never makes one identity the author of the other's messages, and a link that fails
verification is not shown at all.

## Open questions

- Which Nostr kind to use, and whether Buzz wants a NIP for it. The CLI uses a provisional
  constant and reports, without rejecting, an event that carries a different kind.
- Whether a NIP-OA owner key, rather than the agent key, should be able to sign the Buzz side.
  The CLI currently requires the agent key named in the statement to be the event's signer; an
  `auth` tag is allowed but must itself verify (`LINK_NOSTR_OWNER_AUTH_INVALID` if it does not).
