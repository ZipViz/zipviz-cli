## Invalid Test Vectors

Verifiers MUST reject each of the following:

- An event containing two `auth` tags.
- An `auth` tag with fewer or more than four elements.
- An `auth` tag whose `<conditions>` string is `kind=1&` (trailing delimiter).
- An `auth` tag whose `<conditions>` string is `kind=01` (leading zero).
- An `auth` tag whose `<owner-pubkey-hex>` equals `event.pubkey` (self-attestation).
- An otherwise well-formed `auth` tag attached to an event whose Nostr `id` or `sig` is invalid.
