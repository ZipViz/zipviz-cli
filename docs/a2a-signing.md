# A2A v1.0 Agent Card signing

This CLI signs and verifies A2A v1.0 Agent Cards using Ed25519 or P-256 keys. Card canonicalization
follows RFC 8785 and the vendored A2A v1.0 protobuf definition. Signatures establish that the card
content was signed by the holder of a key; they do not establish who operates the agent or whether
the card's claims are true.

## Create a key and publish its public JWKS

Generate a local Ed25519 key. The private key stays in the user-only key directory; do not commit,
publish, or share the `.key` file.

```sh
zipviz keygen --name zipviz-ai-card
zipviz card jwks --key ~/.zipviz/keys/zipviz-ai-card.z.viz.key > jwks.json
```

Publish `jwks.json` at `https://zipviz.ai/.well-known/jwks.json`. The JWKS
contains only public key material.

## Prepare and sign a v1.0 card

The current `zipviz.ai` card is not shaped as an
A2A v1.0 Agent Card: it has top-level `url`, `api_base`, and `contact` fields and an array-valued
`capabilities` field. `card sign` will refuse it with `CARD_SCHEMA_INVALID` or
`CARD_UNCOVERED_FIELDS`. A minimal v1.0 shape, with placeholder values, is:

```json
{
  "name": "ZipViz",
  "description": "A2A agent card description",
  "supportedInterfaces": [
    {
      "url": "https://zipviz.ai/a2a",
      "protocolBinding": "JSONRPC",
      "protocolVersion": "1.0"
    }
  ],
  "version": "1.0.0",
  "capabilities": {},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": []
}
```

Sign the prepared card and verify it locally against the public JWKS:

```sh
zipviz card sign card.json --key ~/.zipviz/keys/zipviz-ai-card.z.viz.key > card.signed.json
zipviz card verify card.signed.json --jwks jwks.json
```

After the signed card and JWKS are published, verify the remote card:

```sh
zipviz check --card zipviz.ai
```

When neither `--key` nor `--jwks` is supplied and a signature has no `jku`, `check --card` uses
`https://<domain>/.well-known/jwks.json`. This same-host fallback is a ZipViz convention, not part
of the A2A specification. Its source label is
`https://<domain>/.well-known/jwks.json (same-host ZipViz fallback, not an A2A convention)`.
A JKU on the card's host is labeled `(same host as the card)`.

The remote check retrieves `https://zipviz.ai/.well-known/agent-card.json`. A card that refers to
another JWKS host is refused unless that host is explicitly allowed:

```sh
zipviz check --card zipviz.ai --allow-jku-host keys.example.net
```

The allowed host is an exact hostname or hostname-and-port match. JWKS redirects are restricted to
that same host. `x5u` and `x5c` are never fetched or used.

The entire `::/8` IPv6 block is refused, including IPv4-mapped `::ffff:0:0/96` and
IPv4-translated `::ffff:0:0:0/96` addresses even when the embedded IPv4 value is public. NAT64,
the discard-only `100::/64`, and the 6bone `3ffe::/16` range are also blocked.

By default, a card is accepted when at least one signature verifies; every signature is still
attempted and reported. Use `--require-all` with either `card verify` or `check --card` to require
all signatures to verify. JSON verification output includes `require_all` and `valid_signatures`.

An absent `typ` or `typ` equal to `JOSE` case-insensitively is accepted without a warning. Other
values, including non-strings, produce the `SIG_TYP_UNEXPECTED` warning (`typ <value> is not JOSE`)
and do not reject an otherwise valid signature. The warning value is capped at 64 characters;
cryptographic signature mismatches remain invalid.

When at least one signature verifies, every other rejected signature adds a
`CARD_SIGNATURE_FAILED_VERIFICATION` warning with its signature index, reason, and claimed key when
known. The only exemptions are `SIG_KEY_NOT_FOUND` and `KEY_JKU_HOST_NOT_ALLOWED`; a remote JWKS
fetch failure maps to `SIG_KEY_NOT_FOUND`. `SIG_KEY_ALG_MISMATCH` still warns although its human
signature line says “not checked.” Warnings are present under both the default and `--require-all`
policies, including when strict policy makes the overall result invalid. JSON output includes the
top-level `warnings` array only when non-empty.

## Signatures and key rotation

Cards can contain multiple signatures. To rotate a key, first add the new public key to the
published JWKS. Sign with the new key while preserving the existing signature:

```sh
zipviz card sign card.signed.json --key ~/.zipviz/keys/new-card-key.z.viz.key --append \
  > card.rotating.json
zipviz card verify card.rotating.json --jwks jwks-with-both-keys.json
```

Keep both public keys available while consumers move to the new signature. After the old key is
removed from the JWKS, default verification still succeeds if the new signature verifies; the old
signature is reported as `SIG_KEY_NOT_FOUND` (“not checked”):

```sh
zipviz card verify card.rotating.json --jwks jwks-new-key-only.json
zipviz check --card example.com
```

Use `--require-all` when every signature must still verify; in this example it exits `7` until the
old key is restored or the old signature is removed:

```sh
zipviz card verify card.rotating.json --jwks jwks-new-key-only.json --require-all
zipviz check --card example.com --require-all
```

This CLI does not provide key revocation.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | At least one signature is valid (or every signature with `--require-all`) and every field is covered |
| `1` | Unexpected or key-file security error |
| `2` | Usage error |
| `6` | Local card, key, or JWKS input could not be read or decoded |
| `7` | Card is malformed or unsigned, or no signature verifies under the selected policy |
| `8` | The selected signature policy passes, but one or more fields are uncovered |
| `9` | Remote card fetch was refused or failed |

JWKS fetch failures during `check --card` are reported on the affected signature and make the
verification exit with `7`. Card-fetch failures use their `FETCH_*` reason and exit with `9`.

## Known limitations / spec notes

- The A2A v1.0.1 §8.5 illustrative sample contains a top-level `security` member, while the
  authoritative `a2a.proto` defines `securityRequirements` (ProtoJSON spelling). The proto is
  normative, so this CLI does not alias `security`. The vendored sample remains verbatim and
  reports `/security` as uncovered; a second proto-adapted fixture uses the proto representation.
- The RFC 9864 `Ed25519` algorithm name is not accepted; use the JWS `EdDSA` algorithm.
- `x5u` and `x5c` certificate-based key discovery are not supported. In particular, `x5u` is never
  fetched.
- There is no key revocation mechanism; key rotation requires an out-of-band JWKS update.
- Duplicate JSON object members are rejected to avoid ambiguity during parsing and signing.
- Some A2A SDKs strip empty values during serialization. This implementation preserves ProtoJSON
  presence according to the vendored schema, so an SDK-generated card can canonicalize differently
  if it removes values that the protobuf representation preserves.
- Publishing the signed card and JWKS, production key management, and registry restrictions such
  as accepting cards only under `zipviz.ai` are outside this CLI change.
