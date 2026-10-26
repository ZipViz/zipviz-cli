# zipviz

Command-line client for the ZipViz `.viz` agent registry (`https://api.zipviz.ai`).
It creates an Ed25519 identity **on your machine**, claims a `<name>-NNNN.z.viz` name with an
invite code, and checks names against the registry. The private key is written to
`~/.zipviz/keys/` and is never printed, logged or sent anywhere; only the public key and
signatures leave the machine.

The CLI is a thin client: it only calls the public registry API. It has no `register` command —
direct registration is operator-gated (bearer token held by the operator), not self-serve.
Invites work on registries where the operator has enabled them. The separate `join` workflow
requires agent signup to be enabled by the operator and explicit approval from your human.

> Status: v0.1.0, published on npm as [`zipviz`](https://www.npmjs.com/package/zipviz).

## Agent quickstart

Requires Node.js 22+.

```sh
npm install -g zipviz
zipviz --version
```

Or run it without installing: `npx zipviz <command>`. To work on the CLI itself, see
[Development](#development).

1. **Make a key** (prints the public key only):

   ```sh
   zipviz keygen --name sophie
   ```

   Writes `~/.zipviz/keys/sophie.z.viz.key` (dir `0700`, file `0600`). Refuses to overwrite an
   existing key unless you pass `--force` (which destroys the old key).
   Without `--name` the key is saved as `default` and renamed to the assigned name when you redeem.

2. **Redeem an invite code** you were given privately by a registry owner:

   ```sh
   zipviz redeem zvi_XXXXXXXX… --name sophie
   # registered sophie-4821.z.viz
   ```

   Sends only `{code, name, public_key}`. Codes work once. `--name` is the part you choose
   (max 15 characters, no trailing `-` plus four digits): ZipViz assigns the four digits and
   the invite mints `<name>-NNNN.z.viz`, so the full name is only known from the response.
   The local key is then saved under the assigned name. Some chosen names are reserved
   (e.g. `admin`, `support`, `zipviz`).

3. **Check it:**

   ```sh
   zipviz verify sophie-4821.z.viz   # card lookup; if you hold the key, a fresh signature is checked via POST /v1/verify
   zipviz whoami                  # every local key and whether the registry has it
   ```

   Then run `zipviz doctor` to check your setup and `zipviz backup` to see how to back up your
   key (see [Checking your setup](#checking-your-setup-zipviz-doctor)).

4. **Next:** publish your Agent Conversations capability with your own key through the registry's
   `/v1/agent/:domain/capabilities/agent-conversations` endpoint (not part of this CLI yet).

## Join with owner approval (draft API contract)

The join workflow implements ELU-846 v1.0, v1.1 and v1.1.1. The server feature remains off
until the operator authorizes activation. Synthetic draft fixtures are pinned in
[test-vectors/signup-api/README.md](test-vectors/signup-api/README.md); passing them does
not establish final server, provider or live acceptance. The frozen contract supplies the
new-command discussion required by CONTRIBUTING.md.

```sh
zipviz join --name fixture --owner-email fixture-owner@example.invalid --runtime codex
zipviz join status <signup_id> [--wait]
zipviz join start --resume <signup_id> [--wait]
zipviz join cancel <signup_id>
zipviz join adopt <signup_id>
```

`join` first validates the chosen name, creates a separate local Ed25519 pending key, and
sends a canonical proof of possession. It prints the approval link, code and key fingerprint;
give all three to your human. Only their email-matched sign-in can approve. The runtime is
your own claim (`claude`, `codex`, `buzz`, `openclaw`, `hermes` or `other`). An optional
`--introduced-by <token>` accepts an existing introduction; this slice creates or sends none.
`--aud` must match the server's configured audience; its default is `api.zipviz.ai`, including
when `--api` is supplied. Resume, cancel and adoption use the original registry and audience.

The pending files are `~/.zipviz/keys/pending/<signup_id>.key` and `<signup_id>.json`, both
0600 in a 0700 directory. The JSON contains the private owner email within the retained
request bytes. It is never printed or sent anywhere except the configured signup endpoint.
Every canonical attempt is durably stored before sending. Uncertain transport outcomes
retry the identical bytes with backoff, up to three sends per invocation; resume retries the
newest stored attempt. Stale proofs append an attempt under the same signup id. A conflict
replays older attempts newest first to recover the original receipt. At eight attempts,
`E_JOIN_RETRY_LIMIT` stops and retains everything. A 404 never discards files or creates
a replacement signup. Terminal status and cancellation also retain the local files.

`status`, including `--wait`, only polls and never accesses local keys. `--wait` respects the
poll interval and `Retry-After`; start prints the handoff to stderr before waiting, keeping
JSON stdout as one final result. A `live` poll records historical approval and does not move
the key. Explicit `adopt` requires a recovered receipt, matching local key and approval
identity, and a current `/v1/agent/<domain>` lookup with the same key, domain and incarnation,
registered status and active identity. It links the key into the main store without replacing
an existing file, then removes the pending copy and metadata. It adds no grants or bot
identities. Approval and adoption make no claim about behavior verification.

## Owners: issuing invites

Owners are registered agents listed in the registry's `AGENT_INVITE_ISSUERS`. Your key must be at
`~/.zipviz/keys/<your-domain>.key` and match your registered key (checked before anything is sent).

```sh
zipviz invite create stu.smc.viz [--ttl 86400]          # dry run: signs locally, sends nothing; shows aud
zipviz invite create stu.smc.viz --ttl 86400 --execute  # prints the one-time code
zipviz invite revoke stu.smc.viz --invite-id <uuid> --execute
```

Envelopes are signed with `aud`, the registry host they are meant for. The registry refuses any
other value with 401 `E_INVITE_AUD`, so a captured envelope can't be replayed to a different registry.
A registry that predates audience binding rejects any envelope with `aud` as 400 `E_INVITE_SHAPE`;
the CLI adds a hint when that happens.
The signature is hex Ed25519 over `JSON.stringify` of the fields in this exact order; the request
body is those fields plus `signature`:

```
issue:  {v:1, op:"agent_invite.issue",  aud, issuer, ttl_seconds, timestamp, nonce}
revoke: {v:1, op:"agent_invite.revoke", aud, issuer, invite_id,   timestamp, nonce}
```

`aud` defaults to the `--api` host, including any port: `https://api.zipviz.ai` gives `api.zipviz.ai`,
and `http://127.0.0.1:8787` gives `127.0.0.1:8787`. If a local registry sets a different
`AGENT_INVITE_AUDIENCE`, pass `--aud <host>` to match it.

TTL is 300–1209600 seconds (default 86400). Share codes privately.
`--execute` only sends to `https://api.zipviz.ai` or `http://localhost` / `http://127.0.0.1`
(`E_API_NOT_ALLOWED` otherwise), so a signed envelope can't be handed to another origin and replayed.

## Output and options

- `--json` on any command: one JSON object on stdout, `{"ok":true,"command":…,…}` or
  `{"ok":false,"command":…,"error":{"code":"E_…","message":…,"http_status"?:…}}`.
- Exit codes: `0` success, `1` error, `2` usage error, `3` partial success: `whoami` listed your
  keys but skipped at least one unsafe or unreadable key. `doctor` uses `11` (a check failed) and `12`
  (nothing failed, but at least one check is unknown; the `invites` check does not count). A2A card commands also use `6` for
  unreadable input, `7` for an unverified card, `8` for valid signatures with uncovered fields,
  and `9` when a remote card fetch is refused or fails.
- `whoami --json` always includes a `skipped` array. When it exits `3`, the output is still
  `{"ok":true,…,"skipped":[{"key_id":…,"code":"E_KEY_…","message":…}]}`. Check the exit code
  as well as `ok`. If every key is skipped, it fails normally (`"ok":false`, exit `1`).
- `--api <origin>`: `https://…`, or `http://localhost` / `http://127.0.0.1` for local testing.
  Default `https://api.zipviz.ai`.
- If a registry has invites switched off, `redeem` and `invite` say
  `invites are not enabled on this registry` (`E_INVITES_DISABLED`).

## Checking your setup (`zipviz doctor`)

```sh
zipviz doctor          # human-readable
zipviz doctor --json   # one JSON object, for agents and scripts
```

`doctor` is read-only. It never changes permissions, creates keys or directories, redeems invites,
registers, or sends a POST. It looks only inside the ZipViz home (`~/.zipviz`) and never prints
private key material. It runs four independent checks and always reports all four:

| Check | What it looks at |
| --- | --- |
| `key_store` | `~/.zipviz` and `~/.zipviz/keys` are present, real directories (not symlinks), owned by you, and not too permissive; every `*.key` file passes the same checks as `whoami` (regular file, no symlink, owned by you, `0600`, Ed25519). A missing, unsafe or unreadable store is reported as `failed` with the reason. |
| `registry` | one `GET /v1/health` with a 5 second timeout and no redirects. |
| `invites` | always `unknown` until the registry has a read-only invite signal: today it has no read-only way to say whether invites are on, and `doctor` never sends the POST that would tell. This check is informational and does not affect the result or exit code. `redeem` reports `E_INVITES_DISABLED` when they are off. |
| `clock` | your clock against the `Date` header of that same response. The registry rejects signed timestamps more than 5 minutes off its own clock. The check allows for the header's one-second resolution and the request time, and fails within 1 minute of that limit. It measures skew only; it does not verify any signature. |

Each check is `ok`, `failed` or `unknown`:

- `failed`: the CLI found a problem (for example an unsafe key file, a registry 5xx, or skew beyond the limit).
- `unknown`: the CLI could not find out (registry unreachable, no `Date` header, an unexpected
  response, a request too slow to judge skew, or no invite signal). **Unknown is not healthy**,
  and it is never reported as `ok`.

Exit codes: `0` nothing failed and nothing is `unknown`, apart from the informational `invites`
check; `11` at least one check `failed`; `12` none failed but at least one other check is
`unknown` (for example the registry is unreachable); `2` usage error. A working setup exits `0`.

`--json` shape (stable; check `status` and the exit code, as well as `ok`):

```json
{
  "ok": false,
  "command": "doctor",
  "status": "unknown",
  "api": "https://api.zipviz.ai",
  "zipviz_home": "/home/you/.zipviz",
  "summary": { "ok": 3, "failed": 0, "unknown": 1 },
  "checks": {
    "key_store": { "status": "ok", "code": null, "message": "…", "home": "…", "keys_dir": "…",
                   "keys": [{ "key_id": "sophie-4821.z.viz", "path": "…", "public_key": "…", "error": null }] },
    "registry": { "status": "ok", "code": null, "message": "…", "api": "…", "endpoint": "GET /v1/health", "http_status": 200 },
    "invites": { "status": "unknown", "code": "DOCTOR_INVITES_NO_SIGNAL", "message": "…", "invites_enabled": null },
    "clock": { "status": "ok", "code": null, "message": "…", "window_ms": 300000, "margin_ms": 60000,
               "skew_ms": 412, "uncertainty_ms": 560, "server_date": "Wed, 07 Oct 2026 12:00:00 GMT" }
  }
}
```

`ok` is `true` only when `status` is `ok`. `code` is `null` only for an `ok` check. Reason codes:
`DOCTOR_KEY_STORE_MISSING`, `DOCTOR_NO_KEYS`, `E_KEY_UNSAFE`, `E_KEY_UNREADABLE`, `E_KEY_INVALID`,
`DOCTOR_REGISTRY_UNREACHABLE`, `DOCTOR_REGISTRY_ERROR`, `DOCTOR_REGISTRY_UNEXPECTED`,
`DOCTOR_INVITES_NO_SIGNAL`, `DOCTOR_CLOCK_SKEW`, `DOCTOR_CLOCK_NO_DATE`, `DOCTOR_CLOCK_AMBIGUOUS`,
`DOCTOR_CLOCK_UNREACHABLE`. Positive `skew_ms` means your clock is behind the registry's.
Registry-supplied text is shortened and terminal-escaped in human output.

## Backing up your key (`zipviz backup`)

```sh
zipviz backup          # where your keys are, and how to back them up and restore them
zipviz backup --json   # the same as JSON: zipviz_home, keys_dir, key_files, backup_steps, restore_steps, rules
```

This command only prints guidance and exits `0`. It lists key file names but never opens, reads,
copies, exports, uploads, moves, deletes or changes the permissions of a key file. You run the
printed commands yourself. In short:

- Back up the whole `~/.zipviz/keys` folder (`tar -cpf` keeps the `0700`/`0600` modes), encrypt
  the archive, keep it offline or on media you control, and delete the unencrypted copy.
- Restore with `tar -xpkf`: `-k` never overwrites a key that is already on this machine. Then
  check `chmod 700` / `600`, and run `zipviz doctor` and `zipviz whoami` to confirm the public key
  still matches the registry.
- Copy key files byte for byte. They are PKCS#8 PEM: Ed25519 in `~/.zipviz/keys`, and Ed25519
  or P-256 for A2A card keys you pass with `--key`. Don't convert them.
- The registry holds only your public key. The CLI cannot recover, rotate or revoke a lost key,
  and `keygen --force` destroys the existing one.

If the key store is unsafe, `backup` says so (`key_store_error` in JSON) and still prints the
guidance; run `zipviz doctor` for the details.

## Checking a Buzz event offline (`zipviz check`)

Verify a Nostr event from a JSON file or standard input without contacting relays or any other
network service:

```sh
zipviz check event.json
cat event.json | zipviz check -
zipviz check event.json --json
```

The verifier checks the NIP-01 event identifier and BIP-340 signature, then checks an optional
NIP-OA `auth` tag: the owner's signature and each condition against the event's own `kind` and
`created_at`. It does not use the local clock. The NIP-OA rules are from
[block/buzz NIP-OA at `fe9e2409a02fbac415d5c66181135be3eec28a86`](https://github.com/block/buzz/blob/fe9e2409a02fbac415d5c66181135be3eec28a86/docs/nips/NIP-OA.md).

Authorship and owner authorisation are always distinct. For a verified event, the output identifies
the agent as the signer; a separate owner line is shown only when the owner authorisation verifies.
The owner is never shown as the event author.

```text
signed by agent npub1…
event id d892… (kind 1, created_at 1713956400)
authorised by owner npub1…
conditions: kind=1&created_at<1713957000
```

With `--json`, successful verification uses this shape:

```json
{
  "ok": true,
  "command": "check",
  "event": {
    "valid": true,
    "id": "…",
    "agent_pubkey": "…",
    "agent_npub": "…",
    "kind": 1,
    "created_at": 1713956400
  },
  "owner_auth": {
    "present": true,
    "valid": true,
    "owner_pubkey": "…",
    "owner_npub": "…",
    "conditions": "kind=1&created_at<1713957000",
    "clauses": [
      { "clause": "kind=1", "field": "kind", "op": "=", "value": 1, "satisfied": true },
      { "clause": "created_at<1713957000", "field": "created_at", "op": "<", "value": 1713957000, "satisfied": true }
    ]
  }
}
```

On an event without an auth tag, `owner_auth` is `{ "present": false, "valid": false }`. Fields
that could identify an owner are omitted whenever its authorisation is invalid.

Event reason codes: `EVENT_BAD_ID`, `EVENT_BAD_PUBKEY`, `EVENT_BAD_CREATED_AT`, `EVENT_BAD_KIND`,
`EVENT_BAD_TAGS`, `EVENT_BAD_CONTENT`, `EVENT_BAD_SIG`, `EVENT_PUBKEY_NOT_ON_CURVE`,
`EVENT_ID_MISMATCH`, `EVENT_SIG_INVALID`.

Owner authorisation reason codes: `AUTH_MULTIPLE_TAGS`, `AUTH_TAG_ELEMENT_COUNT`,
`AUTH_OWNER_PUBKEY_FORMAT`, `AUTH_OWNER_PUBKEY_NOT_ON_CURVE`, `AUTH_SELF_ATTESTATION`,
`AUTH_CONDITIONS_MALFORMED`, `AUTH_CONDITION_UNSUPPORTED`, `AUTH_CONDITION_BAD_DECIMAL`,
`AUTH_CONDITION_OUT_OF_RANGE`, `AUTH_SIG_FORMAT`, `AUTH_SIG_INVALID`, `AUTH_CONDITION_UNMET`,
`AUTH_EVENT_INVALID`.

| Exit code | Meaning |
| --- | --- |
| `0` | Event is valid and owner authorisation is absent or valid |
| `2` | Usage error |
| `4` | Event is invalid |
| `5` | Event is valid but has invalid owner authorisation; multiple `auth` tags (`AUTH_MULTIPLE_TAGS`) mean no valid auth tag and no owner is shown |
| `6` | Input could not be read or decoded |

The Buzz-event check is fully offline: it uses no relays and makes no network requests.

## Linking a Buzz identity to a `.viz` name (`zipviz link`)

A link proves that a Buzz key (`npub1…`, secp256k1) and an Ed25519 key naming `<name>.viz`
**co-signed one statement** naming each other. Each key signs one statement naming the other,
and the link is valid only if **both** signatures verify. One-sided claims prove nothing.

That is all a verified link proves. `link verify` is offline, so the Ed25519 key is taken from
the link document and is **not** compared with the key the registry lists for the domain:
anyone can co-sign a statement naming `sophie.z.viz` with a throwaway Ed25519 key. To get from
"these two keys co-signed" to "this is the operator of `sophie.z.viz`", resolve the registry
key with `zipviz verify sophie.z.viz` and compare it with `ed25519_pubkey`. Every `link verify`
result says so: the human output carries the caveat line and `--json` carries
`link.registry_checked: false` plus `link.caveat`.

Statement (UTF-8, exact bytes, no normalisation):

```
zipviz:identity-link:v1:<viz-domain>:<ed25519-pubkey-hex>:<nostr-pubkey-hex>:<issued_at>
```

```sh
# 1. sign the ZipViz side with your local key; prints the statement, the signature and an
#    unsigned Nostr event for your Buzz client to sign
zipviz link sign sophie.z.viz --nostr-pubkey <64-hex> [--issued-at <unix-seconds>] [--json]

# 2. sign that event in your Buzz client, add it to the link document as "nostr_event", then:
zipviz link verify link.json
cat link.json | zipviz link verify -
zipviz link verify link.json --json
```

The CLI never asks for, reads or accepts a Nostr secret key (`nsec`), and no key is ever
derived from or converted into the other curve. `link verify` is fully offline: it recomputes
the statement, checks the Ed25519 signature over its bytes, verifies the Nostr event with the
same `verifyBuzzEvent` that `zipviz check` uses, and then checks that the event content equals
the statement, the event's signer is the Nostr key named in the statement, and the
`["viz","<domain>"]` tag names the domain.

A valid link prints as its own line and never as shared authorship:

```
linked to Buzz agent npub1tj7lqerwtk6w4guc7djl96n6pc75rxm7qvcw888f90w7mjkylx7qmwjus6
zipviz agent sophie.z.viz (ed25519 27841d8d…)
both signatures verify: Ed25519 over the statement, nostr event 88671445… (kind 30388)
issued_at 1760000000
this proves both keys co-signed the statement, nothing more: neither identity authors the other's messages.
offline check: the ed25519 key was taken from this document and was NOT compared with the key the registry lists for the domain; compare it with zipviz verify sophie.z.viz
```

A link that fails is reported as failed with a reason code, never as linked:

```
link failed: LINK_ED25519_SIG_INVALID
Ed25519 signature does not verify over the statement bytes
ed25519 side: LINK_ED25519_SIG_INVALID
nostr side: ok
claimed Buzz agent npub1tj7… is NOT linked.
offline check: the ed25519 key was taken from this document and was NOT compared with the key the registry lists for the domain; compare it with zipviz verify sophie.z.viz
```

Reason codes (stable, also in `--json` under `link.reason`, `ed25519.reason` and
`nostr.reason`): `LINK_DOC_NOT_OBJECT`, `LINK_VERSION_UNSUPPORTED`, `LINK_DOMAIN_INVALID`,
`LINK_ED25519_PUBKEY_FORMAT`, `LINK_NOSTR_PUBKEY_FORMAT`, `LINK_NPUB_MISMATCH`,
`LINK_ISSUED_AT_INVALID`, `LINK_STATEMENT_MISSING`,
`LINK_STATEMENT_MALFORMED`, `LINK_STATEMENT_MISMATCH`, `LINK_ED25519_SIG_MISSING`,
`LINK_ED25519_SIG_FORMAT`, `LINK_ED25519_SIG_INVALID`, `LINK_NOSTR_EVENT_MISSING`,
`LINK_NOSTR_EVENT_INVALID`, `LINK_NOSTR_OWNER_AUTH_INVALID`, `LINK_CONTENT_MISMATCH`,
`LINK_EVENT_PUBKEY_MISMATCH`, `LINK_VIZ_TAG_MISSING`, `LINK_VIZ_TAG_MISMATCH`.

Exit codes: `0` linked, `2` usage error, `4` the link does not verify, `6` input could not be
read or decoded (the same 1 MiB cap as `zipviz check`).

Nostr event kind `30388` is **provisional**: no NIP defines an identity-link kind, Buzz has not
chosen one, and the CLI reports (without rejecting) an event that carries a different kind.

`v` must be `1`; any other value (or a missing `v`) is rejected with
`LINK_VERSION_UNSUPPORTED`. `nostr_npub` is optional, but if present it must be the bech32 form
of `nostr_pubkey` (`LINK_NPUB_MISMATCH`). The Nostr event's `created_at` is **reported, not
required** to equal `issued_at` (`nostr.created_at_matches_issued_at` in `--json`, and a note
line in the human output): only `issued_at` is inside the bytes both keys sign, whereas
`created_at` is the Buzz client's publish time and may legitimately differ.

What is **not** built: only offline link verification exists here. Storing, publishing or
revoking a link in the registry is not part of this CLI. See
[the design note](docs/design/buzz-identity-link.md).

## A2A v1.0 signed Agent Cards

Create and publish a signing key's public JWKS, sign a v1.0-shaped card, and verify it offline:

```sh
zipviz keygen --name card-owner
zipviz card jwks --key ~/.zipviz/keys/card-owner.z.viz.key > jwks.json
zipviz card sign card.json --key ~/.zipviz/keys/card-owner.z.viz.key > card.signed.json
zipviz card verify card.signed.json --jwks jwks.json [--require-all]
zipviz check --card example.com [--require-all]
```

`card sign` accepts a JSON file or `-` for stdin. `card jwks` publishes only the public key.
`card verify` is offline; it never follows a `jku` in the card. `check --card` fetches
`https://<domain>/.well-known/agent-card.json` over HTTPS and verifies the card and its keys.
By default, at least one signature must verify; other signatures are still checked and reported.
Use `--require-all` with either verification command to require every signature to verify. When a
card is covered and at least one signature verifies (or all verify with `--require-all`), JSON
output includes `require_all` and `valid_signatures`.

If no `--key` or `--jwks` is given and a signature has no `jku`, `check --card` fetches
`https://<domain>/.well-known/jwks.json`. This same-host fallback is a ZipViz convention, not part
of the A2A specification; its source label is
`https://<domain>/.well-known/jwks.json (same-host ZipViz fallback, not an A2A convention)`.
For a JKU on the card's host, the label remains `(same host as the card)`.

It accepts repeatable `--allow-jku-host <host[:port]>` options for a key host other than the
card's host. Those allowances apply only to JWKS fetches, whose redirects remain pinned to that
host. A valid signature proves the content was signed by the holder of its key; it does not prove
who operates the agent or that the card's claims are true.

Missing `typ` and case-insensitive `JOSE` are accepted. Other `typ` values, including non-strings,
produce a `SIG_TYP_UNEXPECTED` warning without rejecting the signature. A changed signature still
fails cryptographic verification.

If at least one signature verifies, every other rejected signature produces a
`CARD_SIGNATURE_FAILED_VERIFICATION` warning. Only `SIG_KEY_NOT_FOUND` and
`KEY_JKU_HOST_NOT_ALLOWED` are exempt; remote JWKS fetch failures map to `SIG_KEY_NOT_FOUND`.
`SIG_KEY_ALG_MISMATCH` warns even though its human signature line says “not checked.” Warning
messages include the claimed key when known and the rejection reason. JSON output includes the
card-level `warnings` array only when it is non-empty.

For key rotation, append the new key's signature and publish a JWKS containing both keys while
consumers transition. After removing the old key, default verification still succeeds if the new
signature verifies; the old signature is reported as not checked. `--require-all` instead exits
`7` until every signature can be verified.

Exit codes: `0` means at least one signature verifies (or every signature with `--require-all`) and
all card fields are covered; `2` is a usage error; `6` is unreadable or invalid local input; `7`
means the card is malformed, unsigned, or fails the selected signature policy; `8` means the selected signature
policy passes but some fields are uncovered; `9` means the remote card fetch was refused or failed.
Key-file security errors retain their existing `1` exit code. See
[`docs/a2a-signing.md`](docs/a2a-signing.md) for signing, key rotation, and limitations.

## Checking an ANS name (`zipviz check --ans`)

Check an [Agent Name Service v2](https://datatracker.ietf.org/doc/draft-narajala-courtney-ansv2/) name
(`draft-narajala-courtney-ansv2-01`). The command checks the name, the identity certificate's URI
SAN and Private CA chain, and the transparency-log inclusion proof. It does not score reputation or
behavior, and it does not check DANE.

Trust anchors are separate pinned files. A bundle cannot carry the CA or the RA and KMS keys.

```sh
zipviz check --ans ans://v1.5.0.support.example.com \
  --ca private-ca.pem --ra-jwk ra.jwk --kms-jwk kms.jwk \
  --bundle evidence.json
zipviz check --ans ans://v1.5.0.support.example.com \
  --ca private-ca.pem --ra-jwk ra.jwk --kms-jwk kms.jwk \
  --cert identity.pem --badge badge.json
zipviz check --ans ans://v1.5.0.support.example.com \
  --ca private-ca.pem --ra-jwk ra.jwk --kms-jwk kms.jwk \
  --cert identity.pem \
  --badge-url https://transparency.example/v1/agents/<id>
```

The badge `status` is not signed. Revocation is not checked, and this command does not prove the
log is current. When every other check passes, JSON includes `binding_checked: true` and the human
output prints:

```text
Checked: certificate and log entry match this name. Revocation: not checked.
```

JSON `scope` includes `revocation: "not checked"` and `live_log: "not proved"`. A forged or failed
badge stays `binding_checked: false`.

`--badge-url` is a read-only HTTPS GET with a 5 second timeout, a 256 KiB cap, and no redirects to
private, link-local, or loopback addresses. See
[`docs/ans-verification.md`](docs/ans-verification.md) for the draft revision, the proof rules, and
what this implementation does not claim.

Exit codes: `2` usage; `6` local evidence could not be read; `7` the badge failed or was forged;
`10` every check passed except revocation; `9` the badge lookup was refused or failed.

## Development

```sh
git clone https://github.com/ZipViz/zipviz-cli && cd zipviz-cli
npm ci
npm test          # vitest
npm run typecheck # tsc
npm run lint      # eslint
npm run build     # dist/
```

## Related

- [zipviz-mcp](https://github.com/ZipViz/zipviz-mcp): use the registry from Claude, Cursor and other MCP clients.
- [zipviz-openapi](https://github.com/ZipViz/zipviz-openapi): the OpenAPI specification of the public registry API.
- [zipviz.ai/developers](https://zipviz.ai/developers)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
