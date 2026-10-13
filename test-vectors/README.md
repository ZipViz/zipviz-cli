# ZipViz v1 `/verify` signature test vectors

> **TEST ONLY keys.** Both keys in `v1-verify.json` come from seeds printed in that
> file, so anyone can rebuild their private halves. They are not secret. Never
> register them, trust them, or use them for anything real.

`v1-verify.json` defines what a correct ZipViz v1 signature verifier does. If you
write a verifier in another language, run it on every case. It conforms when it
gets the same `verified` result for every case, and it should also report the
same `reason`.

## The rule

A v1 envelope has four string fields: `from` (the sender's `.viz` name), `message`,
`timestamp` and `signature`.

1. **Signed bytes.** The sender signs the UTF-8 bytes of
   `JSON.stringify({ v: 1, from, message, timestamp })`. The keys appear in exactly
   that order, with no whitespace. Strings use standard `JSON.stringify` escaping:
   `"`, `\` and control characters are escaped (`\n`, `\t`, `\u0000`…), while
   non-ASCII text such as `ü` or `👋` is written as raw UTF-8, not as `\u` escapes.
   `v` is always the number `1`. It is part of the signed bytes even though the CLI
   does not send it in the request body.
2. **Signature.** Ed25519 (RFC 8032, pure Ed25519 with no prehash) with the private
   key that belongs to `from`. It is sent as standard base64 with padding, which
   decodes to exactly 64 bytes.
3. **Public key.** The verifier uses the key the registry holds for `from`: 32 bytes,
   written as 64 lowercase hex characters.
4. **Freshness.** `timestamp` is an ISO 8601 UTC time in the form
   `Date.prototype.toISOString()` produces, for example `2026-10-13T00:00:00.000Z`.
   It must be no more than 5 minutes (300,000 ms) before or after the verifier's
   clock.

A verifier **rebuilds** the signed bytes from the received field values. It never
signs or checks the raw request body. That is why the key order and whitespace of
the request body do not matter, but every character inside the field values does.

## File format

Top level:

| Field | Meaning |
| -- | -- |
| `warning` | The TEST ONLY notice. |
| `rule` | The rule above, in short form. `window_ms` is `300000`. |
| `test_keys.A`, `test_keys.B` | TEST ONLY keys. `seed_utf8` is the 32-byte Ed25519 seed written as ASCII text (its UTF-8 bytes are the seed). `public_key` is the matching public key in hex. |
| `cases` | The test cases. |

Each case:

| Field | Meaning |
| -- | -- |
| `id` | Stable name for the case. |
| `description` | What was done to the envelope. |
| `public_key` | The key the registry holds for `from`. Verify against this key. |
| `now` | The verifier's clock for this case. Use it instead of the real time. |
| `body` | The exact `POST /v1/verify` request body, as raw JSON text. **This is the input.** |
| `envelope` | `body` parsed, for convenience. Same values as `body`. |
| `signed_bytes` | The bytes a correct verifier rebuilds from `body`. Use it for debugging. A failing case can have a correct `signed_bytes` and still fail, because its signature was made over different bytes. |
| `expected.verified` | `true` or `false`. This is the result a conforming verifier must match. |
| `expected.reason` | `null` when verified, otherwise one of the reason codes below. |

## Reason codes

Only `E_SIG_MISMATCH` is a code the registry is known to return:
`{ "verified": false, "error": "signature mismatch", "code": "E_SIG_MISMATCH" }`.
This repo does not document the registry's codes for the other failures, so these
vectors define their own:

| Reason | Meaning |
| -- | -- |
| `E_FIELD_MISSING` | The body is not a JSON object, or `from`, `message`, `timestamp` or `signature` is missing or not a string. (No case uses this; it is here so the list is complete.) |
| `E_FIELD_EMPTY` | `from`, `timestamp` or `signature` is an empty string. |
| `E_TIMESTAMP_FORMAT` | `timestamp` is not a real ISO 8601 UTC time. |
| `E_SIG_FORMAT` | `signature` is not standard padded base64 of exactly 64 bytes. |
| `E_SIG_MISMATCH` | The signature does not verify over the rebuilt signed bytes with `public_key`. |
| `E_TIMESTAMP_STALE` | `timestamp` is more than 5 minutes before `now`. |
| `E_TIMESTAMP_FUTURE` | `timestamp` is more than 5 minutes after `now`. |

Each failing case breaks exactly one thing, so the order in which a verifier runs
its checks does not change any case's result. The reference verifier checks in the
order of the table above.

## The cases

The `valid` case is byte for byte what `zipviz verify test-alpha-1000.z.viz`
sends when the clock reads `2026-10-13T00:00:00.000Z` and its random UUID is
`00000000-0000-4000-8000-000000000000`. Unless a case says otherwise, `now` is 60
seconds after the valid timestamp and the key is test key A.

| `id` | What changed | Expected |
| -- | -- | -- |
| `valid` | Nothing. Correctly signed, 60 seconds old. | `true` |
| `message_changed_one_char` | The last character of `message` changed after signing. | `false`, `E_SIG_MISMATCH` |
| `wrong_key` | Same body as `valid`, but the registry holds test key B for `from`. | `false`, `E_SIG_MISMATCH` |
| `replayed_different_from` | The `valid` envelope resent with `from` changed to `test-beta-1000.z.viz`. That name is given the **same** key A, so the only thing that makes it fail is that `from` is signed. | `false`, `E_SIG_MISMATCH` |
| `timestamp_too_old` | Correctly signed, but signed 5 minutes 1 second before `now`. | `false`, `E_TIMESTAMP_STALE` |
| `timestamp_too_far_in_future` | Correctly signed, but signed 5 minutes 1 second after `now`. | `false`, `E_TIMESTAMP_FUTURE` |
| `timestamp_just_inside_window` | Correctly signed, 4 minutes 59 seconds before `now`. | `true` |
| `timestamp_malformed` | `timestamp` is `2026-10-13T25:61:00.000Z` (hour 25, minute 61). The signature over it is genuine; only the time is invalid. | `false`, `E_TIMESTAMP_FORMAT` |
| `signature_truncated` | The `valid` signature with its last byte removed (63 bytes). | `false`, `E_SIG_FORMAT` |
| `empty_field` | `from` is an empty string. The signature over the empty name is genuine, but an empty name identifies no one. | `false`, `E_FIELD_EMPTY` |
| `whitespace_added_to_message` | One trailing space added to `message` after signing. | `false`, `E_SIG_MISMATCH` |
| `envelope_key_order_changed` | Same values as `valid`, with the body's keys in a different order (`signature`, `timestamp`, `message`, `from`). | `true` |
| `envelope_whitespace_formatting` | Same values as `valid`, with the body pretty-printed (indentation, newlines). | `true` |
| `signed_with_sorted_keys` | Signed over the same fields with keys in alphabetical order (as JCS / RFC 8785 would produce) instead of the v1 order. | `false`, `E_SIG_MISMATCH` |
| `valid_unicode_and_escapes` | Correctly signed message containing non-ASCII text, an emoji, quotes, a backslash, a newline and a tab. | `true` |

The last three cases go beyond the original list. Two of them cover the other
reading of an ambiguous case (below). The Unicode case catches the most common
cross-language bug: a JSON library that escapes non-ASCII text or adds spaces
after `:` and `,` (Python's `json.dumps` does both by default).

## Decisions on ambiguous cases

- **Whitespace added after signing.** The named case adds whitespace to the
  `message` value, which changes the signed bytes, so it must fail. Whitespace in
  the request body's formatting is not signed (the verifier rebuilds the bytes from
  the field values), so the companion case `envelope_whitespace_formatting` must pass.
- **Changed key order.** The named case reorders the keys of the request body. A
  verifier rebuilds `JSON.stringify({ v, from, message, timestamp })` in fixed
  order, so it must pass. The order inside the signed bytes is fixed by the rule,
  so the companion case `signed_with_sorted_keys` must fail. A verifier that
  checked the raw body bytes, or sorted the keys before checking, would get these
  two cases wrong.
- **Just inside the window.** The limit is "no more than 5 minutes". The CLI's
  `doctor` command treats only skew beyond 300,000 ms as outside the window, but
  the registry's own comparison (`<` or `<=`) is not in this repo. So the vectors
  stay one second either side of the limit (4:59 and 5:01) and do not pin the
  behavior at exactly 5:00.
- **Malformed timestamp.** The value is shaped like a timestamp but is not a real
  time, so every reasonable parser rejects it. The vectors do not decide whether
  other well-formed ISO 8601 variants (for example, without milliseconds) are
  accepted. Every timestamp a valid case uses has the `toISOString()` form.
- **Empty field.** The empty field is `from`. A correctly signed envelope with an
  empty `message` is not covered, because the rule does not say whether that is
  allowed.

## Where the expected results come from

The CLI only signs v1 envelopes (`src/commands.ts`, sent by `zipviz verify`). The
registry checks them; this repo contains no v1 verifier. So
`tests/test-vectors.test.ts` contains a small reference verifier that follows the
rule above and nothing more, and checks every case against it. The same test:

- rebuilds both TEST ONLY keys from their seeds and checks the public keys;
- checks that `LocalKey.sign` from `src/keys.ts` reproduces the `valid` signature
  byte for byte;
- runs `zipviz verify` end to end against an in-memory registry (no network) with a
  fixed clock and UUID, and checks that the request body it sends equals the
  `valid` case's `body` byte for byte;
- checks that each failing case breaks exactly one thing. For example, the
  timestamp cases carry genuine signatures, and the tamper cases reuse the `valid`
  signature.

Ed25519 signatures are deterministic, so anyone can regenerate every signature in
the file from the seeds.

## Out of scope

- The legacy `v=0` format.
- Registry lookup of `from`, rate limits, and the response body beyond `verified`.
- Replay inside the 5-minute window. The registry accepts a valid envelope more
  than once within the window, so the vectors do not
  test replay of an unchanged envelope.
