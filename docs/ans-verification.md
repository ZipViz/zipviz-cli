# ANS name verification

`zipviz check --ans` checks one Agent Name Service name, its identity certificate, and a
transparency-log inclusion proof. It does not establish that the name is still unrevoked, and it
does not score reputation or behaviour.

The dispatch lives in `src/main.ts`, next to `check --card`.

## Draft

Implemented revision: `draft-narajala-courtney-ansv2-01` (13 April 2026,
<https://www.ietf.org/archive/id/draft-narajala-courtney-ansv2-01.txt>, SHA-256
`4b2598939d5804adbc69b75b70b68f80c29930623f3999adc2c0edb69740ab4b`).

That file is the current draft on the IETF datatracker. It replaces `draft-narajala-ans-00`.
Appendix A says its CSRs and signatures are truncated for brevity. Those examples are fixtures
under `tests/fixtures/ans/draft-narajala-courtney-ansv2-01/` and must not verify.

## What is checked

1. **Name.** §5.1 `ans://v<major>.<minor>.<patch>.<agentHost>`. Version components are numeric and
   have no leading zeros. `agentHost` is a dotted LDH name of at least two labels and at most 237
   octets, and it is not an IPv4 address. The whole name is at most 400 octets. The scheme and host
   are compared case-insensitively.
2. **Identity certificate.** §5.4 and §12.1. The leaf is an end-entity certificate with a URI SAN
   for that ANS name. The chain leads to the pinned Private CA, every certificate is inside its
   validity period, and the leaf's SHA-256 fingerprint (full DER, DANE selector 0 / matching type
   1) equals `attestations.identityCert.fingerprint` (`SHA256:` plus hex). RFC 5280 path length is
   enforced, including a pathLenConstraint of 0 on the pinned CA. Name constraints and extended
   key usage are not evaluated; Node's certificate API does not check them.
3. **Transparency log.** Appendix A.4's `GET /v1/agents/{agentId}` badge and §9.1. In the retained draft-01 profile, the leaf hash
   is SHA-256(`0x00` || JCS(event)). The audit path is verified with RFC 9162 §2.1.3.2. §4.3
   requires a SCITT transparency service, and the cited `draft-ietf-scitt-architecture-22` uses
   RFC9162_SHA256; §9.1 says a COSE receipt has the same verification semantics. The KMS signature
   is a detached ES256 JWS (§5.6) over the JCS JSON string of the lowercase hex root. The RA
   signature is a detached ES256 JWS over the JCS of the badge `payload`. The protected header is
   exactly `alg`, `kid`, `typ`, `timestamp`, and `raId`. The RA header `raId` must equal the
   event `raId`. Producer signatures are not checked (§4.3: verification must not require them).

In the draft-01 profile, the RA signature covers `payload` only. Appendix A.4 puts `status` next to that payload, so a
`REVOKED` badge can be edited to `ACTIVE` without breaking the signature. `inclusionProof.treeSize`
and `inclusionProof.leafIndex` are also outside both signatures. The inclusion check uses them, but
they are not a signed log size. The KMS signature is over the root hash only.

There is no fetch of a later log entry, so an old `AGENT_REGISTERED` proof still checks after a
later revocation. This command therefore does not treat an unsigned status as a pass. A signed
`AGENT_REVOKED` event, or a badge that still says `REVOKED` or `EXPIRED`, is not a current
registration. Every other badge whose certificate and inclusion check out returns
`ANS_REVOCATION_NOT_CHECKED` with `valid: false`, `binding_checked: true`, and exit `10`. The human
line is `Checked: certificate and log entry match this name. Revocation: not checked.` A
forged or failed badge keeps exit `7` and `binding_checked: false`. `scope.revocation` is
`"not checked"` and `scope.live_log` is `"not proved"`.

`issuedAt` and `expiresAt` inside the signed event are checked against the verifier's clock when
present. Certificate validity uses the same clock.

## Captured GoDaddy live V1 profile

`merkleProof` selects the explicit `godaddy-live-v1` profile. `inclusionProof` selects the existing
`draft-01` profile, retained for existing offline callers and fixtures. Providing both is an error.
These are separate byte-level formats: the verifier never guesses digest encodings or accepts
`raId` as an alias for a live protected-header `raid`.

The live fixture under `tests/fixtures/ans/godaddy-live-v1/` comes from the public Claudais badge.
Its manifest records capture time, source URLs, SHA-256 hashes and the public certificate export.
The live rules are:

- Hex `leafHash`, canonical padded standard-base64 `path` and `rootHash`, tree version 1.
- Leaf = SHA-256(`0x00` || JCS({payload, schemaVersion, signature})). Read-time `status` and
  `merkleProof` are excluded. The top-level detached log JWS signs JCS({payload, schemaVersion}).
- All three protected headers contain exactly `alg`, `kid`, `raid`, `timestamp`, `typ`;
  `alg` is ES256, `typ` is JWT, and header JSON/base64url is canonical. Key referrals and
  duplicate headers are rejected. The event itself continues to use `raId`.
- The attached root JWS signs a canonical checkpoint with exactly `checkpointFormat: "c2sp/v1"`,
  `origin: "transparency.ans.godaddy.com"`, padded URL-safe-base64 `rootHash`, integer `treesize`,
  and `timestamp`. Its root and size must equal the recomputed inclusion proof; its timestamp
  must equal its protected header. Both log signatures must verify against caller-pinned keys.
  Attached checkpoint JWS is bounded to 16,898 characters (existing segment limits: 8,192 header,
  8,192 payload, 512 signature, two separators), below the 256 KiB fetch / 1 MiB file cap.
  Ordinary strings and draft detached root signatures retain their 512-character limit.
- `--ra-jwk` retains its existing flag name but pins the **outer log attestation signer** in this
  profile; `--kms-jwk` pins the checkpoint signer. The captured provider uses the same log key for
  both, independently obtained from its public `/root-keys` endpoint. Neither is the producer key.
- The log-authenticated producer header's `raid` must equal event `raId`, and its `kid` must
  equal `producer.keyId`. The log signer has a separate authority ID. This checks the binding
  authenticated by the log; it does **not** independently verify the producer signature.
  `scope.producer_signature` therefore remains `"not checked"`. The producer public key was
  not available from the public root-key endpoint; the documented producer-key route returned
  HTTP 403 without authentication. No credential was used or key recovered from a signature.

These exact octets are supported by the captured signatures and the official implementation's
[envelope rules](https://github.com/agentnameservice/ans/blob/main/internal/tl/event/event.go),
[proof encodings](https://github.com/agentnameservice/ans/blob/main/internal/tl/service/merkleproof.go),
and [checkpoint signer](https://github.com/agentnameservice/ans/blob/main/internal/tl/logstore/jwssigner.go).

Unlike draft-01, the live checkpoint authenticates tree size. The leaf index is checked by the
inclusion path. Read-time status remains unsigned; inclusion of an old registration is still
insufficient to prove current status, nonrevocation, or log freshness. Success retains the exact
human binding line, `binding_checked: true`, `valid: false`, and exit 10. A tampered fixture fails
with exit 7. No presenting-agent ownership or ANS↔ZipViz link is established by this check.

## Local evidence

`--ca`, `--ra-jwk`, and `--kms-jwk` are required pinned inputs. `--bundle` may contain only the
identity chain and the badge:

```json
{
  "identityChainPem": "-----BEGIN CERTIFICATE-----\n...",
  "badge": {}
}
```

`trustAnchorPem`, `raKey`, and `kmsKey` inside a bundle are rejected. The command prints the pinned
CA SHA-256 and the RFC 7638 thumbprints of the pinned JWKs. The draft does not specify the body of
`GET /root-keys` beyond "KMS verification keys", so the pinned key is a public P-256 JWK. Private
JWK members are rejected. A `score` field is rejected.

`--badge-url` uses the existing HTTPS client: GET only, 5 second timeout, 256 KiB cap, JSON
responses, and no redirect to a private, link-local, or loopback address.

## Not claimed

- DNS `_ans-badge` discovery and DNSSEC.
- DANE TLSA (Silver / Gold steps 2).
- Binary COSE receipts. The REST badge in Appendix A.4 is what this verifier reads.
- HCS-27 consensus checkpoints (§9.1 layer 2).
- Consistency proofs between two tree heads.
- OCSP or CRL retrieval.
- Server-certificate or mTLS handshakes.
- Trust Index, verifiable-claim evaluation, reputation, or behaviour.
- Live log freshness (`live_log: "not proved"`). The captured live badge proves inclusion at one
  signed tree head, without consulting later log entries.
- A signed tree size in the draft-01 profile; live V1 checks the signed checkpoint size.
- Independent producer-signature verification (both profiles).
