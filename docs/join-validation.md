# ELU-846 CLI join validation

Scope: `ZipViz/zipviz-cli` repository ID `1422517323`, c-cli only. Base:
`34f31f1a053e4d5c47627d871f6ba075ec54d91a` (`main`). Contract: Linear ELU-846
comments v1.0 `9651b947-5111-463b-865a-2bd4ec75005a`, v1.1
`43c56be4-1890-4e0c-9ce2-5f6b1ebc0b1f`, v1.1.1
`db26c0be-45cb-4aad-8926-00fbd6b1d5d3`, Zorro `8998fca0` and Dingo
`fce65dd5`. Latest version wins. Intro commands remain a separate slice.

The exact synthetic DRAFT API artifact is
`Elusor8/zipviz-api@420f0c2cc79f49ecf1d78414c2ef2bead7900902`. Vector SHA-256:
`9500affd45a4084bf20a3371ffe4209680f406d58b266049590fef2ed2ce432a`.
[Fixture provenance](../test-vectors/signup-api/README.md) records all source hashes
and the reproducible typed-fake compilation. No fixture is final server acceptance.

## Local checks

Node 24.19.0, npm 11.17.0; unchanged lockfile.

| Check | Result |
| --- | --- |
| Untouched main lint, typecheck, build | PASS |
| Untouched main full tests | 523 PASS, 1 existing skip |
| Join head lint, typecheck, build | PASS |
| Join head full tests | 697 PASS, 1 existing skip |
| New vector/codec tests | 85 PASS, including all 38 pinned status/code cases |
| New store tests | 14 PASS |
| New lifecycle/transport tests | 75 PASS |
| Fixture regeneration check | PASS |
| Gitleaks 8.30.1 staged/history and unchanged guard harness | PASS |
| `npm audit --omit=dev --audit-level=high` | PASS, zero advisories |
| Full `npm audit --audit-level=high` | FAIL on unchanged main and join: 1 high (Vite), 2 moderate (Vitest/mocker), all development dependencies |
| Baseline sensitivity | Untouched main returns `E_USAGE` for the new join command, zero network calls |

The single skip is the existing foreign-owner test that requires root. The sandbox
blocks child OpenSSL/FIFO fixtures and loopback listeners, producing baseline EPERM
failures. Full suites pass with those local fixture permissions; no product test
was removed or weakened. Hosted Node 22/24 checks are reported on the PR separately.

Tests exercise both delayed original-start commit orderings, crash after durable
append before send, concurrent append recovery, foreign rows, all eight attempts,
404 preservation, exact-byte transport retries, rate-limited polling, cancellation,
private-file/no-follow/owner/mode checks, no-clobber and current registry adoption
fences. The shared public-client843 and existing harness source are untouched.

## Operational and review boundaries

All new tests use disposable synthetic keys, names, owner claims and invalid-domain
email addresses. No real signup, enrollment, grant, provider/tenant call, message,
key deletion, migration, activation or deployment was executed. Production flags
and privacy/retention holds remain unchanged. Live acceptance is blocked pending
the separate server implementation and operational approvals.

This PR remains draft pending one canonical independent non-Codex review routed by
Gavin, Einstein contract review, Gavin final and Stu merge. Internal implementation
and test assistance does not satisfy that independent review requirement.
