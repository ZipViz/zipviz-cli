# CLI join validation

Scope: `ZipViz/zipviz-cli` repository ID `1422517323`, c-cli only. Base:
`34f31f1a053e4d5c47627d871f6ba075ec54d91a` (`main`). The implementation uses
the version 1.0 signing schema with append-only retry history. Intro commands
remain a separate slice.

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
| Original join full tests | 697 PASS, 1 existing skip |
| Updated join full tests | 704 PASS, 1 existing skip |
| New vector/codec tests | 85 PASS, including all 38 pinned status/code cases |
| Store tests | 16 PASS |
| Lifecycle/transport tests | 80 PASS |
| Fixture regeneration check | PASS |
| Gitleaks 8.30.1 staged/history and unchanged guard harness | PASS |
| `npm audit --omit=dev --audit-level=high` | PASS, zero advisories |
| Full `npm audit --audit-level=high` | FAIL on unchanged main and join: 1 high (Vite), 2 moderate (Vitest/mocker), all development dependencies |
| Baseline sensitivity | Untouched main returns `E_USAGE` for the new join command, zero network calls |

This Node24 run uses uid1000 and skips the existing foreign-owner test requiring
root. A separate Node22 run under root instead skips the existing unreadable-file
EACCES case. These are environment-dependent existing skips, not waived checks.
The local scanner is gitleaks8.30.1 on PATH; an environment without
that binary has incomplete local secret gates, regardless of hosted results. The sandbox
blocks child OpenSSL/FIFO fixtures and loopback listeners, producing baseline EPERM
failures. Full suites pass with those local fixture permissions; no product test
was removed or weakened. Hosted Node 22/24 checks are reported on the PR separately.

Tests exercise both delayed original-start commit orderings, crash after durable
append before send, concurrent append recovery, foreign rows, all eight attempts,
404 preservation, exact-byte transport retries, rate-limited polling, cancellation,
private-file/no-follow/owner/mode checks, no-clobber and current registry adoption
fences. The shared public-client843 and existing harness source are untouched.

Concurrent child processes deterministically encounter the same dead-owner lock;
all refuse mutation, and exact retained attempts, receipt bytes and lock inode
remain unchanged. Ordinary mutations never reclaim an existing lock. Post-creation
poll failure retains a historical handoff in one JSON result with unknown current
state, including the approval URL/code, fingerprint, signup id and recovery commands.

## Operational boundaries

All new tests use disposable synthetic keys, names, owner claims and invalid-domain
email addresses. No real signup, enrollment, grant, provider/tenant call, message,
key deletion, migration, activation or deployment was executed. Production flags
and privacy/retention holds remain unchanged. Live acceptance is blocked pending
the separate server implementation and operational approvals.

Synthetic validation is not live service acceptance or permission to activate a
production feature.
