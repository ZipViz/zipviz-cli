# ELU-846 CLI introduction validation

Scope: d-cli only in `ZipViz/zipviz-cli` (repository ID `1422517323`). This slice
depends on PR #12 at exact commit `ecd246397d08f98d777ba319b7ae59545a297c0d`.
It uses a new worktree/branch and does not modify PR #12. Its draft targets
`codex/elu-846-cli-join` until that dependency merges, then requires retargeting
to main. Current main at the start was `34f31f1a053e4d5c47627d871f6ba075ec54d91a`.

Contract: ELU-846 v1.0 `9651b947`, v1.1 H/I/L `43c56be4`, v1.1.1 `db26c0be`.
The frozen design supplies CONTRIBUTING.md's new-command discussion. Slice (d)
is compose-only: no automatic introduction or close-the-loop DM is implemented.
No bot grants or identities are changed.

## Exact draft fixtures

Same API artifact: `Elusor8/zipviz-api@420f0c2cc79f49ecf1d78414c2ef2bead7900902`.
The vector SHA-256 remains
`9500affd45a4084bf20a3371ffe4209680f406d58b266049590fef2ed2ce432a`;
the exact typed fake SHA-256 remains
`1009df5fac822cc019007eaa4748bb3c9ec81703784bd2f1d24bc8757f859cdd`.
All 38 existing vectors pass, including eight intro cases and five signed policy
cases. The production intro token and policy bytes match their valid vectors
exactly. No shared artifact, fake, vector or server protocol was changed.

The `zvic1` confirmation receipt is separate local HMAC state, not a server wire
format or supplemental shared vector. It binds peer HMAC, domain, draft id,
times and token digest; only an explicit `confirm-sent --confirmed-sent` records
the caller's attestation in the private dedupe store. Confirmation of a past send
is allowed after intro expiry and creates no server authority. The receipt is
not transmitted or persisted. These local interface choices require Einstein's
contract check with the rest of the draft.

## Validation

Local Node 24.19.0 / npm 11.17.0:

| Check | Result |
| --- | --- |
| Frozen PR #12 baseline | 697 tests PASS / 1 existing skip; lint/types/build and hosted Node22/24/secret scan PASS |
| d-cli full suite | 853 tests PASS / 1 existing skip |
| New codec/composer tests | 80 PASS |
| New secure store tests | 17 PASS |
| New CLI flow tests | 59 PASS |
| Lint, typecheck, build, fixture regeneration | PASS |
| Exact shared source/vector hashes | PASS |
| Gitleaks 8.30.1 staged/history and unchanged scanner regression harness | PASS |
| Baseline command sensitivity | Frozen PR #12 returns `E_USAGE`, zero network calls, for the new intro command |

The skip is the existing foreign-owner test that requires root. Full suites need
local loopback/OpenSSL/FIFO fixture permissions that the sandbox blocks; no tests
were skipped or weakened to bypass that restriction. Hosted Node22/24 and secret
scan evidence is reported on this slice's PR after publication.

No dependency or lockfile changed. PR #12's audit of this identical lockfile found
zero production advisories; full audit had unchanged development-only findings:
one high in Vite and two moderate in Vitest/mocker. Those baseline findings remain
separate from this source slice; no new package-advisory transmission was needed.

Tests use disposable synthetic Ed25519 material and the pinned draft fake. They
cover exact account-linked/domain copy without a checkmark; current key, domain,
incarnation, revision and active-state fences; policy opt-out/errors/freshness,
including final disk-operation delays; optional peer lookup refusals; caller
attestation labeling; explicit local-only confirmation; authenticated late
confirmation; 30-day/restart dedupe; private no-follow/permissions/owner checks;
atomic locking, concurrent confirmations and no raw peer/token/message persistence.

## Remaining gates

The fake is synthetic DRAFT evidence, not final server or live tenant acceptance.
All flags remain off. No live signup, key creation/enrollment, intro, provider,
tenant, credential, message, grant, purge, migration, deployment or merge was
performed. Privacy/retention holds, CLI843 and existing harness ownership remain
unchanged. Review requires one canonical independent non-Codex reviewer via Gavin,
then Einstein contract check, Gavin final and Stu merge. Internal implementation
support does not satisfy the independent review gate.
