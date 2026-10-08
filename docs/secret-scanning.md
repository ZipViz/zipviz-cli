# Secret scanning

The `Secret scan / gitleaks` workflow runs on pull requests and pushes to `main`.
It downloads gitleaks **8.30.1** and verifies the Linux x64 archive against the
SHA-256 in the upstream release checksum manifest. Updating the scanner requires
reviewing both the version and checksum together; Dependabot does not update this
binary download. No gitleaks action license or repository secret is needed.

The gate uses upstream default detection rules, with two owner-approved exceptions,
anchored to exactly `tests/fixtures/nip-oa/test-vectors.txt` and
`tests/fixtures/ans/godaddy-live-v1/badge.json`. The public NIP upstream fixture was
verified byte for byte. The ANS fixture matches the SHA-256 recorded when captured
from the unauthenticated GoDaddy transparency log on 2026-10-05; its flagged JWT
is a public signed checkpoint. Provenance URLs and hashes are recorded in
`.gitleaks.toml`. All other paths remain scanned.
It ignores `gitleaks:allow` comments. Any finding or scanner error fails the job.
The report and scanner log are temporary, removed on exit, and never uploaded.
Only rule names and file paths are printed for findings; matched values are not
printed. Ask the owner to triage findings before adding any suppression.

## Opt-in local hook

Install gitleaks 8.30.1 and Python 3 on PATH, plus `pre-commit`, then run:

```sh
pre-commit install
pre-commit run gitleaks --all-files
```

The hook scans **staged git changes**, even when invoked with `--all-files`.
To scan all locally fetched history instead:

```sh
bash scripts/scan-secrets.sh history
```

Hook installation is optional and never runs during npm installation. Use
`pre-commit uninstall` to remove it. The same script and detection configuration
are used in CI and locally. Scanning is local; no credential verification against
providers is performed.

## Scope and limits

CI checks history reachable from refs fetched by checkout (`fetch-depth: 0`),
including the checked-out PR merge commit. It does not fetch all GitHub pull
request refs or inspect issue bodies, PR discussions, Actions logs, other repos,
or hosted settings. This is a repository regression gate, not an org-wide sweep
or open-source publication clearance. Repository settings, tokens, publishing
and deployment are managed separately.

Existing CI, the Node 22/24 matrix and SHA action pins remain in place. Required-check/branch-protection settings are owner-managed.

The owner approved the NIP-OA exact-file exception on 2026-10-05. The fixture matches the public NIP-OA test-vector
fenced block at upstream `fe9e2409a02fbac415d5c66181135be3eec28a86` byte for byte.
The separately cited short commit `004a8aa` does not resolve in `block/buzz`;
this exception uses the full verified revision recorded in the fixture README.

Run `python3 scripts/test-secret-scan.py` to verify the bounded exception. CI
runs the same regression checks before scanning history. Temporary synthetic
repos prove both exact approved paths are accepted, clean controls pass, fourteen similar
paths are rejected, and `gitleaks:allow` is ignored. Both staged and history scans
are checked; the nonfunctional synthetic value must never appear in output.
Any future content added at either exact approved path is also excluded, so changes
to those fixtures require owner review. There are no rule-wide or value exclusions.

The public ANS exception was approved by the owner on 2026-10-05. It changes no
verifier, JWT detection rule, scanner flags, workflow, or live activation. The
fixture's manifest records the capture URL/time/hash, and its certificate,
signed log envelope, inclusion path, and checkpoint remain cryptographically checked.
