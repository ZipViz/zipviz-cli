#!/usr/bin/env python3
"""Bounded local regression checks using a nonfunctional synthetic token."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
APPROVED_PATH = "tests/fixtures/nip-oa/test-vectors.txt"
APPROVED_BADGE_PATH = "tests/fixtures/ans/godaddy-live-v1/badge.json"
BADGE_NEGATIVE_PATHS = (
    "elsewhere/badge.json",
    "prefix/tests/fixtures/ans/godaddy-live-v1/badge.json",
    "tests/fixtures/ans/godaddy-live-v1/badge.json.suffix",
    "tests/fixtures/ans/godaddy-live-v1/prefix-badge.json",
    "tests/fixtures/ans/godaddy-live-v1/sibling.json",
    "tests/fixtures/ans/godaddy-live-v1/subdir/badge.json",
    "tests/fixtures/ans/godaddy-live-v1-other/badge.json",
)
# Deliberately nonfunctional; constructed locally, never sent to a provider.
SYNTHETIC_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
NEGATIVE_PATHS = (
    "elsewhere/test-vectors.txt",
    "prefix/tests/fixtures/nip-oa/test-vectors.txt",
    "tests/fixtures/nip-oa/test-vectors.txt.suffix",
    "tests/fixtures/nip-oa/prefix-test-vectors.txt",
    "tests/fixtures/nip-oa/sibling.txt",
    "tests/fixtures/nip-oa/subdir/test-vectors.txt",
    "tests/fixtures/nip-oa-other/test-vectors.txt",
)


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def scan(repo, mode, expected):
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/scan-secrets.sh"), mode],
        cwd=repo, capture_output=True, text=True, env=os.environ.copy(),
    )
    output = result.stdout + result.stderr
    assert result.returncode == expected, f"{mode}: unexpected exit {result.returncode}"
    assert SYNTHETIC_TOKEN not in output, "Matched value leaked to output"
    if expected == 1:
        assert '"rule": "github-pat"' in output, "Synthetic token was not detected"


def run_case(path, content, expected):
    with tempfile.TemporaryDirectory(prefix="zipviz-secret-regression-") as directory:
        repo = Path(directory)
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "Synthetic Fixture")
        git(repo, "config", "user.email", "synthetic@example.invalid")
        (repo / ".gitleaks.toml").write_bytes((ROOT / ".gitleaks.toml").read_bytes())
        (repo / "clean.txt").write_text("No credential in this control.\n")
        git(repo, "add", ".")
        git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "Clean control")
        scan(repo, "history", 0)
        scan(repo, "staged", 0)
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        git(repo, "add", ".")
        scan(repo, "staged", expected)
        git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic regression")
        scan(repo, "history", expected)


if __name__ == "__main__":
    fixture = (ROOT / APPROVED_PATH).read_bytes()
    run_case(APPROVED_PATH, fixture, 0)
    synthetic = ('token = "' + SYNTHETIC_TOKEN + '"\n').encode()
    # Policy tests also run before the interop fixture lands on main.
    run_case(APPROVED_BADGE_PATH, synthetic, 0)
    for path in (*NEGATIVE_PATHS, *BADGE_NEGATIVE_PATHS):
        run_case(path, synthetic, 1)
    run_case("inline-allow.txt", synthetic.rstrip() + b" # gitleaks:allow\n", 1)
    run_case("tests/fixtures/ans/godaddy-live-v1/inline-allow.json",
             synthetic.rstrip() + b" # gitleaks:allow\n", 1)
    print("Secret gate regressions passed: exact public fixture, clean controls, "
          "fourteen similar paths, inline allow rejection, staged/history redaction.")
