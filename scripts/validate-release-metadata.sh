#!/usr/bin/env sh
set -eu

test -s release-notes/RELEASE_NOTES_0.1.0.md
test -s docs/RELEASE_PLAN.md
test -s docs/VERSION_PLAN.md
test -s docs/CRATE_VERSION_MATRIX.md
test -x scripts/release_crates.py
test -f scripts/release_policy.py
test -x scripts/test-release-crates.py
test -x scripts/test-release-readiness.sh
test -x scripts/validate-current-pentest.sh
test -f security/pentest/README.md
test -f release-crates.toml
grep -q '^version = "0.1.0"$' Cargo.toml
cmp -s README.md crates/brynja/README.md
test "$(git ls-files PENTEST.md)" = ""
