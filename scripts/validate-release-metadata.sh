#!/usr/bin/env sh
set -eu

version="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("release-crates.toml", "rb"))["release"]["version"])'
)"
facade_version="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("crates/brynja/Cargo.toml", "rb"))["package"]["version"])'
)"
release_notes="release-notes/RELEASE_NOTES_${version}.md"

test "$facade_version" = "$version"
test -s "$release_notes"
test -s docs/RELEASE_PLAN.md
test -s docs/VERSION_PLAN.md
test -s docs/CRATE_VERSION_MATRIX.md
test -s package-policy.toml
test -s github-release-controls.toml
test -x scripts/release_crates.py
test -f scripts/release_policy.py
test -x scripts/test-release-crates.py
test -x scripts/test-release-readiness.sh
test -x scripts/check-github-release-controls.py
test -x scripts/test-github-release-controls.py
test -x scripts/validate-current-pentest.sh
test -x scripts/install-ci-tools.sh
test -s scripts/ci-tools.lock
test -f security/pentest/README.md
test -f release-crates.toml
cmp -s README.md crates/brynja/README.md
grep -q 'run: scripts/install-ci-tools.sh' .github/workflows/ci.yml
grep -q 'run: scripts/check-github-release-controls.py --public' \
    .github/workflows/ci.yml
test "$(git ls-files PENTEST.md)" = ""
