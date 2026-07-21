#!/usr/bin/env sh
set -eu

test -s release-notes/RELEASE_NOTES_0.1.0.md
test -s docs/RELEASE_PLAN.md
test -s docs/VERSION_PLAN.md
test -s docs/CRATE_VERSION_MATRIX.md
grep -q '^version = "0.1.0"$' Cargo.toml
cmp -s README.md crates/brynja/README.md
test "$(git ls-files PENTEST.md)" = ""

