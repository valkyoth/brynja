#!/usr/bin/env bash
set -euo pipefail

fixture="assurance/kmac-conformance-rejected/Cargo.toml"
evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-kmac-conformance.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

if CARGO_TARGET_DIR="$evidence_dir/target" cargo check --locked --manifest-path "$fixture" \
    >"$evidence_dir/stdout" 2>"$evidence_dir/stderr"; then
    echo "default KMAC build unexpectedly exposed conformance constructors" >&2
    exit 1
fi
grep -q 'new_conformance' "$evidence_dir/stderr"

CARGO_TARGET_DIR="$evidence_dir/enabled" cargo check --locked \
    --manifest-path assurance/kmac-differential/Cargo.toml

echo "default KMAC builds reject conformance constructors; explicit assurance feature compiles"
