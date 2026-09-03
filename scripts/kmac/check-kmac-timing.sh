#!/usr/bin/env bash
set -euo pipefail

target_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-kmac-timing.XXXXXX")"
trap 'rm -rf "$target_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$target_dir" cargo run --release --locked --quiet \
    --manifest-path assurance/kmac-timing/Cargo.toml
