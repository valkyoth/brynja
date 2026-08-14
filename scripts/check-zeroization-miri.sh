#!/usr/bin/env bash
set -euo pipefail

miri_cache="$(mktemp -d "${TMPDIR:-/tmp}/brynja-miri.XXXXXX")"
trap 'rm -rf -- "$miri_cache"' EXIT HUP INT TERM

CARGO_HOME="$miri_cache/cargo" XDG_CACHE_HOME="$miri_cache" \
    cargo +nightly-2026-08-14 miri test \
    -p brynja-core \
    --test secret_memory \
    --target x86_64-unknown-linux-gnu

CARGO_HOME="$miri_cache/cargo" XDG_CACHE_HOME="$miri_cache" \
    cargo +nightly-2026-08-14 miri test \
    -p brynja-sanitization \
    --test behavior \
    --target x86_64-unknown-linux-gnu

CARGO_HOME="$miri_cache/cargo" XDG_CACHE_HOME="$miri_cache" \
    cargo +nightly-2026-08-14 miri test \
    -p brynja-hash-sha2 \
    --test sha256 \
    downstream_style_real_content_uses_only_public_api \
    --target x86_64-unknown-linux-gnu

CARGO_HOME="$miri_cache/cargo" XDG_CACHE_HOME="$miri_cache" \
    cargo +nightly-2026-08-14 miri test \
    -p brynja-hash-sha2 \
    --test sha256 \
    padding_boundaries_have_exact_digests \
    --target x86_64-unknown-linux-gnu
