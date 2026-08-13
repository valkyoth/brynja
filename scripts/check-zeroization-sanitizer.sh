#!/usr/bin/env bash
set -euo pipefail

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-13 test \
    -p brynja-core \
    --test secret_memory \
    --target x86_64-unknown-linux-gnu
