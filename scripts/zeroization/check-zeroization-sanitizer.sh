#!/usr/bin/env bash
set -euo pipefail

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-core \
    --test secret_memory \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --lib \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha224 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha256 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha384 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha512 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha512_224 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha2 \
    --test sha512_256 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-08-28 test \
    -p brynja-hash-sha3 \
    --tests \
    --target x86_64-unknown-linux-gnu
