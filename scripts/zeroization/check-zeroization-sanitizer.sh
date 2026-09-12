#!/usr/bin/env bash
set -euo pipefail

# Verified native SHA-NI host; missing hardware is a blocker, never a skip/PASS.
python3 scripts/sha2/check-sha2-hardened-asan.py
python3 scripts/sha3/check-keccak-hardened-asan.py

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha3 --features static-execution --test cshake_execution \
    --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-crypto-cpu-std --features sponge-execution --lib sponge \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 -p brynja-crypto-cpu --all-features --lib hardened_execution \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --test execution \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-crypto-cpu --features runtime-execution --lib runtime_execution \
    --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-crypto-cpu-std --features runtime-execution --lib execution \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-crypto-cpu --features static-execution --lib static_authority \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    --manifest-path assurance/general-sha512-t/Cargo.toml \
    --lib --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 run \
    --locked --offline --release --manifest-path assurance/general-sha512-t/Cargo.toml \
    --bin general-sha512-t-profile --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 --features general-sha512-t --test general_hash --lib \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 --features general-sha512-t --test general \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    --manifest-path assurance/legacy-hash-final/Cargo.toml \
    --lib --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-legacy-sha1 --features cpu --lib --test cpu \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    --manifest-path assurance/legacy-hash-public-api/Cargo.toml \
    --lib --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-core \
    --test secret_memory \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --lib \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test bit_inputs \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test hardened \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha224 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha256 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha384 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha512 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha512_224 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha2 \
    --test sha512_256 \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha3 \
    --lib \
    final_bit_output_clears_the_exact_reader_source \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha3 \
    --lib \
    borrowing_reader_never_extracts_the_absorbing_owner \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha3 \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-sha3 --features static-execution --lib --test execution \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-mac-kmac \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-mac-kmac --features hardened-execution --lib --test execution \
    --target x86_64-unknown-linux-gnu

python3 scripts/kmac/check-kmac-execution.py --asan

python3 scripts/tuplehash/check-tuplehash-execution.py --asan

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-tuple --features hardened-execution --lib --test execution \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-tuple \
    --test api \
    forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-tuple \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-parallel \
    --features runtime-execution \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-hash-parallel-std \
    --features runtime-execution \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-legacy-sha1 \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-legacy-md5 \
    --tests \
    --target x86_64-unknown-linux-gnu

RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test \
    -p brynja-legacy-md5 --features cpu --lib --test cpu \
    --target x86_64-unknown-linux-gnu
