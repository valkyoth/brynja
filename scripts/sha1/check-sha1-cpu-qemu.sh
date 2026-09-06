#!/usr/bin/env bash
set -euo pipefail
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max'
export RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+neon,+sha2 -C linker=rust-lld'
cargo test --locked -p brynja-legacy-sha1 --features cpu --lib cpu:: \
    --target aarch64-unknown-linux-musl
cargo run --locked --release --manifest-path assurance/sha1-cpu-public-api/Cargo.toml \
    --target aarch64-unknown-linux-musl
echo 'AArch64 SHA-1 forced-path QEMU correctness: PASS; supplemental only, not native evidence'
