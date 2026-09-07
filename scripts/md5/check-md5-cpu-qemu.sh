#!/usr/bin/env bash
set -euo pipefail
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max'
export RUSTFLAGS='--cfg brynja_md5_cpu_evidence -C target-feature=+neon -C linker=rust-lld'
cargo test --locked -p brynja-legacy-md5 --features cpu,cpu-evidence --lib cpu:: \
    --target aarch64-unknown-linux-musl
cargo run --locked --release --manifest-path assurance/md5-cpu-public-api/Cargo.toml \
    --target aarch64-unknown-linux-musl
echo 'AArch64 MD5 forced-path QEMU correctness: PASS; supplemental only, not native evidence'
