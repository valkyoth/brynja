#!/usr/bin/env bash
set -euo pipefail
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max'
export RUSTFLAGS='--cfg brynja_md5_cpu_evidence -C target-feature=+neon -C linker=rust-lld'
cargo test --locked -p brynja-legacy-md5 --features cpu,cpu-evidence --lib cpu:: \
    --target aarch64-unknown-linux-musl
cargo run --locked --release --manifest-path assurance/md5-cpu-public-api/Cargo.toml \
    --target aarch64-unknown-linux-musl
echo 'AArch64 MD5 forced-path QEMU correctness: PASS; supplemental only, not native evidence'
export RUSTFLAGS='-C target-feature=+neon -C linker=rust-lld'
export BRYNJA_REQUIRE_MD5_EXECUTION=1
cargo test --locked --offline -p brynja-legacy-md5 --features execution --lib --test execution \
    --target aarch64-unknown-linux-musl -- --nocapture
cargo test --locked --offline -p brynja-legacy-md5-std --features runtime-execution --test execution \
    --target aarch64-unknown-linux-musl -- --nocapture
cargo build --locked --offline --release --manifest-path assurance/md5-execution/Cargo.toml \
    --target aarch64-unknown-linux-musl
python3 scripts/md5/check-md5-execution-differential.py --width 4 --qemu \
    --binary "${CARGO_TARGET_DIR:-assurance/md5-execution/target}/aarch64-unknown-linux-musl/release/brynja-md5-execution-fixture"
echo 'AArch64 ordinary MD5 operational QEMU: PASS; no candidate evidence cfg; not native qualification'
