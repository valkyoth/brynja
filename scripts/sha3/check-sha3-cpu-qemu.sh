#!/usr/bin/env bash
set -euo pipefail

command -v qemu-aarch64 >/dev/null 2>&1 || {
    echo "SHA-3 CPU QEMU check requires qemu-aarch64" >&2
    exit 1
}
rustup target list --installed | grep -Eq '^aarch64-unknown-linux-musl$' || {
    echo "SHA-3 CPU QEMU check requires aarch64-unknown-linux-musl" >&2
    exit 1
}

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu max' \
RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+neon,+sha3 -C linker=rust-lld' \
    cargo run --quiet --locked \
    --manifest-path assurance/sha3-cpu-candidate/Cargo.toml \
    --target aarch64-unknown-linux-musl

echo "AArch64 SHA3 candidate matches all six byte-oriented identities under supplemental QEMU execution"
