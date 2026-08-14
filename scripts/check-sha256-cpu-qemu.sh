#!/usr/bin/env bash
set -euo pipefail

command -v qemu-aarch64 >/dev/null 2>&1 || {
    echo "SHA-256 CPU QEMU check requires qemu-aarch64" >&2
    exit 1
}
rustup target list --installed | grep -Eq '^aarch64-unknown-linux-musl$' || {
    echo "SHA-256 CPU QEMU check requires aarch64-unknown-linux-musl" >&2
    exit 1
}

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+neon,+sha2 -C linker=rust-lld' \
    cargo test --quiet --locked -p brynja-hash-sha2 --features cpu \
    --test sha256_accelerated --target aarch64-unknown-linux-musl

echo "AArch64 SHA2 candidate matches scalar under supplemental QEMU execution"
