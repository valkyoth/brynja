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
command -v qemu-riscv64 >/dev/null 2>&1 || {
    echo "SHA-256 CPU QEMU check requires qemu-riscv64" >&2
    exit 1
}
rustup target list --installed | grep -Eq '^riscv64gc-unknown-linux-gnu$' || {
    echo "SHA-256 CPU QEMU check requires riscv64gc-unknown-linux-gnu" >&2
    exit 1
}

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+neon,+sha2,+sha3 -C linker=rust-lld' \
    cargo test --quiet --locked -p brynja-crypto-cpu --lib \
    --target aarch64-unknown-linux-musl
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
RUSTFLAGS='--cfg brynja_cpu_evidence -C target-feature=+neon,+sha2,+sha3 -C linker=rust-lld' \
    cargo test --quiet --locked -p brynja-hash-sha2 --features cpu \
    --lib --test sha256_accelerated --test sha2_accelerated \
    --target aarch64-unknown-linux-musl

if command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
    riscv_linker=riscv64-linux-gnu-gcc
    riscv_sysroot=/usr/riscv64-linux-gnu
elif command -v riscv64-suse-linux-gcc >/dev/null 2>&1; then
    riscv_linker=riscv64-suse-linux-gcc
    riscv_sysroot="$(riscv64-suse-linux-gcc --print-sysroot)"
else
    echo "SHA-256 CPU QEMU check requires a RISC-V GNU cross linker" >&2
    exit 1
fi
test -d "$riscv_sysroot" || {
    echo "SHA-256 CPU QEMU sysroot is unavailable" >&2
    exit 1
}

CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64 -cpu max -L $riscv_sysroot -E LD_LIBRARY_PATH=/lib:/lib64:/lib64/lp64d:/usr/lib:/usr/lib64" \
RUSTFLAGS="--cfg brynja_cpu_evidence -C target-feature=+zknh -C linker=$riscv_linker" \
    cargo test --quiet --locked -p brynja-crypto-cpu --lib \
    --target riscv64gc-unknown-linux-gnu
CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64 -cpu max -L $riscv_sysroot -E LD_LIBRARY_PATH=/lib:/lib64:/lib64/lp64d:/usr/lib:/usr/lib64" \
RUSTFLAGS="--cfg brynja_cpu_evidence -C target-feature=+zknh -C linker=$riscv_linker" \
    cargo test --quiet --locked -p brynja-hash-sha2 --features cpu \
    --lib --test sha256_accelerated --test sha2_accelerated \
    --target riscv64gc-unknown-linux-gnu

echo "AArch64 SHA2/SHA512 and RISC-V Zknh candidates match all six SHA-2 identities under supplemental QEMU execution"
