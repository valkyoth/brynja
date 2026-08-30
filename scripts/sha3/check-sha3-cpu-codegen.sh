#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d /tmp/brynja-sha3-codegen-XXXXXX)"
trap 'rm -rf "$temporary"' EXIT
cd "$workspace"

compile_and_find() {
    local target="$1"
    local output="$2"
    local toolchain="$3"
    CARGO_TARGET_DIR="$temporary/$output" \
        cargo "+$toolchain" rustc --quiet --locked --release \
        -p brynja-crypto-cpu --target "$target" --lib -- --emit=asm
    mapfile -t assembly < <(find "$temporary/$output" -type f -name '*.s' -print)
    if test "${#assembly[@]}" -ne 1; then
        echo "SHA-3 CPU codegen expected one assembly file for $target" >&2
        exit 1
    fi
    printf '%s\n' "${assembly[0]}"
}

for toolchain in 1.90.0 1.98.0; do
    x86_assembly="$(compile_and_find x86_64-unknown-linux-gnu "x86-$toolchain" "$toolchain")"
    for instruction in vpxor vpandn; do
        grep -Eq "(^|[[:space:]])${instruction}[[:alnum:]]*([[:space:]]|$)" "$x86_assembly" || {
            echo "x86_64 AVX2 Keccak codegen under $toolchain omitted $instruction" >&2
            exit 1
        }
    done

    arm_assembly="$(compile_and_find aarch64-unknown-linux-gnu "aarch64-$toolchain" "$toolchain")"
    for instruction in eor3 rax1 bcax; do
        grep -Eq "(^|[[:space:]])${instruction}([[:space:]]|$)" "$arm_assembly" || {
            echo "AArch64 SHA3 Keccak codegen under $toolchain omitted $instruction" >&2
            exit 1
        }
    done
done

echo "SHA-3 CPU codegen contains AVX2 and AArch64 SHA3 instructions under Rust 1.90.0 and 1.98.0"
