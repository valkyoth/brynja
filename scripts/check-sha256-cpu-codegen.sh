#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/.." && pwd)"
temporary="$(mktemp -d /tmp/brynja-sha256-codegen-XXXXXX)"
trap 'rm -rf "$temporary"' EXIT

compile_and_find() {
    local target="$1"
    local output="$2"
    CARGO_TARGET_DIR="$temporary/$output" \
        cargo rustc --quiet --locked --release -p brynja-crypto-cpu \
        --target "$target" --lib -- --emit=asm
    mapfile -t assembly < <(find "$temporary/$output" -type f -name '*.s' -print)
    if test "${#assembly[@]}" -ne 1; then
        echo "SHA-256 CPU codegen expected one assembly file for $target" >&2
        exit 1
    fi
    printf '%s\n' "${assembly[0]}"
}

x86_assembly="$(compile_and_find x86_64-unknown-linux-gnu x86)"
grep -Fq -- 'sha256rnds2' "$x86_assembly" || {
    echo "x86_64 SHA-256 codegen omitted sha256rnds2" >&2
    exit 1
}

arm_assembly="$(compile_and_find aarch64-unknown-linux-gnu aarch64)"
for instruction in 'sha256h' 'sha256h2'; do
    grep -Fq -- "$instruction" "$arm_assembly" || {
        echo "AArch64 SHA-256 codegen omitted $instruction" >&2
        exit 1
    }
done

echo "SHA-256 CPU codegen contains x86 SHA and AArch64 SHA2 instructions"
