#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.98.0}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+${toolchain}"
fi

codegen_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-zeroization-codegen.XXXXXX")"
trap 'rm -rf "$codegen_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$codegen_dir" cargo "$toolchain" rustc \
    -p brynja-core \
    --release \
    --target "$target" \
    --lib \
    -- \
    --emit=mir,llvm-ir,asm

mapfile -t mir_files < <(find "$codegen_dir" -type f -name 'brynja_core-*.mir')
mapfile -t llvm_files < <(find "$codegen_dir" -type f -name 'brynja_core-*.ll')
mapfile -t assembly_files < <(find "$codegen_dir" -type f -name 'brynja_core-*.s')
[[ "${#mir_files[@]}" -eq 1 ]] || {
    echo "expected one brynja-core MIR artifact" >&2
    exit 1
}
[[ "${#llvm_files[@]}" -eq 1 ]] || {
    echo "expected one brynja-core LLVM IR artifact" >&2
    exit 1
}
[[ "${#assembly_files[@]}" -eq 1 ]] || {
    echo "expected one brynja-core assembly artifact" >&2
    exit 1
}

grep -q 'fn zeroize_region_volatile' "${mir_files[0]}"
grep -q 'write_volatile::<u8>' "${mir_files[0]}"
grep -q 'zeroize_region_volatile' "${llvm_files[0]}"
grep -Eq 'store volatile i8 0,' "${llvm_files[0]}"
assembly_body="$codegen_dir/zeroize-region-volatile.s"
awk '
    /zeroize_region_volatile[^:]*:$/ { active = 1; print; next }
    active && /^_*[RZ][^:]*:$/ { exit }
    active { print }
' "${assembly_files[0]}" >"$assembly_body"
grep -q 'zeroize_region_volatile' "$assembly_body"

case "$target" in
    x86_64-*)
        grep -Eq 'movb[[:space:]]+\$0,' "$assembly_body"
        ;;
    aarch64-*)
        grep -Eq 'strb[[:space:]]+wzr,' "$assembly_body"
        ;;
    thumbv7em-*)
        grep -Eq 'strb[[:space:]]+r[0-9]+,' "$assembly_body"
        ;;
    riscv32imac-*)
        grep -Eq 'sb[[:space:]]+zero,' "$assembly_body"
        ;;
    *)
        echo "zeroization assembly policy has no target rule: $target" >&2
        exit 1
        ;;
esac

echo "zeroization stores survive MIR, LLVM IR, and $target assembly under ${toolchain#+}"
