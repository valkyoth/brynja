#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.97.1}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+${toolchain}"
fi

codegen_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-constant-time-codegen.XXXXXX")"
trap 'rm -rf "$codegen_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$codegen_dir" cargo "$toolchain" rustc \
    --manifest-path assurance/constant-time-codegen/Cargo.toml \
    --release \
    --target "$target" \
    --lib \
    -- \
    --emit=llvm-ir,asm

mapfile -t llvm_files < <(find "$codegen_dir" -type f -name 'brynja_constant_time_codegen_fixture-*.ll')
mapfile -t assembly_files < <(find "$codegen_dir" -type f -name 'brynja_constant_time_codegen_fixture-*.s')
[[ "${#llvm_files[@]}" -eq 1 ]] || {
    echo "expected one constant-time LLVM artifact" >&2
    exit 1
}
[[ "${#assembly_files[@]}" -eq 1 ]] || {
    echo "expected one constant-time assembly artifact" >&2
    exit 1
}

python3 scripts/constant_time_codegen.py "${llvm_files[0]}" "${assembly_files[0]}"
echo "constant-time evidence roots preserve fixed work in LLVM and $target assembly under ${toolchain#+}"
