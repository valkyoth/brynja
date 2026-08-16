#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.97.1}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+$toolchain"
fi

output="$(mktemp -d "${TMPDIR:-/tmp}/brynja-sanitization-codegen.XXXXXX")"
trap 'rm -rf -- "$output"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$output" cargo "$toolchain" rustc \
    -p brynja-sanitization --release --test behavior --target "$target" -- \
    --emit=mir,llvm-ir,asm

mapfile -t mir < <(find "$output" -type f -name 'behavior-*.mir')
mapfile -t llvm < <(find "$output" -type f -name 'behavior-*.ll')
mapfile -t assembly < <(find "$output" -type f -name 'behavior-*.s')
[[ "${#mir[@]}" -eq 1 && "${#llvm[@]}" -eq 1 && "${#assembly[@]}" -eq 1 ]] || {
    echo "expected one adapter MIR, LLVM IR, and assembly artifact" >&2
    exit 1
}

grep -q 'SanitizedSecret::<32>::clear' "${mir[0]}"
grep -Eq 'store volatile i8 0,' "${llvm[0]}"
grep -q 'brynja_sanitization' "${assembly[0]}"
grep -q 'secure_clear' "${assembly[0]}"

echo "adapter explicit-clear path preserves volatile stores in MIR, LLVM IR, and $target assembly under ${toolchain#+}"
