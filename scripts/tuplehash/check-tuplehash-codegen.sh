#!/usr/bin/env bash
set -euo pipefail

target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$#" -eq 0 ]]; then
    toolchains=(1.90.0 1.98.1)
else
    toolchains=("$1")
fi

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-tuplehash-codegen.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

for raw_toolchain in "${toolchains[@]}"; do
    toolchain="$raw_toolchain"
    if [[ "$toolchain" != +* ]]; then
        toolchain="+$toolchain"
    fi
    toolchain_dir="$evidence_dir/${toolchain#+}"
    for profile in development release; do
        profile_flag=()
        if [[ "$profile" == "release" ]]; then
            profile_flag=(--release)
        fi
        CARGO_TARGET_DIR="$toolchain_dir/$profile" cargo "$toolchain" rustc \
            --locked -p brynja-hash-tuple "${profile_flag[@]}" --target "$target" --lib -- \
            --emit=mir,llvm-ir,asm
    done
    mapfile -t mir < <(find "$toolchain_dir" -type f -name 'brynja_hash_tuple-*.mir')
    mapfile -t llvm < <(find "$toolchain_dir" -type f -name 'brynja_hash_tuple-*.ll')
    mapfile -t assembly < <(find "$toolchain_dir" -type f -name 'brynja_hash_tuple-*.s')
    [[ "${#mir[@]}" -eq 2 && "${#llvm[@]}" -eq 2 && "${#assembly[@]}" -eq 2 ]]
    for artifact in "${mir[@]}"; do
        grep -q 'TupleCore' "$artifact"
        grep -q 'fn core_state::<impl at .*>::wipe(_1: &mut TupleCore)' "$artifact"
        grep -q 'Backend::wipe' "$artifact"
        test "$(grep -c 'clear_owned_region' "$artifact")" -ge 6
        grep -q 'fn item::<impl at .*>::drop(_1: &mut TupleItemWriter' "$artifact"
        grep -q 'abandon_item' "$artifact"
        grep -q 'finalize_xof_erasing_source' "$artifact"
    done
    for artifact in "${llvm[@]}" "${assembly[@]}"; do
        grep -q 'TupleCore' "$artifact"
        grep -q 'clear_owned_region' "$artifact"
    done
done

echo "TupleHash source-owned state transitions and cleanup survive Rust ${toolchains[*]} development/release MIR, LLVM IR, and $target assembly"
