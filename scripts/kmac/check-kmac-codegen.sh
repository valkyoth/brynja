#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.98.0}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+${toolchain}"
fi

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-kmac-codegen.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

for profile in development release; do
    profile_flag=()
    if [[ "$profile" == "release" ]]; then
        profile_flag=(--release)
    fi
    CARGO_TARGET_DIR="$evidence_dir/$profile" cargo "$toolchain" rustc \
        --locked -p brynja-mac-kmac "${profile_flag[@]}" --target "$target" --lib -- \
        --emit=mir,llvm-ir,asm
done

mapfile -t mir_files < <(find "$evidence_dir" -type f -name 'brynja_mac_kmac-*.mir')
mapfile -t llvm_files < <(find "$evidence_dir" -type f -name 'brynja_mac_kmac-*.ll')
mapfile -t assembly_files < <(find "$evidence_dir" -type f -name 'brynja_mac_kmac-*.s')
[[ "${#mir_files[@]}" -eq 2 && "${#llvm_files[@]}" -eq 2 && "${#assembly_files[@]}" -eq 2 ]]

for mir in "${mir_files[@]}"; do
    grep -q 'fn core_state::<impl at .*core_state.rs.*>::drop(_1: &mut KmacCore' "$mir"
    grep -q 'fn core_state::<impl at .*core_state.rs.*>::wipe(_1: &mut KmacCore' "$mir"
    grep -q 'fn core_state::<impl at .*core_state.rs.*>::wipe(_1: &mut KmacMetadata)' "$mir"
    grep -q 'fn packer::<impl at .*packer.rs.*>::drop(_1: &mut SecretEncodedInteger' "$mir"
    grep -q 'fn packer::<impl at .*packer.rs.*>::drop(_1: &mut SecretPacker' "$mir"
    grep -q 'fn packer::<impl at .*packer.rs.*>::drop(_1: &mut SecretTail' "$mir"
    core_owner="$(awk '
        /^fn core_state::<impl at .*>::wipe\(_1: &mut KmacCore/ { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$mir")"
    metadata="$(awk '
        /^fn core_state::<impl at .*>::wipe\(_1: &mut KmacMetadata\)/ { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$mir")"
    packer="$(awk '
        /^fn packer::<impl at .*>::drop\(_1: &mut SecretPacker/ { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$mir")"
    encoded="$(awk '
        /^fn packer::<impl at .*>::drop\(_1: &mut SecretEncodedInteger/ { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$mir")"
    tail="$(awk '
        /^fn packer::<impl at .*>::drop\(_1: &mut SecretTail/ { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$mir")"
    grep -q 'core::mem::drop::<Option<S>>' <<<"$core_owner"
    [[ "$(grep -c 'clear_owned_region' <<<"$metadata")" -eq 2 ]]
    [[ "$(grep -c 'clear_owned_region' <<<"$packer")" -eq 3 ]]
    [[ "$(grep -c 'clear_owned_region' <<<"$encoded")" -eq 2 ]]
    [[ "$(grep -c 'clear_owned_region' <<<"$tail")" -eq 2 ]]
    grep -q 'fn packer::<impl at .*>::flush(_1: &mut SecretPacker' "$mir"
done

for artifact in "${llvm_files[@]}" "${assembly_files[@]}"; do
    grep -q 'KmacCore' "$artifact"
    grep -q 'SecretPacker' "$artifact"
done

echo "KMAC nested owner, encoded-key metadata, and arbitrary-bit staging cleanup survive development/release MIR, LLVM IR, and $target assembly under ${toolchain#+}"
