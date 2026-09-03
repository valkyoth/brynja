#!/usr/bin/env bash
set -euo pipefail

target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$#" -eq 0 ]]; then
    toolchains=(1.90.0 1.98.0)
else
    toolchains=("$1")
fi

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-kmac-codegen.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

extract_function() {
    local pattern="$1"
    local artifact="$2"
    awk -v pattern="$pattern" '
        index($0, pattern) > 0 { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$artifact"
}

for raw_toolchain in "${toolchains[@]}"; do
    toolchain="$raw_toolchain"
    if [[ "$toolchain" != +* ]]; then
        toolchain="+$toolchain"
    fi
    toolchain_dir="$evidence_dir/${toolchain#+}"
    for package in brynja-mac-kmac brynja-hash-sha3; do
        for profile in development release; do
            profile_flag=()
            if [[ "$profile" == "release" ]]; then
                profile_flag=(--release)
            fi
            CARGO_TARGET_DIR="$toolchain_dir/$package/$profile" cargo "$toolchain" rustc \
                --locked -p "$package" "${profile_flag[@]}" --target "$target" --lib -- \
                --emit=mir,llvm-ir,asm
        done
    done

    mapfile -t kmac_mir < <(find "$toolchain_dir/brynja-mac-kmac" -type f -name 'brynja_mac_kmac-*.mir')
    mapfile -t sha3_mir < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.mir')
    mapfile -t kmac_llvm < <(find "$toolchain_dir/brynja-mac-kmac" -type f -name 'brynja_mac_kmac-*.ll')
    mapfile -t sha3_llvm < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.ll')
    mapfile -t kmac_asm < <(find "$toolchain_dir/brynja-mac-kmac" -type f -name 'brynja_mac_kmac-*.s')
    mapfile -t sha3_asm < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.s')
    [[ "${#kmac_mir[@]}" -eq 2 && "${#sha3_mir[@]}" -eq 2 ]]
    [[ "${#kmac_llvm[@]}" -eq 2 && "${#sha3_llvm[@]}" -eq 2 ]]
    [[ "${#kmac_asm[@]}" -eq 2 && "${#sha3_asm[@]}" -eq 2 ]]

    for mir in "${kmac_mir[@]}"; do
        if grep -qE 'Option<S>|state\.take\(\)|take_state' "$mir"; then
            echo "KMAC MIR moved inline secret state under ${toolchain#+}" >&2
            exit 1
        fi
        fixed="$(extract_function '>::finish_fixed(' "$mir")"
        xof="$(extract_function '>::finish_xof(' "$mir")"
        cleanup="$(extract_function '>::wipe(_1: &mut KmacCore' "$mir")"
        grep -Fq '= &mut ((*_1).0: S);' <<<"$fixed"
        grep -q 'append_right_encode::<S>' <<<"$fixed"
        grep -Fq '= &mut ((*_1).0: S);' <<<"$xof"
        grep -q 'append_right_encode::<S>' <<<"$xof"
        grep -Fq '= &mut ((*_1).0: S);' <<<"$cleanup"
        grep -q '<S as CshakeState>::wipe_in_place' <<<"$cleanup"
        grep -q 'finalize_xof_erasing_source(_1: &mut HardenedCshake128)' "$mir"
        grep -q 'finalize_xof_erasing_source(_1: &mut HardenedCshake256)' "$mir"
        grep -q 'fn core_state::<impl at .*>::wipe(_1: &mut KmacMetadata)' "$mir"
        grep -q 'fn packer::<impl at .*>::drop(_1: &mut SecretEncodedInteger' "$mir"
        grep -q 'fn packer::<impl at .*>::drop(_1: &mut SecretPacker' "$mir"
        grep -q 'fn packer::<impl at .*>::drop(_1: &mut SecretTail' "$mir"
    done

    for mir in "${sha3_mir[@]}"; do
        transition128="$(extract_function ">::take_reader_erasing_source(_1: &mut HardenedCshake128" "$mir")"
        transition256="$(extract_function ">::take_reader_erasing_source(_1: &mut HardenedCshake256" "$mir")"
        for transition_and_rate in "168:$transition128" "136:$transition256"; do
            rate="${transition_and_rate%%:*}"
            transition="${transition_and_rate#*:}"
            grep -Fq "HardenedFips202Owner<${rate}>" <<<"$transition"
            grep -Fq "= &mut ((*_1).0: hardened::owner::HardenedFips202Owner<${rate}>);" <<<"$transition"
            grep -Fq "HardenedFips202Owner::<${rate}>::wipe(move" <<<"$transition"
        done
        if grep -q 'Option<HardenedFips202Owner' "$mir"; then
            echo "hardened cSHAKE transition introduced optional inline owner" >&2
            exit 1
        fi
    done

    for artifact in "${kmac_llvm[@]}" "${kmac_asm[@]}"; do
        grep -q 'KmacCore' "$artifact"
        grep -q 'SecretPacker' "$artifact"
    done
    for artifact in "${sha3_llvm[@]}" "${sha3_asm[@]}"; do
        grep -q 'take_reader_erasing_source' "$artifact"
        grep -q 'HardenedFips202Owner' "$artifact"
    done
done

echo "KMAC source-owned state transitions and cleanup survive Rust ${toolchains[*]} development/release MIR, LLVM IR, and $target assembly"
