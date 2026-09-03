#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.98.0}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+${toolchain}"
fi

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-sha3-hardened.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

for profile in development release; do
    profile_flag=()
    if [[ "$profile" == "release" ]]; then
        profile_flag=(--release)
    fi
    CARGO_TARGET_DIR="$evidence_dir/$profile" cargo "$toolchain" rustc \
        --locked -p brynja-hash-sha3 "${profile_flag[@]}" --target "$target" --lib -- \
        --emit=mir,llvm-ir,asm
done

mapfile -t mir_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha3-*.mir')
mapfile -t llvm_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha3-*.ll')
mapfile -t assembly_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha3-*.s')
[[ "${#mir_files[@]}" -eq 2 && "${#llvm_files[@]}" -eq 2 && "${#assembly_files[@]}" -eq 2 ]]

for mir in "${mir_files[@]}"; do
    grep -q 'fn owner::<impl at .*owner.rs.*>::drop(_1: &mut HardenedFips202Owner' "$mir"
    grep -Eq 'HardenedFips202Owner::<RATE>::wipe\((move|copy) _1\)' "$mir"
    wipe_calls="$(awk '
        /^fn owner::<impl at .*owner.rs.*>::wipe\(/ { active = 1; next }
        active && /^fn / { exit }
        active && /clear_owned_region/ { count += 1 }
        END { print count + 0 }
    ' "$mir")"
    [[ "$wipe_calls" -eq 13 ]]
    temporary_sections="$(awk '
        /^fn read_word\(/ || /^fn write_word\(/ || /::squeeze_final_bits_secret\(/ { active = 1 }
        active { print }
        active && /^}/ { active = 0 }
    ' "$mir")"
    [[ -n "$temporary_sections" ]]
    if grep -Eq 'let (mut )?_[0-9]+: \[u8; (1|8)\]' <<<"$temporary_sections"; then
        echo "hardened FIPS 202 MIR contains a secret-derived byte-array temporary" >&2
        exit 1
    fi
done
for llvm in "${llvm_files[@]}"; do
    grep -q 'HardenedFips202Owner.*wipe' "$llvm"
    if grep -Eq '^  %(array|byte) = alloca \[(1|8) x i8\]' "$llvm"; then
        echo "hardened FIPS 202 LLVM contains a named secret-derived byte-array allocation" >&2
        exit 1
    fi
done
for assembly in "${assembly_files[@]}"; do
    grep -q 'HardenedFips202Owner.*wipe' "$assembly"
done

echo "hardened FIPS 202 cleanup and no-local-byte-array boundary survive development/release MIR, LLVM IR, and $target assembly under ${toolchain#+}"
