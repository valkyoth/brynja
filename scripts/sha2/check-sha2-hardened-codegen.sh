#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-1.98.0}"
target="${2:-x86_64-unknown-linux-gnu}"
if [[ "$toolchain" != +* ]]; then
    toolchain="+${toolchain}"
fi

evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-sha2-hardened.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$evidence_dir" cargo "$toolchain" rustc \
    --locked -p brynja-hash-sha2 --release --target "$target" --lib -- \
    --emit=mir,llvm-ir,asm

mapfile -t mir_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha2-*.mir')
mapfile -t llvm_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha2-*.ll')
mapfile -t assembly_files < <(find "$evidence_dir" -type f -name 'brynja_hash_sha2-*.s')
[[ "${#mir_files[@]}" -eq 1 && "${#llvm_files[@]}" -eq 1 && "${#assembly_files[@]}" -eq 1 ]]

grep -q 'fn owner::<impl at .*owner.rs.*>::drop(_1: &mut HardenedSha2Owner)' "${mir_files[0]}"
grep -q 'HardenedSha2Owner::wipe(move _1)' "${mir_files[0]}"
wipe_calls="$(awk '
    /^fn owner::<impl at .*owner.rs.*>::wipe\(/ { active = 1; next }
    active && /^fn / { exit }
    active && /clear_owned_region/ { count += 1 }
    END { print count + 0 }
' "${mir_files[0]}")"
[[ "$wipe_calls" -eq 8 ]]
grep -q 'HardenedSha2Owner.*wipe' "${llvm_files[0]}"
grep -q 'HardenedSha2Owner.*drop' "${assembly_files[0]}"

echo "hardened SHA-2 owner cleanup survives MIR, LLVM IR, and $target assembly under ${toolchain#+}"
