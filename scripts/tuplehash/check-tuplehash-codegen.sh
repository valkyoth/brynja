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

extract_function() {
    local pattern="$1"
    local artifact="$2"
    awk -v pattern="$pattern" '
        index($0, pattern) > 0 { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$artifact"
}

extract_llvm_function() {
    local pattern="$1"
    local artifact="$2"
    awk -v pattern="$pattern" '
        /^define / && index($0, pattern) > 0 && index($0, "%self") > 0 { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$artifact"
}

extract_llvm_any_function() {
    local pattern="$1"
    local artifact="$2"
    awk -v pattern="$pattern" '
        /^define / && index($0, pattern) > 0 { active = 1 }
        active { print }
        active && /^}/ { exit }
    ' "$artifact"
}

extract_assembly_function() {
    local pattern="$1"
    local artifact="$2"
    awk -v pattern="$pattern" '
        /^(_ZN|_RNvM|_RNvC)[^:]*:$/ && index($0, pattern) > 0 { active = 1 }
        active { print }
        active && /^[[:space:]]*\.size/ && index($0, pattern) > 0 { exit }
    ' "$artifact"
}

extract_call_block() {
    local pattern="$1"
    awk -v pattern="$pattern" '
        /^    bb[0-9]+.*: \{/ {
            if (active && found) { printf "%s", block; active = 0; found = 0; exit }
            active = 1; found = 0; block = $0 ORS; next
        }
        active { block = block $0 ORS; if (index($0, pattern) > 0) { found = 1 } }
        END { if (active && found) { printf "%s", block } }
    '
}

extract_named_block() {
    local label="$1"
    awk -v label="$label" '
        $0 ~ "^    " label ".*: \\{" { active = 1 }
        active && $0 ~ "^    bb[0-9]+.*: \\{" && index($0, label ":") == 0 { exit }
        active { print }
    '
}

require_fragment() {
    local body="$1"
    local fragment="$2"
    local label="$3"
    if [[ "$body" != *"$fragment"* ]]; then
        echo "TupleHash compiler evidence omitted $label: $fragment" >&2
        return 1
    fi
}

reject_secret_copy() {
    local body="$1"
    local label="$2"
    if grep -Eq 'alloca \[104[0-2] x i8\]|llvm\.memcpy[^\n]*i64 104[0-2]' <<<"$body"; then
        echo "TupleHash compiler evidence found a secret-owner copy in $label" >&2
        return 1
    fi
}

for raw_toolchain in "${toolchains[@]}"; do
    toolchain="$raw_toolchain"
    if [[ "$toolchain" != +* ]]; then
        toolchain="+$toolchain"
    fi
    toolchain_dir="$evidence_dir/${toolchain#+}"
    for package in brynja-hash-tuple brynja-hash-sha3; do
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
    for profile in development release; do
        profile_flag=()
        if [[ "$profile" == "release" ]]; then
            profile_flag=(--release)
        fi
        CARGO_TARGET_DIR="$toolchain_dir/package-external/$profile" cargo "$toolchain" rustc \
            --locked --manifest-path assurance/tuplehash-public-api/Cargo.toml \
            "${profile_flag[@]}" --target "$target" --lib -- --emit=llvm-ir,asm
    done

    mapfile -t tuple_mir < <(find "$toolchain_dir/brynja-hash-tuple" -type f -name 'brynja_hash_tuple-*.mir')
    mapfile -t sha3_mir < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.mir')
    mapfile -t tuple_llvm < <(find "$toolchain_dir/brynja-hash-tuple" -type f -name 'brynja_hash_tuple-*.ll')
    mapfile -t sha3_llvm < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.ll')
    mapfile -t tuple_asm < <(find "$toolchain_dir/brynja-hash-tuple" -type f -name 'brynja_hash_tuple-*.s')
    mapfile -t sha3_asm < <(find "$toolchain_dir/brynja-hash-sha3" -type f -name 'brynja_hash_sha3-*.s')
    mapfile -t external_llvm < <(find "$toolchain_dir/package-external" -type f -name 'brynja_tuplehash_public_api_fixture-*.ll')
    mapfile -t external_asm < <(find "$toolchain_dir/package-external" -type f -name 'brynja_tuplehash_public_api_fixture-*.s')
    [[ "${#tuple_mir[@]}" -eq 2 && "${#sha3_mir[@]}" -eq 2 ]]
    [[ "${#tuple_llvm[@]}" -eq 2 && "${#sha3_llvm[@]}" -eq 2 ]]
    [[ "${#tuple_asm[@]}" -eq 2 && "${#sha3_asm[@]}" -eq 2 ]]
    [[ "${#external_llvm[@]}" -eq 2 && "${#external_asm[@]}" -eq 2 ]]

    for mir in "${tuple_mir[@]}"; do
        for operation in squeeze_final_public squeeze_final_secret; do
            finalizer="$(extract_function ">::${operation}(_1: BackendReader" "$mir")"
            grep -Eq '= &mut .*as Strength128.*HardenedCshake128' <<<"$finalizer"
            grep -Eq '= &mut .*as Strength256.*HardenedCshake256' <<<"$finalizer"
            grep -q "${operation/squeeze_final_/squeeze_final_bits_}_in_place" <<<"$finalizer"
        done
        backend_final="$(extract_function '>::finalize_in_place(_1: &mut Backend' "$mir")"
        grep -q 'HardenedCshake128::enter_squeezing_in_place' <<<"$backend_final"
        grep -q 'HardenedCshake256::enter_squeezing_in_place' <<<"$backend_final"
        reader_drop="$(extract_function '>::drop(_1: &mut BackendReader<' "$mir")"
        grep -q 'Backend::wipe' <<<"$reader_drop"
        tuple_finish="$(extract_function '>::finish_in_place(_1: &mut TupleCore' "$mir")"
        grep -Fq '= &((*_1).1: [u8; 1]);' <<<"$tuple_finish"
        grep -q 'Fips202BitString::' <<<"$tuple_finish"
        grep -q 'Backend::finalize_in_place' <<<"$tuple_finish"
        tuple_cleanup="$(extract_function '>::wipe(_1: &mut TupleCore)' "$mir")"
        grep -Fq '= &mut ((*_1).3: [u8; 16]);' <<<"$tuple_cleanup"
        grep -q 'clear_owned_region' <<<"$tuple_cleanup"
        item_drop="$(extract_function '>::drop(_1: &mut TupleItemWriter' "$mir")"
        grep -q 'TupleCore::abandon_item' <<<"$item_drop"
        encoding_drop="$(extract_function '>::drop(_1: &mut SecretEncodedInteger)' "$mir")"
        grep -Fq '= &mut ((*_1).0: [u8; 17]);' <<<"$encoding_drop"
        grep -Fq '= &mut ((*_1).1: [u8; 1]);' <<<"$encoding_drop"
        test "$(grep -c 'clear_owned_region' <<<"$encoding_drop")" -eq 2
        grep -q 'checked_remaining_after' "$mir"
        grep -q 'complete_item' "$mir"
    done

    for mir in "${sha3_mir[@]}"; do
        for strength in 128 256; do
            transition="$(extract_function ">::enter_squeezing_in_place(_1: &mut HardenedCshake${strength}" "$mir")"
            grep -q 'CshakeLifecycle::Squeezing' <<<"$transition"
            grep -q "HardenedCshake${strength}::finish" <<<"$transition"
            finish="$(extract_function ">::finish(_1: &mut HardenedCshake${strength}" "$mir")"
            grep -q 'HardenedFips202Owner::<' <<<"$finish"
            for class in public secret; do
                in_place="$(extract_function ">::squeeze_final_bits_${class}_in_place(_1: &mut HardenedCshake${strength}" "$mir")"
                grep -q 'CshakeLifecycle::Vacated' <<<"$in_place"
                grep -q 'HardenedFips202Owner::<.*>::wipe' <<<"$in_place"
            done
            for class in public secret; do
                finalizer="$(extract_function ">::squeeze_final_bits_${class}_erasing_source(_1: &mut HardenedCshake${strength}Reader" "$mir")"
                operation='as FnOnce<()>>::call_once'
                if [[ "$class" == "public" ]]; then
                    operation='hardened::sponge::<impl'
                fi
                call_block="$(extract_call_block "$operation" <<<"$finalizer")"
                grep -q 'CshakeLifecycle::Vacated' <<<"$call_block"
                wipe_target="$(grep -F "$operation" <<<"$call_block" | sed -n 's/.*return: \(bb[0-9][0-9]*\).*/\1/p' | head -n 1)"
                [[ -n "$wipe_target" ]]
                wipe_block="$(extract_named_block "$wipe_target" <<<"$finalizer")"
                grep -q 'HardenedFips202Owner::<.*>::wipe' <<<"$wipe_block"
            done
            wipe="$(extract_function ">::wipe_in_place(_1: &mut HardenedCshake${strength}Reader" "$mir")"
            grep -q 'HardenedFips202Owner::<' <<<"$wipe"
            grep -q '::wipe(move' <<<"$wipe"
        done
    done

    for artifact in "${tuple_llvm[@]}" "${tuple_asm[@]}"; do
        grep -q 'BackendReader' "$artifact"
        grep -q 'SecretEncodedInteger' "$artifact"
        grep -q 'clear_owned_region' "$artifact"
    done
    for artifact in "${tuple_llvm[@]}"; do
        for boundary in Backend17finalize_in_place TupleCore15finish_in_place; do
            body="$(extract_llvm_function "$boundary" "$artifact")"
            require_fragment "$body" "define " "LLVM in-place boundary $boundary"
            reject_secret_copy "$body" "$boundary in $(basename "$artifact")"
        done
    done
    for artifact in "${tuple_asm[@]}"; do
        for boundary in Backend17finalize_in_place TupleCore15finish_in_place; do
            body="$(extract_assembly_function "$boundary" "$artifact")"
            require_fragment "$body" "$boundary" "assembly in-place boundary $boundary"
            if [[ "$body" == *"memcpy"* ]]; then
                echo "TupleHash assembly copied an owner in $boundary" >&2
                exit 1
            fi
        done
    done
    for artifact in "${external_llvm[@]}"; do
        for boundary in public_api_fixture8hardened public_api_fixture9streaming; do
            body="$(extract_llvm_any_function "$boundary" "$artifact")"
            require_fragment "$body" "finalize" "package-external finalization $boundary"
            reject_secret_copy "$body" "$boundary in $(basename "$artifact")"
        done
    done
    for artifact in "${external_asm[@]}"; do
        for boundary in public_api_fixture8hardened public_api_fixture9streaming; do
            body="$(extract_assembly_function "$boundary" "$artifact")"
            require_fragment "$body" "finalize" "package-external assembly $boundary"
            if grep -Eq 'memcpy.*104[0-2]' <<<"$body"; then
                echo "TupleHash package-external assembly copied a secret owner in $boundary" >&2
                exit 1
            fi
        done
    done
    for artifact in "${sha3_llvm[@]}"; do
        for strength in 128 256; do
            for class in public secret; do
                body="$(extract_llvm_function "HardenedCshake${strength}Reader40squeeze_final_bits_${class}_erasing_source" "$artifact")"
                require_fragment "$body" "squeeze_final_bits_${class}" \
                    "LLVM reader operation for $strength/$class"
                require_fragment "$body" "HardenedFips202Owner" \
                    "LLVM reader owner for $strength/$class"
                require_fragment "$body" "4wipe" \
                    "LLVM reader cleanup for $strength/$class"
            done
        done
    done
    for artifact in "${sha3_asm[@]}"; do
        for strength in 128 256; do
            for class in public secret; do
                body="$(extract_assembly_function "HardenedCshake${strength}Reader40squeeze_final_bits_${class}_erasing_source" "$artifact")"
                require_fragment "$body" "squeeze_final_bits_${class}" \
                    "assembly reader operation for $strength/$class"
                require_fragment "$body" "HardenedFips202Owner" \
                    "assembly reader owner for $strength/$class"
                require_fragment "$body" "4wipe" \
                    "assembly reader cleanup for $strength/$class"
            done
        done
    done
done

echo "TupleHash exact source and reader cleanup survives Rust ${toolchains[*]} development/release MIR, LLVM IR, and $target assembly"
