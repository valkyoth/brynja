#!/usr/bin/env bash
set -euo pipefail

miri_cache="$(mktemp -d "${TMPDIR:-/tmp}/brynja-miri.XXXXXX")"
trap 'rm -rf -- "$miri_cache"' EXIT HUP INT TERM

run_miri() {
    CARGO_HOME="$miri_cache/cargo" \
        CARGO_TARGET_DIR="$miri_cache/target" \
        XDG_CACHE_HOME="$miri_cache" \
        cargo +nightly-2026-09-04 miri test "$@" \
        --target x86_64-unknown-linux-gnu
}

quick_core() {
    run_miri --manifest-path crates/brynja-core/Cargo.toml \
        --test secret_memory direct_clear_covers_every_byte_and_small_length
}

full_core() {
    run_miri -p brynja-core --test secret_memory
}

quick_sanitization() {
    run_miri --manifest-path assurance/sanitization-admission/Cargo.toml \
        --test behavior explicit_clear_covers_the_complete_fixed_storage
}

full_sanitization() {
    run_miri -p brynja-sanitization --test behavior
}

quick_sha2() {
    run_miri --manifest-path crates/brynja-hash-sha2/Cargo.toml \
        --test sha256 downstream_style_real_content_uses_only_public_api
}

full_sha2() {
    run_miri -p brynja-hash-sha2 --test sha224 \
        official_short_and_long_vectors_match_fips_and_nist_cavp
    run_miri -p brynja-hash-sha2 --test sha224 \
        every_padding_boundary_matches_independent_expected_results
    run_miri -p brynja-hash-sha2 --test bit_inputs \
        selected_official_nist_bit_vectors_match_every_identity
    run_miri -p brynja-hash-sha2 --test hardened
    run_miri -p brynja-hash-sha2 --test sha256 \
        downstream_style_real_content_uses_only_public_api
    run_miri -p brynja-hash-sha2 --test sha256 \
        padding_boundaries_have_exact_digests
    run_miri -p brynja-hash-sha2 --test sha384 \
        every_padding_boundary_matches_independent_expected_results
    run_miri -p brynja-hash-sha2 --test sha512 \
        every_padding_boundary_matches_independent_expected_results
    run_miri -p brynja-hash-sha2 --test sha512_224 \
        every_padding_boundary_matches_independent_expected_results
    run_miri -p brynja-hash-sha2 --test sha512_256 \
        every_padding_boundary_matches_independent_expected_results
}

quick_sha3() {
    run_miri --manifest-path crates/brynja-hash-sha3/Cargo.toml \
        --test sha3_256 official_fips202_zero_and_1600_bit_vectors_match
}

full_sha3() {
    run_miri -p brynja-hash-sha3 --lib \
        final_bit_output_clears_the_exact_reader_source
    run_miri -p brynja-hash-sha3 --lib \
        borrowing_reader_never_extracts_the_absorbing_owner
    for sha3_test in sha3_384 sha3_512; do
        run_miri -p brynja-hash-sha3 --test "$sha3_test" \
            suffix_and_rate_boundaries_have_exact_digests
    done
    for shake_test in shake128 shake256; do
        run_miri -p brynja-hash-sha3 --test "$shake_test" \
            suffix_and_rate_boundaries_have_exact_output
    done
    run_miri -p brynja-hash-sha3 --test bit_inputs \
        curated_nist_cavp_vectors_cover_every_function_and_bit_residue
    run_miri -p brynja-hash-sha3 --test hardened
    run_miri -p brynja-hash-sha3 --test cshake \
        every_official_nist_cshake_example_matches
}

quick_kmac() {
    run_miri --manifest-path crates/brynja-mac-kmac/Cargo.toml \
        --test api domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix
}

full_kmac() {
    run_miri -p brynja-mac-kmac --tests
}

quick_tuplehash() {
    run_miri --manifest-path crates/brynja-hash-tuple/Cargo.toml \
        --test api tuple_boundaries_order_and_empty_items_are_distinct
}

full_tuplehash() {
    run_miri -p brynja-hash-tuple --test api \
        forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch
    run_miri -p brynja-hash-tuple --tests
}

quick_parallelhash() {
    run_miri --manifest-path crates/brynja-hash-parallel/Cargo.toml \
        --test api hardened_output_and_workspace_clear_on_drop
}

full_parallelhash() {
    run_miri -p brynja-hash-parallel --tests
}

all_groups=(core sanitization sha2 sha3 kmac tuplehash parallelhash)
mode="${1:---full}"
shift || true

case "$mode" in
    --full)
        test "$#" -eq 0 || {
            echo "--full accepts no group names" >&2
            exit 2
        }
        selected=" ${all_groups[*]} "
        ;;
    --focused)
        selected=" $* "
        ;;
    --group)
        test "$#" -eq 1 || {
            echo "--group requires exactly one group name" >&2
            exit 2
        }
        selected=" $1 "
        ;;
    *)
        echo "usage: $0 --full | --focused [groups...] | --group group" >&2
        exit 2
        ;;
esac

for group in "$@"; do
    case " ${all_groups[*]} " in
        *" $group "*) ;;
        *)
            echo "unknown Miri group: $group" >&2
            exit 2
            ;;
    esac
done

for group in "${all_groups[@]}"; do
    if [[ "$selected" == *" $group "* ]]; then
        echo "Miri group $group: full"
        "full_${group}"
    elif test "$mode" = "--focused"; then
        echo "Miri group $group: smoke"
        "quick_${group}"
    fi
done
