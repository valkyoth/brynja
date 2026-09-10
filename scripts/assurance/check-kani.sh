#!/usr/bin/env sh
set -eu

mode="${1:---run}"
selected_groups="all"
if test "$mode" = "--required-groups"; then
    shift
    test "$#" -gt 0 || { echo "--required-groups requires groups" >&2; exit 2; }
    for group in "$@"; do
        case "$group" in
            core|sanitization|md5|sha1|sha2|sha3|kmac|tuplehash|parallelhash|legacy|acceleration|static_cpu) ;;
            *) echo "unknown Kani group: $group" >&2; exit 2 ;;
        esac
    done
    selected_groups=" $* "
    set -- --required
    mode="--required"
fi
if [ "$#" -gt 1 ] || {
    [ "$mode" != "--policy-only" ] &&
        [ "$mode" != "--required" ] &&
        [ "$mode" != "--run" ]
}; then
    echo "usage: scripts/assurance/check-kani.sh [--policy-only|--required|--run]" >&2
    exit 2
fi

kani_toolchain="$(
    sed -n 's/^kani = "\([^"]*\)"$/\1/p' assurance/policy.toml |
        head -n 1
)"
kani_version="$(
    sed -n '/^id = "kani"$/,/^\[\[tools\]\]$/ {
        s/^version = "\([^"]*\)"$/\1/p
    }' assurance/policy.toml |
        head -n 1
)"

test -n "$kani_toolchain"
test -n "$kani_version"

harnesses="$(
    grep -R -h --include='*.rs' '#\[kani::proof\]' crates |
        wc -l |
        tr -d ' '
)"
test "$harnesses" = "29" || {
    echo "Kani policy: expected exactly twenty-nine admitted MD5/SHA-1/SHA-2/SHA-3/SP 800-185/KMAC/TupleHash/ParallelHash harnesses, found ${harnesses}" >&2
    exit 1
}

confined_harnesses="$(
    grep -R -l --include='*.rs' '#\[kani::proof\]' crates |
        sort
)"
expected_harness_files="$(printf '%s\n' \
    crates/brynja-hash-parallel/src/lib.rs \
    crates/brynja-hash-sha2/src/bit_input.rs \
    crates/brynja-hash-sha2/src/hardened/output.rs \
    crates/brynja-hash-sha2/src/lib.rs \
    crates/brynja-hash-sha3/src/bit_string.rs \
    crates/brynja-hash-sha3/src/hardened/sponge.rs \
    crates/brynja-hash-sha3/src/lib.rs \
    crates/brynja-hash-sha3/src/sp800185.rs \
    crates/brynja-hash-sha3/src/sponge.rs \
    crates/brynja-hash-tuple/src/lib.rs \
    crates/brynja-legacy-md5/src/batch/control.rs \
    crates/brynja-legacy-md5/src/engine.rs \
    crates/brynja-legacy-sha1/src/engine.rs \
    crates/brynja-mac-kmac/src/policy.rs)"
test "$confined_harnesses" = "$expected_harness_files" || {
    echo "Kani policy: admitted harnesses escaped the reviewed MD5/SHA-1/SHA-2/SHA-3/KMAC/TupleHash/ParallelHash leaf crates" >&2
    exit 1
}

if [ "$mode" = "--policy-only" ]; then
    echo "Kani policy: twenty-nine portable MD5/SHA-1/SHA-2/SHA-3/SP 800-185/KMAC/TupleHash/ParallelHash bounds are inventoried; full proofs are local tag-gate evidence"
    exit 0
fi

require_kani=0
if [ "$mode" = "--required" ]; then
    require_kani=1
fi

skip_or_fail() {
    if [ "$require_kani" = "1" ]; then
        echo "Kani proof: $1; verifier evidence is required by the local tag gate" >&2
        exit 1
    fi
    echo "Kani proof: SKIP; $1"
    exit 0
}

if ! rustup toolchain list | grep -Eq "^${kani_toolchain}($|-)"; then
    skip_or_fail "verifier Rust ${kani_toolchain} is not installed"
fi

installed="$(
    rustup run "$kani_toolchain" cargo kani --version 2>/dev/null || true
)"
if [ -z "$installed" ]; then
    skip_or_fail "cargo-kani ${kani_version} is not installed"
fi
test "$installed" = "cargo-kani ${kani_version}" || {
    echo "Kani proof: installed ${installed}, expected cargo-kani ${kani_version}" >&2
    exit 1
}

selected() {
    test "$selected_groups" = all && return 0
    case "$selected_groups" in *" $1 "*) return 0 ;; *) return 1 ;; esac
}
if selected md5; then
    rustup run "$kani_toolchain" cargo kani -p brynja-legacy-md5 --features batch
fi
if selected sha1; then
    rustup run "$kani_toolchain" cargo kani -p brynja-legacy-sha1
fi
if selected sha2; then
    rustup run "$kani_toolchain" cargo kani -p brynja-hash-sha2
fi
if selected sha3; then
    rustup run "$kani_toolchain" cargo kani -p brynja-hash-sha3
fi
if selected kmac; then
    rustup run "$kani_toolchain" cargo kani -p brynja-mac-kmac
fi
if selected tuplehash; then
    rustup run "$kani_toolchain" cargo kani -p brynja-hash-tuple
fi
if selected parallelhash; then
    rustup run "$kani_toolchain" cargo kani -p brynja-hash-parallel
fi
echo "Kani proof: cargo-kani ${kani_version} with Rust ${kani_toolchain}; selected groups passed: ${selected_groups} (29 harnesses inventoried globally)"
