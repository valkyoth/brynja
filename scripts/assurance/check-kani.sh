#!/usr/bin/env sh
set -eu

mode="${1:---run}"
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
test "$harnesses" = "18" || {
    echo "Kani policy: expected exactly eighteen admitted SHA-2/SHA-3 harnesses, found ${harnesses}" >&2
    exit 1
}

confined_harnesses="$(
    grep -R -l --include='*.rs' '#\[kani::proof\]' crates |
        sort
)"
expected_harness_files="$(printf '%s\n' \
    crates/brynja-hash-sha2/src/bit_input.rs \
    crates/brynja-hash-sha2/src/hardened/output.rs \
    crates/brynja-hash-sha2/src/lib.rs \
    crates/brynja-hash-sha3/src/bit_string.rs \
    crates/brynja-hash-sha3/src/hardened/sponge.rs \
    crates/brynja-hash-sha3/src/lib.rs \
    crates/brynja-hash-sha3/src/sponge.rs)"
test "$confined_harnesses" = "$expected_harness_files" || {
    echo "Kani policy: admitted harnesses escaped the SHA-2/SHA-3 leaf crates" >&2
    exit 1
}

if [ "$mode" = "--policy-only" ]; then
    echo "Kani policy: eighteen portable SHA-2/SHA-3 bounds are inventoried; full proofs are local tag-gate evidence"
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

rustup run "$kani_toolchain" cargo kani -p brynja-hash-sha2
rustup run "$kani_toolchain" cargo kani -p brynja-hash-sha3
echo "Kani proof: cargo-kani ${kani_version} with Rust ${kani_toolchain}; eighteen SHA-2/SHA-3 bounds passed"
