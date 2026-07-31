#!/usr/bin/env sh
set -eu

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

if ! rustup toolchain list | grep -Eq "^${kani_toolchain}($|-)"; then
    echo "Kani policy: SKIP; verifier Rust ${kani_toolchain} is not installed"
    exit 0
fi

installed="$(
    rustup run "$kani_toolchain" cargo kani --version 2>/dev/null || true
)"
if [ -z "$installed" ]; then
    echo "Kani policy: SKIP; cargo-kani ${kani_version} is not installed"
    exit 0
fi
test "$installed" = "cargo-kani ${kani_version}" || {
    echo "Kani policy: installed ${installed}, expected cargo-kani ${kani_version}" >&2
    exit 1
}

if grep -R -q --include='*.rs' '#\\[kani::proof\\]' crates; then
    echo "Kani policy: proof harness exists before its numbered admission" >&2
    exit 1
fi

echo "Kani policy: cargo-kani ${kani_version} with ${kani_toolchain}; no proof harness admitted"
