#!/usr/bin/env bash
set -euo pipefail

toolchains=(1.90.0 1.91.0 1.92.0 1.93.0 1.94.0 1.95.0 1.96.0 1.96.1 1.97.0 1.97.1 1.98.0 1.98.1)
for toolchain in "${toolchains[@]}"; do
    if ! rustup toolchain list | grep -Eq "^${toolchain}(-|$)"; then
        rustup toolchain install "$toolchain" --profile minimal
    fi
    cargo "+$toolchain" check --workspace --all-features
    cargo "+$toolchain" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml
    cargo "+$toolchain" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib
    cargo "+$toolchain" test --locked -p brynja-legacy-sha1
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/sha256-public-api/Cargo.toml
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/sha2-public-api/Cargo.toml
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/sha3-public-api/Cargo.toml
    cargo "+$toolchain" test --quiet --locked \
        --manifest-path assurance/cshake-public-api/Cargo.toml
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/hash-final-acceptance/Cargo.toml
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/sp800185-public-api/Cargo.toml
    cargo "+$toolchain" run --quiet --locked \
        --manifest-path assurance/sp800185-final/Cargo.toml
done
