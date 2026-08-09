#!/usr/bin/env bash
set -euo pipefail

manifest="assurance/sanitization-admission/Cargo.toml"

cargo +1.97.1 fmt --manifest-path "$manifest" --check
cargo +1.97.1 test --manifest-path "$manifest" --locked
cargo +1.97.1 clippy --manifest-path "$manifest" --lib --locked -- -D warnings

if [[ "${1:-}" == "--matrix" ]]; then
    compilers=(1.90.0 1.91.0 1.92.0 1.93.0 1.94.0 1.95.0 1.96.0 1.96.1 1.97.0 1.97.1)
    targets=(
        x86_64-unknown-linux-gnu
        x86_64-pc-windows-msvc
        x86_64-unknown-freebsd
        x86_64-apple-darwin
        aarch64-linux-android
        aarch64-apple-ios
        thumbv7em-none-eabi
        riscv32imac-unknown-none-elf
        x86_64-unknown-none
        wasm32-unknown-unknown
    )
    for compiler in "${compilers[@]}"; do
        cargo "+$compiler" check --manifest-path "$manifest" --locked
    done
    for target in "${targets[@]}"; do
        cargo +1.97.1 check --manifest-path "$manifest" --locked --target "$target"
    done
    cargo deny --manifest-path "$manifest" check advisories bans licenses sources
    cargo audit --file assurance/sanitization-admission/Cargo.lock --deny warnings --no-fetch
fi
