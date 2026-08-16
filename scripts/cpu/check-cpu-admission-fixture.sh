#!/usr/bin/env bash
set -euo pipefail

manifest="assurance/cpu-admission-fixture/Cargo.toml"
source_file="assurance/cpu-admission-fixture/src/lib.rs"

if grep -En '(^|[^[:alnum:]_])(unsafe|Atomic[A-Za-z0-9_]*|std::|alloc::)([^[:alnum:]_]|$)' "$source_file"; then
    echo "CPU admission fixture gained forbidden low-level, atomic, std, or alloc code" >&2
    exit 1
fi

cargo test --manifest-path "$manifest"
for target in thumbv7em-none-eabi riscv32imac-unknown-none-elf x86_64-unknown-none; do
    cargo check --manifest-path "$manifest" --target "$target"
done

echo "CPU admission scalar/mock fixtures pass on std, no_std, and no-atomics targets"
