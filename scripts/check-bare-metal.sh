#!/usr/bin/env sh
set -eu

installed="$(rustup target list --installed)"
python3 scripts/check-assurance.py --targets |
while IFS= read -r target; do
    printf '%s\n' "$installed" | grep -Fxq "$target" || {
        echo "missing bare-metal Rust target: ${target}" >&2
        exit 1
    }
    cargo check --workspace --all-features --target "$target"
    cargo check --manifest-path assurance/cpu-admission-fixture/Cargo.toml --target "$target"
done
