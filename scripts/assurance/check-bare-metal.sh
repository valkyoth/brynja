#!/usr/bin/env sh
set -eu

installed="$(rustup target list --installed)"
python3 scripts/assurance/check-assurance.py --targets |
while IFS= read -r target; do
    printf '%s\n' "$installed" | grep -Fxq "$target" || {
        echo "missing bare-metal Rust target: ${target}" >&2
        exit 1
    }
    cargo check --workspace --exclude brynja-crypto-cpu-std \
        --exclude brynja-hash-parallel-std --exclude brynja-legacy-sha1-std --all-features --target "$target"
    cargo check --manifest-path assurance/cpu-admission-fixture/Cargo.toml --target "$target"
    cargo check --locked --manifest-path assurance/sha256-public-api/Cargo.toml \
        --lib --target "$target"
    cargo check --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib --target "$target"
    cargo check --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib --target "$target"
    cargo check --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib --target "$target"
    cargo check --locked --manifest-path assurance/sha2-public-api/Cargo.toml \
        --lib --target "$target"
    cargo check --locked --manifest-path assurance/sha3-public-api/Cargo.toml \
        --lib --target "$target"
    cargo check --locked --manifest-path assurance/cshake-public-api/Cargo.toml \
        --lib --target "$target"
    cargo check --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml \
        --lib --target "$target"
    cargo check --locked --manifest-path assurance/sp800185-public-api/Cargo.toml \
        --lib --target "$target"
done
