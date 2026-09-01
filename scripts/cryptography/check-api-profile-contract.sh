#!/usr/bin/env sh
set -eu

manifest="assurance/api-profile-contract/Cargo.toml"
cargo test --locked --manifest-path "$manifest"
cargo check --locked --manifest-path "$manifest" --target thumbv7em-none-eabi
echo "sealed hardened capability and typed public/secret output contract: PASS"
