#!/usr/bin/env sh
set -eu

version="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' rust-toolchain.toml | head -n 1)"
test -n "$version"
rustup toolchain install "$version" --profile minimal --component clippy --component rustfmt

