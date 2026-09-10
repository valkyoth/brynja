#!/usr/bin/env bash
set -euo pipefail

stage="${1:-}"
test "$#" -eq 1 || { echo "usage: $0 public|internal" >&2; exit 2; }
actual="$(python3 -c 'import tomllib; print(tomllib.load(open("release-crates.toml", "rb"))["release"]["stage"])')"
test "$stage" = "$actual" || { echo "Miri stage differs from release plan" >&2; exit 2; }
exec python3 scripts/release/run-verification.py miri
