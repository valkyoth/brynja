#!/usr/bin/env sh
set -eu

scripts/checks.sh
scripts/check-bare-metal.sh
scripts/update-standards-snapshots.py --check
scripts/release_crates.py --check
scripts/check-rust-version-matrix.sh
scripts/check_latest_tools.sh
scripts/check-github-release-controls.py
cargo deny check
cargo audit --deny warnings
scripts/generate-sbom.sh --check
scripts/validate-release-readiness.sh v0.10.0
