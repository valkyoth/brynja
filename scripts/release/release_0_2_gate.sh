#!/usr/bin/env sh
set -eu

scripts/checks.sh
scripts/release/release_crates.py --check
scripts/ci/check-rust-version-matrix.sh
scripts/ci/check_latest_tools.sh
scripts/release/check-github-release-controls.py
cargo deny check
cargo audit --deny warnings
scripts/release/generate-sbom.sh --check
scripts/release/validate-release-readiness.sh v0.2.0
