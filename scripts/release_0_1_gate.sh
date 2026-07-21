#!/usr/bin/env sh
set -eu

scripts/checks.sh
scripts/check-rust-version-matrix.sh
scripts/check_latest_tools.sh
cargo deny check
cargo audit --deny warnings
scripts/generate-sbom.sh --check
scripts/validate-release-readiness.sh v0.1.0

