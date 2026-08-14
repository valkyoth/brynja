#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
test "$#" -eq 1 || {
    echo "usage: scripts/tag_gate.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}

scripts/checks.sh
scripts/check-bare-metal.sh
scripts/check-sha256-cpu-qemu.sh
scripts/update-standards-snapshots.py --check
scripts/release_crates.py --check
scripts/check-rust-version-matrix.sh
scripts/check_latest_tools.sh
scripts/check-sanitization-admission.py --online
scripts/check-sanitization-candidate.sh --matrix
scripts/check-github-release-controls.py
cargo deny check
cargo audit --deny warnings
scripts/generate-sbom.sh --check

stage="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("release-crates.toml", "rb"))["release"]["stage"])'
)"
if test "$stage" = "internal"; then
    scripts/validate-development-milestone.sh "$version"
else
    scripts/validate-release-readiness.sh "$version"
fi

if test -z "${BRYNJA_RELEASE_PUBLISH_TAG:-}"; then
    echo "tag gate: required local Kani proofs"
    scripts/check-kani.sh --required
else
    echo "tag gate: using the Kani evidence already required before tag creation"
fi
