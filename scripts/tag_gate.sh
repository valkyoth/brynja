#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
test "$#" -eq 1 || {
    echo "usage: scripts/tag_gate.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}

scripts/checks.sh
scripts/assurance/check-bare-metal.sh
scripts/sha2/check-sha256-cpu-qemu.sh
scripts/standards/update-standards-snapshots.py --check
python3 scripts/standards/check-authority-lifecycle.py --release
authority_artifact_dir="$(
    mktemp -d "${TMPDIR:-/tmp}/brynja-authority.XXXXXX"
)"
authority_artifact="${authority_artifact_dir}/observation.json"
trap 'rm -f -- "$authority_artifact"; rmdir -- "$authority_artifact_dir"' EXIT
python3 scripts/standards/observe-authority-lifecycle.py \
    --artifact "$authority_artifact"
scripts/release/release_crates.py --check
scripts/ci/check-rust-version-matrix.sh
scripts/ci/check_latest_tools.sh
scripts/sanitization/check-sanitization-admission.py --online
scripts/sanitization/check-sanitization-candidate.sh --matrix
scripts/release/check-github-release-controls.py
cargo deny check
cargo audit --deny warnings
scripts/release/generate-sbom.sh --check

stage="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("release-crates.toml", "rb"))["release"]["stage"])'
)"
if test "$stage" = "internal"; then
    scripts/release/validate-development-milestone.sh "$version"
else
    scripts/release/validate-release-readiness.sh "$version"
fi

if test -z "${BRYNJA_RELEASE_PUBLISH_TAG:-}"; then
    echo "tag gate: required local Kani proofs"
    scripts/assurance/check-kani.sh --required
else
    echo "tag gate: using the Kani evidence already required before tag creation"
fi
