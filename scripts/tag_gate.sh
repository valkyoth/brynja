#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if test "$#" -eq 3 && test "$2" = "--approve-full"; then
    export BRYNJA_FULL_VERIFICATION_APPROVAL="$3"
elif test "$#" -ne 1; then
    echo "usage: scripts/tag_gate.sh vX.Y.Z[-rc.N] [--approve-full plan-fingerprint]" >&2
    exit 2
fi

# No expensive work starts until scope is understood or explicitly approved.
python3 scripts/release/run-verification.py plan --check
verify() {
    python3 scripts/release/run-verification.py command -- "$@"
}

scripts/checks.sh
scripts/assurance/check-bare-metal.sh
verify scripts/sha2/check-sha256-cpu-qemu.sh
verify scripts/sha1/check-sha1-cpu-qemu.sh
verify scripts/md5/check-md5-cpu-qemu.sh
verify scripts/kmac/check-kmac-timing.sh
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
verify scripts/sanitization/check-sanitization-candidate.sh --matrix
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
    echo "tag gate: required local AddressSanitizer evidence"
    python3 scripts/release/run-verification.py asan
    echo "tag gate: required stage-aware local Miri evidence"
    scripts/zeroization/check-tag-miri.sh "$stage"
    echo "tag gate: required local Kani proofs"
    python3 scripts/release/run-verification.py kani
else
    echo "tag gate: using the sanitizer, Miri, and Kani evidence already required before tag creation"
fi
