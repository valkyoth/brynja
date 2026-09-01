#!/usr/bin/env sh
set -eu

version="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("release-crates.toml", "rb"))["release"]["version"])'
)"
facade_version="$(
    python3 -c \
        'import tomllib; print(tomllib.load(open("crates/brynja/Cargo.toml", "rb"))["package"]["version"])'
)"
release_notes="release-notes/RELEASE_NOTES_${version}.md"

test "$facade_version" = "$version"
test -s "$release_notes"
test -s docs/RELEASE_PLAN.md
test -s docs/VERSION_PLAN.md
test -s docs/CRATE_VERSION_MATRIX.md
test -s package-policy.toml
test -s github-release-controls.toml
test -s standards/README.md
test -s standards/source-policy.toml
test -s standards/source-ledger.json
test -s standards/ERRATA.json
test -s standards/SHA256SUMS
test -s standards/snapshots/rfc-index.json
test -s standards/authority-lifecycle-policy.toml
test -s standards/authority-lifecycle.json
test -s standards/authority-reviews.json
test -s standards/authority-freshness.json
test -s standards/snapshots/authority-landings.json
test -s .github/workflows/standards-lifecycle.yml
test -s scripts/README.md
test -s scripts/inventory.toml
test -s security/cryptographic-api-profile-policy.toml
test -s security/cryptographic-api-profile-register.json
test -s docs/cryptographic-api-profile-register.md
test -s assurance/api-profile-contract/Cargo.toml
test -s assurance/api-profile-contract/Cargo.lock
test -s assurance/api-profile-contract/src/lib.rs
test -x scripts/cryptography/check-api-profiles.py
test -x scripts/cryptography/test-api-profiles.py
test -x scripts/cryptography/check-api-profile-contract.sh
test -f scripts/cryptography/api_profile_contracts.py
test -f scripts/cryptography/api_profile_model.py
test -f scripts/cryptography/rust_source_contract.py
test -x scripts/repository/check-script-layout.py
test -x scripts/repository/test-script-layout.py
test -x scripts/sha3/check-sha3.py
test -x scripts/sha3/test-sha3.py
test -x scripts/sha3/check-sha3-differential.py
test -f scripts/sha3/sha3_policy.py
test -f scripts/sha3/sha3_reviewed_hashes.py
test -s assurance/sha3-differential/Cargo.toml
test -s assurance/sha3-differential/Cargo.lock
test -s assurance/sha3-differential/src/main.rs
test -x scripts/release/release_crates.py
test -x scripts/standards/check-standards-ledger.py
test -x scripts/standards/test-standards-ledger.py
test -x scripts/standards/check-protocol-surfaces.py
test -x scripts/standards/test-protocol-surfaces.py
test -x scripts/standards/check-requirements.py
test -x scripts/standards/test-requirements.py
test -x scripts/standards/test-requirement-domains.py
test -x scripts/standards/test-requirement-transports.py
test -x scripts/standards/test-requirement-sections.py
test -x scripts/standards/test-requirement-lifecycles.py
test -x scripts/standards/test-requirement-history.py
test -f scripts/standards/requirements_lib.py
test -f scripts/standards/requirements_history.py
test -f scripts/standards/requirements_mapping.py
test -f scripts/standards/requirements_domain.py
test -f scripts/standards/requirements_domain_coverage.py
test -f scripts/standards/requirements_bundle.py
test -f scripts/standards/requirements_bundle_coverage.py
test -f scripts/standards/requirements_sections.py
test -f scripts/standards/requirements_transport.py
test -f scripts/standards/requirements_validation.py
test -f scripts/standards/requirements_test_support.py
test -x scripts/standards/update-standards-snapshots.py
test -x scripts/standards/check-authority-lifecycle.py
test -x scripts/standards/observe-authority-lifecycle.py
test -x scripts/standards/capture-authority-landings.py
test -x scripts/standards/test-authority-lifecycle.py
test -f scripts/standards/lifecycle_model.py
test -f scripts/standards/lifecycle_network.py
test -f scripts/standards/lifecycle_reviews.py
test -x scripts/assurance/check-assurance.py
test -x scripts/assurance/test-assurance.py
test -x scripts/assurance/assurance_mutation.py
test -x scripts/assurance/assurance_differential.py
test -x scripts/assurance/assurance_io.py
test -x scripts/assurance/assurance_process.py
test -x scripts/assurance/assurance_process_tree.py
test -x scripts/assurance/check-bare-metal.sh
test -x scripts/assurance/check-kani.sh
test -x scripts/repository/check-commit-classification.py
test -x scripts/repository/test-commit-classification.py
test -x scripts/repository/check-verification-status.py
test -x scripts/repository/test-verification-status.py
test -f scripts/assurance/assurance_policy.py
test -f scripts/assurance/assurance_process.py
test -s assurance/policy.toml
test -s assurance/evidence.json
test -s assurance/README.md
test -s docs/KANI.md
test -f scripts/release/release_policy.py
test -f scripts/release/release_change_policy.py
test -x scripts/release/test-release-crates.py
test -x scripts/release/test-release-readiness.sh
test -x scripts/repository/check-unsafe-policy.py
test -x scripts/repository/test-unsafe-policy.py
test -f scripts/repository/unsafe_policy.py
test -x scripts/repository/check-first-party-rust-crypto.py
test -x scripts/repository/test-first-party-rust-crypto.py
test -f scripts/repository/first_party_rust_crypto.py
test -x scripts/constant-time/check-constant-time.py
test -x scripts/constant-time/test-constant-time.py
test -f scripts/constant-time/constant_time_policy.py
test -x scripts/constant-time/check-constant-time-codegen.sh
test -x scripts/constant-time/constant_time_codegen.py
test -x scripts/constant-time/test-constant-time-codegen.py
test -x scripts/constant-time/check-constant-time-evidence.py
test -x scripts/constant-time/test-constant-time-evidence.py
test -f scripts/constant-time/constant_time_evidence.py
test -x scripts/foundations/check-provider-contract.py
test -x scripts/foundations/test-provider-contract.py
test -f scripts/foundations/provider_contract_policy.py
test -x scripts/foundations/check-entropy-contract.py
test -x scripts/foundations/test-entropy-contract.py
test -f scripts/foundations/entropy_contract_policy.py
test -x scripts/foundations/check-clock-contract.py
test -x scripts/foundations/test-clock-contract.py
test -f scripts/foundations/clock_contract_policy.py
test -x scripts/foundations/check-pending-contract.py
test -x scripts/foundations/test-pending-contract.py
test -f scripts/foundations/pending_contract_policy.py
test -x scripts/foundations/check-fips-architecture.py
test -x scripts/foundations/test-fips-architecture.py
test -f scripts/foundations/fips_architecture_policy.py
test -x scripts/foundations/check-security-outcome.py
test -x scripts/foundations/test-security-outcome.py
test -f scripts/foundations/security_outcome_policy.py
test -x scripts/foundations/check-security-event.py
test -x scripts/foundations/test-security-event.py
test -f scripts/foundations/security_event_policy.py
test -x scripts/protocols/check-record-framing.py
test -x scripts/protocols/test-record-framing.py
test -f scripts/protocols/record_framing_policy.py
test -x scripts/pki/check-der-reader.py
test -x scripts/pki/test-der-reader.py
test -f scripts/pki/der_reader_policy.py
test -x scripts/pki/check-asn1-values.py
test -x scripts/pki/test-asn1-values.py
test -f scripts/pki/asn1_value_policy.py
test -x scripts/cpu/check-cpu-boundary.py
test -x scripts/cpu/test-cpu-boundary.py
test -f scripts/cpu/cpu_boundary_policy.py
test -s security/cpu-acceleration-boundary.toml
test -s assurance/constant-time-matrix.toml
test -s assurance/constant-time-codegen/Cargo.toml
test -s assurance/constant-time-codegen/Cargo.lock
test -s assurance/constant-time-codegen/src/lib.rs
grep -q 'python3 scripts/constant-time/check-constant-time.py' scripts/checks.sh
grep -q 'python3 scripts/constant-time/test-constant-time.py' scripts/checks.sh
grep -q 'scripts/constant-time/check-constant-time-codegen.sh 1.98.0 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'python3 scripts/constant-time/test-constant-time-codegen.py' scripts/checks.sh
grep -q 'python3 scripts/constant-time/check-constant-time-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/constant-time/test-constant-time-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/cryptography/check-api-profiles.py' scripts/checks.sh
grep -q 'python3 scripts/cryptography/test-api-profiles.py' scripts/checks.sh
grep -q 'scripts/cryptography/check-api-profile-contract.sh' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-provider-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-provider-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-entropy-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-entropy-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-clock-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-clock-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-pending-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-pending-contract.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-fips-architecture.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-fips-architecture.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-security-outcome.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-security-outcome.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/check-security-event.py' scripts/checks.sh
grep -q 'python3 scripts/foundations/test-security-event.py' scripts/checks.sh
grep -q 'python3 scripts/protocols/check-record-framing.py' scripts/checks.sh
grep -q 'python3 scripts/protocols/test-record-framing.py' scripts/checks.sh
grep -q 'python3 scripts/pki/check-asn1-values.py' scripts/checks.sh
grep -q 'python3 scripts/pki/test-asn1-values.py' scripts/checks.sh
grep -q 'python3 scripts/cpu/check-cpu-boundary.py' scripts/checks.sh
grep -q 'python3 scripts/cpu/test-cpu-boundary.py' scripts/checks.sh
test -s docs/first-party-rust-cryptography.md
test -x scripts/zeroization/check-zeroization-codegen.sh
test -x scripts/sanitization/check-sanitization-adapter-codegen.sh
test -x scripts/zeroization/check-zeroization-evidence.py
test -x scripts/zeroization/test-zeroization-evidence.py
test -x scripts/zeroization/check-zeroization-miri.sh
test -x scripts/zeroization/check-zeroization-sanitizer.sh
test -f scripts/zeroization/zeroization_evidence.py
test -s assurance/zeroization-matrix.toml
test -x scripts/sanitization/check-sanitization-admission.py
test -x scripts/sanitization/test-sanitization-admission.py
test -x scripts/sanitization/check-sanitization-candidate.sh
test -f scripts/sanitization/sanitization_admission.py
test -s security/dependency-admissions/sanitization-2.0.3.toml
test -s docs/sanitization-admission-review.md
test -s assurance/sanitization-admission/Cargo.toml
test -s assurance/sanitization-admission/Cargo.lock
test -s assurance/sanitization-admission/src/lib.rs
test -s assurance/sanitization-admission/tests/behavior.rs
test -x scripts/repository/check_shell_syntax.sh
test -x scripts/repository/test-shell-syntax.sh
test -x scripts/release/check-github-release-controls.py
test -x scripts/release/test-github-release-controls.py
test -x scripts/release/validate-current-pentest.sh
test -x scripts/release/validate-development-milestone.sh
test -x scripts/tag_gate.sh
test -x scripts/ci/install-ci-tools.sh
test -s scripts/ci/ci-tools.lock
test -f security/pentest/README.md
test -s docs/evidence-index.md
test -s standards/surface-policy.json
test -s standards/protocol-surfaces.json
test -s standards/protocol-surface-coverage.md
test -s requirements/README.md
test -s requirements/policy.json
test -s requirements/domain-scope.toml
test -s requirements/domain-sections.toml
test -s requirements/domains/cryptography.toml
test -s requirements/domains/encoding.toml
test -s requirements/domains/pkix.toml
test -s requirements/domains/ocsp.toml
test -s requirements/domains/ct.toml
test -s requirements/schema.json
test -s requirements/matrix.json
test -s requirements/indexes.json
test -s requirements/coverage.md
test -s requirements/domain-coverage.json
test -s requirements/transport-scope.toml
test -s requirements/transport-sections.toml
test -s requirements/transport-exceptions.toml
test -s requirements/transport-coverage.json
test -s standards/transport-surfaces/tls.toml
test -s standards/transport-surfaces/tls12.toml
test -s standards/transport-surfaces/quic.toml
test -s standards/transport-surfaces/dtls.toml
test -f release-crates.toml
if cmp -s README.md crates/brynja/README.md; then
    echo "GitHub and crates.io READMEs must remain purpose-specific" >&2
    exit 1
fi
grep -q 'run: scripts/ci/install-ci-tools.sh' .github/workflows/ci.yml
grep -q 'python3 scripts/assurance/check-assurance.py' scripts/checks.sh
grep -q 'python3 scripts/sha3/check-sha3.py' scripts/checks.sh
grep -q 'python3 scripts/sha3/test-sha3.py' scripts/checks.sh
grep -q 'python3 scripts/sha3/check-sha3-differential.py' scripts/checks.sh
grep -q 'python3 scripts/repository/check-script-layout.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-script-layout.py' scripts/checks.sh
grep -q 'python3 scripts/repository/check-tracked-build-artifacts.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-tracked-build-artifacts.py' scripts/checks.sh
grep -q 'scripts/assurance/check-kani.sh --policy-only' scripts/checks.sh
grep -q 'python3 scripts/repository/check-commit-classification.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-commit-classification.py' scripts/checks.sh
grep -q 'python3 scripts/repository/check-verification-status.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-verification-status.py' scripts/checks.sh
grep -q 'scripts/repository/test-shell-syntax.sh' scripts/checks.sh
grep -q 'python3 scripts/repository/check-unsafe-policy.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-unsafe-policy.py' scripts/checks.sh
grep -q 'python3 scripts/repository/check-first-party-rust-crypto.py' scripts/checks.sh
grep -q 'python3 scripts/repository/test-first-party-rust-crypto.py' scripts/checks.sh
grep -q 'python3 scripts/zeroization/check-zeroization-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/zeroization/test-zeroization-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/sanitization/check-sanitization-admission.py' scripts/checks.sh
grep -q 'python3 scripts/sanitization/test-sanitization-admission.py' scripts/checks.sh
grep -q 'scripts/sanitization/check-sanitization-candidate.sh' scripts/checks.sh
grep -q 'scripts/zeroization/check-zeroization-codegen.sh 1.98.0 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'scripts/sanitization/check-sanitization-adapter-codegen.sh 1.98.0 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'scripts/sanitization/check-sanitization-admission.py --online' scripts/tag_gate.sh
grep -q 'scripts/sanitization/check-sanitization-candidate.sh --matrix' scripts/tag_gate.sh
grep -q 'python3 scripts/standards/check-authority-lifecycle.py --release' scripts/tag_gate.sh
grep -q 'python3 scripts/standards/observe-authority-lifecycle.py' scripts/tag_gate.sh
grep -q 'mktemp -d "${TMPDIR:-/tmp}/brynja-authority.XXXXXX"' scripts/tag_gate.sh
if grep -q 'brynja-authority-lifecycle-observation.json' scripts/tag_gate.sh; then
    echo "tag gate must not use a predictable lifecycle artifact" >&2
    exit 1
fi
grep -q 'python3 scripts/standards/check-authority-lifecycle.py' scripts/checks.sh
grep -q 'python3 scripts/standards/test-authority-lifecycle.py' scripts/checks.sh
grep -q 'python3 scripts/standards/observe-authority-lifecycle.py' .github/workflows/standards-lifecycle.yml
if grep -q -- '--write-freshness' .github/workflows/standards-lifecycle.yml; then
    echo "scheduled lifecycle workflow must not write repository freshness state" >&2
    exit 1
fi
grep -q 'scripts/assurance/check-kani.sh --required' scripts/tag_gate.sh
if grep -q 'run: scripts/release/validate-current-pentest.sh' .github/workflows/ci.yml; then
    echo "ordinary CI must not enforce pentest freshness; tag and release gates own it" >&2
    exit 1
fi
grep -q 'run: scripts/release/validate-current-pentest.sh --required' .github/workflows/release.yml
python3 -c '
from pathlib import Path
workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
checkout = """      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
"""
if checkout not in workflow:
    raise SystemExit("repository gate requires complete history and release tags")
step = """      - name: Validate protected release controls
        env:
          GH_TOKEN: ${{ github.token }}
        run: scripts/release/check-github-release-controls.py --public
"""
if step not in workflow:
    raise SystemExit("live release-control step requires step-scoped GH_TOKEN")
'
test "$(git ls-files PENTEST.md)" = ""
