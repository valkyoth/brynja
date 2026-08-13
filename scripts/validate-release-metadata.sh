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
test -x scripts/release_crates.py
test -x scripts/check-standards-ledger.py
test -x scripts/test-standards-ledger.py
test -x scripts/check-protocol-surfaces.py
test -x scripts/test-protocol-surfaces.py
test -x scripts/check-requirements.py
test -x scripts/test-requirements.py
test -x scripts/test-requirement-domains.py
test -x scripts/test-requirement-transports.py
test -x scripts/test-requirement-sections.py
test -x scripts/test-requirement-lifecycles.py
test -x scripts/test-requirement-history.py
test -f scripts/requirements_lib.py
test -f scripts/requirements_history.py
test -f scripts/requirements_mapping.py
test -f scripts/requirements_domain.py
test -f scripts/requirements_domain_coverage.py
test -f scripts/requirements_bundle.py
test -f scripts/requirements_bundle_coverage.py
test -f scripts/requirements_sections.py
test -f scripts/requirements_transport.py
test -f scripts/requirements_validation.py
test -f scripts/requirements_test_support.py
test -x scripts/update-standards-snapshots.py
test -x scripts/check-assurance.py
test -x scripts/test-assurance.py
test -x scripts/assurance_mutation.py
test -x scripts/assurance_differential.py
test -x scripts/assurance_io.py
test -x scripts/assurance_process.py
test -x scripts/assurance_process_tree.py
test -x scripts/check-bare-metal.sh
test -x scripts/check-kani.sh
test -x scripts/check-commit-classification.py
test -x scripts/test-commit-classification.py
test -x scripts/check-verification-status.py
test -x scripts/test-verification-status.py
test -f scripts/assurance_policy.py
test -f scripts/assurance_process.py
test -s assurance/policy.toml
test -s assurance/evidence.json
test -s assurance/README.md
test -s docs/KANI.md
test -f scripts/release_policy.py
test -f scripts/release_change_policy.py
test -x scripts/test-release-crates.py
test -x scripts/test-release-readiness.sh
test -x scripts/check-unsafe-policy.py
test -x scripts/test-unsafe-policy.py
test -f scripts/unsafe_policy.py
test -x scripts/check-first-party-rust-crypto.py
test -x scripts/test-first-party-rust-crypto.py
test -f scripts/first_party_rust_crypto.py
test -x scripts/check-constant-time.py
test -x scripts/test-constant-time.py
test -f scripts/constant_time_policy.py
test -x scripts/check-constant-time-codegen.sh
test -x scripts/constant_time_codegen.py
test -x scripts/test-constant-time-codegen.py
test -x scripts/check-constant-time-evidence.py
test -x scripts/test-constant-time-evidence.py
test -f scripts/constant_time_evidence.py
test -x scripts/check-provider-contract.py
test -x scripts/test-provider-contract.py
test -f scripts/provider_contract_policy.py
test -x scripts/check-entropy-contract.py
test -x scripts/test-entropy-contract.py
test -f scripts/entropy_contract_policy.py
test -x scripts/check-clock-contract.py
test -x scripts/test-clock-contract.py
test -f scripts/clock_contract_policy.py
test -x scripts/check-pending-contract.py
test -x scripts/test-pending-contract.py
test -f scripts/pending_contract_policy.py
test -x scripts/check-fips-architecture.py
test -x scripts/test-fips-architecture.py
test -f scripts/fips_architecture_policy.py
test -x scripts/check-security-outcome.py
test -x scripts/test-security-outcome.py
test -f scripts/security_outcome_policy.py
test -x scripts/check-security-event.py
test -x scripts/test-security-event.py
test -f scripts/security_event_policy.py
test -x scripts/check-cpu-boundary.py
test -x scripts/test-cpu-boundary.py
test -f scripts/cpu_boundary_policy.py
test -s security/cpu-acceleration-boundary.toml
test -s assurance/constant-time-matrix.toml
test -s assurance/constant-time-codegen/Cargo.toml
test -s assurance/constant-time-codegen/Cargo.lock
test -s assurance/constant-time-codegen/src/lib.rs
grep -q 'python3 scripts/check-constant-time.py' scripts/checks.sh
grep -q 'python3 scripts/test-constant-time.py' scripts/checks.sh
grep -q 'scripts/check-constant-time-codegen.sh 1.97.1 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'python3 scripts/test-constant-time-codegen.py' scripts/checks.sh
grep -q 'python3 scripts/check-constant-time-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/test-constant-time-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/check-provider-contract.py' scripts/checks.sh
grep -q 'python3 scripts/test-provider-contract.py' scripts/checks.sh
grep -q 'python3 scripts/check-entropy-contract.py' scripts/checks.sh
grep -q 'python3 scripts/test-entropy-contract.py' scripts/checks.sh
grep -q 'python3 scripts/check-clock-contract.py' scripts/checks.sh
grep -q 'python3 scripts/test-clock-contract.py' scripts/checks.sh
grep -q 'python3 scripts/check-pending-contract.py' scripts/checks.sh
grep -q 'python3 scripts/test-pending-contract.py' scripts/checks.sh
grep -q 'python3 scripts/check-fips-architecture.py' scripts/checks.sh
grep -q 'python3 scripts/test-fips-architecture.py' scripts/checks.sh
grep -q 'python3 scripts/check-security-outcome.py' scripts/checks.sh
grep -q 'python3 scripts/test-security-outcome.py' scripts/checks.sh
grep -q 'python3 scripts/check-security-event.py' scripts/checks.sh
grep -q 'python3 scripts/test-security-event.py' scripts/checks.sh
grep -q 'python3 scripts/check-cpu-boundary.py' scripts/checks.sh
grep -q 'python3 scripts/test-cpu-boundary.py' scripts/checks.sh
test -s docs/first-party-rust-cryptography.md
test -x scripts/check-zeroization-codegen.sh
test -x scripts/check-sanitization-adapter-codegen.sh
test -x scripts/check-zeroization-evidence.py
test -x scripts/test-zeroization-evidence.py
test -x scripts/check-zeroization-miri.sh
test -x scripts/check-zeroization-sanitizer.sh
test -f scripts/zeroization_evidence.py
test -s assurance/zeroization-matrix.toml
test -x scripts/check-sanitization-admission.py
test -x scripts/test-sanitization-admission.py
test -x scripts/check-sanitization-candidate.sh
test -f scripts/sanitization_admission.py
test -s security/dependency-admissions/sanitization-2.0.3.toml
test -s docs/sanitization-admission-review.md
test -s assurance/sanitization-admission/Cargo.toml
test -s assurance/sanitization-admission/Cargo.lock
test -s assurance/sanitization-admission/src/lib.rs
test -s assurance/sanitization-admission/tests/behavior.rs
test -x scripts/check_shell_syntax.sh
test -x scripts/test-shell-syntax.sh
test -x scripts/check-github-release-controls.py
test -x scripts/test-github-release-controls.py
test -x scripts/validate-current-pentest.sh
test -x scripts/validate-development-milestone.sh
test -x scripts/tag_gate.sh
test -x scripts/install-ci-tools.sh
test -s scripts/ci-tools.lock
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
cmp -s README.md crates/brynja/README.md
grep -q 'run: scripts/install-ci-tools.sh' .github/workflows/ci.yml
grep -q 'python3 scripts/check-assurance.py' scripts/checks.sh
grep -q 'scripts/check-kani.sh' scripts/checks.sh
grep -q 'python3 scripts/check-commit-classification.py' scripts/checks.sh
grep -q 'python3 scripts/test-commit-classification.py' scripts/checks.sh
grep -q 'python3 scripts/check-verification-status.py' scripts/checks.sh
grep -q 'python3 scripts/test-verification-status.py' scripts/checks.sh
grep -q 'scripts/test-shell-syntax.sh' scripts/checks.sh
grep -q 'python3 scripts/check-unsafe-policy.py' scripts/checks.sh
grep -q 'python3 scripts/test-unsafe-policy.py' scripts/checks.sh
grep -q 'python3 scripts/check-first-party-rust-crypto.py' scripts/checks.sh
grep -q 'python3 scripts/test-first-party-rust-crypto.py' scripts/checks.sh
grep -q 'python3 scripts/check-zeroization-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/test-zeroization-evidence.py' scripts/checks.sh
grep -q 'python3 scripts/check-sanitization-admission.py' scripts/checks.sh
grep -q 'python3 scripts/test-sanitization-admission.py' scripts/checks.sh
grep -q 'scripts/check-sanitization-candidate.sh' scripts/checks.sh
grep -q 'scripts/check-zeroization-codegen.sh 1.97.1 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'scripts/check-sanitization-adapter-codegen.sh 1.97.1 x86_64-unknown-linux-gnu' scripts/checks.sh
grep -q 'scripts/check-sanitization-admission.py --online' scripts/tag_gate.sh
grep -q 'scripts/check-sanitization-candidate.sh --matrix' scripts/tag_gate.sh
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
        run: scripts/check-github-release-controls.py --public
"""
if step not in workflow:
    raise SystemExit("live release-control step requires step-scoped GH_TOKEN")
'
test "$(git ls-files PENTEST.md)" = ""
