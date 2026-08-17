#!/usr/bin/env sh
set -eu

cargo fmt --all --check
python3 scripts/repository/check-script-layout.py
python3 scripts/repository/test-script-layout.py
python3 scripts/repository/check-tracked-build-artifacts.py
python3 scripts/repository/test-tracked-build-artifacts.py
scripts/repository/check_shell_syntax.sh
scripts/repository/test-shell-syntax.sh
python3 scripts/repository/check-unsafe-policy.py
python3 scripts/repository/test-unsafe-policy.py
python3 scripts/repository/check-first-party-rust-crypto.py
python3 scripts/repository/test-first-party-rust-crypto.py
python3 scripts/constant-time/check-constant-time.py
python3 scripts/constant-time/test-constant-time.py
scripts/constant-time/check-constant-time-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
python3 scripts/constant-time/test-constant-time-codegen.py
python3 scripts/constant-time/check-constant-time-evidence.py
python3 scripts/constant-time/test-constant-time-evidence.py
python3 scripts/foundations/check-provider-contract.py
python3 scripts/foundations/test-provider-contract.py
python3 scripts/foundations/check-entropy-contract.py
python3 scripts/foundations/test-entropy-contract.py
python3 scripts/foundations/check-clock-contract.py
python3 scripts/foundations/test-clock-contract.py
python3 scripts/foundations/check-pending-contract.py
python3 scripts/foundations/test-pending-contract.py
python3 scripts/foundations/check-fips-architecture.py
python3 scripts/foundations/test-fips-architecture.py
python3 scripts/foundations/check-security-outcome.py
python3 scripts/foundations/test-security-outcome.py
python3 scripts/foundations/check-security-event.py
python3 scripts/foundations/test-security-event.py
python3 scripts/protocols/check-record-framing.py
python3 scripts/protocols/test-record-framing.py
python3 scripts/pki/check-der-reader.py
python3 scripts/pki/test-der-reader.py
python3 scripts/pki/check-asn1-values.py
python3 scripts/pki/test-asn1-values.py
python3 scripts/sha2/check-sha256.py
python3 scripts/sha2/test-sha256.py
python3 scripts/sha2/check-sha256-public-api.py
python3 scripts/sha2/test-sha256-public-api.py
python3 scripts/sha2/check-sha2-public-api.py
python3 scripts/sha2/test-sha2-public-api.py
python3 scripts/sha3/check-sha3.py
python3 scripts/sha3/test-sha3.py
python3 scripts/sha3/check-sha3-differential.py
scripts/sha2/check-sha256-cpu-codegen.sh
python3 scripts/cpu/check-backend-contract.py
python3 scripts/cpu/test-backend-contract.py
python3 scripts/cpu/check-cpu-boundary.py
python3 scripts/cpu/test-cpu-boundary.py
python3 scripts/cpu/check-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence-runner.py
scripts/cpu/check-cpu-admission-fixture.sh
python3 scripts/zeroization/check-zeroization-evidence.py
python3 scripts/zeroization/test-zeroization-evidence.py
python3 scripts/sanitization/check-sanitization-admission.py
python3 scripts/sanitization/test-sanitization-admission.py
scripts/sanitization/check-sanitization-candidate.sh
scripts/zeroization/check-zeroization-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/sanitization/check-sanitization-adapter-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/repository/check_doc_links.sh
python3 scripts/repository/check-commit-classification.py
python3 scripts/repository/test-commit-classification.py
python3 scripts/repository/check-verification-status.py
python3 scripts/repository/test-verification-status.py
python3 scripts/release/check-release-plan.py
scripts/release/test-release-plan.sh
scripts/repository/validate-workspace.sh
python3 scripts/repository/test-workspace-metadata.py
python3 scripts/release/test-github-release-controls.py
scripts/release/validate-release-metadata.sh
scripts/release/release_crates.py --check
python3 scripts/release/test-release-crates.py
scripts/release/test-release-readiness.sh
scripts/repository/check-packages.sh
scripts/standards/verify-rfcs.sh
scripts/standards/verify-local-references.sh
python3 scripts/standards/check-standards-ledger.py
python3 scripts/standards/test-standards-ledger.py
python3 scripts/standards/check-protocol-surfaces.py
python3 scripts/standards/test-protocol-surfaces.py
python3 scripts/standards/test-surface-security.py
python3 scripts/standards/check-requirements.py
python3 scripts/standards/test-requirements.py
python3 scripts/standards/test-requirement-domains.py
python3 scripts/standards/test-requirement-transports.py
python3 scripts/standards/test-requirement-sections.py
python3 scripts/standards/test-requirement-lifecycles.py
python3 scripts/standards/test-requirement-history.py
python3 scripts/standards/test-requirement-residuals.py
python3 scripts/assurance/check-assurance.py
python3 scripts/assurance/test-assurance.py
scripts/assurance/check-kani.sh --policy-only
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
