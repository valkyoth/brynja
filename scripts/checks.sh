#!/usr/bin/env sh
set -eu

cargo fmt --all --check
scripts/check_shell_syntax.sh
scripts/test-shell-syntax.sh
scripts/check_doc_links.sh
python3 scripts/check-commit-classification.py
python3 scripts/test-commit-classification.py
python3 scripts/check-verification-status.py
python3 scripts/test-verification-status.py
python3 scripts/check-release-plan.py
scripts/test-release-plan.sh
scripts/validate-workspace.sh
python3 scripts/test-workspace-metadata.py
python3 scripts/test-github-release-controls.py
scripts/validate-release-metadata.sh
scripts/release_crates.py --check
python3 scripts/test-release-crates.py
scripts/test-release-readiness.sh
scripts/check-packages.sh
scripts/verify-rfcs.sh
scripts/verify-local-references.sh
python3 scripts/check-standards-ledger.py
python3 scripts/test-standards-ledger.py
python3 scripts/check-protocol-surfaces.py
python3 scripts/test-protocol-surfaces.py
python3 scripts/test-surface-security.py
python3 scripts/check-requirements.py
python3 scripts/test-requirements.py
python3 scripts/test-requirement-domains.py
python3 scripts/test-requirement-transports.py
python3 scripts/test-requirement-sections.py
python3 scripts/test-requirement-lifecycles.py
python3 scripts/test-requirement-history.py
python3 scripts/test-requirement-residuals.py
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-kani.sh
if ! cmp -s README.md crates/brynja/README.md; then
    echo "README.md and crates/brynja/README.md must remain identical" >&2
    diff -u README.md crates/brynja/README.md >&2 || true
    exit 1
fi
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
