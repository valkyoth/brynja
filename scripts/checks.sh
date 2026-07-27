#!/usr/bin/env sh
set -eu

cargo fmt --all --check
scripts/check_shell_syntax.sh
scripts/check_doc_links.sh
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
