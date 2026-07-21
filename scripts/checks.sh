#!/usr/bin/env sh
set -eu

cargo fmt --all --check
scripts/check_shell_syntax.sh
scripts/check_doc_links.sh
python3 scripts/check-release-plan.py
scripts/test-release-plan.sh
scripts/validate-workspace.sh
scripts/validate-release-metadata.sh
python3 scripts/validate-release-crates.py
scripts/check-packages.sh
scripts/verify-rfcs.sh
scripts/verify-local-references.sh
if ! cmp -s README.md crates/brynja/README.md; then
    echo "README.md and crates/brynja/README.md must remain identical" >&2
    diff -u README.md crates/brynja/README.md >&2 || true
    exit 1
fi
cargo check --workspace --all-features
cargo check --workspace --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
