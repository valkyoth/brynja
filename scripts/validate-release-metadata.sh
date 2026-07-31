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
test -x scripts/test-release-crates.py
test -x scripts/test-release-readiness.sh
test -x scripts/check-github-release-controls.py
test -x scripts/test-github-release-controls.py
test -x scripts/validate-current-pentest.sh
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
python3 -c '
from pathlib import Path
workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
step = """      - name: Validate protected release controls
        env:
          GH_TOKEN: ${{ github.token }}
        run: scripts/check-github-release-controls.py --public
"""
if step not in workflow:
    raise SystemExit("live release-control step requires step-scoped GH_TOKEN")
'
test "$(git ls-files PENTEST.md)" = ""
