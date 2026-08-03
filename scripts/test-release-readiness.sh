#!/usr/bin/env bash
set -euo pipefail

unset BRYNJA_RELEASE_PUBLISH_TAG

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/brynja-readiness.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM
source_script="$(pwd)/scripts/validate-release-readiness.sh"
source_current="$(pwd)/scripts/validate-current-pentest.sh"
signing_key="$fixture_root/signing-key"
allowed_signers="$fixture_root/allowed-signers"
ssh-keygen -q -t ed25519 -N "" -f "$signing_key"
printf 'release-test@example.invalid %s\n' "$(cat "${signing_key}.pub")" \
    >"$allowed_signers"

make_fixture() {
    local name="$1"
    local repository="$fixture_root/$name"
    mkdir -p "$repository/scripts" "$repository/security/pentest"
    cp "$source_script" "$repository/scripts/validate-release-readiness.sh"
    cp "$source_current" "$repository/scripts/validate-current-pentest.sh"
    (
        cd "$repository"
        git init -q
        git config user.email "release-test@example.invalid"
        git config user.name "Brynja Release Test"
        git config gpg.format ssh
        git config user.signingkey "$signing_key"
        git config gpg.ssh.allowedSignersFile "$allowed_signers"
        printf 'fixture\n' >README.md
        printf '[release]\nversion = "0.2.0"\n' >release-crates.toml
        git add README.md release-crates.toml scripts
        git commit -q -m "fixture"
    )
    printf '%s\n' "$repository"
}

write_report() {
    local result="${1:-PASS}"
    local open_findings="${2:-0}"
    local retest="${3:-$result}"
    cat >security/pentest/v0.2.0.md <<EOF
Version: v0.2.0
Status: ${result}
Open-Findings: ${open_findings}
Retest: ${retest}
Date: 2026-07-26
Tester: Brynja release fixture
Scope: Complete v0.2.0 release candidate.

## Findings

No findings.
EOF
}

commit_report() {
    git add security/pentest/v0.2.0.md
    git commit -q -m "docs: record v0.2.0 pentest"
}

sign_tag() {
    local message="${1:-brynja v0.2.0}"
    git tag -s v0.2.0 -m "$message"
}

assert_fails_with() {
    local expected="$1"
    shift
    if "$@" >"$fixture_root/stdout" 2>"$fixture_root/stderr"; then
        echo "expected command to fail: $*" >&2
        exit 1
    fi
    grep -Fq "$expected" "$fixture_root/stderr" || {
        echo "expected stderr to contain: $expected" >&2
        cat "$fixture_root/stderr" >&2
        exit 1
    }
}

repository="$(make_fixture missing-report)"
(
    cd "$repository"
    scripts/validate-current-pentest.sh
    assert_fails_with "missing required pentest report" \
        scripts/validate-current-pentest.sh --required
    assert_fails_with "usage: scripts/validate-current-pentest.sh" \
        scripts/validate-current-pentest.sh --required unexpected
    assert_fails_with "missing pentest report" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture internal-milestone-without-report)"
(
    cd "$repository"
    printf '[release]\nversion = "0.11.0"\nmilestone = "0.11.0"\nstage = "internal"\n' \
        >release-crates.toml
    git add release-crates.toml
    git commit -q -m "chore: enter internal milestone"
    scripts/validate-current-pentest.sh
    assert_fails_with "missing required pentest report" \
        scripts/validate-current-pentest.sh --required
)

repository="$(make_fixture uncommitted-report)"
(
    cd "$repository"
    write_report
    assert_fails_with "pentest report must be committed at HEAD" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture failed-report)"
(
    cd "$repository"
    write_report FAIL 1
    commit_report
    assert_fails_with "pentest report must record Status: PASS" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture open-finding)"
(
    cd "$repository"
    write_report PASS 1 PASS
    commit_report
    assert_fails_with "pentest report must record Open-Findings: 0" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture failed-retest)"
(
    cd "$repository"
    write_report PASS 0 FAIL
    commit_report
    assert_fails_with "pentest report must record Retest: PASS" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture pending-retest)"
(
    cd "$repository"
    write_report "RETEST REQUIRED" 0 PENDING
    commit_report
    scripts/validate-current-pentest.sh
    assert_fails_with "pentest report must record Status: PASS" \
        scripts/validate-current-pentest.sh --required
)

repository="$(make_fixture malformed-pending-retest)"
(
    cd "$repository"
    write_report "RETEST REQUIRED" 0 FAIL
    commit_report
    assert_fails_with "pending pentest report must record Retest: PENDING" \
        scripts/validate-current-pentest.sh
)

repository="$(make_fixture stale-pending-report)"
(
    cd "$repository"
    write_report "RETEST REQUIRED" 0 PENDING
    commit_report
    printf 'unreviewed remediation\n' >fix.txt
    git add fix.txt
    git commit -q -m "fix: omit pending report update"
    assert_fails_with "repository changed after pentest without updating" \
        scripts/validate-current-pentest.sh
)

repository="$(make_fixture initial-candidate)"
(
    cd "$repository"
    printf 'candidate\n' >implementation.txt
    write_report
    git add implementation.txt security/pentest/v0.2.0.md
    git commit -q -m "release: prepare v0.2.0 candidate"
    scripts/validate-current-pentest.sh
    scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture stale-report)"
(
    cd "$repository"
    write_report
    commit_report
    printf 'ci fix\n' >fix.txt
    git add fix.txt
    git commit -q -m "fix: address CI"
    assert_fails_with "repository changed after pentest without updating" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture updated-report)"
(
    cd "$repository"
    write_report
    commit_report
    printf 'ci fix\n' >fix.txt
    printf '\nCI fix reviewed and retested.\n' >>security/pentest/v0.2.0.md
    git add fix.txt security/pentest/v0.2.0.md
    git commit -q -m "fix: address CI and update pentest"
    scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture dirty-candidate)"
(
    cd "$repository"
    write_report
    commit_report
    printf 'dirty\n' >dirty.txt
    assert_fails_with "release candidate worktree must be clean" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture modified-report)"
(
    cd "$repository"
    write_report
    commit_report
    printf '\nUncommitted report edit.\n' >>security/pentest/v0.2.0.md
    assert_fails_with "pentest report differs from the committed HEAD version" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture symlink-report)"
(
    cd "$repository"
    mkdir -p security/pentest
    write_report
    mv security/pentest/v0.2.0.md report-target.md
    ln -s ../../report-target.md security/pentest/v0.2.0.md
    git add report-target.md security/pentest/v0.2.0.md
    git commit -q -m "docs: add symlinked report"
    assert_fails_with "must be a regular non-executable committed file" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture lightweight-tag)"
(
    cd "$repository"
    write_report
    commit_report
    git tag v0.2.0
    assert_fails_with "must be an annotated signed tag" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture unsigned-tag)"
(
    cd "$repository"
    write_report
    commit_report
    git tag -a v0.2.0 -m "brynja v0.2.0"
    assert_fails_with "signature verification failed" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture wrong-tag-subject)"
(
    cd "$repository"
    write_report
    commit_report
    sign_tag "release v0.2.0"
    assert_fails_with "subject must be: Brynja v0.2.0" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture branded-tag-subject)"
(
    cd "$repository"
    write_report
    commit_report
    sign_tag "Brynja v0.2.0"
    BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture tag-flow)"
(
    cd "$repository"
    write_report
    commit_report
    scripts/validate-release-readiness.sh v0.2.0
    sign_tag
    assert_fails_with "pre-tag release readiness requires absent tag" \
        scripts/validate-release-readiness.sh v0.2.0
    BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture cumulative-baseline)"
(
    cd "$repository"
    printf '[release]\nversion = "0.15.0"\nbaseline = "0.10.0"\nstage = "public"\n' \
        >release-crates.toml
    mkdir -p security/pentest
    cat >security/pentest/v0.15.0.md <<EOF
Version: v0.15.0
Baseline: v0.10.0
Status: PASS
Open-Findings: 0
Retest: PASS
Date: 2026-08-03
Tester: Brynja release fixture
Scope: Cumulative changes after v0.10.0 through the v0.15.0 candidate.

## Findings

No findings.
EOF
    git add release-crates.toml security/pentest/v0.15.0.md
    git commit -q -m "docs: record cumulative checkpoint"
    scripts/validate-release-readiness.sh v0.15.0
    sed -i 's/Baseline: v0.10.0/Baseline: v0.9.0/' \
        security/pentest/v0.15.0.md
    git add security/pentest/v0.15.0.md
    git commit -q -m "docs: break cumulative baseline"
    assert_fails_with "baseline must be v0.10.0" \
        scripts/validate-release-readiness.sh v0.15.0
)

repository="$(make_fixture mismatched-publish-context)"
(
    cd "$repository"
    write_report
    commit_report
    sign_tag
    assert_fails_with "publish tag context must match release version" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.1 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture missing-publish-tag)"
(
    cd "$repository"
    write_report
    commit_report
    assert_fails_with "publish tag context requires existing tag: v0.2.0" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture stale-tag)"
(
    cd "$repository"
    write_report
    commit_report
    sign_tag
    printf 'later\n' >later.txt
    printf '\nLater candidate retested.\n' >>security/pentest/v0.2.0.md
    git add later.txt security/pentest/v0.2.0.md
    git commit -q -m "fix: advance candidate and report"
    assert_fails_with "publish tag v0.2.0 does not point at HEAD" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

echo "release readiness enforces the committed-report fix, CI, and tag flow"
