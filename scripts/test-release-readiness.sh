#!/usr/bin/env bash
set -euo pipefail

unset BRYNJA_RELEASE_PUBLISH_TAG

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/brynja-readiness.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM
source_script="$(pwd)/scripts/validate-release-readiness.sh"
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
    (
        cd "$repository"
        git init -q
        git config user.email "release-test@example.invalid"
        git config user.name "Brynja Release Test"
        git config gpg.format ssh
        git config user.signingkey "$signing_key"
        git config gpg.ssh.allowedSignersFile "$allowed_signers"
        printf 'fixture\n' >README.md
        git add README.md scripts/validate-release-readiness.sh
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
    assert_fails_with "missing pentest report" \
        scripts/validate-release-readiness.sh v0.2.0
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

repository="$(make_fixture initial-candidate)"
(
    cd "$repository"
    printf 'candidate\n' >implementation.txt
    write_report
    git add implementation.txt security/pentest/v0.2.0.md
    git commit -q -m "release: prepare v0.2.0 candidate"
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
    assert_fails_with "subject must be: brynja v0.2.0" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture tag-flow)"
(
    cd "$repository"
    write_report
    commit_report
    sign_tag
    assert_fails_with "tag already exists: v0.2.0" \
        scripts/validate-release-readiness.sh v0.2.0
    BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
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
