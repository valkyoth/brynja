#!/usr/bin/env sh
set -eu

unset BRYNJA_RELEASE_PUBLISH_TAG

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/brynja-readiness.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM
source_script="$(pwd)/scripts/validate-release-readiness.sh"

make_fixture() {
    name="$1"
    repository="$fixture_root/$name"
    mkdir -p "$repository/scripts" "$repository/security/pentest"
    cp "$source_script" "$repository/scripts/validate-release-readiness.sh"
    (
        cd "$repository"
        git init -q
        git config user.email "release-test@example.invalid"
        git config user.name "Brynja Release Test"
        printf 'fixture\n' >README.md
        git add README.md
        git commit -q -m "fixture"
    )
    printf '%s\n' "$repository"
}

write_report() {
    reviewed_commit="$1"
    cat >security/pentest/v0.2.0.md <<EOF
Status: PASS
Reviewed-Commit: ${reviewed_commit}
Date: 2026-07-26
Tester: Brynja release fixture
Scope: Release tag state.
EOF
}

assert_fails_with() {
    expected="$1"
    shift
    if "$@" >"$fixture_root/stdout" 2>"$fixture_root/stderr"; then
        echo "expected command to fail: $*" >&2
        exit 1
    fi
    grep -q "$expected" "$fixture_root/stderr" || {
        echo "expected stderr to contain: $expected" >&2
        cat "$fixture_root/stderr" >&2
        exit 1
    }
}

repository="$(make_fixture pre-tag)"
(
    cd "$repository"
    reviewed="$(git rev-parse HEAD)"
    write_report "$reviewed"
    scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture existing-tag)"
(
    cd "$repository"
    reviewed="$(git rev-parse HEAD)"
    write_report "$reviewed"
    git tag v0.2.0
    assert_fails_with "tag already exists: v0.2.0" \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture post-tag)"
(
    cd "$repository"
    reviewed="$(git rev-parse HEAD)"
    write_report "$reviewed"
    git add security/pentest/v0.2.0.md
    git commit -q -m "release report"
    git tag v0.2.0
    BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture missing-tag)"
(
    cd "$repository"
    reviewed="$(git rev-parse HEAD)"
    write_report "$reviewed"
    assert_fails_with "publish tag context requires existing tag: v0.2.0" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

repository="$(make_fixture stale-tag)"
(
    cd "$repository"
    reviewed="$(git rev-parse HEAD)"
    write_report "$reviewed"
    git tag v0.2.0
    printf 'later\n' >later.txt
    git add later.txt
    git commit -q -m "later"
    assert_fails_with "publish tag v0.2.0 does not point at HEAD" \
        env BRYNJA_RELEASE_PUBLISH_TAG=v0.2.0 \
        scripts/validate-release-readiness.sh v0.2.0
)

echo "release readiness rejects missing, existing, and stale tag contexts"
