#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "$1" >&2
    exit 1
}

field_value() {
    local label="$1"
    local count
    count="$(grep -Ec "^${label}:" "$report" || true)"
    test "$count" -eq 1 ||
        fail "pentest report requires exactly one ${label} field"
    sed -n "s/^${label}: //p" "$report"
}

allow_pending=false
if test "${1:-}" = "--allow-pending"; then
    allow_pending=true
    shift
fi

version="${1:-}"
test "$#" -eq 1 || {
    echo "usage: scripts/validate-release-readiness.sh [--allow-pending] vX.Y.Z[-rc.N]" >&2
    exit 2
}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || {
    echo "usage: scripts/validate-release-readiness.sh [--allow-pending] vX.Y.Z[-rc.N]" >&2
    exit 2
}

report="security/pentest/${version}.md"
publish_tag="${BRYNJA_RELEASE_PUBLISH_TAG:-}"

test -s "$report" || fail "missing pentest report: ${report}"
git cat-file -e "HEAD:${report}" 2>/dev/null ||
    fail "pentest report must be committed at HEAD: ${report}"
test "$(git ls-tree HEAD -- "$report" | awk '{ print $1 " " $2 }')" = \
    "100644 blob" ||
    fail "pentest report must be a regular non-executable committed file"
git diff --quiet HEAD -- "$report" ||
    fail "pentest report differs from the committed HEAD version: ${report}"

status="$(git status --porcelain --untracked-files=all)"
test -z "$status" || fail "release candidate worktree must be clean"

test "$(field_value Version)" = "$version" ||
    fail "pentest report version must be ${version}"
status_value="$(field_value Status)"
retest_value="$(field_value Retest)"
pending=false
if test "$allow_pending" = true &&
    test "$status_value" = "RETEST REQUIRED"; then
    pending=true
    test "$retest_value" = "PENDING" ||
        fail "pending pentest report must record Retest: PENDING"
else
    test "$status_value" = "PASS" ||
        fail "pentest report must record Status: PASS"
    test "$retest_value" = "PASS" ||
        fail "pentest report must record Retest: PASS"
fi
test "$(field_value Open-Findings)" = "0" ||
    fail "pentest report must record Open-Findings: 0"
date="$(field_value Date)"
[[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
    fail "pentest report requires Date: YYYY-MM-DD"
test -n "$(field_value Tester)" ||
    fail "pentest report requires a Tester"
test -n "$(field_value Scope)" ||
    fail "pentest report requires a Scope"

parents="$(git rev-parse HEAD^@ 2>/dev/null || true)"
for parent in $parents; do
    if git cat-file -e "${parent}:${report}" 2>/dev/null; then
        changed_paths="$(git diff --name-only "$parent" HEAD)"
        if printf '%s\n' "$changed_paths" | grep -Fvxq "$report"; then
            printf '%s\n' "$changed_paths" | grep -Fxq "$report" ||
                fail "repository changed after pentest without updating ${report}"
        fi
    fi
done

if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
    test "$publish_tag" = "$version" ||
        fail "tag already exists: ${version}"
    test "$(git cat-file -t "refs/tags/${version}")" = "tag" ||
        fail "publish tag ${version} must be an annotated signed tag"
    git verify-tag "$version" >/dev/null 2>&1 ||
        fail "publish tag ${version} signature verification failed"
    tag_subject="$(
        git for-each-ref \
            --format='%(contents:subject)' \
            "refs/tags/${version}"
    )"
    test "$tag_subject" = "brynja ${version}" ||
        fail "publish tag ${version} subject must be: brynja ${version}"
    tag_target="$(
        git cat-file -p "refs/tags/${version}" |
            sed -n 's/^object //p' |
            head -n 1
    )"
    test "$(git cat-file -t "$tag_target")" = "commit" ||
        fail "publish tag ${version} must point directly to a commit"
    tag_commit="$(git rev-parse "refs/tags/${version}^{commit}")"
    head_commit="$(git rev-parse HEAD)"
    test "$tag_commit" = "$head_commit" ||
        fail "publish tag ${version} does not point at HEAD"
elif test -n "$publish_tag"; then
    fail "publish tag context requires existing tag: ${version}"
fi

if test "$pending" = true; then
    echo "${version} has a current committed pending-retest report; release remains blocked"
else
    echo "${version} has a current committed PASS pentest report and is tag-ready"
fi
