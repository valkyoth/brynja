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

version="${1:-}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || {
    echo "usage: scripts/validate-release-readiness.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}

report="security/pentest/${version}.md"
publish_tag="${BRYNJA_RELEASE_PUBLISH_TAG:-}"

test -s "$report" || fail "missing pentest report: ${report}"
git cat-file -e "HEAD:${report}" 2>/dev/null ||
    fail "pentest report must be committed at HEAD: ${report}"
git diff --quiet HEAD -- "$report" ||
    fail "pentest report differs from the committed HEAD version: ${report}"

status="$(git status --porcelain --untracked-files=all)"
test -z "$status" || fail "release candidate worktree must be clean"

test "$(field_value Version)" = "$version" ||
    fail "pentest report version must be ${version}"
test "$(field_value Status)" = "PASS" ||
    fail "pentest report must record Status: PASS"
test "$(field_value Open-Findings)" = "0" ||
    fail "pentest report must record Open-Findings: 0"
test "$(field_value Retest)" = "PASS" ||
    fail "pentest report must record Retest: PASS"
date="$(field_value Date)"
[[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
    fail "pentest report requires Date: YYYY-MM-DD"
test -n "$(field_value Tester)" ||
    fail "pentest report requires a Tester"
test -n "$(field_value Scope)" ||
    fail "pentest report requires a Scope"

parent="$(git rev-parse -q --verify HEAD^ 2>/dev/null || true)"
if test -n "$parent" && git cat-file -e "${parent}:${report}" 2>/dev/null; then
    changed_paths="$(git diff --name-only "$parent" HEAD)"
    if printf '%s\n' "$changed_paths" | grep -Fvxq "$report"; then
        printf '%s\n' "$changed_paths" | grep -Fxq "$report" ||
            fail "repository changed after pentest without updating ${report}"
    fi
fi

if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
    test "$publish_tag" = "$version" ||
        fail "tag already exists: ${version}"
    tag_commit="$(git rev-list -n 1 "$version")"
    head_commit="$(git rev-parse HEAD)"
    test "$tag_commit" = "$head_commit" ||
        fail "publish tag ${version} does not point at HEAD"
elif test -n "$publish_tag"; then
    fail "publish tag context requires existing tag: ${version}"
fi

echo "${version} has a current committed PASS pentest report and is tag-ready"
