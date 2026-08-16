#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "$1" >&2
    exit 1
}

version="${1:-}"
test "$#" -eq 1 || {
    echo "usage: scripts/release/validate-development-milestone.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || {
    echo "usage: scripts/release/validate-development-milestone.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}

scripts/release/release_crates.py --check

context="$(
    python3 -c \
        'import tomllib; r = tomllib.load(open("release-crates.toml", "rb"))["release"]; print("|".join((r["version"], r["milestone"], r["stage"], str(r.get("exceptional", False)).lower())))'
)"
IFS='|' read -r planned_version milestone stage exceptional <<EOF
${context}
EOF

test "$stage" = "internal" ||
    fail "development milestone readiness requires stage=internal"
test "$planned_version" = "${version#v}" ||
    fail "development milestone version must be ${version#v}"
test "$milestone" = "${version#v}" ||
    fail "development milestone tag must match release milestone"

status="$(git status --porcelain --untracked-files=all)"
test -z "$status" || fail "development milestone worktree must be clean"
git verify-commit HEAD >/dev/null 2>&1 ||
    fail "development milestone HEAD must be a signed commit"
if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
    fail "development milestone tag already exists: ${version}"
fi

report="security/pentest/${version}.md"
if test "$exceptional" = "true"; then
    scripts/release/validate-current-pentest.sh --required
    echo "${version} has the mandatory exceptional committed PASS pentest report"
elif test -e "$report"; then
    scripts/release/validate-current-pentest.sh --required
    echo "${version} has an exceptional committed PASS pentest report"
else
    echo "${version} is tag-ready after user-confirmed green GitHub and CodeQL; no scheduled pentest or crates.io publication applies"
fi
