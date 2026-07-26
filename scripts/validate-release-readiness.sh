#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || {
    echo "usage: scripts/validate-release-readiness.sh vX.Y.Z[-rc.N]" >&2
    exit 2
}
report="security/pentest/${version}.md"
publish_tag="${BRYNJA_RELEASE_PUBLISH_TAG:-}"
test -s "$report"
grep -q '^Status: PASS$' "$report"
grep -Eq '^Reviewed-Commit: [0-9a-f]{40}$' "$report"
grep -Eq '^Date: [0-9]{4}-[0-9]{2}-[0-9]{2}$' "$report"
grep -Eq '^Tester: .+' "$report"
grep -Eq '^Scope: .+' "$report"
if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
    if [ "$publish_tag" != "$version" ]; then
        echo "tag already exists: ${version}" >&2
        exit 1
    fi
    tag_commit="$(git rev-list -n 1 "$version")"
    head_commit="$(git rev-parse HEAD)"
    if [ "$tag_commit" != "$head_commit" ]; then
        echo "publish tag ${version} does not point at HEAD" >&2
        exit 1
    fi
elif [ -n "$publish_tag" ]; then
    echo "publish tag context requires existing tag: ${version}" >&2
    exit 1
fi
