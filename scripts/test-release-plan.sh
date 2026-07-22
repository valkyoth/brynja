#!/usr/bin/env bash
set -euo pipefail

release_tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-release-plan.XXXXXX")"
version_tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-version-plan.XXXXXX")"
trap 'rm -f "$release_tmp" "$version_tmp"' EXIT HUP INT TERM

cp docs/RELEASE_PLAN.md "$release_tmp"
cp docs/VERSION_PLAN.md "$version_tmp"
python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp"

sed -i '0,/Status: planned/{/Status: planned/d;}' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing Status field" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/Plan scope: Preserve/s//Plan scope: Alter/' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted scope drift" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.2\.0 - /s/- /- Altered /' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted title drift" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/Run pentest for this exact commit\./s//Run review./' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing pentest exit" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/- implement the Plan scope exactly/{/- implement the Plan scope exactly/d;}' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted too few deliverables" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$release_tmp"
sed -i '0,/### v0\.128\.0 /{/### v0\.128\.0 /d;}' "$release_tmp"
if python3 scripts/check-release-plan.py "$release_tmp" "$version_tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing version" >&2
    exit 1
fi
