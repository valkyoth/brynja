#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-release-plan.XXXXXX")"
trap 'rm -f "$tmp"' EXIT HUP INT TERM

cp docs/RELEASE_PLAN.md "$tmp"
python3 scripts/check-release-plan.py "$tmp"

sed -i '0,/Status: planned/{/Status: planned/d;}' "$tmp"
if python3 scripts/check-release-plan.py "$tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing Status field" >&2
    exit 1
fi

cp docs/RELEASE_PLAN.md "$tmp"
sed -i '0,/Run pentest for this exact commit\./s//Run review./' "$tmp"
if python3 scripts/check-release-plan.py "$tmp" >/dev/null 2>&1; then
    echo "release plan validator accepted a missing pentest exit" >&2
    exit 1
fi

