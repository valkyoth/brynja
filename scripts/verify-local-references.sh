#!/usr/bin/env bash
set -euo pipefail

test -s references/LOCAL_SOURCES
test -s references/LOCAL_SHA256SUMS
expected="$(sed -n 's/^[0-9a-f]\{64\}  \([^ ]*\.pdf\)$/\1/p' references/LOCAL_SHA256SUMS | sort)"
sources="$(sed -n 's/^\([^ ]*\.pdf\) https:\/\/nvlpubs\.nist\.gov\/[^ ]* [a-z0-9-][a-z0-9-]*$/\1/p' references/LOCAL_SOURCES | sort)"
[[ -n "$expected" && "$expected" == "$sources" ]] || exit 1
if [[ "${VERIFY_LOCAL_REFERENCE_FILES:-0}" = "1" ]]; then
    (
        cd references/local
        sha256sum --check --strict ../LOCAL_SHA256SUMS
    )
fi

