#!/usr/bin/env bash
set -euo pipefail

test -s references/LOCAL_SOURCES
test -s references/LOCAL_SHA256SUMS
expected="$(sed -n 's/^[0-9a-f]\{64\}  \([^ ]*\.pdf\)$/\1/p' references/LOCAL_SHA256SUMS | sort)"
sources="$(
    awk '
        NF && $1 !~ /^#/ {
            if (NF != 3 ||
                $1 !~ /^[A-Za-z0-9._-]+\.pdf$/ ||
                $2 !~ /^https:\/\/(docs\.riscv\.org|nvlpubs\.nist\.gov|www\.itu\.int)\// ||
                $3 !~ /^[a-z0-9-]+$/) {
                exit 1
            }
            print $1
        }
    ' references/LOCAL_SOURCES | sort
)"
[[ -n "$expected" && "$expected" == "$sources" ]] || exit 1
if [[ "${VERIFY_LOCAL_REFERENCE_FILES:-0}" = "1" ]]; then
    (
        cd references/local
        sha256sum --check --strict ../LOCAL_SHA256SUMS
    )
fi
