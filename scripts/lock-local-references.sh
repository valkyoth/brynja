#!/usr/bin/env bash
set -euo pipefail

actual="$(find references/local -maxdepth 1 -type f -name '*.pdf' -printf '%f\n' | sort)"
sources="$(sed -n 's/^\([^ ]*\.pdf\) https:\/\/nvlpubs\.nist\.gov\/[^ ]* [a-z0-9-][a-z0-9-]*$/\1/p' references/LOCAL_SOURCES | sort)"
[[ -n "$actual" && "$actual" == "$sources" ]] || {
    echo "local source manifest and downloaded set differ" >&2
    diff <(printf '%s\n' "$sources") <(printf '%s\n' "$actual") || true
    exit 1
}
# This script deliberately never computes or replaces the trust pins. New
# hashes must be obtained through an independent review channel and entered
# manually before fetch-local-references.sh can admit the bytes.
scripts/verify-local-references.sh
echo "Local-only reference bytes match the independently reviewed pins."
