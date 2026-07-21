#!/usr/bin/env bash
set -euo pipefail

actual="$(find rfc -maxdepth 1 -type f -name 'rfc*.txt' -printf '%f\n' | sort)"
sources="$(sed -n 's/^\([0-9][0-9]*\) https:\/\/www\.rfc-editor\.org\/rfc\/rfc[0-9][0-9]*\.txt [a-z0-9-][a-z0-9-]*$/rfc\1.txt/p' rfc/SOURCES | sort)"

if [[ -z "$actual" || "$actual" != "$sources" ]]; then
    echo "RFC sources and local file set differ" >&2
    diff <(printf '%s\n' "$sources") <(printf '%s\n' "$actual") || true
    exit 1
fi

(
    cd rfc
    sha256sum rfc*.txt > SHA256SUMS
)
chmod a-w rfc/rfc*.txt rfc/SHA256SUMS
scripts/verify-rfcs.sh

