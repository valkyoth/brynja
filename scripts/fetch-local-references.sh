#!/usr/bin/env bash
set -euo pipefail

test -s references/LOCAL_SOURCES
mkdir -p references/local

while read -r filename url role; do
    [[ -n "${filename:-}" ]] || continue
    [[ "$filename" != \#* ]] || continue
    case "$url" in
        https://nvlpubs.nist.gov/*) ;;
        *)
            echo "unapproved local reference URL: $url" >&2
            exit 1
            ;;
    esac
    [[ -n "${role:-}" && "$filename" != */* ]] || exit 1
    destination="references/local/$filename"
    [[ -e "$destination" ]] && continue
    temporary="${destination}.tmp"
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 120 "$url" --output "$temporary"
    test -s "$temporary"
    mv "$temporary" "$destination"
done < references/LOCAL_SOURCES

echo "Local-only references fetched. Inspect them, then run scripts/lock-local-references.sh."

