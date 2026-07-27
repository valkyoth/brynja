#!/usr/bin/env bash
set -euo pipefail

test -s references/LOCAL_SOURCES
test -s references/LOCAL_SHA256SUMS
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
    expected_hash="$(
        sed -n "s/^\\([0-9a-f]\\{64\\}\\)  ${filename//./\\.}$/\\1/p" \
            references/LOCAL_SHA256SUMS
    )"
    if [[ -z "$expected_hash" ]]; then
        echo "missing independently reviewed SHA-256 pin for $filename" >&2
        exit 1
    fi
    temporary="${destination}.tmp"
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 120 "$url" --output "$temporary"
    test -s "$temporary"
    actual_hash="$(sha256sum "$temporary" | awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo "$filename differs from its independently reviewed pin" >&2
        exit 1
    fi
    mv "$temporary" "$destination"
    trap - EXIT HUP INT TERM
done < references/LOCAL_SOURCES

scripts/lock-local-references.sh
echo "Local-only references match the independently reviewed source pins."
