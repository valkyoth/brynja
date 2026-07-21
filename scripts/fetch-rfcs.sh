#!/usr/bin/env bash
set -euo pipefail

test -s rfc/SOURCES
mkdir -p rfc

while read -r number url role; do
    [[ -n "${number:-}" ]] || continue
    [[ "$number" != \#* ]] || continue
    expected="https://www.rfc-editor.org/rfc/rfc${number}.txt"
    if [[ "$url" != "$expected" || -z "${role:-}" ]]; then
        echo "invalid RFC source entry for ${number}" >&2
        exit 1
    fi
    destination="rfc/rfc${number}.txt"
    if [[ -e "$destination" ]]; then
        continue
    fi
    temporary="${destination}.tmp"
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 90 "$url" --output "$temporary"
    test -s "$temporary"
    mv "$temporary" "$destination"
done < rfc/SOURCES

echo "RFCs fetched. Inspect provenance and bytes, then run scripts/lock-rfcs.sh."

