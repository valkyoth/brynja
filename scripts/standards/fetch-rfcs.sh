#!/usr/bin/env bash
set -euo pipefail

test -s rfc/SOURCES
test -s rfc/SHA256SUMS
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
    expected_hash="$(
        sed -n "s/^\\([0-9a-f]\\{64\\}\\)  rfc${number}\\.txt$/\\1/p" \
            rfc/SHA256SUMS
    )"
    if [[ -z "$expected_hash" ]]; then
        echo "missing independently reviewed SHA-256 pin for RFC ${number}" >&2
        exit 1
    fi
    temporary="${destination}.tmp"
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 90 "$url" --output "$temporary"
    test -s "$temporary"
    actual_hash="$(sha256sum "$temporary" | awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo "RFC ${number} differs from its independently reviewed pin" >&2
        exit 1
    fi
    mv "$temporary" "$destination"
    trap - EXIT HUP INT TERM
done < rfc/SOURCES

scripts/standards/lock-rfcs.sh
echo "RFCs match the independently reviewed source pins."
