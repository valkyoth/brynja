#!/usr/bin/env bash
set -euo pipefail

while IFS= read -r manifest; do
    package="$(sed -n 's/^name = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1)"
    [[ -n "$package" ]] || exit 1
    listing="$(cargo package -p "$package" --allow-dirty --no-verify --list)"
    for required in Cargo.toml LICENSE-APACHE LICENSE-MIT README.md src/lib.rs; do
        grep -qx "$required" <<<"$listing" || {
            echo "$package archive is missing $required" >&2
            exit 1
        }
    done
    if grep -Eq '(^|/)(rfc|references|security)/' <<<"$listing"; then
        echo "$package archive contains repository-only material" >&2
        exit 1
    fi
    readme="$(dirname "$manifest")/README.md"
    diff -u <(sed -n '1,24p' README.md) <(sed -n '1,24p' "$readme") >/dev/null || {
        echo "$package README does not use the shared Brynja header" >&2
        exit 1
    }
done < <(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml | sort)
