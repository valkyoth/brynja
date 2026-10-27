#!/usr/bin/env bash
set -euo pipefail

python3 scripts/repository/check-crate-readmes.py
python3 scripts/repository/test-package-contents.py
python3 scripts/repository/test-package-fixtures.py
python3 scripts/parallelhash/test-parallelhash-package-fixtures.py

while IFS= read -r manifest; do
    package="$(sed -n 's/^name = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1)"
    [[ -n "$package" ]] || exit 1
    listing="$(cargo package -p "$package" --allow-dirty --no-verify --list)"
    python3 scripts/repository/package_contents.py "$manifest" <<<"$listing"
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
done < <(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml | sort)
