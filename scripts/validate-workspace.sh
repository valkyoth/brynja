#!/usr/bin/env bash
set -euo pipefail

violations="$(find crates scripts -type f \
    \( -name '*.rs' -o -name '*.py' -o -name '*.sh' \) \
    -exec wc -l {} \; | awk '$1 > 500 { print }')"
if [[ -n "$violations" ]]; then
    echo "code files exceed 500 lines:" >&2
    echo "$violations" >&2
    exit 1
fi

while IFS= read -r source; do
    grep -q '#!\[no_std\]' "$source" || {
        echo "missing no_std crate attribute: $source" >&2
        exit 1
    }
done < <(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -printf '%h/src/lib.rs\n' | sort)

if grep -q '^source = ' Cargo.lock; then
    echo "Cargo.lock contains a third-party source" >&2
    exit 1
fi

metadata_no_default="$(mktemp "${TMPDIR:-/tmp}/brynja-metadata-none.XXXXXX")"
metadata_all="$(mktemp "${TMPDIR:-/tmp}/brynja-metadata-all.XXXXXX")"
trap 'rm -f "$metadata_no_default" "$metadata_all"' EXIT HUP INT TERM
cargo metadata --format-version 1 --no-default-features > "$metadata_no_default"
cargo metadata --format-version 1 --all-features > "$metadata_all"
python3 scripts/validate-workspace-metadata.py \
    --mode no-default-features "$metadata_no_default"
python3 scripts/validate-workspace-metadata.py \
    --mode all-features "$metadata_all"
