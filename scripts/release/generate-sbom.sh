#!/usr/bin/env sh
set -eu

mode="${1:---write}"
target="sbom/brynja.spdx.json"
tmp="$(mktemp "${TMPDIR:-/tmp}/brynja-sbom.XXXXXX")"
trap 'rm -f "$tmp"' EXIT HUP INT TERM

cargo sbom --output-format spdx_json_2_3 > "$tmp"
test -s "$tmp"
case "$mode" in
    --check)
        test -s "$target"
        python3 scripts/release/compare_sbom.py "$target" "$tmp"
        ;;
    --write)
        # The public timestamp can be supplied for source archives or shallow
        # checkouts. In a full clone default to the last lockfile change.
        epoch="${SOURCE_DATE_EPOCH-$(git log -1 --format=%ct -- Cargo.lock)}"
        python3 scripts/release/compare_sbom.py --prepare "$tmp" "$epoch"
        mkdir -p sbom
        mv "$tmp" "$target"
        ;;
    *)
        echo "usage: scripts/release/generate-sbom.sh [--check|--write]" >&2
        exit 2
        ;;
esac

