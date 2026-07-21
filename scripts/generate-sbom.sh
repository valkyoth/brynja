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
        python3 scripts/compare_sbom.py "$target" "$tmp"
        ;;
    --write)
        mkdir -p sbom
        mv "$tmp" "$target"
        ;;
    *)
        echo "usage: scripts/generate-sbom.sh [--check|--write]" >&2
        exit 2
        ;;
esac

