#!/usr/bin/env bash
set -euo pipefail

stage="${1:-}"
test "$#" -eq 1 || {
    echo "usage: $0 public|internal" >&2
    exit 2
}

miri_runner="scripts/zeroization/check-zeroization-miri.sh"
case "$stage" in
    public)
        echo "tag gate: public crates.io checkpoint requires complete Miri evidence"
        "$miri_runner" --full
        ;;
    internal)
        if ! base="$({
            git describe --tags --first-parent --match "v[0-9]*" --abbrev=0 HEAD
        } 2>/dev/null)"; then
            echo "tag gate: no prior signed-tag boundary; requiring complete Miri evidence"
            "$miri_runner" --full
            exit 0
        fi
        if ! git verify-tag "$base" >/dev/null 2>&1; then
            echo "tag gate: prior boundary $base is not a valid signed tag; requiring complete Miri evidence"
            "$miri_runner" --full
            exit 0
        fi
        selection="$(python3 scripts/zeroization/miri_scope.py --base "$base")"
        if test "$selection" = "full"; then
            echo "tag gate: shared boundary changed since $base; requiring complete Miri evidence"
            "$miri_runner" --full
            exit 0
        fi
        IFS=' ' read -r -a groups <<< "$selection"
        echo "tag gate: focused Miri evidence since $base; full groups: ${selection:-none}"
        "$miri_runner" --focused "${groups[@]}"
        ;;
    *)
        echo "unknown release stage for Miri: $stage" >&2
        exit 2
        ;;
esac
