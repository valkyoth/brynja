#!/usr/bin/env sh
set -eu

missing=0
for file in README.md CHANGELOG.md SECURITY.md docs/*.md rfc/*.md references/*.md release-notes/*.md; do
    [ -f "$file" ] || continue
    sed -n 's/.*](\([^)]*\.md\)).*/\1/p' "$file" | while IFS= read -r link; do
        case "$link" in
            http://*|https://*) continue ;;
            /*) target=".$link" ;;
            *) target="$(dirname "$file")/$link" ;;
        esac
        if [ ! -f "$target" ]; then
            echo "missing markdown link target: $file -> $link" >&2
            exit 1
        fi
    done || missing=1
done

test "$missing" -eq 0

