#!/usr/bin/env bash
set -euo pipefail

architecture="${1:-}"
instruction="${2:-}"
assembly="${3:-}"

case "$architecture:$instruction" in
    x86_64:sha256rnds2)
        pattern='(^|[[:space:]])sha256rnds2([[:space:]]|$)'
        ;;
    aarch64:sha256h)
        # ELF uses `sha256h`; Mach-O uses Apple's `sha256h.4s` spelling.
        pattern='(^|[[:space:]])sha256h([.]4s)?([[:space:]]|$)'
        ;;
    *)
        echo "unsupported SHA-256 assembly instruction check" >&2
        exit 64
        ;;
esac

if test ! -f "$assembly" || test -L "$assembly"; then
    echo "SHA-256 assembly input must be a regular file" >&2
    exit 66
fi

grep -Eq -- "$pattern" "$assembly"
