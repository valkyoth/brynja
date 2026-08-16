#!/usr/bin/env sh
set -eu

if test "$#" -eq 0; then
    find scripts -type f -name '*.sh' -exec "$0" {} +
    exit 0
fi

for script in "$@"; do
    shebang="$(sed -n '1p' "$script")"
    case "$shebang" in
        '#!/usr/bin/env bash'|'#!/usr/bin/bash'|'#!/bin/bash')
            bash -n "$script"
            ;;
        '#!/usr/bin/env sh'|'#!/usr/bin/sh'|'#!/bin/sh')
            sh -n "$script"
            ;;
        *)
            echo "$script: unsupported or missing shell shebang" >&2
            exit 1
            ;;
    esac
done
