#!/usr/bin/env sh
set -eu

find scripts -type f -name '*.sh' -exec sh -n {} \;

