#!/usr/bin/env sh
# External licensed test tool only. Do not redistribute it with Brynja.
set -eu
if test "${BRYNJA_ACCEPT_INTEL_SDE_LICENSE:-}" != 1; then
    echo 'Intel SDE requires explicit license acceptance before download.' >&2
    exit 1
fi
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
sde_directory="$(mktemp -d "${TMPDIR:-/tmp}/brynja-sde.XXXXXX")"
sde_archive="$sde_directory/sde.tar.xz"
curl --fail --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 30 --max-time 300 --retry 2 \
    --output "$sde_archive" \
    https://downloadmirror.intel.com/924984/sde-external-10.13.1-2026-07-28-lin.tar.xz
printf '%s  %s\n' \
    94e97d623fec54385686e1e7ba65ebc9941748c05ee451423948334892bf2b50 \
    "$sde_archive" | sha256sum --check --status
tar --extract --xz --file "$sde_archive" --directory "$sde_directory" \
    --no-same-owner --no-same-permissions
sde_executable="$sde_directory/sde-external-10.13.1-2026-07-28-lin/sde64"
test -f "$sde_executable"
test -x "$sde_executable"
printf '%s\n' "$sde_executable"
