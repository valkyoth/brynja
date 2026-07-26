#!/usr/bin/env sh
set -eu

mode="${1:-install}"
if [ "$mode" != "install" ] && [ "$mode" != "--verify-only" ]; then
    echo "usage: scripts/install-ci-tools.sh [--verify-only]" >&2
    exit 2
fi

lock_file="scripts/ci-tools.lock"
download_root="https://static.crates.io/crates"
tool_tmp="$(mktemp -d "${TMPDIR:-/tmp}/brynja-ci-tools.XXXXXX")"
trap 'rm -rf "$tool_tmp"' EXIT HUP INT TERM

fail() {
    echo "CI tool install failed: $*" >&2
    exit 1
}

count=0
seen=" "
while IFS=' ' read -r name version expected_hash extra; do
    [ -n "$name" ] || continue
    [ -z "${extra:-}" ] || fail "invalid lock entry for ${name}"
    case "$name" in
        cargo-deny|cargo-audit|cargo-sbom) ;;
        *) fail "unexpected tool in lock: ${name}" ;;
    esac
    case "$seen" in
        *" ${name} "*) fail "duplicate tool in lock: ${name}" ;;
    esac
    seen="${seen}${name} "
    [ "${#expected_hash}" -eq 64 ] || fail "invalid SHA-256 length for ${name}"
    case "$expected_hash" in
        *[!0-9a-f]*) fail "invalid SHA-256 for ${name}" ;;
    esac

    archive="${tool_tmp}/${name}-${version}.crate"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        "${download_root}/${name}/${name}-${version}.crate" \
        --output "$archive"
    actual_hash="$(sha256sum "$archive")"
    actual_hash="${actual_hash%% *}"
    if [ "$actual_hash" != "$expected_hash" ]; then
        fail "${name} ${version} archive checksum mismatch"
    fi

    if [ "$mode" = "install" ]; then
        source_dir="${tool_tmp}/${name}-${version}"
        tar --extract --gzip --file "$archive" --directory "$tool_tmp"
        [ -f "${source_dir}/Cargo.toml" ] ||
            fail "${name} ${version} archive has an unexpected layout"
        cargo install --locked --path "$source_dir"
    fi
    count=$((count + 1))
done <"$lock_file"

[ "$count" -eq 3 ] || fail "lock must contain exactly three approved tools"
