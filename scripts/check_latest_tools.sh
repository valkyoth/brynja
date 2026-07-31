#!/usr/bin/env sh
set -eu

ci_file=".github/workflows/ci.yml"
tool_lock="scripts/ci-tools.lock"
manifest_url="${RUST_STABLE_MANIFEST_URL:-https://static.rust-lang.org/dist/channel-rust-stable.toml}"

pinned_rust="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' rust-toolchain.toml | head -n 1)"
latest_rust="$(curl -fsSL "$manifest_url" | sed -n '/^\[pkg\.rust\]$/,/^\[/ { s/^version = "\([0-9][0-9.]*\) .*/\1/p; }' | head -n 1)"
test -n "$pinned_rust"
test -n "$latest_rust"
if [ "$pinned_rust" != "$latest_rust" ]; then
    echo "Rust is stale: pinned ${pinned_rust}, latest ${latest_rust}" >&2
    exit 1
fi

for tool in cargo-deny cargo-audit cargo-sbom; do
    pinned="$(sed -n "s/^${tool} \\([0-9][^ ]*\\) [0-9a-f]\\{64\\}$/\\1/p" "$tool_lock" | head -n 1)"
    latest="$(cargo info "$tool" | sed -n 's/^version: //p' | head -n 1)"
    test -n "$pinned"
    test -n "$latest"
    if [ "$pinned" != "$latest" ]; then
        echo "${tool} is stale: pinned ${pinned}, latest ${latest}" >&2
        exit 1
    fi
done

scripts/install-ci-tools.sh --verify-only
python3 scripts/check-assurance.py --network

failed=0
for workflow in .github/workflows/*.yml; do
    while IFS= read -r ref; do
        case "$ref" in
            [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
            *)
                echo "GitHub Action is not pinned to a full SHA: ${ref}" >&2
                failed=1
                ;;
        esac
    done <<EOF
$(sed -n 's/^[[:space:]]*uses: [^@][^@]*@\([^[:space:]]*\).*/\1/p' "$workflow")
EOF
done
test "$failed" -eq 0

pin_line="$(sed -n 's/.*uses: actions\/checkout@\([0-9a-f]\{40\}\) # \(v[0-9][0-9.]*\).*/\1 \2/p' "$ci_file" | head -n 1)"
test -n "$pin_line"
pinned_sha="$(printf '%s\n' "$pin_line" | awk '{ print $1 }')"
pinned_tag="$(printf '%s\n' "$pin_line" | awk '{ print $2 }')"
latest_tag="$(git ls-remote --tags --refs https://github.com/actions/checkout.git 'refs/tags/v*' | sed 's#.*refs/tags/##' | grep -E '^v[0-9]+(\.[0-9]+)*$' | sort -V | tail -n 1)"
latest_sha="$(git ls-remote --tags --refs https://github.com/actions/checkout.git "refs/tags/${latest_tag}" | awk '{ print $1 }')"
if [ "$pinned_tag" != "$latest_tag" ] || [ "$pinned_sha" != "$latest_sha" ]; then
    echo "actions/checkout is stale or has the wrong SHA" >&2
    exit 1
fi
