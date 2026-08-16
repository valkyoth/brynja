#!/usr/bin/env bash
set -euo pipefail

violations="$(find crates scripts -type f \
    \( -name '*.rs' -o -name '*.py' -o -name '*.sh' \) \
    -exec wc -l {} \; | awk '$1 > 500 { print }')"
if [[ -n "$violations" ]]; then
    echo "code files exceed 500 lines:" >&2
    echo "$violations" >&2
    exit 1
fi

while IFS= read -r source; do
    if [[ "$source" == "crates/brynja-crypto-cpu-std/src/lib.rs" ]]; then
        if grep -q '#!\[no_std\]' "$source"; then
            echo "opt-in CPU host adapter must remain an explicit std crate: $source" >&2
            exit 1
        fi
        continue
    fi
    grep -q '#!\[no_std\]' "$source" || {
        echo "missing no_std crate attribute: $source" >&2
        exit 1
    }
done < <(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -printf '%h/src/lib.rs\n' | sort)

python3 - <<'PY'
import tomllib
packages = tomllib.load(open("Cargo.lock", "rb")).get("package", [])
external = [p for p in packages if "source" in p]
if len(external) != 1:
    raise SystemExit(f"Cargo.lock must contain exactly one admitted external package: {external}")
package = external[0]
expected = {
    "name": "sanitization",
    "version": "2.0.3",
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "checksum": "75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f",
}
if any(package.get(key) != value for key, value in expected.items()):
    raise SystemExit(f"Cargo.lock admitted package identity drifted: {package}")
if package.get("dependencies"):
    raise SystemExit("Cargo.lock sanitization selection gained a dependency")
PY

metadata_no_default="$(mktemp "${TMPDIR:-/tmp}/brynja-metadata-none.XXXXXX")"
metadata_all="$(mktemp "${TMPDIR:-/tmp}/brynja-metadata-all.XXXXXX")"
trap 'rm -f "$metadata_no_default" "$metadata_all"' EXIT HUP INT TERM
cargo metadata --format-version 1 --no-default-features > "$metadata_no_default"
cargo metadata --format-version 1 --all-features > "$metadata_all"
python3 scripts/repository/validate-workspace-metadata.py \
    --mode no-default-features "$metadata_no_default"
python3 scripts/repository/validate-workspace-metadata.py \
    --mode all-features "$metadata_all"
