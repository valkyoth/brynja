#!/usr/bin/env bash
set -euo pipefail
toolchain="${1:-1.98.1}"
target="${2:-x86_64-unknown-linux-gnu}"
evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-md5-codegen.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM
CARGO_TARGET_DIR="$evidence_dir" cargo "+$toolchain" rustc --locked \
    -p brynja-legacy-md5 --release --target "$target" --lib -- --emit=mir,llvm-ir,asm
python3 - "$evidence_dir" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for extension in ('mir', 'll', 's'):
    paths = list(root.rglob('brynja_legacy_md5-*.' + extension))
    assert len(paths) == 1, (extension, paths)
    text = paths[0].read_text()
    # These private-state guards are intentionally active in release builds.
    # Fault-injection release tests exercise their pre-write failure behavior.
    for operation in ('update', 'padding'):
        assert f'MD5 {operation} offset invariant' in text, 'release invariant guard missing'
    assert 'Md5Owner' in text and 'wipe' in text, extension
    if extension == 'mir':
        import re
        wipe = re.search(r'^fn owner::<impl at [^\n]+>::wipe\(.*?(?=^fn |\Z)', text, re.S | re.M)
        assert wipe and wipe[0].count('clear_owned_region(') == 5
        assert 'Md5Owner::wipe(move _1)' in text
    elif extension == 'll':
        assert 'clear_owned_region' in text
print('MD5 owner Drop/wipe and five clearing regions survive MIR/LLVM/assembly')
PY
