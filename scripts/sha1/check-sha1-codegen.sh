#!/usr/bin/env bash
set -euo pipefail
toolchain="${1:-1.98.1}"
target="${2:-x86_64-unknown-linux-gnu}"
evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/brynja-sha1-codegen.XXXXXX")"
trap 'rm -rf "$evidence_dir"' EXIT HUP INT TERM
CARGO_TARGET_DIR="$evidence_dir" cargo "+$toolchain" rustc --locked \
    -p brynja-legacy-sha1 --release --target "$target" --lib -- --emit=mir,llvm-ir,asm
python3 - "$evidence_dir" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for extension in ('mir', 'll', 's'):
    paths = list(root.rglob('brynja_legacy_sha1-*.' + extension))
    assert len(paths) == 1, (extension, paths)
    text = paths[0].read_text()
    # MIR can retain unused diagnostic constants even with assertions disabled.
    # They must not reach optimized LLVM IR or emitted machine code.
    if extension != 'mir':
        assert 'offset invariant' not in text, 'debug invariant retained in release code'
    assert 'Sha1Owner' in text and 'wipe' in text, extension
    if extension == 'mir':
        import re
        wipe = re.search(r'^fn owner::<impl at [^\n]+>::wipe\(.*?(?=^fn |\Z)', text, re.S | re.M)
        assert wipe and wipe[0].count('clear_owned_region(') == 6
        assert 'Sha1Owner::wipe(move _1)' in text
    elif extension == 'll':
        assert 'clear_owned_region' in text
print('SHA-1 owner Drop/wipe and six clearing regions survive MIR/LLVM/assembly')
PY
