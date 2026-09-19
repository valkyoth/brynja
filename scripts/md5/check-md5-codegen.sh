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
import re
import sys
root = pathlib.Path(sys.argv[1])
row = {}
for extension in ('mir', 'll', 's'):
    paths = list(root.rglob('brynja_legacy_md5-*.' + extension))
    assert len(paths) == 1, (extension, paths)
    text = paths[0].read_text()
    row[extension] = text
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
sys.path.insert(0, str(pathlib.Path('scripts/cryptography').resolve()))
import mir_cleanup_flow as flow

def scoped(data):
    prefix = 'crates/brynja-legacy-md5/src/hardened_in_place.rs:'
    compact = lambda text: re.sub(r'\s+', '', re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', text))
    for owner in ('Md5', 'Cleanup'):
        function = flow.exact_function(data['mir'], (prefix, '::drop(', "_1: &mut hardened_in_place::" + owner + "<'_>"))
        blocks = flow.basic_blocks(function)
        guarded = owner == 'Cleanup'
        assert set(blocks) == ({'bb0', 'bb1', 'bb2'} if guarded else {'bb0', 'bb1'})
        if guarded:
            assert re.fullmatch(r'(?P<c>_\d+)=copy\(\(\*_1\)\.1:bool\);switchInt\(move(?P=c)\)->\[0:bb1,otherwise:bb2\];}', compact(blocks['bb0']))
        current, successor = ('bb1', 'bb2') if guarded else ('bb0', 'bb1')
        pattern = (r'(?P<p>_\d+)=(?:no_retag)?copy\(\(\*_1\)\.0:&mutowner::Md5Owner\);'
                   r'_\d+=Md5Owner::wipe\(move(?P=p)\)->\[return:' + successor + r',unwind(?:unreachable|continue)\];}')
        assert re.fullmatch(pattern, compact(blocks[current])), 'exact borrowed owner wipe'
        assert compact(blocks[successor]) == 'return;}}'
        functions = re.findall(r'^define [^\n]*\{.*?^}', data['ll'], re.M | re.S)
        chosen = [f for f in functions if 'hardened_in_place' in f.splitlines()[0]
                  and owner in f.splitlines()[0] and 'drop' in f.splitlines()[0]]
        assert len(chosen) == 1, 'unique scoped destructor'
        calls = [line for line in chosen[0].splitlines() if not line.lstrip().startswith(';') and 'call ' in line]
        assert len(calls) == 1 and 'Md5Owner' in calls[0] and 'wipe' in calls[0]
        symbol = re.search(r'@([^ (]+)', chosen[0].splitlines()[0])[1].strip('"')
        assembly = re.search(r'^' + re.escape(symbol) + r':\n.*?(?=^\.Lfunc_end)', data['s'], re.M | re.S)
        assert assembly and re.search(r'(?:callq?|jmpq?|bl|b)\s+[^\n]*Md5Owner[^\n]*wipe', assembly[0])

scoped(row)
for extension, before, after in (
    ('mir', '0: bb1, otherwise: bb2', '1: bb1, otherwise: bb2'),
    ('mir', 'Md5Owner::wipe(', 'Md5Owner::omitted('),
    ('ll', '4wipe', '4skip'),
    ('s', '4wipe', '4skip'),
):
    assert before in row[extension], 'live scoped cleanup mutant'
    try:
        scoped(dict(row, **{extension: row[extension].replace(before, after)}))
    except (AssertionError, flow.MirCleanupFlowError):
        continue
    raise AssertionError('scoped MD5 cleanup mutant survived')
print('Scoped MD5 guard/handle cleanup survives MIR/LLVM/assembly; four mutations rejected')
PY
