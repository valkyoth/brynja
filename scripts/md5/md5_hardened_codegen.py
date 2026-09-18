"""Whole owned-region destruction and exact opaque SIMD register boundaries."""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow
sys.path.insert(0, str(ROOT / 'assurance/register-cleanup'))
import check_md5 as boundary


def require(condition, label):
    if not condition:
        raise ValueError('MD5 hardened compiler evidence: ' + label)


def mir_check(mir, panic):
    header = ('fn scratch::', '::drop(_1: &mut Scratch)')
    if panic == 'abort':
        flow.require_owner_cleanup(mir, header, 'Scratch::wipe(')
    else:
        function = flow.exact_function(mir, header)
        blocks = flow.basic_blocks(function)
        calls = flow.exact_calls(blocks, 'Scratch::wipe(')
        require(len(calls) == 1 and calls[0][1] in ('move _1', 'copy _1'), 'Drop receiver')
        graph, exits = flow.control_flow(blocks)
        nodes = flow.reachable(graph)
        dominance = flow.dominators(graph, nodes)
        require(all(calls[0][0] in dominance[e] for e in exits & nodes), 'Drop bypass')
    function = flow.exact_function(mir, ('fn scratch::', '::wipe(_1: &mut Scratch)'))
    blocks = flow.basic_blocks(function)
    require(set(blocks) == {f'bb{i}' for i in range(9)}, 'whole-region clearing CFG')
    unwind = 'unreachable' if panic == 'abort' else 'continue'
    def compact(body):
        return re.sub(r'\s+', '', re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', body))
    for field, width in enumerate((4, 16, 4, 3)):
        pattern = (r'(?P<array>_\d+)=&mut\(\(\*_1\)\.' + str(field) + r':\[\[u8;32\];' + str(width) +
            r'\]\);(?P<slice>_\d+)=(?:copy|move)(?P=array)as&mut\[\[u8;32\]\]\(PointerCoercion\(Unsize,Implicit\)\);'
            r'(?P<flat>_\d+)=slice::<impl\[\[u8;32\]\]>::as_flattened_mut\((?:move|copy)(?P=slice)\)'
            r'->\[return:bb' + str(field*2+1) + r',unwind' + unwind + r'\];\}')
        found = re.fullmatch(pattern, compact(blocks[f'bb{field*2}']))
        require(found is not None, f'whole field provenance {field}')
        pattern = r'_\d+=clear_owned_region\((?:move|copy)' + re.escape(found['flat']) + r'\)->\[return:bb' + str(field*2+2) + r',unwind' + unwind + r'\];\}'
        require(re.fullmatch(pattern, compact(blocks[f'bb{field*2+1}'])), f'cleared field receiver {field}')
    require(compact(blocks['bb8']) == 'return;}}', 'wipe return')


def asm_body(text, tokens):
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', text))
    matches = [text[m.end():labels[i+1].start() if i+1 < len(labels) else len(text)]
               for i, m in enumerate(labels) if all(t in m[1] for t in tokens)]
    require(len(matches) == 1, 'absent/ambiguous assembly function: '+repr(tokens))
    return matches[0]


def artifacts_check(mir, llvm, assembly, target, panic):
    mir_check(mir, panic)
    # A wrapper or ordinary kernel cannot donate instructions to this identity.
    arch = 'x86' if target.startswith('x86_64') else 'arm'
    body = asm_body(assembly, ('brynja_legacy_md5', arch+'_secret', '6kernel8compress'))
    boundary.inspect(body, arch)
    wipe = asm_body(assembly, ('brynja_legacy_md5', 'scratch', 'Scratch', 'wipe'))
    require('clear_owned_region' in wipe, 'emitted clearing boundary')
    functions = re.findall(r'^define [^\n]*\{.*?^}', llvm, re.M | re.S)
    wipes = [f for f in functions if all(t in f.splitlines()[0] for t in ('scratch','Scratch','wipe'))]
    require(len(wipes) == 1, 'LLVM wipe identity')
    for width in (128, 512, 96):
        require(re.search(r'call[^\n]*clear_owned_region[^\n]*i64[^\n]*\b'+str(width)+r'\)', wipes[0]), 'LLVM complete region width '+str(width))


def compile_and_check(output, compiler, target, panic='abort', manifest=None):
    features = '+avx2' if target.startswith('x86_64') else '+neon'
    env = dict(os.environ)
    for key in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTDOCFLAGS','CARGO_BUILD_TARGET'):
        env.pop(key, None)
    env.update(CARGO_TARGET_DIR=str(output), RUSTFLAGS=f'-C target-feature={features} -C panic={panic}')
    command = ['cargo','+'+compiler,'rustc','--locked','--offline','--release','-p','brynja-legacy-md5',
               '--target',target,'--lib']
    if manifest: command += ['--manifest-path', str(manifest)]
    else: command += ['--features','hardened-execution']
    subprocess.run(command+['--','--emit=mir,llvm-ir,asm'],cwd=ROOT,env=env,check=True,timeout=180)
    contents = []
    for extension in ('mir','ll','s'):
        paths = list((output/target/'release/deps').glob('brynja_legacy_md5*.'+extension))
        require(len(paths)==1,'artifact identity '+extension)
        contents.append(paths[0].read_text())
    artifacts_check(*contents,target,panic)
    return contents
