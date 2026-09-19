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
    scoped_check(mir, llvm, assembly)
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


def scoped_check(mir, llvm, assembly):
    """Exact borrowed guard receiver plus eight unrolled whole-owner wipe calls.

    This binds the selected compiler's actual layout, not a public Rust layout
    promise or a whole-API register/spill-erasure claim.
    """
    prefix = 'src/batch/hardened_execution/in_place.rs:'
    compact = lambda text: re.sub(r'\s+', '', re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', text))
    functions = re.findall(r'^define [^\n]*\{.*?^}', llvm, re.M | re.S)
    clears = [f for f in functions if all(t in f.splitlines()[0] for t in ('hardened_execution', 'in_place', '5clear'))]
    require(len(clears) == 1, 'scoped clear LLVM identity')
    header, *lines = clears[0].splitlines()
    argument = re.search(r'(%[\w.]+)\)', header)
    require(argument is not None, 'scoped clear LLVM argument')
    receiver = argument[1]
    require(receiver.startswith('%'), 'scoped clear LLVM receiver')
    instructions = [line.strip() for line in lines
                    if line.strip() and not line.lstrip().startswith(';') and line.strip() not in ('start:', '}')]
    require(len(instructions) == 17 and instructions[-1] == 'ret void', 'scoped whole-lane straight-line cleanup')
    for lane in range(8):
        offset = 8 + 113 * lane
        pointer = re.fullmatch(r'(%[\w.]+) = getelementptr inbounds(?: nuw)? i8, ptr '+re.escape(receiver)+r', i64 '+str(offset), instructions[2*lane])
        require(pointer is not None, 'scoped lane receiver offset '+str(lane))
        call = instructions[2*lane+1]
        require(re.fullmatch(r'(?:tail )?call void @[^ (]*Md5Owner[^ (]*wipe[^ (]*\(ptr [^\n,()]*'+re.escape(pointer[1])+r'\)(?: #\d+)?',
                             re.sub(r'dereferenceable\(\d+\)', 'dereferenceable', call)), 'scoped exact lane wipe '+str(lane))
    body = asm_body(assembly, ('brynja_legacy_md5', 'hardened_execution', 'in_place', '5clear'))
    if '@GOTPCREL' in body:
        # Closed x86 grammar: the callee is held in r14 then copied to rax
        # before the final tail call. Do not count arbitrary indirect calls.
        instructions = [re.sub(r'\s+', ' ', line.strip()) for line in body.splitlines()
                        if re.match(r'^\s+[a-z]', line)]
        loads = [i for i in instructions if re.fullmatch(r'movq [^ ]*Md5Owner[^ ]*wipe[^ ]*@GOTPCREL\(%rip\), %r14', i)]
        require(len(loads) == 1, 'scoped assembly wipe callee')
        expected = ['pushq %r14', 'pushq %rbx', 'pushq %rax', 'movq %rdi, %rbx',
                    'addq $8, %rdi', loads[0], 'callq *%r14']
        for lane in range(1, 7):
            expected += [f'leaq {8+113*lane}(%rbx), %rdi', 'callq *%r14']
        expected += ['addq $799, %rbx', 'movq %rbx, %rdi', 'movq %r14, %rax',
                     'addq $8, %rsp', 'popq %rbx', 'popq %r14', 'jmpq *%rax']
        require(instructions == expected, 'scoped assembly exact eight receivers/calls')
    else:
        require(len(re.findall(r'(?:callq?|jmpq?|bl|b)\s+[^\n]*Md5Owner[^\n]*wipe', body)) == 8, 'scoped emitted eight-lane clearing')
    for owner in ('Scope', 'Batch'):
        blocks = flow.basic_blocks(flow.exact_function(mir, (prefix, '::drop(', owner+"<'_, '_>")))
        pattern = (r'(?P<p>_\d+)=(?:no_retag)?copy\(\(\*_1\)\.0:&mutbatch::hardened_execution::Batch<\x27_>\);'
                   r'_\d+=clear\(move(?P=p)\)->\[return:bb1,unwind(?:unreachable|continue)\];}')
        require(re.fullmatch(pattern, compact(blocks['bb0'])), 'scoped borrowed destructor receiver '+owner)
        if owner == 'Scope':
            require(re.fullmatch(r'(?P<c>_\d+)=copy\(\(\*_1\)\.1:bool\);switchInt\(move(?P=c)\)->\[0:bb2,otherwise:bb3\];}', compact(blocks['bb1'])), 'scoped incomplete-scope failure branch')
        identity = rf'(?:{len(owner)}{owner}|\.\.{owner}\$)'
        destructors = [f for f in functions if all(t in f.splitlines()[0] for t in ('hardened_execution', 'in_place', '4drop'))
                       and re.search(identity, f.splitlines()[0])]
        require(len(destructors) == 1, 'scoped destructor LLVM identity '+owner)
        calls = [line for line in destructors[0].splitlines() if not line.lstrip().startswith(';') and re.search(r'\b(?:call|invoke)\b', line)]
        require(sum('in_place' in line and '5clear' in line for line in calls) == 1, 'scoped destructor LLVM clearing '+owner)
        symbol = re.search(r'@([^ (]+)', destructors[0].splitlines()[0])[1].strip('"')
        body = asm_body(assembly, (symbol,))
        require(re.search(r'(?:callq?|jmpq?|bl|b)\s+[^\n]*in_place[^\n]*5clear', body), 'scoped destructor assembly clearing '+owner)


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
    for index, old, new in (
        (0, 'clear(move', 'omitted(move'),
        (0, '0: bb2, otherwise: bb3', '1: bb2, otherwise: bb3'),
        (1, 'i64 799', 'i64 686'),
        (1, '5clear', '5other'),
        (2, '5clear', '5other'),
    ):
        require(old in contents[index], 'live scoped compiler mutation')
        changed = list(contents)
        changed[index] = changed[index].replace(old, new)
        try: scoped_check(*changed)
        except (ValueError, flow.MirCleanupFlowError): pass
        else: raise AssertionError('scoped compiler mutation survived: '+old)
    return contents
