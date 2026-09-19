"""Feature-enabled owned-memory and opaque kernel-boundary emitted-code checks."""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow
# Packaging redirects ROOT to the extracted crate workspace. The inspector is
# tooling from this checkout, not an input supplied by that temporary package.
sys.path.insert(0, str(ROOT / 'assurance/register-cleanup'))
import check_sha1 as boundary


def require(condition, message):
    if not condition: raise ValueError('SHA-1 hardened compiler evidence: ' + message)


def mir_check(mir, panic='abort'):
    for namespace, owner in (('fn owner::', 'Sha1Owner'), ('fn cpu::secret::', 'Scratch')):
        header = (namespace, f'::drop(_1: &mut {owner})')
        if panic == 'abort':
            flow.require_owner_cleanup(mir, header, f'{owner}::wipe(')
        else:
            # Cross-crate MIR does not mark clearing as nounwind in an unwind
            # build. Prove the actual Drop receiver/call and all exit edges;
            # source review and runtime unwind probes cover non-panicking clear.
            function = flow.exact_function(mir, header)
            blocks = flow.basic_blocks(function)
            block, argument = flow.exact_calls(blocks, f'{owner}::wipe(')[0]
            require(argument in ('move _1', 'copy _1'), 'Drop cleared a different receiver')
            graph, exits = flow.control_flow(blocks)
            nodes = flow.reachable(graph)
            dominance = flow.dominators(graph, nodes)
            require(all(block in dominance[e] for e in exits & nodes), 'Drop bypassed wipe')
    for namespace, owner, count in (('fn owner::', 'Sha1Owner', 6), ('fn cpu::secret::', 'Scratch', 1)):
        function = flow.exact_function(mir, (namespace, f'::wipe(_1: &mut {owner})'))
        require(function.count('clear_owned_region(') == count, 'clearing region count: ' + owner)
        # Closed grammar for these straight-line, whole-byte-array owners. It
        # rejects wrong fields, alias replacement, partial clearing, extra work,
        # skipped calls and alternate control flow (not a generic MIR parser).
        widths = (20, 64, 320, 8, 1, 20) if owner == 'Sha1Owner' else (16,)
        blocks = flow.basic_blocks(function)
        require(set(blocks) == {f'bb{i}' for i in range(count+1)}, 'wipe CFG changed')
        for index, width in enumerate(widths):
            body = re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', blocks[f'bb{index}'])
            body = re.sub(r'\s+', '', body)
            pattern = (r'(?P<array>_\d+)=&mut\(\(\*_1\)\.' + str(index) + r':\[u8;' + str(width) +
                r'\]\);(?P<slice>_\d+)=(?:copy|move)(?P=array)as&mut\[u8\]\(PointerCoercion\(Unsize,Implicit\)\);'
                r'_\d+=clear_owned_region\((?:move|copy)(?P=slice)\)->\[return:bb' + str(index+1) +
                r',unwind' + ('unreachable' if panic == 'abort' else 'continue') + r'\];\}')
            require(re.fullmatch(pattern, body), f'wrong clearing provenance/flow: {owner} field {index}')
        last = re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', blocks[f'bb{count}'])
        require(re.sub(r'\s+', '', last) == 'return;}}', 'wipe return changed')
    for namespace in ('cpu::secret', 'hardened_execution::stream'):
        function = flow.exact_function(mir, (f'fn {namespace}::', f'::drop(_1: &mut {namespace}::Operation<'))
        require('Sha1Owner::wipe(' in function and ('quarantine(' in function or '::quarantine)' in function),
                'failure guard lost clearing or revocation: ' + namespace)
    compress = flow.exact_function(mir, ('fn cpu::secret::', '::compress('))
    require('compress_secret(' in compress and 'Scratch' in compress and 'drop(' in compress,
            'dispatch no longer owns the secret kernel scratch')
    if panic == 'unwind':
        cleanup = '\n'.join(body for name, body in flow.basic_blocks(compress).items()
                            if re.search(r'\b' + name + r' \(cleanup\)', compress))
        require('drop(' in cleanup and 'resume;' in cleanup, 'dispatch lost unwind cleanup edges')


def assembly_functions(assembly, tokens):
    # ELF and Mach-O Rust symbols; local labels cannot satisfy a Rust identity.
    labels = list(re.finditer(r'(?m)^(_+(?:R|ZN)[^\s:]+):[^\n]*$', assembly))
    found = []
    for index, match in enumerate(labels):
        if all(token in match[1] for token in tokens):
            end = labels[index+1].start() if index+1 < len(labels) else len(assembly)
            found.append(assembly[match.end():end])
    return found


def assembly_function(assembly, tokens):
    found = assembly_functions(assembly, tokens)
    require(len(found) == 1, 'ambiguous or absent assembly function: ' + repr(tokens))
    return found[0]


def kernel_body(assembly, llvm, target):
    kernel = 'x86_sha1' if target.startswith(('x86_64', 'i686')) else 'aarch64_sha1'
    # The opaque private function cannot inline. A wrapper/ordinary kernel or
    # inlined authority cannot donate instructions to this exact source identity.
    return assembly_function(assembly, ('brynja_legacy_sha1', kernel, '6secret8compress'))


def artifacts_check(mir, llvm, assembly, target, panic='abort'):
    mir_check(mir, panic)
    scoped_check(mir, llvm, assembly)
    kernel = 'x86_sha1' if target.startswith(('x86_64', 'i686')) else 'aarch64_sha1'
    body = kernel_body(assembly, llvm, target)
    instructions = ('sha1msg1', 'sha1msg2', 'sha1nexte', 'sha1rnds4') if kernel == 'x86_sha1' else (
        'sha1c', 'sha1p', 'sha1m', 'sha1h', 'sha1su0', 'sha1su1')
    for instruction in instructions:
        require(re.search(r'^\s+' + instruction + r'(?:\.[\w]+)?\s', body, re.M),
                'hardened kernel omitted ' + instruction)
    boundary.inspect(body, 'x86' if kernel == 'x86_sha1' else 'arm')
    for owner in ('Scratch', 'Sha1Owner'):
        body = assembly_function(assembly, ('brynja_legacy_sha1', owner, 'wipe'))
        require('clear_owned_region' in body, owner + ' emitted clear disappeared')
        definitions = re.findall(r'^define [^\n]*' + owner + r'[^\n]*wipe[^\n]*\{.*?^}', llvm, re.M | re.S)
        require(len(definitions) == 1 and 'clear_owned_region' in definitions[0], owner + ' LLVM clear disappeared')


def scoped_check(mir, llvm, assembly):
    prefix = 'src/hardened_execution/in_place.rs:'
    compact = lambda text: re.sub(r'\s+', '', re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', text))
    clear = flow.basic_blocks(flow.exact_function(mir, (prefix, '::clear(', '_1: &mut Storage')))
    require(set(clear) == {'bb0', 'bb1'}, 'scoped storage clearing CFG')
    require(re.fullmatch(r'(?P<p>_\d+)=&mut\(\(\*_1\)\.0:owner::Sha1Owner\);_\d+=Sha1Owner::wipe\(move(?P=p)\)->\[return:bb1,unwind(?:unreachable|continue)\];}', compact(clear['bb0'])), 'scoped storage owner provenance')
    require(compact(clear['bb1']) == '((*_1).2:bool)=constfalse;return;}}', 'scoped storage terminal flag')
    for owner in ('Scope', 'Sha1', 'Operation'):
        function = flow.exact_function(mir, (prefix, '::drop(', owner + "<'_, '_>"))
        blocks = flow.basic_blocks(function)
        entry = 'bb0'
        if owner == 'Operation':
            require(re.fullmatch(r'(?P<c>_\d+)=copy\(\(\*_1\)\.1:bool\);switchInt\(move(?P=c)\)->\[0:bb1,otherwise:bb\d+\];}', compact(blocks['bb0'])), 'scoped operation failure edge')
            entry = 'bb1'
        pattern = (r'(?P<p>_\d+)=(?:no_retag)?copy\(\(\*_1\)\.0:&mut(?:hardened_execution::in_place::)?Storage<\x27_>\);'
                   r'_\d+=Storage::<\x27_>::clear\(move(?P=p)\)->\[return:bb\d+,unwind(?:unreachable|continue)\];}')
        require(re.fullmatch(pattern, compact(blocks[entry])), 'scoped guard clears exact borrowed storage: '+owner)
        identity = rf'(?:{len(owner)}{owner}|\.\.{owner}\$)'
        definitions = [f for f in re.findall(r'^define [^\n]*\{.*?^}', llvm, re.M | re.S)
                       if all(t in f.splitlines()[0] for t in ('hardened_execution', 'in_place', '4drop'))
                       and re.search(identity, f.splitlines()[0])]
        require(len(definitions) == 1, 'scoped destructor LLVM identity: '+owner)
        calls = [line for line in definitions[0].splitlines() if not line.lstrip().startswith(';') and re.search(r'\b(?:call|invoke)\b', line)]
        require(sum('Sha1Owner' in line and 'wipe' in line for line in calls) == 1, 'scoped destructor LLVM wipe: '+owner)
        symbol = re.search(r'@([^ (]+)', definitions[0].splitlines()[0])[1].strip('"')
        body = assembly_function(assembly, (symbol,))
        require(re.search(r'(?:callq?|jmpq?|bl|b)\s+[^\n]*Sha1Owner[^\n]*wipe', body), 'scoped destructor assembly wipe: '+owner)


def compile_and_check(output, compiler, target, panic='abort'):
    environment = dict(os.environ, CARGO_TARGET_DIR=str(output), CARGO_PROFILE_RELEASE_PANIC=panic)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET'):
        environment.pop(key, None)
    subprocess.run(['cargo', '+' + compiler, 'rustc', '--locked', '--offline', '--release',
        '-p', 'brynja-legacy-sha1', '--features', 'hardened-execution', '--target', target,
        '--lib', '--', '--emit=mir,llvm-ir,asm'], cwd=ROOT, env=environment, check=True, timeout=180)
    contents = []
    for extension in ('mir', 'll', 's'):
        paths = list(output.rglob('brynja_legacy_sha1-*.' + extension))
        require(len(paths) == 1, 'ambiguous artifact inventory')
        contents.append(paths[0].read_text())
    artifacts_check(*contents, target, panic)
    for index, before, after in (
        (0, '0: bb1, otherwise:', '1: bb1, otherwise:'),
        (0, "Storage::<'_>::clear(", "Storage::<'_>::omitted("),
        (0, 'Sha1Owner::wipe(', 'Sha1Owner::omitted('),
        (1, '4wipe', '4skip'), (2, '4wipe', '4skip'),
    ):
        require(before in contents[index], 'live scoped compiler mutation')
        changed = list(contents)
        changed[index] = changed[index].replace(before, after)
        try: scoped_check(*changed)
        except (ValueError, flow.MirCleanupFlowError): pass
        else: raise AssertionError('scoped compiler mutation survived: '+before)
    return contents
