"""Feature-enabled emitted-code checks; source-owned clearing, not register erasure."""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow


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
    kernel = 'x86_sha1' if target.startswith('x86_64') else 'aarch64_sha1'
    tokens = ('brynja_legacy_sha1', kernel, 'compress_secret')
    found = assembly_functions(assembly, tokens)
    if found:
        require(len(found) == 1, 'ambiguous hardened kernel')
        body = found[0]
    else:
        # Apple enables SHA1 in the baseline, permitting this private kernel
        # to inline. Inspect only its secret-authority caller, never the whole
        # file or the ordinary session. Keep other targets fail-closed.
        require(target == 'aarch64-apple-darwin', 'absent standalone hardened kernel')
        tokens = ('brynja_legacy_sha1', '3cpu6secret', '9Authority8compress')
        body = assembly_function(assembly, tokens)
        definitions = re.findall(r'^define [^\n]*\{.*?^}', llvm, re.M | re.S)
        definitions = [part for part in definitions if all(token in part.splitlines()[0] for token in tokens)]
        require(len(definitions) == 1, 'ambiguous or absent hardened authority LLVM')
        for instruction in ('sha1c', 'sha1p', 'sha1m', 'sha1h', 'sha1su0', 'sha1su1'):
            require(re.search(r'\bcall\b[^\n]*@llvm\.aarch64\.crypto\.' + instruction + r'\(', definitions[0]),
                    'inlined hardened authority omitted LLVM ' + instruction)
    return body


def artifacts_check(mir, llvm, assembly, target, panic='abort'):
    mir_check(mir, panic)
    kernel = 'x86_sha1' if target.startswith('x86_64') else 'aarch64_sha1'
    body = kernel_body(assembly, llvm, target)
    instructions = ('sha1msg1', 'sha1msg2', 'sha1nexte', 'sha1rnds4') if kernel == 'x86_sha1' else (
        'sha1c', 'sha1p', 'sha1m', 'sha1h', 'sha1su0', 'sha1su1')
    for instruction in instructions:
        require(re.search(r'^\s+' + instruction + r'(?:\.[\w]+)?\s', body, re.M),
                'hardened kernel omitted ' + instruction)
    for owner in ('Scratch', 'Sha1Owner'):
        body = assembly_function(assembly, ('brynja_legacy_sha1', owner, 'wipe'))
        require('clear_owned_region' in body, owner + ' emitted clear disappeared')
        definitions = re.findall(r'^define [^\n]*' + owner + r'[^\n]*wipe[^\n]*\{.*?^}', llvm, re.M | re.S)
        require(len(definitions) == 1 and 'clear_owned_region' in definitions[0], owner + ' LLVM clear disappeared')


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
    return contents
