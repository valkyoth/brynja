#!/usr/bin/env python3
"""Development regression campaign for the hardened Keccak batch foundation.

This is not native qualification or the complete v0.24.48 acceptance gate.
Compiled mutants execute only with an explicitly selected compiled-target
bundle. The operator must uphold that bundle on the test machine.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FAMILY = 'keccak'
NAMESPACE = 'keccak_hardened_batch'
SOURCE = 'crates/brynja-crypto-cpu/src/keccak_hardened_batch/'
FEATURE = 'keccak-hardened-batch'
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow


def require(condition, message):
    if not condition:
        raise ValueError('hardened Keccak batch regression: ' + message)


def run(command, root, env):
    result = subprocess.run(command, cwd=root, env=env, capture_output=True,
                            text=True, timeout=300)
    require(result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:])
    return result


def inspect(mir, llvm, assembly, target):
    destructor = ('fn scratch::<impl', '/'+NAMESPACE+'/scratch.rs:', '::drop(')
    flow.require_owner_cleanup(mir, destructor, 'scratch::Workspace::wipe(')
    wipe = flow.exact_function(mir, ('fn scratch::<impl', '/'+NAMESPACE+'/scratch.rs:', '::wipe('))
    blocks = flow.basic_blocks(wipe)
    require(set(blocks) == {f'bb{i}' for i in range(9)}, 'wipe control flow changed')
    # Exact field -> whole flattened slice -> clear provenance, with no
    # reassignment or branch between them. Source byte fields are 0..3.
    for i, count in enumerate((25, 5, 5, 25)):
        compact = lambda value: re.sub(r'\s+', '', re.sub(r'Storage(?:Live|Dead)\(_\d+\);', '', value))
        first = compact(blocks[f'bb{2*i}'])
        second = compact(blocks[f'bb{2*i+1}'])
        pattern = (r'(?P<array>_\d+)=&mut\(\(\*_1\)\.' + str(i) + r':\[\[u8;32\];' + str(count) +
                   r'\]\);(?P<slice>_\d+)=(?:copy|move)(?P=array)as&mut\[\[u8;32\]\]'
                   r'\(PointerCoercion\(Unsize,Implicit\)\);(?P<flat>_\d+)='
                   r'slice::<impl\[\[u8;32\]\]>::as_flattened_mut\((?:copy|move)(?P=slice)\)'
                   r'->\[return:bb' + str(2*i+1) + r',unwindunreachable\];\}')
        match = re.fullmatch(pattern, first)
        require(match is not None, 'whole owned field/flatten provenance')
        require(re.fullmatch(r'_\d+=clear_owned_region\((?:copy|move)' + match['flat'] +
                            r'\)->\[return:bb' + str(2*i+2) + r',unwindunreachable\];\}', second),
                'clear argument/control flow')
    require(compact(blocks['bb8']) == 'return;}}', 'wipe terminal block')
    operation = flow.exact_function(mir, ('fn '+NAMESPACE+'::<impl', '::drop(_1: &mut Operation<'))
    require('scratch::Workspace::wipe(' in operation and '.1:' in operation, 'operation lost workspace cleanup')
    definitions = re.findall(r'^define [^\n]*\{.*?^}', llvm, re.M | re.S)
    wipes = [body for body in definitions if all(token in body.splitlines()[0] for token in
                                               (NAMESPACE, 'Workspace', 'wipe'))]
    require(len(wipes) == 1, 'ambiguous LLVM wipe')
    calls = [line for line in wipes[0].splitlines() if not line.lstrip().startswith(';')
             and 'call ' in line and 'clear_owned_region' in line]
    require(len(calls) == 4, 'LLVM lost a clearing region')
    require([int(re.search(r'i(?:32|64) (?:noundef )?(\d+)\)', line)[1]) for line in calls] ==
            [800, 160, 160, 800], 'LLVM region widths')
    # The wrapper and opaque function are separate symbols. Select the
    # latter exactly, never inspect an unrelated ordinary/vector kernel.
    architecture = 'x86' if target.startswith('x86_64') else 'arm'
    pattern = (r'^[_A-Za-z][^\n]*' + NAMESPACE + r'[0-9]+' + architecture +
               r'6secret7permute[^\n]*:\s*(?://[^\n]*)?\n')
    matches = list(re.finditer(pattern, assembly, re.M))
    require(len(matches) == 1, 'missing/ambiguous opaque batch permutation symbol')
    tail = assembly[matches[0].start():]
    symbol = matches[0][0].split(':', 1)[0]
    ending = re.search(r'(?m)^\s*\.size\s+' + re.escape(symbol) + r',.*$', tail)
    require(ending is not None, 'missing exact opaque permutation end')
    # Linux's exact .size terminator also works when panic=abort omits CFI
    # at the MSRV. Normalize it for the shared instruction-only inspector.
    assembly = tail[:ending.end()] + '\n.cfi_endproc\n'
    # Whole-crate optimization specializes the public constants pointer.
    # These address-only operations do not load any data. Remove them only
    # before the opaque block; secret loads/stack spills still fail below.
    marker = '# BRYNJA_SECRET_BEGIN' if architecture == 'x86' else '// BRYNJA_SECRET_BEGIN'
    prefix, remainder = assembly.split(marker)
    if architecture == 'x86':
        prefix = re.sub(r'(?m)^\s*leaq\s+\.L[A-Za-z0-9_.]+\(%rip\),\s*%r[a-z0-9]+\s*$', '', prefix)
    else:
        prefix = re.sub(r'(?m)^\s*adrp\s+x[0-9]+,\s*\.L[A-Za-z0-9_.]+\s*$', '', prefix)
    boundary_assembly = prefix + marker + remainder
    sys.path.insert(0, str(ROOT / 'assurance/register-cleanup'))
    import check_keccak as boundary
    boundary.configure_keccak_batch()
    boundary.validator(architecture, boundary_assembly)


def compile_evidence(root, env, toolchain, target):
    run(['cargo', '+'+toolchain, 'rustc', '--locked', '--offline', '--release',
         '-p', 'brynja-crypto-cpu', '--no-default-features', '--features', FEATURE,
         '--target', target, '--', '--emit=mir,llvm-ir,asm'], root, env)
    base = Path(env['CARGO_TARGET_DIR']) / target / 'release/deps'
    artifacts = []
    for extension in ('mir', 'll', 's'):
        paths = list(base.glob('brynja_crypto_cpu-*.' + extension))
        require(len(paths) == 1, 'ambiguous emitted artifact')
        artifacts.append(paths[0].read_text())
    inspect(*artifacts, target)
    for index, before, after in (
        (0, '((*_1).0: [[u8; 32]; 25])', '((*_1).3: [[u8; 32]; 25])'),
        (0, 'clear_owned_region(', 'omitted_clear('),
        (1, 'clear_owned_region', 'omitted_clear'),
        (2, 'vpandn' if target.startswith('x86') else 'bic', 'omitted_instruction'),
    ):
        require(before in artifacts[index], 'inspector mutation anchor')
        changed = list(artifacts)
        changed[index] = changed[index].replace(before, after)
        try:
            inspect(*changed, target)
        except (ValueError, flow.MirCleanupFlowError):
            pass
        else:
            raise ValueError('inspector accepted a mutated artifact: ' + before)
    marker = '# ' if target.startswith('x86_64') else '// '
    load = 'movq (%rdi), %rax\n' if target.startswith('x86_64') else 'ldr x4, [x0]\n'
    for before, after in (
        (marker + 'BRYNJA_SECRET_BEGIN', load + marker + 'BRYNJA_SECRET_BEGIN'),
        (marker + 'BRYNJA_SECRET_END', marker + 'BRYNJA_SECRET_END\n' + load),
        ('BRYNJA_REGISTER_ERASE', 'MISSING_ERASURE_BOUNDARY'),
        ('6secret7permute', '6secret7missing'),
        ('.size', '.missing_size'),
    ):
        require(before in artifacts[2], 'opaque inspector mutation anchor')
        changed = artifacts[2].replace(before, after)
        try:
            inspect(artifacts[0], artifacts[1], changed, target)
        except (ValueError, flow.MirCleanupFlowError):
            pass
        else:
            raise ValueError('opaque inspector accepted a mutated artifact: ' + before)
    print(f'Hardened {FAMILY} batch compiler smoke: PASS; {toolchain}; {target}')


def layout_rejections(root, env, toolchain, target):
    """The byte reborrow must never survive a changed aggregate layout."""
    architecture = 'x86' if target.startswith('x86_64') else 'arm'
    path = root / SOURCE / (architecture + '.rs')
    original = path.read_text()
    size = 1920
    cases = [(f'size_of::<Workspace>() == {size}', f'size_of::<Workspace>() == {size - 1}')]
    cases += [(f'offset_of!(Workspace, {field}) == {offset}',
               f'offset_of!(Workspace, {field}) == {offset + 1}')
              for field, offset in (('state', 0), ('columns', 800),
                                    ('deltas', 960), ('staging', 1120))]
    command = ['cargo', '+'+toolchain, 'check', '--locked', '--offline',
               '-p', 'brynja-crypto-cpu', '--no-default-features',
               '--features', FEATURE, '--target', target]
    for release in (False, True):
        selected = command + (['--release'] if release else [])
        run(selected, root, env)
        for before, after in cases:
            require(original.count(before) == 1, 'layout mutation anchor')
            try:
                path.write_text(original.replace(before, after))
                result = subprocess.run(selected, cwd=root, env=env, text=True,
                                        capture_output=True, timeout=300)
                require(result.returncode != 0 and 'E0080' in result.stderr
                        and 'assertion failed' in result.stderr,
                        'layout mutation survived or unrelated compilation failure')
            finally:
                path.write_text(original)
        run(selected, root, env)
    print(f'Hardened {FAMILY} batch exact layout: ten debug/release mutations rejected')


def mutations(root, env, toolchain, target):
    command = ['cargo', '+'+toolchain, 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu',
               '--no-default-features', '--features', FEATURE, '--target', target,
               '--lib', NAMESPACE+'::tests::']
    env = dict(env, **{'BRYNJA_REQUIRE_'+FAMILY.upper()+'_HARDENED_BATCH': '1'})
    run(command, root, env)
    cases = [('scratch.rs', f'clear_owned_region(self.{field}.as_flattened_mut())', 'Ok::<(), ()>(())')
             for field in ('state', 'columns', 'deltas', 'staging')]
    cases += [
        ('scratch.rs', 'self.wipe();\n        #[cfg(test)]', '// omitted wipe\n        #[cfg(test)]'),
        ('mod.rs', 'self.workspace.wipe();', '// omitted operation wipe'),
        ('mod.rs', 'if !self.complete {', 'if false {'),
        ('mod.rs', 'platform::dispatch(self.kernel(), operation.workspace)?;', '// omitted dispatch'),
        ('mod.rs', '.checked_add(1)\n            .ok_or(Error::Invariant)?', '.wrapping_add(1)'),
        ('mod.rs', '};\n        self.ensure_healthy()?;\n        operation', '};\n        operation'),
        ('mod.rs', 'operation.workspace)?;\n        self.ensure_healthy()?;', 'operation.workspace)?;'),
        ('scratch.rs', '.enumerate().take(width)', '.enumerate().take(width.saturating_sub(1))'),
    ]
    rejected = 0
    for name, before, after in cases:
        path = root / SOURCE / name
        original = path.read_text()
        # Word and byte entry points each need their own load-bearing mutation:
        # changing both together could mask an untested entry point.
        doubled = ('platform::dispatch', '.checked_add', '};\n        self.ensure_healthy',
                   'operation.workspace)?;', '.enumerate().take')
        count = 2 if before.startswith(doubled) else 1
        require(original.count(before) == count, 'mutation anchor: ' + before)
        pieces = original.split(before)
        for occurrence in range(count):
            try:
                changed = pieces[0]
                for index, piece in enumerate(pieces[1:]):
                    changed += (after if index == occurrence else before) + piece
                path.write_text(changed)
                result = subprocess.run(command, cwd=root, env=env, text=True,
                                        capture_output=True, timeout=300)
                require(result.returncode != 0 and 'test result: FAILED' in result.stdout,
                        'mutant survived or failed to compile: ' + before + '\n' + result.stderr[-1500:])
                rejected += 1
            finally:
                path.write_text(original)
    run(command, root, env)
    print(f'Hardened {FAMILY} batch compiled cleanup/route/accounting mutants: {rejected} rejected')



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    parser.add_argument('--mutations', action='store_true')
    args = parser.parse_args()
    require(args.target.startswith(('x86_64', 'aarch64')), 'unsupported architecture')
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-keccak-batch-') as directory:
        root = Path(directory)
        for crate in ('brynja-core', 'brynja-crypto-cpu'):
            shutil.copytree(ROOT / 'crates' / crate, root / 'crates' / crate,
                            ignore=shutil.ignore_patterns('target'))
        manifest = (ROOT / 'Cargo.toml').read_text().replace('default-members = ["crates/brynja"]',
                                                          'default-members = ["crates/brynja-crypto-cpu"]')
        (root / 'Cargo.toml').write_text(manifest)
        env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'))
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET'):
            env.pop(key, None)
        run(['cargo', '+'+args.toolchain, 'generate-lockfile', '--offline'], root, env)
        compile_evidence(root, env, args.toolchain, args.target)
        if args.mutations:
            layout_rejections(root, env, args.toolchain, args.target)
            env['RUSTFLAGS'] = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64') else '+neon')
            if args.target == 'aarch64-unknown-linux-musl':
                env['RUSTFLAGS'] += ' -C linker=rust-lld'
            mutations(root, env, args.toolchain, args.target)
        env['RUSTDOCFLAGS'] = env.get('RUSTFLAGS', '')
        run(['cargo', '+'+args.toolchain, 'test', '--locked', '--offline',
             '-p', 'brynja-crypto-cpu', '--no-default-features', '--features', FEATURE,
             '--target', args.target, '--doc', NAMESPACE], root, env)

if __name__ == '__main__':
    main()
