#!/usr/bin/env python3
"""Development regression campaign for the hardened SHA-2 batch foundations.

This is not native qualification or the complete v0.24.48 acceptance gate.
Compiled mutants execute only with an explicitly selected compiled-target
bundle. The operator must uphold that bundle on the test machine.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FAMILY = 'sha256'
NAMESPACE = 'sha256_hardened_batch'
SOURCE = 'crates/brynja-crypto-cpu/src/sha256_hardened_batch/'
FEATURE = 'sha256-hardened-batch'
LEAF = 'hardened_batch'
LEAF_FEATURE = 'hardened-batch-execution'
sys.path.insert(0, str(ROOT / 'scripts/cryptography'))
import mir_cleanup_flow as flow


def require(condition, message):
    if not condition:
        raise ValueError('hardened SHA-256 batch regression: ' + message)


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
    for i, count in enumerate((8, 64 if FAMILY == 'sha256' else 80, 8, 6)):
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
            [256, 2048 if FAMILY == 'sha256' else 2560, 256, 192], 'LLVM region widths')
    # Reuse the ordinary instruction inspector's exact function-boundary and
    # lane-width checks, mapping only the namespace of this separate kernel.
    spec = importlib.util.spec_from_file_location('batch_codegen', ROOT / f'scripts/sha2/check-{FAMILY}-batch-codegen.py')
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    checker.inspect(assembly.replace(NAMESPACE, FAMILY+'_batch'), target)


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
        (0, '((*_1).0: [[u8; 32]; 8])', '((*_1).2: [[u8; 32]; 8])'),
        (0, 'clear_owned_region(', 'omitted_clear('),
        (1, 'clear_owned_region', 'omitted_clear'),
        (2, ('vpaddd' if FAMILY == 'sha256' else 'vpaddq') if target.startswith('x86') else 'ushr', 'omitted_instruction'),
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
    print(f'Hardened {FAMILY} batch compiler smoke: PASS; {toolchain}; {target}')


def mutations(root, env, toolchain, target):
    command = ['cargo', '+'+toolchain, 'test', '--locked', '--offline', '-p', 'brynja-crypto-cpu',
               '--no-default-features', '--features', FEATURE, '--target', target,
               '--lib', NAMESPACE+'::tests::']
    env = dict(env, **{'BRYNJA_REQUIRE_'+FAMILY.upper()+'_HARDENED_BATCH': '1'})
    run(command, root, env)
    cases = [('scratch.rs', f'clear_owned_region(self.{field}.as_flattened_mut())', 'Ok::<(), ()>(())')
             for field in ('initial', 'schedule', 'work', 'temporary')]
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


def public_conversion_rejection(root, env, toolchain, target):
    """Reject a real conversion, not a misspelled or unavailable digest type."""
    consumer = root / 'public-conversion'
    (consumer / 'src').mkdir(parents=True)
    (consumer / 'Cargo.toml').write_text(
        '[package]\nname="hardened-conversion-probe"\nversion="0.0.0"\nedition="2024"\n'
        '[workspace]\n[dependencies]\n'
        'brynja-hash-sha2={path="../crates/brynja-hash-sha2", default-features=false, '
        'features=["'+LEAF_FEATURE+'"]}\n')
    path = consumer / 'src/lib.rs'
    command = ['cargo', '+'+toolchain, 'check', '--offline', '--manifest-path',
               str(consumer / 'Cargo.toml'), '--target', target]
    digests = ('Sha256Digest',) if FAMILY == 'sha256' else ('Sha512Digest', 'Sha512TDigest')
    for digest in digests:
        imports = ('use brynja_hash_sha2::{'+digest+', '+LEAF+'::SecretBatchOutput};\n')
        path.write_text(imports + 'pub fn types(_: Option<'+digest+'>, _: Option<SecretBatchOutput<\'_>>) {}\n')
        run(command, root, env)
        path.write_text(imports + 'pub fn convert(out: SecretBatchOutput<\'_>) -> '+digest+' { out.into() }\n')
        result = subprocess.run(command + ['--locked'], cwd=root, env=env, text=True,
                                capture_output=True, timeout=300)
        require(result.returncode != 0 and 'error[E0277]' in result.stderr
                and 'error[E0412]' not in result.stderr,
                'secret/public conversion must fail for missing From, not an unknown type: '+result.stderr)
    print(f'Hardened {FAMILY} public conversion: valid types; missing From rejected')


def leaf_mutations(root, env, toolchain, target):
    command = ['cargo', '+'+toolchain, 'test', '--locked', '--offline', '-p', 'brynja-hash-sha2',
               '--no-default-features', '--features', LEAF_FEATURE, '--target', target,
               '--lib', LEAF+'::']
    env = dict(env, **{'BRYNJA_REQUIRE_'+FAMILY.upper()+'_HARDENED_BATCH': '1'})
    run(command, root, env)
    env['RUSTDOCFLAGS'] = env.get('RUSTFLAGS', '')
    run(command[:-2] + ['--doc', LEAF], root, env)
    public_conversion_rejection(root, env, toolchain, target)
    source = root / 'crates/brynja-hash-sha2/src' / LEAF
    cases = [('workspace.rs', f'clear_owned_region(self.{field}.as_flattened_mut())', 'Ok::<(), ()>(())')
             for field in ('states', 'packed', 'blocks', 'output', 'offsets')]
    cases += [('workspace.rs', f'clear_owned_region(&mut self.{field})', 'Ok::<(), ()>(())')
              for field in ('indices', 'active')]
    cases += [
        ('workspace.rs', 'self.scalar.wipe();', '// missing scalar teardown'),
        ('workspace.rs', 'self.wipe();\n        #[cfg(test)]', '// missing destructor wipe\n        #[cfg(test)]'),
        ('output.rs', 'clear_owned_region(destination)', 'Ok::<(), ()>(())'),
        ('output.rs', 'destination.copy_from_slice(source);', '// missing declassification write'),
        ('output.rs', '*out = *byte;', '// missing public output write'),
        ('mod.rs', 'self.workspace.wipe();', '// missing operation cleanup'),
        ('mod.rs', 'if !self.complete {', 'if false {'),
        ('engine.rs', 'executor.check()?;', '// missing final revalidation'),
        ('engine.rs', 'Algorithm::Sha224 => crate::sha224::INITIAL_STATE',
                       'Algorithm::Sha224 => crate::sha256::INITIAL_STATE'),
        ('engine.rs', 'byte | (0x80_u8 >> valid)', 'byte'),
        ('engine.rs', 'remainder.len() >= 56', 'remainder.len() > 56'),
        ('engine.rs', 'length.to_be_bytes()', 'length.to_le_bytes()'),
        ('engine.rs', 'scalar(s, control, report)?;', '// omitted complete message block'),
        ('engine.rs', 'total.checked_add(additional).ok_or(Error::Invariant)',
                       'Ok(total.wrapping_add(additional))'),
    ]
    if FAMILY == 'sha512':
        cases = [(name, before, after) for name, before, after in cases
                 if not before.startswith('Algorithm::Sha224')]
        cases = [(name, before.replace('>= 56', '>= 112'), after.replace('> 56', '> 112'))
                 for name, before, after in cases]
        cases += [
            ('algorithm.rs', 'Self::Sha384 => crate::sha384::INITIAL_STATE',
                             'Self::Sha384 => crate::sha512::INITIAL_STATE'),
            ('algorithm.rs', 't.last_byte_mask()', '0xff'),
            ('algorithm.rs', '0x1000 | t.bits()', '0x1000 | 9'),
            ('engine.rs', 'control.charge(1)?;\n                report.scalar_blocks',
                          'control.charge(0)?;\n                report.scalar_blocks'),
        ]
    for name, before, after in cases:
        path = source / name
        original = path.read_text()
        require(original.count(before) == 1, 'leaf mutation anchor: ' + before)
        try:
            path.write_text(original.replace(before, after))
            result = subprocess.run(command, cwd=root, env=env, text=True,
                                    capture_output=True, timeout=300)
            require(result.returncode != 0 and 'test result: FAILED' in result.stdout,
                    'leaf mutant survived or failed to compile: ' + before + '\n' + result.stderr[-1500:])
        finally:
            path.write_text(original)
    run(command, root, env)
    print(f'Hardened {FAMILY} leaf compiled cleanup/framing/route mutants: {len(cases)} rejected')


def main():
    global FAMILY, NAMESPACE, SOURCE, FEATURE, LEAF, LEAF_FEATURE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', choices=('sha256', 'sha512'), default='sha256')
    parser.add_argument('--toolchain', default='1.98.1')
    parser.add_argument('--target', default='x86_64-unknown-linux-gnu')
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--leaf', action='store_true', help='also run the leaf tests and compiled mutants')
    args = parser.parse_args()
    FAMILY = args.family
    NAMESPACE = FAMILY+'_hardened_batch'
    SOURCE = 'crates/brynja-crypto-cpu/src/'+NAMESPACE+'/'
    FEATURE = FAMILY+'-hardened-batch'
    LEAF = 'hardened_batch' if FAMILY == 'sha256' else 'hardened_batch512'
    LEAF_FEATURE = 'hardened-batch-execution' if FAMILY == 'sha256' else 'hardened-batch512-execution'
    require(args.target.startswith(('x86_64', 'aarch64')), 'unsupported evidence architecture')
    with tempfile.TemporaryDirectory(prefix='brynja-hardened-sha256-batch-') as directory:
        root = Path(directory)
        crates = ['brynja-core', 'brynja-crypto-cpu']
        if args.leaf:
            crates += ['brynja-hash-core', 'brynja-hash-sha2']
        for crate in crates:
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
        if args.mutations or args.leaf:
            env['RUSTFLAGS'] = '-C target-feature=' + ('+avx,+avx2' if args.target.startswith('x86_64') else '+neon')
            if args.target == 'aarch64-unknown-linux-musl':
                env['RUSTFLAGS'] += ' -C linker=rust-lld'
            if args.mutations:
                mutations(root, env, args.toolchain, args.target)
            if args.leaf:
                leaf_mutations(root, env, args.toolchain, args.target)


if __name__ == '__main__':
    main()
