#!/usr/bin/env python3
"""Packaged TupleHash execution APIs, affine ownership, and real compiled mutants."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/sha3'))
spec = importlib.util.spec_from_file_location('sha3_package', ROOT / 'scripts/sha3/check-sha3-execution.py')
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
shared.PACKAGES = (*shared.PACKAGES, 'brynja-hash-tuple')


def package(destination, env):
    _, roots = shared.package(destination, env)
    consumer = destination / 'tuplehash-consumer'
    shutil.copytree(ROOT / 'assurance/tuplehash-execution', consumer, ignore=shutil.ignore_patterns('target'))
    manifest = (consumer / 'Cargo.toml').read_text()
    for name, root in roots.items():
        manifest = manifest.replace(f'../../crates/{name}"', root.as_posix() + '"')
    manifest += '\n[features]\nhardened-execution=[]\n[patch.crates-io]\n'
    manifest += '\n'.join(f'{name}={{path="{root.as_posix()}"}}' for name, root in roots.items()) + '\n'
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'tests').mkdir(exist_ok=True)
    shutil.copyfile(roots['brynja-hash-tuple'] / 'tests/execution.rs', consumer / 'tests/execution.rs')
    return consumer, roots


def negatives(consumer, env):
    path = consumer / 'src/main.rs'
    original = path.read_text()
    prefix = '\n#[allow(dead_code)] fn rejected() { use brynja_hash_tuple::execution as api; '
    cases = []
    for name in ('TupleHash128', 'TupleHash256', 'TupleHashXof128', 'TupleHashXof256',
                 'HardenedTupleHash128', 'HardenedTupleHash256', 'HardenedTupleHashXof128',
                 'HardenedTupleHashXof256', 'Reader', 'HardenedReader', 'TupleItemWriter', 'KeccakSession'):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T:{bound}>(){{}} check::<api::{name}>();', 'E0277'))
    cases.extend((
        ('fn ordinary<T:api::HardenedState>(){} ordinary::<api::TupleHash128>();', 'E0277'),
        ('fn writer(h:&mut api::TupleHash128) { if let Ok(mut w)=h.begin_item(8) { let _=h.push_item(&[]); let _=w.update(&[]); } }', 'E0499'),
        ('struct Forged; impl api::HardenedState for Forged {}', 'E0277'),
        ('fn reuse(h:api::TupleHash128) { let mut b=[0;32]; let _=h.finalize(&mut b); let _=h.report(); }', 'E0382'),
        ('fn reuse(h:api::HardenedTupleHash256) { let mut b=[0;32]; let _=h.finalize_secret(&mut b); let _=h.report(); }', 'E0382'),
        ('fn borrow(h:&mut api::HardenedTupleHashXof128) { if let Ok(mut r)=h.finalize_xof() { let _=h.push_item(&[]); let _=r.squeeze_secret(&mut []); } }', 'E0499'),
        ('fn convert(x:brynja_hash_tuple::TupleHashSecretOutput) { let _: &[u8]=x; }', 'E0308'),
        ('let _:api::Mode = true.into();', 'E0277'),
    ))
    try:
        for code, diagnostic in cases:
            path.write_text(original + prefix + code + '}\n')
            result = shared.run(['cargo', 'check', '--offline'], consumer, env, False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('TupleHash ownership negative failed for wrong reason: ' + result.stderr)
    finally:
        path.write_text(original)
    print(f'Packaged TupleHash execution ownership: PASS; rejected={len(cases)}', flush=True)


def mutations(consumer, roots, env):
    root = roots['brynja-hash-tuple'] / 'src/execution'
    manifest = roots['brynja-hash-tuple'] / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' +
        '\n'.join(f'{name}={{path="{path.as_posix()}"}}' for name, path in roots.items()) + '\n')
    cases = [
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.' + field + ');', '',
         'metadata_cleanup_covers_every_owned_region')
        for field in ('pending', 'used', 'items', 'remaining', 'input_bits', 'output_bits', 'phase', 'staging')
    ]
    cases += [
        ('core_state.rs', 'if !self.completed {', 'if self.completed {', 'operation_guard_clears_on_early_return'),
        ('core_state.rs', 'let _ = clear_owned_region(bytes);', '', 'output_overflow_clears_secrets'),
    ]
    for file, before, after, test in cases:
        path = root / file
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous TupleHash mutation: ' + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(['cargo', 'test', '--offline', '-p', 'brynja-hash-tuple',
                    '--features', 'hardened-execution', '--lib', *profile, test], roots['brynja-hash-tuple'], env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('TupleHash mutant failed to execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print(f'Packaged TupleHash compiled cleanup/overflow mutants: PASS; rejected={len(cases)*2}', flush=True)


def algorithm_mutations(consumer, roots, env):
    root = roots['brynja-hash-tuple'] / 'src/execution'
    request = 'tuple128 0 - 256 2 24 000102 48 101112131415\n'
    expected = 'c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1\n'
    cases = (
        ('backend.rs', 'b"TupleHash"', 'b"WRONG"'),
        ('backend.rs', 'dispatch!(self, update(bytes))', 'let _ = (self, bytes); Ok(())'),
        ('core_state.rs', 'SecretEncodedInteger::left(bits)', 'SecretEncodedInteger::right(bits)'),
        ('core_state.rs', 'SecretEncodedInteger::right(bits)', 'SecretEncodedInteger::right(0)'),
    )
    def run(profile):
        return subprocess.run(['cargo', 'run', '--offline', '--quiet', *profile, '--', 'portable'],
            cwd=consumer, env=env, input=request, text=True, capture_output=True, timeout=180)
    for profile in ([], ['--release']):
        control = run(profile)
        if control.returncode or control.stdout != expected:
            raise ValueError('official TupleHash mutation control failed: ' + control.stderr)
    for name, before, after in cases:
        path = root / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous algorithm mutation')
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = run(profile)
                if 'could not compile' in result.stderr or 'panicked at' in result.stderr:
                    raise ValueError('algorithm mutant did not execute cleanly: ' + result.stderr)
                if result.returncode == 0 and result.stdout == expected:
                    raise ValueError('algorithm/verification mutant escaped: ' + before)
        finally:
            path.write_text(original)
    print('Packaged TupleHash algorithm/verification mutants: PASS; rejected=8', flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix='brynja-tuplehash-package-') as directory:
        destination = Path(directory)
        env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
        consumer, roots = package(destination, env)
        guide = (ROOT / 'docs/tuplehash-accelerated-execution.md').read_text()
        example = guide.split('```rust\n', 1)[1].split('```', 1)[0]
        (consumer / 'examples').mkdir()
        (consumer / 'examples/guide.rs').write_text(example)
        shared.run(['cargo', 'check', '--offline', '--example', 'guide'], consumer, env)
        for profile in ([], ['--release']):
            result = shared.run(['cargo', 'test', '--offline', '--features', 'hardened-execution',
                                 '--test', 'execution', *profile], consumer, env)
            if '6 passed; 0 failed' not in result.stdout:
                raise ValueError('packaged TupleHash execution suite incomplete')
        negatives(consumer, env)
        mutations(consumer, roots, env)
        algorithm_mutations(consumer, roots, env)
    print('Packaged TupleHash hardened execution public API: PASS')


if __name__ == '__main__':
    main()
