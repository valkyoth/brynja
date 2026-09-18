#!/usr/bin/env python3
"""Packaged TupleHash execution APIs, affine ownership, and real compiled mutants."""
import importlib.util
import argparse
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
    scoped = 'brynja_hash_tuple::hardened_in_place'
    for strength in (128, 256):
        state = f'{scoped}::TupleHash{strength}'
        for name in (f'TupleHash{strength}Workspace', f'TupleHash{strength}', f'TupleHash{strength}ItemWriter'):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<{scoped}::{name}>();', 'E0277'))
        cases += [
            (f'fn reuse(s:{state}) {{ let _=s.finalize_secret(&mut []); s.cancel(); }}', 'E0382'),
            (f'fn public(s:{state}) {{ let _=s.finalize_public(&mut []); }}', 'E0061'),
            (f'fn query(s:{state}) {{ let _=s.item_count(); }}', 'E0599'),
            (f'fn query(s:{state}) {{ let _=s.check_additional_bits(1); }}', 'E0599'),
            (f'fn query(w:{scoped}::TupleHash{strength}ItemWriter) {{ let _=w.remaining_bits(); }}', 'E0599'),
        ]
        xof = f'{scoped}::TupleHashXof{strength}'
        for name in (xof, xof + 'Workspace', xof + 'Reader'):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<{name}>();', 'E0277'))
        cases += [
            (f'fn reuse(s:{xof}) {{ let _=s.finalize_xof(); s.cancel(); }}', 'E0382'),
            (f'fn reuse(r:{xof}Reader) {{ let _=r.squeeze_final_bits_secret(&mut [],0); r.cancel(); }}', 'E0382'),
            (f'fn public(mut r:{xof}Reader) {{ let _=r.squeeze_public(&mut []); }}', 'E0061'),
            (f'fn query(s:{xof}) {{ let _=s.item_count(); }}', 'E0599'),
            (f'fn query(s:{xof}) {{ let _=s.check_additional_bits(1); }}', 'E0599'),
        ]
        accelerated = 'brynja_hash_tuple::execution::in_place'
        state = f'{accelerated}::TupleHash{strength}'
        for name in (f'TupleHash{strength}Workspace', f'TupleHash{strength}', f'TupleHash{strength}ItemWriter'):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<{accelerated}::{name}>();', 'E0277'))
        cases += [
            (f'fn reuse(s:{state}) {{ let _=s.finalize_secret(&mut []); s.cancel(); }}', 'E0382'),
            (f'fn public(s:{state}) {{ let _=s.finalize_public(&mut []); }}', 'E0061'),
            (f'fn query(s:{state}) {{ let _=s.item_count(); }}', 'E0599'),
            (f'fn query(s:{state}) {{ let _=s.check_additional_bits(1); }}', 'E0599'),
            (f'fn escape() -> Result<{accelerated}::TupleHash{strength}Workspace<\'static>, api::Error> {{ '
             'let a=brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).map_err(|_|api::Error::AccelerationUnavailable)?; '
             f'{accelerated}::TupleHash{strength}Workspace::new(api::KeccakSession::from_static(&a).map_err(|_|api::Error::AccelerationUnavailable)?) }}', 'E0515'),
        ]
        xof = f'{accelerated}::TupleHashXof{strength}'
        for name in (xof, xof + 'Workspace', xof + 'Reader'):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<{name}>();', 'E0277'))
        cases += [
            (f'fn reuse(s:{xof}) {{ let _=s.finalize_xof(); s.cancel(); }}', 'E0382'),
            (f'fn reuse(r:{xof}Reader) {{ let _=r.squeeze_final_bits_secret(&mut [],0); r.cancel(); }}', 'E0382'),
            (f'fn public(mut r:{xof}Reader) {{ let _=r.squeeze_public(&mut []); }}', 'E0061'),
            (f'fn query(s:{xof}) {{ let _=s.item_count(); }}', 'E0599'),
            (f'fn query(s:{xof}) {{ let _=s.check_additional_bits(1); }}', 'E0599'),
            (f'fn escape() -> Result<{xof}Workspace<\'static>, api::Error> {{ '
             'let a=brynja_crypto_cpu::static_execution::Authority::new(brynja_crypto_cpu::static_execution::Kernel::X86Keccak).map_err(|_|api::Error::AccelerationUnavailable)?; '
             f'{xof}Workspace::new(api::KeccakSession::from_static(&a).map_err(|_|api::Error::AccelerationUnavailable)?) }}', 'E0515'),
        ]
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
        ('core_state.rs', '.and_then(|n| n.checked_add(bits))', '',
         'begin_preflights_the_complete_item_but_commits_only_its_prefix'),
        ('core_state.rs', 'write_counter(&mut core.metadata.input_bits, total)?;\n        write_counter(&mut core.metadata.remaining, bits)?;',
         'write_counter(&mut core.metadata.input_bits, total + bits)?;\n        write_counter(&mut core.metadata.remaining, bits)?;',
         'begin_preflights_the_complete_item_but_commits_only_its_prefix'),
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
        ('core_state.rs', 'prefix.left(bits)', 'prefix.right(bits)'),
        ('core_state.rs', 'suffix.right(bits)', 'suffix.right(0)'),
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


def encoding_mutations(roots, env):
    crate = roots['brynja-hash-tuple']
    path = crate / 'src/secret_encoding.rs'
    original = path.read_text()
    cases = (
        ('self.reset();', '', 1),
        ('fn right(&mut self, value: u128) -> Result<(), TupleHashError> {\n        self.reset();',
         'fn right(&mut self, value: u128) -> Result<(), TupleHashError> {', 1),
        ('clear_owned_region(&mut self.bytes)', 'core::hint::black_box(&mut self.bytes)', 1),
        ('if !(2..=17).contains(&length)', 'if length > 17', 1),
        ('*target = byte;', '*target = byte ^ 1;', 1),
    )
    def run(profile, success=True):
        return shared.run(['cargo', 'test', '--offline', '--lib', *profile,
                           'secret_encoding::tests'], crate, env, success)
    for profile in ([], ['--release']):
        if '3 passed; 0 failed' not in run(profile).stdout:
            raise ValueError('secret encoding mutation control incomplete')
    for before, after, count in cases:
        if original.count(before) < count:
            raise ValueError('missing secret encoding mutation target')
        try:
            path.write_text(original.replace(before, after, count))
            for profile in ([], ['--release']):
                result = run(profile, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('secret encoding mutant did not execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print('Packaged TupleHash borrowed encoding mutants: PASS; rejected=10', flush=True)


def scoped_mutations(roots, env):
    crate = roots['brynja-hash-tuple']
    root = crate / 'src/hardened_in_place'
    cases = [('core_state.rs', f'clear_owned_region(&mut self.{field})', f'core::hint::black_box(&mut self.{field})')
             for field in ('pending', 'used', 'items', 'remaining', 'input_bits', 'phase', 'staging')]
    cases += [
        ('core_state.rs', 'self.0.wipe();', ''),
        ('core_state.rs', 'self.core.cancel();', ''),
        ('core_state.rs', 'self.state = None;', ''),
        ('core_state.rs', 'self.phase(1)?;', ''),
        ('core_state.rs', 'if read(&core.cleanup.0.remaining) != 0', 'if false'),
        ('core_state.rs', 'total\n            .checked_add(bits)', 'total\n            .checked_add(0)'),
        ('core_state.rs', 'clear_owned_region(bytes)', 'core::hint::black_box(&mut *bytes)'),
        ('core_state.rs', 'suffix.right(bits)?;', 'suffix.right(0)?;'),
        ('fixed.rs', 'bytes_input(b"TupleHash")?', 'bytes_input(b"WRONG")?'),
        ('fixed.rs', 'if !self.complete { self.core.cancel(); }', ''),
        ('core_state.rs', 'self.finish(0)', 'self.finish(1)'),
        ('reader.rs', '*self.reader = None;', ''),
        ('reader.rs', 'self.metadata.wipe();', ''),
        ('reader.rs', 'if !self.complete {', 'if self.complete {'),
        ('reader.rs', 'clear_owned_region(output);\n        let mut guard', 'core::hint::black_box(&mut *output);\n        let mut guard'),
        ('reader.rs', 'clear_owned_region(output);\n        let reader', 'core::hint::black_box(&mut *output);\n        let reader'),
        ('backend.rs', 'self.squeeze_public(output, Sha3PublicDeclassification::acknowledge())',
         'Ok::<(), brynja_hash_sha3::HardenedSha3Error>(())'),
    ]
    command = ['cargo', 'test', '--offline', '--lib', 'hardened_in_place::']
    for profile in ([], ['--release']):
        if '13 passed; 0 failed' not in shared.run(command + profile, crate, env).stdout:
            raise ValueError('scoped TupleHash mutation control incomplete')
    for name, before, after in cases:
        path = root / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous scoped mutation: ' + before)
        print('Scoped TupleHash mutation: ' + name + ': ' + before, flush=True)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(command + profile, crate, env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('scoped mutant failed to execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print(f'Packaged scoped TupleHash mutants: PASS; rejected={len(cases)*2}', flush=True)


def accelerated_mutations(consumer, roots, env):
    root = roots['brynja-hash-tuple'] / 'src/hardened_in_place'
    cases = [
        ('accelerated.rs', 'brynja_core::clear_owned_region(self.0)', 'core::hint::black_box(&mut *self.0)'),
        ('accelerated/fixed.rs', 'bytes_input(b"TupleHash")?', 'bytes_input(b"WRONG")?'),
        ('accelerated/backend.rs', 'self.state.update(bytes)', 'Ok::<(), brynja_hash_sha3::hardened_execution::Error>(())'),
        ('accelerated/backend.rs', '.squeeze_final_bits_secret(output, valid)', '.squeeze_final_bits_secret(output, 8)'),
        ('core_state.rs', 'self.finish(0)', 'self.finish(1)'),
        ('reader.rs', '.read_public(output)?', '.read_public(&mut [])?'),
        ('reader.rs', 'clear_owned_region(output);\n        let mut guard', 'core::hint::black_box(&mut *output);\n        let mut guard'),
        ('reader.rs', 'clear_owned_region(output);\n        let reader', 'core::hint::black_box(&mut *output);\n        let reader'),
    ]
    command = ['cargo', 'test', '--offline', '--test', 'scoped_accelerated']
    for profile in ([], ['--release']):
        if '7 passed; 0 failed' not in shared.run(command + profile, consumer, env).stdout:
            raise ValueError('native scoped TupleHash positive control incomplete')
    for name, before, after in cases:
        path = root / name
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous accelerated scoped mutation: ' + before)
        print('Native scoped TupleHash mutation: ' + name + ': ' + before, flush=True)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(command + profile, consumer, env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('accelerated scoped mutant did not execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print(f'Packaged native scoped TupleHash mutants: PASS; rejected={len(cases)*2}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    native = parser.add_mutually_exclusive_group()
    native.add_argument('--native-x86', action='store_true')
    native.add_argument('--native-arm', action='store_true')
    args = parser.parse_args()
    native_env = None
    if args.native_x86 or args.native_arm:
        native_env = importlib.import_module('check-tuplehash-execution').native_environment(args.native_arm)
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
            scoped = shared.run(['cargo', 'test', '--offline', '--test', 'scoped', *profile], consumer, env)
            if '4 passed; 0 failed' not in scoped.stdout:
                raise ValueError('packaged scoped TupleHash suite incomplete')
        negatives(consumer, env)
        mutations(consumer, roots, env)
        algorithm_mutations(consumer, roots, env)
        encoding_mutations(roots, env)
        scoped_mutations(roots, env)
        if native_env is not None:
            accelerated_mutations(consumer, roots, dict(native_env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR']))
    print('Packaged TupleHash hardened execution public API: PASS')


if __name__ == '__main__':
    main()
