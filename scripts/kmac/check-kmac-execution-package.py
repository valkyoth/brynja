#!/usr/bin/env python3
"""Packaged KMAC execution APIs, affine ownership, and real compiled mutants."""
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
shared.PACKAGES = (*shared.PACKAGES, 'brynja-mac-kmac')


def package(destination, env):
    _, roots = shared.package(destination, env)
    consumer = destination / 'kmac-consumer'
    shutil.copytree(ROOT / 'assurance/kmac-execution', consumer, ignore=shutil.ignore_patterns('target'))
    manifest = (consumer / 'Cargo.toml').read_text()
    for name, root in roots.items():
        manifest = manifest.replace(f'../../crates/{name}"', root.as_posix() + '"')
    manifest += '\n[features]\nhardened-execution=[]\n[patch.crates-io]\n'
    manifest += '\n'.join(f'{name}={{path="{root.as_posix()}"}}' for name, root in roots.items()) + '\n'
    (consumer / 'Cargo.toml').write_text(manifest)
    (consumer / 'tests').mkdir(exist_ok=True)
    shutil.copyfile(roots['brynja-mac-kmac'] / 'tests/execution.rs', consumer / 'tests/execution.rs')
    return consumer, roots


def negatives(consumer, env):
    path = consumer / 'src/main.rs'
    original = path.read_text()
    prefix = '\n#[allow(dead_code)] fn rejected() { use brynja_mac_kmac::execution as api; '
    cases = []
    for name in ('Kmac128', 'Kmac256', 'KmacXof128', 'KmacXof256', 'Reader', 'KeccakSession'):
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T:{bound}>(){{}} check::<api::{name}>();', 'E0277'))
    cases.extend((
        ('struct Forged; impl api::HardenedState for Forged {}', 'E0277'),
        ('fn reuse(h:api::Kmac128) { let mut b=[0;32]; let _=h.finalize_tag(&mut b); let _=h.report(); }', 'E0382'),
        ('fn reuse(h:api::Kmac256) { let mut b=[0;32]; let _=h.finalize_secret(&mut b); let _=h.report(); }', 'E0382'),
        ('fn borrow(h:&mut api::KmacXof128) { if let Ok(mut r)=h.finalize_xof() { let _=h.update(&[]); let _=r.squeeze_secret(&mut []); } }', 'E0499'),
        ('fn convert(x:brynja_mac_kmac::KmacSecretOutput) { let _: &[u8]=x; }', 'E0308'),
        ('let _:api::Mode = true.into();', 'E0277'),
    ))
    scoped = 'brynja_mac_kmac::hardened_in_place'
    for name in ('Kmac128Workspace', 'Kmac256Workspace', 'Kmac128', 'Kmac256',
                 'KmacXof128Workspace', 'KmacXof256Workspace', 'KmacXof128',
                 'KmacXof256', 'KmacXof128Reader', 'KmacXof256Reader'):
        ty = f'{scoped}::{name}' + ("<'static>" if 'Workspace' not in name else '')
        for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
            cases.append((f'fn check<T:{bound}>(){{}} check::<{ty}>();', 'E0277'))
    for width in (128, 256):
        cases.append((f'fn reuse(h:{scoped}::Kmac{width}) {{ let mut b=[0;32]; let _=h.finalize_tag(&mut b); let _=h.key_policy(); }}', 'E0382'))
        cases.append((f'let mut w={scoped}::Kmac{width}Workspace::new(); let _=w.with(&[0;32], b"", |_| w.with(&[0;32], b"", |_| ()));', 'E0499'))
        cases.append((f'fn reuse(h:{scoped}::KmacXof{width}) {{ let _=h.finalize_xof(); let _=h.key_policy(); }}', 'E0382'))
        cases.append((f'fn reuse(h:{scoped}::KmacXof{width}Reader) {{ h.cancel(); let _=h.service_status(); }}', 'E0382'))
        cases.append((f'fn public(r:&mut {scoped}::KmacXof{width}Reader) {{ let _=r.squeeze_public(&mut []); }}', 'E0061'))
    for width in (128, 256):
        for name, lifetimes in ((f'Kmac{width}Workspace', "<'static>"),
                                (f'Kmac{width}', "<'static, 'static>")):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<api::in_place::{name}{lifetimes}>();', 'E0277'))
        cases.append((f'fn reuse(h:api::in_place::Kmac{width}) {{ let mut b=[0;32]; let _=h.finalize_secret(&mut b); let _=h.key_policy(); }}', 'E0382'))
        cases.append((f'fn overlap(w:&mut api::in_place::Kmac{width}Workspace) {{ let _=w.with(&[0;32],b"",|_|w.with(&[0;32],b"",|_|())); }}', 'E0500'))
        for name, lifetimes in ((f'KmacXof{width}Workspace', "<'static>"),
                                (f'KmacXof{width}', "<'static, 'static>"),
                                (f'KmacXof{width}Reader', "<'static, 'static>")):
            for bound in ('Send', 'Sync', 'Copy', 'Clone', 'core::fmt::Debug'):
                cases.append((f'fn check<T:{bound}>(){{}} check::<api::in_place::{name}{lifetimes}>();', 'E0277'))
        cases.append((f'fn reuse(h:api::in_place::KmacXof{width}) {{ let _=h.finalize_xof(); let _=h.key_policy(); }}', 'E0382'))
        cases.append((f'fn reuse(h:api::in_place::KmacXof{width}Reader) {{ h.cancel(); let _=h.service_status(); }}', 'E0382'))
        cases.append((f'fn public(r:&mut api::in_place::KmacXof{width}Reader) {{ let _=r.squeeze_public(&mut []); }}', 'E0061'))
    try:
        for code, diagnostic in cases:
            path.write_text(original + prefix + code + '}\n')
            result = shared.run(['cargo', 'check', '--offline'], consumer, env, False)
            if f'error[{diagnostic}]' not in result.stderr:
                raise ValueError('KMAC ownership negative failed for wrong reason: ' + result.stderr)
    finally:
        path.write_text(original)
    print(f'Packaged KMAC execution ownership: PASS; rejected={len(cases)}', flush=True)


def mutations(consumer, roots, env):
    root = roots['brynja-mac-kmac'] / 'src/execution'
    manifest = roots['brynja-mac-kmac'] / 'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' +
        '\n'.join(f'{name}={{path="{path.as_posix()}"}}' for name, path in roots.items()) + '\n')
    cases = (
        ('../packer.rs', 'brynja_core::xor_secret_byte_bits(pending, byte, position, take, used)',
         'Ok::<(), brynja_core::SecretBitRangeError>(())', 'borrowed_fragments_match_bit_oracle'),
        ('../packer.rs', 'xor_secret_byte_bits(pending, byte, position, take, used)',
         'xor_secret_byte_bits(pending, byte, 0, take, used)', 'borrowed_fragments_match_bit_oracle'),
        ('../packer.rs', 'xor_secret_byte_bits(pending, byte, position, take, used)',
         'xor_secret_byte_bits(pending, byte, position, take, 0)', 'borrowed_fragments_match_bit_oracle'),
        ('../packer.rs', 'if valid > 8 || self.used() >= 8',
         'if valid > 8', 'invalid_fragment_shape_rejects'),
        ('../packer.rs', 'clear_owned_region(&mut self.pending)', 'core::hint::black_box(&mut self.pending)', 'partial_tail_borrows_final_frame'),
        ('../packer.rs', 'clear_owned_region(&mut self.used)', 'core::hint::black_box(&mut self.used)', 'partial_tail_borrows_final_frame'),
        ('../packer.rs', 'clear_owned_region(&mut self.emitted)', 'core::hint::black_box(&mut self.emitted)', 'partial_tail_borrows_final_frame'),
        ('../packer.rs', 'self.storage.wipe();', '', 'partial_tail_borrows_final_frame'),
        ('../packer.rs', 'fn left_encode(&mut self, value: u128) -> Result<(), KmacError> {\n        self.wipe();',
         'fn left_encode(&mut self, value: u128) -> Result<(), KmacError> {', 'encoded_integer_initializes_in_place'),
        ('../packer.rs', 'let bytes = if self.used() == 0 {\n            &[][..]\n        } else {\n            &self.storage.pending[..]',
         'let copied = self.storage.pending;\n        let bytes = if self.used() == 0 {\n            &[][..]\n        } else {\n            &copied[..]', 'partial_tail_borrows_final_frame'),
        ('../packer.rs', 'self.state.absorb(input)?;',
         'for byte in input { self.state.absorb(core::slice::from_ref(byte))?; }',
         'large_final_chunks_keep_bulk_absorption'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.phase);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.key_class);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.message_bytes);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.output_bits);', '', 'every_metadata_region'),
        ('core_state.rs', 'if !self.completed {', 'if self.completed {', 'every_metadata_region'),
        ('core_state.rs', '.checked_add(length)', '.checked_sub(length)', 'overflow_clears_owner'),
        ('core_state.rs', 'let _ = clear_owned_region(output);', '', 'overflow_clears_owner'),
        ('../hardened_in_place/core_state.rs', 'clear_owned_region(&mut self.key_class)', 'core::hint::black_box(&mut self.key_class)', 'outer_guard_clears_all_regions'),
        ('../hardened_in_place/core_state.rs', 'clear_owned_region(&mut self.verification)', 'core::hint::black_box(&mut self.verification)', 'outer_guard_clears_all_regions'),
        ('../hardened_in_place/core_state.rs', 'clear_owned_region(&mut self.difference)', 'core::hint::black_box(&mut self.difference)', 'outer_guard_clears_all_regions'),
        ('../hardened_in_place/core_state.rs', 'self.0.wipe();', '', 'outer_guard_clears_all_regions'),
        ('../hardened_in_place/core_state.rs', 'self.core.state.0 = None;', '', 'rejected_and_unwinding_updates_destroy_state'),
        ('../hardened_in_place/core_state.rs', 'self.core.cleanup.0.wipe();', '', 'rejected_and_unwinding_updates_destroy_state'),
        ('../hardened_in_place/core_state.rs', 'let _ = clear_owned_region(output);', '', 'scoped_lifecycle_strength'),
        ('../hardened_in_place/core_state.rs', 'production && bits < strength', 'production && bits < 0', 'scoped_lifecycle_strength'),
        ('../hardened_in_place/core_state.rs', 'append_suffix(&mut self.state, input, bits,', 'append_suffix(&mut self.state, input, 0,', 'scoped_known_answer'),
        ('../hardened_in_place/core_state.rs', 'cleanup.0.difference.ct_eq(&[0])', 'cleanup.0.difference.ct_eq(&cleanup.0.difference)', 'scoped_lifecycle_strength'),
        ('../hardened_in_place/fixed.rs', 'key.bit_len() < $strength', 'key.bit_len() < 0', 'scoped_lifecycle_strength'),
        ('../hardened_in_place/fixed.rs', 'let cleanup = Guard(&mut self.metadata);', 'let mut cleanup = core::mem::ManuallyDrop::new(Guard(&mut self.metadata));', 'scoped_lifecycle_strength'),
        ('../hardened_in_place/fixed.rs', 'bytes(b"KMAC")?', 'bytes(b"WRONG")?', 'scoped_known_answer'),
        ('../hardened_in_place/core_state.rs', 'self.finish(input, 0, 0, false)', 'self.finish(input, 8, 0, false)', 'scoped_xof_returned_secret'),
        ('../hardened_in_place/core_state.rs', 'if production && self.key_policy() != KmacKeyPolicy::FullStrength {\n            return Err(KmacError::KeyTooShort);\n        }\n        // KMACXOF', '// KMACXOF', 'xof_production_rejects_weak_keys'),
        ('../hardened_in_place/reader.rs', '*self.reader = None;', '', 'reader_failure_and_unwind'),
        ('../hardened_in_place/reader.rs', 'self.metadata.wipe();', '', 'reader_failure_and_unwind'),
        ('../hardened_in_place/reader.rs', 'operation.complete = true;\n        Ok(())', 'Ok(())', 'scoped_xof_all_tails'),
        ('../hardened_in_place/reader.rs', 'operation.complete = true;\n        Ok(KmacSecretOutput::new(secret))', 'Ok(KmacSecretOutput::new(secret))', 'scoped_xof_all_tails'),
        ('../hardened_in_place/reader.rs', 'let _ = clear_owned_region(output);\n        let mut operation', 'let mut operation', 'reader_failure_and_unwind'),
        ('../hardened_in_place/reader.rs', 'let _ = clear_owned_region(output);\n        let reader', 'let reader', 'consuming_reader_failures'),
        ('../hardened_in_place/reader.rs', 'reader.final_public(\n            Fips202Output::new(output, valid)', 'reader.final_public(\n            Fips202Output::new(output, 8)', 'scoped_xof_lifecycle_shapes'),
        ('../hardened_in_place/accelerated.rs', 'brynja_core::clear_owned_region(self.0)', 'core::hint::black_box(&mut *self.0)', 'scoped_accelerated_scratch_guard'),
    )
    for profile in ([], ['--release']):
        control = shared.run(['cargo', 'test', '--offline', '-p', 'brynja-mac-kmac',
            '--features', 'hardened-execution,conformance-testing', '--lib', *profile, 'hardened_in_place'],
            roots['brynja-mac-kmac'], env)
        if '13 passed; 0 failed' not in control.stdout:
            raise ValueError('scoped KMAC mutation positive control incomplete')
    for file, before, after, test in cases:
        path = root / file
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous KMAC mutation: ' + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(['cargo', 'test', '--offline', '-p', 'brynja-mac-kmac',
                    '--features', 'hardened-execution,conformance-testing', '--lib', *profile, test], roots['brynja-mac-kmac'], env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('KMAC mutant failed to execute: ' + result.stderr)
        finally:
            path.write_text(original)
    print(f'Packaged KMAC compiled cleanup/overflow mutants: PASS; rejected={len(cases)*2}', flush=True)


def algorithm_mutations(consumer, roots, env):
    root = roots['brynja-mac-kmac'] / 'src/execution'
    key = bytes(range(0x40, 0x60)).hex()
    request = f'kmac128 256 {key} 0 - 32 00010203 256\n'
    expected = 'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e\n'
    cases = (
        ('backend.rs', 'b"KMAC"', 'b"WRONG"'),
        ('backend.rs', 'dispatch!(self, update(bytes))', 'let _ = (self, bytes); Ok(())'),
        ('core_state.rs', 'if xof { 0 } else { bits }', 'if xof { bits } else { 0 }'),
        ('output.rs', 'difference.accumulate(*actual ^ *expected)', 'difference.accumulate(*actual ^ *actual); let _ = expected'),
    )
    def run(profile):
        return subprocess.run(['cargo', 'run', '--offline', '--quiet', *profile, '--', 'portable'],
            cwd=consumer, env=env, input=request, text=True, capture_output=True, timeout=180)
    for profile in ([], ['--release']):
        control = run(profile)
        if control.returncode or control.stdout != expected:
            raise ValueError('official KMAC mutation control failed: ' + control.stderr)
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
    print('Packaged KMAC algorithm/verification mutants: PASS; rejected=8', flush=True)


def native_xof_mutations(consumer, roots, env):
    path = roots['brynja-mac-kmac'] / 'src/hardened_in_place/accelerated/xof.rs'
    original = path.read_text()
    cases = (
        ('self.finish(None, true)', 'self.finish(None, false)'),
        ('self.finish(Some(input), true)', 'self.finish(None, true)'),
        ('self.inner.public(output)', 'Ok(())'),
        ('self.inner.secret(output)', 'Err(KmacError::SecretMemory)'),
        ('self.inner.final_public(output, valid)', 'self.inner.final_public(output, 8)'),
        ('self.inner.final_secret(output, valid)', 'self.inner.final_secret(output, 8)'),
    )
    command = ['cargo', 'test', '--offline', '--test', 'scoped']
    for profile in ([], ['--release']):
        result = shared.run(command + profile, consumer, env)
        if '4 passed; 0 failed' not in result.stdout:
            raise ValueError('native scoped KMAC control did not execute all tests')
    for before, after in cases:
        if original.count(before) != 1:
            raise ValueError('ambiguous scoped XOF mutation: ' + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(command + profile, consumer, env, False)
                if 'test result: FAILED' not in result.stdout:
                    raise ValueError('native scoped XOF mutant did not fail at runtime: ' + before + result.stderr)
        finally:
            path.write_text(original)
    print('Packaged native scoped KMACXOF mutants: PASS; rejected=12', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    native = parser.add_mutually_exclusive_group()
    native.add_argument('--native-x86', action='store_true')
    native.add_argument('--native-arm', action='store_true')
    args = parser.parse_args()
    native_env = None
    if args.native_x86 or args.native_arm:
        module = importlib.import_module('check-kmac-execution')
        native_env = module.native_environment(args.native_arm)
    with tempfile.TemporaryDirectory(prefix='brynja-kmac-package-') as directory:
        destination = Path(directory)
        env = dict(os.environ, CARGO_TARGET_DIR=str(destination / 'target'))
        consumer, roots = package(destination, env)
        guide = (ROOT / 'docs/kmac-accelerated-execution.md').read_text()
        example = guide.split('```rust\n', 1)[1].split('```', 1)[0]
        (consumer / 'examples').mkdir()
        (consumer / 'examples/guide.rs').write_text(example)
        shared.run(['cargo', 'check', '--offline', '--example', 'guide'], consumer, env)
        for profile in ([], ['--release']):
            result = shared.run(['cargo', 'test', '--offline', '--features', 'hardened-execution',
                                 '--test', 'execution', *profile], consumer, env)
            if '7 passed; 0 failed' not in result.stdout:
                raise ValueError('packaged KMAC execution suite incomplete')
        negatives(consumer, env)
        mutations(consumer, roots, env)
        algorithm_mutations(consumer, roots, env)
        if native_env is not None:
            selected = dict(native_env, CARGO_TARGET_DIR=env['CARGO_TARGET_DIR'])
            native_xof_mutations(consumer, roots, selected)
    print('Packaged KMAC hardened execution public API: PASS')


if __name__ == '__main__':
    main()
