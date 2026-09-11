#!/usr/bin/env python3
"""Packaged KMAC execution APIs, affine ownership, and real compiled mutants."""
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
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.phase);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.key_class);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.message_bytes);', '', 'every_metadata_region'),
        ('core_state.rs', 'let _ = clear_owned_region(&mut self.output_bits);', '', 'every_metadata_region'),
        ('core_state.rs', 'if !self.completed {', 'if self.completed {', 'every_metadata_region'),
        ('core_state.rs', '.checked_add(length)', '.checked_sub(length)', 'overflow_clears_owner'),
        ('core_state.rs', 'let _ = clear_owned_region(output);', '', 'overflow_clears_owner'),
    )
    for file, before, after, test in cases:
        path = root / file
        original = path.read_text()
        if original.count(before) != 1:
            raise ValueError('ambiguous KMAC mutation: ' + before)
        try:
            path.write_text(original.replace(before, after))
            for profile in ([], ['--release']):
                result = shared.run(['cargo', 'test', '--offline', '-p', 'brynja-mac-kmac',
                    '--features', 'hardened-execution', '--lib', *profile, test], roots['brynja-mac-kmac'], env, False)
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


def main():
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
    print('Packaged KMAC hardened execution public API: PASS')


if __name__ == '__main__':
    main()
