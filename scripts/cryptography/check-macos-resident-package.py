#!/usr/bin/env python3
"""Bounded native Apple Silicon development acceptance, not release qualification.

Uses actual extracted packages and Python hashlib as independent SHA-256 oracle.
No publication, gate change, privileged operation or dump capture.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout[-4000:]}\n{result.stderr[-6000:]}')
    return result.stdout


def mutations(cargo, hosted, env):
    prefix = 'macos_resident::'
    cases = (
        ('src/macos_resident/resource/darwin.rs',
         'let _ = brynja_core::clear_owned_region(bytes);', 'core::hint::black_box(&mut *bytes);',
         prefix + 'resource::darwin::tests::worker_placement_join_and_whole_payload_clear'),
        ('src/macos_resident/resource/darwin.rs',
         'unsafe { mlock(data.as_ptr().cast(), layout.payload) }', '0',
         prefix + 'resource::darwin::tests::worker_placement_join_and_whole_payload_clear'),
        ('src/macos_resident/sha256.rs', 'if !self.complete {', 'if self.complete {',
         prefix + 'sha256::tests::native::post_write_error_clears_both_resources_and_allows_reuse'),
    )
    for name, old, new, test in cases:
        path = hosted / name
        original = path.read_text()
        if original.count(old) != 1:
            raise ValueError('resident mutation anchor changed: ' + name)
        command = [*cargo, 'test', '--locked', '--offline', '--release', '--no-default-features',
                   '--features', 'macos-resident,strict-sha2', '--lib', test, '--', '--exact']
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('mutation baseline did not execute')
        try:
            path.write_text(original.replace(old, new))
            result = subprocess.run(command, cwd=hosted, env=env, text=True,
                                    capture_output=True, timeout=600)
            if not result.returncode or 'test result: FAILED. 0 passed; 1 failed;' not in result.stdout:
                raise ValueError('mutant survived or failed to compile: ' + name + '\n' + result.stderr[-4000:])
        finally:
            path.write_text(original)
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('restored baseline failed')
    print('Resident locking/stack-clear/output-clear compiled mutants: 3 rejected', flush=True)


def execute(toolchain, destination):
    cargo = ['cargo', '+' + toolchain]
    identity = subprocess.check_output(['rustc', '+' + toolchain, '-vV'], text=True)
    if 'host: aarch64-apple-darwin' not in identity.splitlines():
        raise ValueError('requires native Apple Silicon macOS; no cross-run pass')
    env = dict(os.environ, RUSTUP_TOOLCHAIN=toolchain, CARGO_TARGET_DIR=str(destination / 'target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(name, None)
    sys.path.insert(0, str(ROOT / 'scripts/sha3'))
    spec = importlib.util.spec_from_file_location('resident_packages', ROOT / 'scripts/sha3/check-sha3-execution.py')
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    _, roots = shared.package(destination, env)
    consumer = destination / 'resident-consumer'
    (consumer / 'src').mkdir(parents=True)
    patches = '\n'.join(f'{name} = {{ path = {json.dumps(str(path))} }}' for name, path in roots.items())
    manifest = ('[package]\nname="resident-consumer"\nversion="0.0.0"\nedition="2024"\n'
                '[workspace]\n[dependencies]\nbrynja-crypto-cpu-std = { path = ' +
                json.dumps(str(roots['brynja-crypto-cpu-std'])) +
                ', default-features=false, features=["macos-resident", "strict-sha2"] }\n'
                '[patch.crates-io]\n' + patches + '\n')
    (consumer / 'Cargo.toml').write_text(manifest)
    source = ('use brynja_crypto_cpu_std::macos_resident::{Sha256Session,Limits,Error};\n'
              'fn main() -> Result<(),Error> { let mut s=Sha256Session::new(Limits {'
              'stack_bytes:262144,max_stack_mapping_bytes:1048576,max_output_mapping_bytes:65536,'
              'max_message_bytes:8192,max_chunks:16})?;\n')
    lengths = (0, 1, 2, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 511, 1024, 4096, 8192)
    for length in lengths:
        message = bytes((i * 73 + length) % 256 for i in range(length))
        source += '{ let input: &[u8] = &' + repr(list(message)) + ';\n'
        source += 'assert_eq!(s.hash(input)?.expose(), &' + repr(list(hashlib.sha256(message).digest())) + '); }\n'
    source += 'println!("RESIDENT_PACKAGE_ORACLE: 17 passed; dump exclusion NOT claimed"); Ok(()) }\n'
    (consumer / 'src/main.rs').write_text(source)
    run([*cargo, 'generate-lockfile', '--offline'], consumer, env)
    metadata = json.loads(run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env))
    expected = {'resident-consumer', 'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}
    if {p['name'] for p in metadata['packages']} != expected:
        raise ValueError('packaged resident dependency closure changed')
    for package in metadata['packages']:
        parent = consumer if package['name'] == 'resident-consumer' else roots[package['name']]
        if package['source'] is not None or Path(package['manifest_path']).resolve() != (parent/'Cargo.toml').resolve():
            raise ValueError('dependency escaped extracted packages')
    for profile in ([], ['--release']):
        output = run([*cargo, 'run', '--locked', '--offline', *profile], consumer, env)
        if 'RESIDENT_PACKAGE_ORACLE: 17 passed; dump exclusion NOT claimed' not in output.splitlines():
            raise ValueError('oracle did not run')
        print(output.strip(), flush=True)
    hosted = roots['brynja-crypto-cpu-std']
    manifest = hosted/'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' + patches + '\n')
    run([*cargo, 'generate-lockfile', '--offline'], hosted, env)
    for target in ('--lib', '--doc'):
        output = run([*cargo, 'test', '--locked', '--offline', '--no-default-features',
                      '--features', 'macos-resident,strict-sha2', target, 'macos_resident'], hosted, env)
        if '0 failed' not in output or 'test result: ok. 0 passed;' in output:
            raise ValueError('packaged resident tests did not execute')
        print(output, flush=True)
    mutations(cargo, hosted, env)
    print('Packaged macOS resident profile: PASS; development evidence only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-macos-resident-') as directory:
        execute(args.toolchain, Path(directory))
