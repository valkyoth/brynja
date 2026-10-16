#!/usr/bin/env python3
"""Extracted native Mac batch development checks; not release qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import macos_resident_batch_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
FEATURE = 'macos-resident-batch'
PREFIX = 'macos_resident::batch::'


def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout[-4000:]}\n{result.stderr[-6000:]}')
    return result.stdout


def mutations(cargo, hosted, env):
    cases = [
        ('mod.rs', 'if !self.keep {', 'if self.keep {',
         'failures_and_forgotten_outputs_preserve_only_ordinary_reuse'),
        ('mod.rs', 'self.scratch.clear();', 'core::hint::black_box(&mut self.scratch);',
         'failures_and_forgotten_outputs_preserve_only_ordinary_reuse'),
        ('mod.rs', 'self.output.clear();', 'core::hint::black_box(&mut self.output);',
         'sparse_outputs_invalid_bits_and_declassification_are_transactional'),
        ('mod.rs', 'if types::reusable(&result) {', 'if true {',
         'failures_and_forgotten_outputs_preserve_only_ordinary_reuse'),
        ('worker.rs', 'Ok(sha256::Input::new(\n        algorithm,',
         'Ok(sha256::Input::new(\n        sha256::Algorithm::Sha256,',
         'native_batch_routes_bits_boundaries_and_general_parameters'),
    ]
    for name, old, new, test in cases:
        path = hosted / 'src/macos_resident/batch' / name
        original = path.read_text()
        if old not in original:
            raise ValueError('mutation anchor missing: ' + name)
        command = [*cargo, 'test', '--locked', '--offline', '--release',
                   '--no-default-features', '--features', FEATURE, '--lib',
                   PREFIX + 'tests::native::' + test, '--', '--exact']
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('mutation baseline did not execute')
        try:
            path.write_text(original.replace(old, new))
            result = subprocess.run(command, cwd=hosted, env=env, text=True,
                                    capture_output=True, timeout=600)
            if not result.returncode or 'test result: FAILED. 0 passed; 1 failed;' not in result.stdout:
                raise ValueError('mutant survived or failed compilation: ' + name + ': ' + old +
                                 '\n' + result.stdout[-2000:] + '\n' + result.stderr[-4000:])
        finally:
            path.write_text(original)
        if 'test result: ok. 1 passed;' not in run(command, hosted, env):
            raise ValueError('restored baseline failed')
    print(f'Resident batch compiled mutants: {len(cases)} rejected', flush=True)


def execute(toolchain, destination):
    cargo = ['cargo', '+' + toolchain]
    identity = subprocess.check_output(['rustc', '+' + toolchain, '-vV'], text=True)
    if 'host: aarch64-apple-darwin' not in identity.splitlines():
        raise ValueError('requires native Apple Silicon macOS')
    print(identity, flush=True)
    env = dict(os.environ, RUSTUP_TOOLCHAIN=toolchain, CARGO_TARGET_DIR=str(destination/'target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(name, None)
    env['RUSTFLAGS'] = '-C target-feature=+neon'
    sys.path.insert(0, str(ROOT/'scripts/sha3'))
    spec = importlib.util.spec_from_file_location('batch_packages', ROOT/'scripts/sha3/check-sha3-execution.py')
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    _, roots = shared.package(destination, env)
    consumer = destination/'resident-batch-consumer'
    (consumer/'src').mkdir(parents=True)
    patches = '\n'.join(f'{name} = {{ path = {json.dumps(str(path))} }}' for name, path in roots.items())
    dependencies = '\n'.join(
        name + ' = { path = ' + json.dumps(str(roots[name])) + ', default-features=false' +
        (', features=["macos-resident-batch"]' if name.endswith('-std') else '') + ' }'
        for name in ('brynja-crypto-cpu-std', 'brynja-hash-sha2', 'brynja-hash-sha3'))
    (consumer/'Cargo.toml').write_text(
        '[package]\nname="resident-batch-consumer"\nversion="0.0.0"\nedition="2024"\n'
        '[workspace]\n[dependencies]\n' + dependencies + '\n[patch.crates-io]\n' + patches + '\n')
    if oracle.write_consumer(consumer) != 662:
        raise ValueError('oracle population drift')
    run([*cargo, 'generate-lockfile', '--offline'], consumer, env)
    metadata = json.loads(run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env))
    expected = {'resident-batch-consumer', 'brynja-core', 'brynja-hash-core', 'brynja-hash-sha2',
                'brynja-hash-sha3', 'brynja-crypto-cpu', 'brynja-crypto-cpu-std'}
    if {p['name'] for p in metadata['packages']} != expected:
        raise ValueError('packaged dependency closure drift')
    for package in metadata['packages']:
        parent = consumer if package['name'] == 'resident-batch-consumer' else roots[package['name']]
        if package['source'] is not None or Path(package['manifest_path']).resolve() != (parent/'Cargo.toml').resolve():
            raise ValueError('dependency escaped extracted packages')
    for profile, panic in (([], 'unwind'), (['--release'], 'unwind'), (['--release'], 'abort')):
        output = run([*cargo, 'run', '--locked', '--offline', *profile], consumer,
                     dict(env, RUSTFLAGS=env['RUSTFLAGS'] + ' -C panic=' + panic))
        if 'RESIDENT_BATCH_ORACLE: scalar=662; NEON=616; ineligible=46' not in output.splitlines():
            raise ValueError('oracle did not execute')
        print(f'{profile or ["debug"]}; panic={panic}: {output.strip()}', flush=True)
    hosted = roots['brynja-crypto-cpu-std']
    manifest = hosted/'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' + patches + '\n')
    run([*cargo, 'generate-lockfile', '--offline'], hosted, env)
    for profile in ([], ['--release']):
        output = run([*cargo, 'test', '--locked', '--offline', *profile, '--no-default-features',
                      '--features', FEATURE, '--lib', PREFIX, '--', '--nocapture'], hosted, env)
        if 'test result: ok. 6 passed; 0 failed; 0 ignored;' not in output:
            raise ValueError('native batch population changed')
        for token in ('MACOS_RESIDENT_BATCH: Sha256(Some(Neon)); named_differential=512',
                      'MACOS_RESIDENT_BATCH: Sha512(Some(Neon)); named_differential=256',
                      'MACOS_RESIDENT_KECCAK_BATCH: Keccak(Some(Neon)); differential=1024'):
            if token not in output.splitlines():
                raise ValueError('required NEON test missing: ' + token)
        print(output, flush=True)
    output = run([*cargo, 'test', '--locked', '--offline', '--no-default-features',
                  '--features', FEATURE, '--doc', PREFIX], hosted, env)
    if 'test result: ok. 12 passed; 0 failed; 0 ignored;' not in output:
        raise ValueError('ownership doctest population changed')
    print(output, flush=True)
    mutations(cargo, hosted, env)
    print('Packaged resident batches: PASS; development evidence only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-resident-batch-') as directory:
        execute(args.toolchain, Path(directory))
