#!/usr/bin/env python3
"""Extracted native Mac ParallelHash development checks; not release qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import macos_resident_parallel_oracle as oracle

ROOT = Path(__file__).resolve().parents[2]
FEATURE = 'macos-resident-acceleration'
PREFIX = 'macos_resident::'


def readme_example(hosted, consumer):
    text = (hosted / 'README.md').read_text()
    example = text.split('```rust\n', 1)[1].split('```', 1)[0]
    if 'use brynja_hash_parallel_std::macos_resident::{Algorithm, Limits, Session};' not in example:
        raise ValueError('resident README example missing or reordered')
    (consumer / 'ResidentReadme.md').write_text('```rust\n' + example + '```\n')
    (consumer / 'src/lib.rs').write_text(
        '#[doc = include_str!("../ResidentReadme.md")] pub struct ResidentReadme;\n')


def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=600)
    if result.returncode:
        raise RuntimeError(f'{command}\n{result.stdout[-4000:]}\n{result.stderr[-6000:]}')
    return result.stdout


def mutations(cargo, hosted, env):
    cases = [
        ('mod.rs', 'if !self.keep {', 'if self.keep {',
         'tests::native::failures_after_leaf_root_and_output_clear_and_allow_reuse'),
        ('mod.rs', 'self.cvs.clear();', 'core::hint::black_box(&mut self.cvs);',
         'tests::native::whole_owned_capacity_clears_even_before_admission'),
        ('mod.rs', 'self.output.clear();', 'core::hint::black_box(&mut self.output);',
         'tests::native::malformed_budget_cancelled_and_forgotten_outputs_clear'),
        ('compiled.rs', 'if matches!(result, Ok(()) | Err(Error::Cancelled | Error::InvalidBits)) {', 'if true {',
         'compiled::tests::native::worker_root_faults_join_clear_and_classify_reuse'),
        ('resource/darwin/thread/group.rs', 'slot.mapping.clear();',
         'core::hint::black_box(&mut slot.mapping);',
         'resource::darwin::thread::group::tests::concurrent_workers_use_disjoint_resident_stacks_and_borrowed_outputs'),
    ]
    for name, old, new, test in cases:
        path = hosted / 'src/macos_resident' / name
        original = path.read_text()
        if old not in original:
            raise ValueError('mutation anchor missing: ' + name)
        command = [*cargo, 'test', '--locked', '--offline', '--release',
                   '--no-default-features', '--features', FEATURE, '--lib',
                   PREFIX + test, '--', '--exact']
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
    print(f'Resident ParallelHash compiled mutants: {len(cases)} rejected', flush=True)


def execute(toolchain, destination):
    cargo = ['cargo', '+' + toolchain]
    identity = subprocess.check_output(['rustc', '+' + toolchain, '-vV'], text=True)
    if 'host: aarch64-apple-darwin' not in identity.splitlines():
        raise ValueError('requires native Apple Silicon macOS')
    print(identity, flush=True)
    env = dict(os.environ, RUSTUP_TOOLCHAIN=toolchain, CARGO_TARGET_DIR=str(destination/'target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(name, None)
    env['RUSTFLAGS'] = '-C target-feature=+neon,+sha3'
    sys.path.insert(0, str(ROOT/'scripts/sha3'))
    spec = importlib.util.spec_from_file_location('batch_packages', ROOT/'scripts/sha3/check-sha3-execution.py')
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    shared.PACKAGES = (*shared.PACKAGES, 'brynja-hash-parallel', 'brynja-hash-parallel-std')
    _, roots = shared.package(destination, env)
    consumer = destination/'resident-parallel-consumer'
    (consumer/'src').mkdir(parents=True)
    patches = '\n'.join(f'{name} = {{ path = {json.dumps(str(path))} }}' for name, path in roots.items())
    dependencies = '\n'.join(
        name + ' = { path = ' + json.dumps(str(roots[name])) + ', default-features=false' +
        (', features=["macos-resident-acceleration"]' if name.endswith('-std') else '') + ' }'
        for name in ('brynja-hash-parallel-std',))
    (consumer/'Cargo.toml').write_text(
        '[package]\nname="resident-parallel-consumer"\nversion="0.0.0"\nedition="2024"\n'
        '[workspace]\n[features]\ndefault=["macos-resident"]\nmacos-resident=[]\n'
        '[dependencies]\n' + dependencies + '\n[patch.crates-io]\n' + patches + '\n')
    if oracle.write_consumer(consumer) != 274:
        raise ValueError('oracle population drift')
    readme_example(roots['brynja-hash-parallel-std'], consumer)
    run([*cargo, 'generate-lockfile', '--offline'], consumer, env)
    docs = run([*cargo, 'test', '--locked', '--offline', '--doc'], consumer, env)
    if 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in docs:
        raise ValueError('resident README example did not execute: ' + docs)
    print(docs, flush=True)
    metadata = json.loads(run([*cargo, 'metadata', '--locked', '--offline', '--format-version', '1'], consumer, env))
    expected = {'resident-parallel-consumer', 'brynja-core', 'brynja-hash-core', 'brynja-hash-parallel',
                'brynja-hash-sha3', 'brynja-crypto-cpu', 'brynja-hash-parallel-std'}
    if {p['name'] for p in metadata['packages']} != expected:
        raise ValueError('packaged dependency closure drift')
    for package in metadata['packages']:
        parent = consumer if package['name'] == 'resident-parallel-consumer' else roots[package['name']]
        if package['source'] is not None or Path(package['manifest_path']).resolve() != (parent/'Cargo.toml').resolve():
            raise ValueError('dependency escaped extracted packages')
    for profile, panic in (([], 'unwind'), (['--release'], 'unwind'), (['--release'], 'abort')):
        output = run([*cargo, 'run', '--locked', '--offline', *profile], consumer,
                     dict(env, RUSTFLAGS=env['RUSTFLAGS'] + ' -C panic=' + panic))
        if 'RESIDENT_PARALLELHASH_ORACLE: scalar=548; Arm=548; NEON=548; workers=1,3' not in output.splitlines():
            raise ValueError('oracle did not execute')
        print(f'{profile or ["debug"]}; panic={panic}: {output.strip()}', flush=True)
    hosted = roots['brynja-hash-parallel-std']
    manifest = hosted/'Cargo.toml'
    manifest.write_text(manifest.read_text() + '\n[workspace]\n[patch.crates-io]\n' + patches + '\n')
    run([*cargo, 'generate-lockfile', '--offline'], hosted, env)
    for profile in ([], ['--release']):
        output = run([*cargo, 'test', '--locked', '--offline', *profile, '--no-default-features',
                      '--features', FEATURE, '--lib', PREFIX, '--', '--nocapture'], hosted, env)
        if 'test result: ok. 26 passed; 0 failed; 0 ignored;' not in output:
            raise ValueError('native batch population changed')
        for token in ('MACOS_RESIDENT_PARALLELHASH: Single(ArmKeccak); differential=288',
                      'MACOS_RESIDENT_PARALLELHASH: Batch(Neon); differential=288'):
            if token not in output.splitlines():
                raise ValueError('required NEON test missing: ' + token)
        print(output, flush=True)
    output = run([*cargo, 'test', '--locked', '--offline', '--no-default-features',
                  '--features', FEATURE, '--doc', PREFIX], hosted, env)
    if 'test result: ok. 17 passed; 0 failed; 0 ignored;' not in output:
        raise ValueError('ownership doctest population changed')
    print(output, flush=True)
    mutations(cargo, hosted, env)
    print('Packaged resident ParallelHash: PASS; development evidence only', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default='1.99.1')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='brynja-resident-parallel-') as directory:
        execute(args.toolchain, Path(directory))
