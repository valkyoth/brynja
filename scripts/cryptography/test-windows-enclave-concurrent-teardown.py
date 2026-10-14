#!/usr/bin/env python3
"""Instrument an isolated copy around real concurrent Entry teardown.

Runs the existing 68-case oracle campaign unchanged, with post-guard mapping and
image-pin assertions. Extra private cases cover unused Drop and host unwind.
This proves resource release, not physical erasure or fatal-path protection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path('crates/brynja-crypto-cpu-std/src/windows_enclave/native/parallel_concurrent/mod.rs')
FIXTURE = Path('assurance/windows-enclave-probe/concurrent_teardown.rs')
CAMPAIGN = 'windows_enclave::parallel_concurrent::tests::native::development_parallel_concurrent_host_campaign'
EXTRA = 'windows_enclave::native::parallel_concurrent::teardown_probe::unopened_drop_and_entry_unwind'
BEFORE = '''        let guard = Entry(self);
        guard.0.run(request, output)'''
AFTER = '''        let base = self.base;
        let result = {
            let guard = Entry(self);
            guard.0.run(request, output)
        };
        teardown_probe::freed(base);
        teardown_probe::pin_released();
        println!("CONCURRENT_TEARDOWN: operation; rejected={}; mapping=free; pin=released", result.is_err());
        result'''


def instrument(source, fixture):
    if source.count(BEFORE) != 1:
        raise ValueError('concurrent Entry instrumentation anchor')
    return source.replace(BEFORE, AFTER) + '\n#[cfg(test)] mod teardown_probe {\n' + fixture + '\n}\n'


def validate(label, code, output):
    if 'running 1 test' not in output:
        raise ValueError('native concurrent test did not run')
    if label == 'skip-teardown':
        if code != 101 or 'panicked at' not in output or 'concurrent enclave mapping retained' not in output:
            raise ValueError('teardown mutant not rejected for retained mapping')
        return
    if code or 'test result: ok. 1 passed; 0 failed; 0 ignored;' not in output:
        raise ValueError('native concurrent test failed')
    if label == 'extra':
        for case in ('unopened-drop', 'entry-unwind'):
            if output.count(f'CONCURRENT_TEARDOWN: {case}; mapping=free; pin=released') != 1:
                raise ValueError('missing concurrent lifetime case')
    elif label == 'campaign':
        passed = output.count('CONCURRENT_TEARDOWN: operation; rejected=false; mapping=free; pin=released')
        rejected = output.count('CONCURRENT_TEARDOWN: operation; rejected=true; mapping=free; pin=released')
        if passed + rejected != 68 or not passed or not rejected or 'PARALLEL_CONCURRENT_HOST: cases=68;' not in output:
            raise ValueError('incomplete real concurrent operation population')
    else:
        raise ValueError('unknown campaign')


def run(args):
    if os.name != 'nt':
        raise RuntimeError('native Windows required; no skipped pass')
    if args.output.exists():
        raise ValueError('refusing to overwrite observation')
    if hashlib.sha256(args.image.read_bytes()).hexdigest() != args.sha256:
        raise ValueError('image hash mismatch')
    env = dict(os.environ)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_TARGET',
                'CARGO_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(key, None)
    env.update(BRYNJA_PARALLEL_CONCURRENT_IMAGE=str(args.image.resolve()),
               BRYNJA_PARALLEL_CONCURRENT_SHA256=args.sha256,
               BRYNJA_PARALLEL_CONCURRENT_VECTORS=str(args.vectors.resolve()), CARGO_INCREMENTAL='0')
    records = []
    with tempfile.TemporaryDirectory(prefix='brynja-concurrent-teardown-') as directory:
        root = Path(directory)
        for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
            shutil.copyfile(ROOT / name, root / name)
        shutil.copytree(ROOT / 'crates', root / 'crates', ignore=shutil.ignore_patterns('target', '__pycache__'))
        source = instrument((ROOT / SOURCE).read_text(), (ROOT / FIXTURE).read_text())
        for profile, label in [('debug', 'campaign'), ('debug', 'extra'),
                               ('release', 'campaign'), ('release', 'extra'), ('release', 'skip-teardown')]:
            changed = source
            if label == 'skip-teardown':
                anchor = '    fn teardown(&mut self) {\n'
                if source.count(anchor) != 1:
                    raise ValueError('missing teardown mutant anchor')
                changed = source.replace(anchor, anchor + '        return;\n')
            (root / SOURCE).write_text(changed)
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '-p',
                       'brynja-crypto-cpu-std', '--all-features', '--lib']
            if profile == 'release':
                command.append('--release')
            command += [EXTRA if label == 'extra' else CAMPAIGN, '--', '--exact', '--nocapture', '--test-threads=1']
            if label != 'extra':
                command.append('--ignored')
            print(f'CONCURRENT_TEARDOWN_STEP: {profile}; {label}', flush=True)
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=1200)
            output = result.stdout + result.stderr
            print(output, flush=True)
            validate(label, result.returncode, output)
            records.append(dict(profile=profile, label=label, exit_code=result.returncode, output=output))
    record = dict(schema=1, runs=records, image_sha256=args.sha256,
                  vectors_sha256=hashlib.sha256(args.vectors.read_bytes()).hexdigest(),
                  source_sha256={str(p): hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                 for p in (SOURCE, FIXTURE, Path(__file__).resolve().relative_to(ROOT))},
                  production_qualified=False, physical_erasure_proven=False, fatal_path_tested=False)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print('Native concurrent mapping/pin teardown: PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--vectors', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
