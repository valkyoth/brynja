#!/usr/bin/env python3
"""Real development-enclave teardown, not OS mocks or page-erasure proof.

Copies the workspace into temporary storage and appends a test-only private
module. Shipping production functions are unchanged except in explicit mutant
runs. No development hook is added to the published crate. Requires a reviewed
development-signed scalar KMAC image and native Windows x64 VBS support.
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
NATIVE = Path('crates/brynja-crypto-cpu-std/src/windows_enclave/native')
FIXTURE = Path('scripts/cryptography/windows_enclave_native_teardown.rs')
TEST = 'windows_enclave::native::lifecycle::native_teardown::real_post_failure_teardown'


def validate_result(label, code, output):
    if 'running 1 test' not in output:
        raise AssertionError('native test did not execute')
    if label == 'normal':
        expected = {
            f'NATIVE_TEARDOWN: {case}; explicit={explicit}; mapping=free; pin=released'
            for case in ('normal', 'bad-version', 'bad-sequence', 'bad-receipt', 'unwind')
            for explicit in ('false', 'true')
        }
        expected.add('NATIVE_TEARDOWN: fresh-owner=PASS; cases=10; erasure=NOT_PROVEN')
        # The first marker shares libtest's "test ..." line under --nocapture.
        markers = [line[line.index('NATIVE_TEARDOWN: '):]
                   for line in output.splitlines() if 'NATIVE_TEARDOWN: ' in line]
        if code != 0 or len(markers) != len(expected) or set(markers) != expected:
            raise AssertionError('native campaign failed or incomplete')
    else:
        reason = {'skip-destruction': 'enclave mapping retained',
                  'fake-destruction': 'enclave mapping retained',
                  'clear-quarantine': 'destruction must not clear quarantine'}[label]
        if code != 101 or 'panicked at' not in output or reason not in output:
            raise AssertionError('mutant was not rejected by its expected assertion')


def run(args):
    if os.name != 'nt':
        raise RuntimeError('requires native Windows; refusing a skipped pass')
    digest = hashlib.sha256(args.image.read_bytes()).hexdigest()
    if digest != args.sha256:
        raise ValueError('image hash mismatch')
    if args.output.exists():
        raise ValueError('refusing to overwrite an observation')
    env = dict(os.environ)
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(key, None)
    env.update(BRYNJA_TEARDOWN_IMAGE=str(args.image.resolve()),
               BRYNJA_TEARDOWN_SHA256=digest, CARGO_INCREMENTAL='0')
    records = []
    with tempfile.TemporaryDirectory(prefix='brynja-native-teardown-') as directory:
        root = Path(directory)
        for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
            shutil.copyfile(ROOT / name, root / name)
        shutil.copytree(ROOT / 'crates', root / 'crates',
                        ignore=shutil.ignore_patterns('target', '__pycache__'))
        path = root / NATIVE / 'lifecycle.rs'
        source = path.read_text()
        fixture = (ROOT / FIXTURE).read_text()
        suffix = '\n#[cfg(test)] mod native_teardown {\n' + fixture + '\n}\n'
        variants = [
            ('normal', source),
            ('skip-destruction', source.replace('&& self.destroy_quarantined().is_err()', '')),
            ('fake-destruction', source.replace(
                'sys::destroy(self.base, self.initialized, &mut self.terminated)?;',
                'let _ = (self.base, self.initialized, &mut self.terminated);')),
            ('clear-quarantine', source.replace('self.slot = 0;',
                                                'self.uncertain = false; self.slot = 0;')),
        ]
        for label, changed in variants:
            if label != 'normal' and changed == source:
                raise AssertionError('missing mutant anchor: ' + label)
            path.write_text(changed + suffix)
            for profile in (['debug', 'release'] if label == 'normal' else ['release']):
                command = ['cargo', '+' + args.toolchain, 'test', '--locked', '--offline',
                           '-p', 'brynja-crypto-cpu-std', '--all-features', '--lib']
                if profile == 'release':
                    command.append('--release')
                command += [TEST, '--', '--exact', '--nocapture', '--test-threads=1']
                print(f'NATIVE_TEARDOWN_STEP: {label}; {profile}', flush=True)
                result = subprocess.run(command, cwd=root, env=env, capture_output=True,
                                        text=True, timeout=1200)
                output = result.stdout + result.stderr
                print(output, flush=True)
                validate_result(label, result.returncode, output)
                records.append(dict(variant=label, profile=profile,
                                    exit_code=result.returncode, output=output))
    observation = dict(schema=1, image_sha256=digest, rust_toolchain=args.toolchain,
                       runs=records, production_qualified=False, independent_retest=False,
                       physical_page_erasure_proven=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(observation, indent=2) + '\n')
    print('Native teardown: debug/release ten cases each; three mutants rejected; PASS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', default='1.98.1')
    run(parser.parse_args())
