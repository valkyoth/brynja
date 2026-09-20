#!/usr/bin/env python3
"""Development-only threaded coordinator vectors and genuine compiled mutants."""
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import check_callers as audit


def golden_vectors():
    path = audit.ROOT / 'scripts/parallelhash/check-parallelhash-differential.py'
    spec = importlib.util.spec_from_file_location('parallelhash', path)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    expected = {form + strength: oracle.parallel_hash(rate, oracle.oracle.byte_bits(bytes(range(128))),
                8, [], 256, bool(form)).hex()
                for form in ('', 'xof') for strength, rate in (('128', 168), ('256', 136))}
    source = (audit.FIXTURE / 'tests/threaded_vectors/mod.rs').read_text()
    rows = re.findall(r'\(\s*"((?:xof)?(?:128|256))",\s*"([0-9a-f]{64})"', source)
    if len(rows) != 4 or dict(rows) != expected:
        raise ValueError('threaded coordinator independent vector drift')
    print('Threaded coordinator vectors: four identities independently regenerated', flush=True)


def mutations():
    audit.require_native_avx2(Path('/proc/cpuinfo').read_text())
    with tempfile.TemporaryDirectory(prefix='brynja-threaded-callers-') as temporary:
        fixture = Path(temporary) / 'fixture'
        shutil.copytree(audit.FIXTURE, fixture, ignore=shutil.ignore_patterns('target'))
        manifest = fixture / 'Cargo.toml'
        manifest.write_text(manifest.read_text().replace('../../../crates/', str(audit.ROOT / 'crates') + '/'))
        source = fixture / 'src/threaded.rs'
        original = source.read_text()
        cases = (
            ('drop($secret);', 'core::mem::forget($secret);', 1),
            ('bytes != $secret.expose()', 'bytes != bytes', 1),
            ('report.leaves == leaves as u128', 'true', 1),
            ('report.accelerated_leaves == accelerated', 'true', 1),
            ('report.thread_width == jobs.min(2)', 'true', 1),
            ('block_size: 8', 'block_size: 16', 1),
            ('token.cancel();', '/* missing cancellation */', 1),
            ('api::Preference::RequireStatic', 'api::Preference::Portable', 3),
        )
        env = audit.clean_environment()
        env['CARGO_TARGET_DIR'] = str(Path(temporary) / 'target')
        env['RUSTFLAGS'] = '-C target-feature=+avx2'
        for profile in ([], ['--release']):
            command = ['cargo', '+1.98.1', 'test', '--locked', '--offline', '--manifest-path',
                       str(manifest), '--features', 'threaded', '--test', 'audit', *profile]
            control = audit.run(command, env)
            if '6 passed; 0 failed; 0 ignored;' not in control:
                raise ValueError('threaded coordinator controls did not execute')
            for before, after, count in cases:
                if original.count(before) != count:
                    raise ValueError('ambiguous threaded mutation: ' + before)
                try:
                    source.write_text(original.replace(before, after))
                    result = subprocess.run(command, cwd=audit.ROOT, env=env, text=True,
                                            capture_output=True, timeout=180, check=False)
                    if result.returncode == 0 or 'test result: FAILED.' not in result.stdout:
                        raise ValueError('threaded mutant did not compile and fail: ' + before + result.stderr[-3000:])
                finally:
                    source.write_text(original)
    print('Threaded coordinator compiled regressions: 16 rejected in debug/release', flush=True)


if __name__ == '__main__':
    golden_vectors()
    mutations()
