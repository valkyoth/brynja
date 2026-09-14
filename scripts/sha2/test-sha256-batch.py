#!/usr/bin/env python3
"""Batch policy and native sanitizer enforcement regressions without crypto reruns."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import sha256_batch_acceptance as acceptance
import sha256_batch_policy as policy


def reject(call):
    try: call()
    except (ValueError, RuntimeError, FileNotFoundError): return
    raise AssertionError('expected rejection')


def source_regressions():
    with tempfile.TemporaryDirectory(prefix='brynja-batch-policy-') as directory:
        root = Path(directory)
        for name in (*policy.paths(), policy.REVIEW):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / name, destination)
        policy.validate(root)
        for name in ('crates/brynja-crypto-cpu/src/sha256_batch/x86.rs',
                     'crates/brynja-crypto-cpu/src/sha256_batch/arm.rs',
                     'crates/brynja-hash-sha2/src/batch/engine.rs',
                     'crates/brynja-crypto-cpu-std/src/sha256_batch/platform.rs',
                     'scripts/checks.sh', 'scripts/sha2/check-sha256-batch-asan.py'):
            path = root / name; original = path.read_bytes()
            path.write_bytes(original + b'\n// changed\n')
            reject(lambda: policy.validate(root))
            path.write_bytes(original)
        path = root / 'crates/brynja-crypto-cpu/src/sha256_batch/x86.rs'
        original = path.read_bytes()
        path.unlink()
        reject(lambda: policy.validate(root))
        path.symlink_to(policy.ROOT / 'crates/brynja-crypto-cpu/src/sha256_batch/x86.rs')
        reject(lambda: policy.validate(root))
        path.unlink(); path.write_bytes(original)
        path = root / 'crates/brynja-hash-sha2/src/batch/unreviewed.rs'
        path.write_text('// unreviewed source\n')
        reject(lambda: policy.validate(root))
    print('Nine batch hash/removal/symlink/new-source regressions rejected')


def sanitizer_regressions():
    sanitizer = acceptance.load('sha256_batch_asan_test', 'check-sha256-batch-asan.py')
    for parent in ({}, {'ASAN_OPTIONS': 'detect_leaks=0', 'LSAN_OPTIONS': 'exitcode=0',
                        'CARGO_ENCODED_RUSTFLAGS': '--cfg\x1ffake'}):
        for failure in (None, 'LeakSanitizer leak', 'ptrace denied', 'AddressSanitizer overflow'):
            def run(command, **kwargs):
                env = kwargs['env']
                assert env['ASAN_OPTIONS'] == 'detect_leaks=1:halt_on_error=1:exitcode=1'
                assert env['LSAN_OPTIONS'] == 'exitcode=23'
                assert env['BRYNJA_REQUIRE_SHA256_BATCH'] == '1'
                assert env['RUSTFLAGS'] == '-Zsanitizer=address -C target-feature=+avx,+avx2'
                assert 'CARGO_ENCODED_RUSTFLAGS' not in env
                if failure: raise ValueError(failure)
                return SimpleNamespace(stdout='SHA256_BATCH_VECTOR: Avx2; calls=2048')
            with patch.dict(os.environ, parent, clear=True), patch.object(sanitizer.platform, 'system', return_value='Linux'), \
                 patch.object(sanitizer.platform, 'machine', return_value='x86_64'), \
                 patch.object(Path, 'read_text', return_value='flags : avx avx2\n'), \
                 patch.object(sanitizer.acceptance, 'run', side_effect=run):
                if failure: reject(sanitizer.main)
                else: sanitizer.main()
    print('Eight native batch sanitizer clean/hostile-environment/failure cases passed')


if __name__ == '__main__':
    source_regressions()
    sanitizer_regressions()
