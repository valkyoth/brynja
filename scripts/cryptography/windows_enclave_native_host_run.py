#!/usr/bin/env python3
"""Bounded native host campaign with exact counters; public-data research only."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from datetime import datetime, timezone

IMAGE_SHA256 = '4bb0192b984a45e101e7031fdab8bc9e48667d300397b5344a37d52282288ba5'
VARIANTS = ('normal', 'fail-create', 'fail-load', 'fail-init', 'fail-delete')
MUTANTS = ('early', 'cleanup')


def validate(value, variant):
    normal = variant == 'normal'
    expected = {'result': 0 if normal else 10, 'created': 5 if normal else 1,
                'deleted': 5 if normal else 1, 'calls': 63 if normal else 0,
                'retained': 0, 'cleanup_errors': 0}
    if variant == 'fail-delete':
        expected = {'result': 14, 'created': 1, 'deleted': 0, 'calls': 60,
                    'retained': 1, 'cleanup_errors': 2}
    if variant in MUTANTS:
        count = 3 if variant == 'early' else 4
        expected = {'result': 21, 'created': count, 'deleted': count,
                    'calls': 62 if variant == 'early' else 63, 'retained': 0, 'cleanup_errors': 0}
    if variant not in VARIANTS + MUTANTS or value != expected or any(type(v) is not int for v in value.values()):
        raise ValueError('native host campaign or teardown incomplete')


def run(directory, image):
    if hashlib.sha256(image.read_bytes()).hexdigest() != IMAGE_SHA256:
        raise ValueError('unchanged signed research enclave image required')
    build = json.loads((directory / 'host-build.json').read_text())
    for name, expected in build['archives'].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError('host archive does not match cross-build: ' + name)
    for path, expected in build['source_sha256'].items():
        if path.startswith('assurance/windows-enclave-probe/'):
            if hashlib.sha256((directory / Path(path).name).read_bytes()).hexdigest() != expected:
                raise ValueError('host source does not match cross-build: ' + path)
    records = []
    for variant in VARIANTS + MUTANTS:
        executable = directory / (variant + '.exe')
        result = subprocess.run([str(executable), str(image)], capture_output=True, text=True, timeout=30)
        (directory / (variant + '.stdout')).write_text(result.stdout)
        (directory / (variant + '.stderr')).write_text(result.stderr)
        expected_exit = 97 if variant in MUTANTS else 0
        if result.returncode != expected_exit or len(result.stdout) > 8192 or result.stderr:
            raise RuntimeError(f'{variant} failed: {result.returncode}; {result.stdout[-8192:]} {result.stderr[-8192:]}')
        value = json.loads(result.stdout)
        validate(value, variant)
        records.append({'variant': variant, 'exit_code': result.returncode, 'result': value,
                        'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()})
    return {'synthetic_only': True, 'strict_qualified': False, 'confidential_ingress': False,
            'captured_at': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'image_sha256': IMAGE_SHA256, 'image_source_commit': '53ec2efe1b39d70619b1f0b530f5d1865fc421f8',
            'build': build, 'records': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    record = run(args.directory.resolve(), args.image.resolve())
    (args.directory / 'host-run.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Native Rust-owned public host: PASS; 63 normal-campaign calls; three startup-failure controls; '
          'synthetic deletion failure retained/rejected; two compiled Rust mutants rejected; strict qualification: NO')
