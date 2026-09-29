#!/usr/bin/env python3
"""Bounded metadata-only Rust host campaign; public-data research only."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from datetime import datetime, timezone

IMAGE_SHA256 = '97cd72cf14508361603bc0f453f545362bd23af638f8b300a608ee1a685d9470'
VARIANTS = ('normal', 'fail-create', 'fail-load', 'fail-init', 'fail-delete')
MUTANTS = ('early', 'cleanup', 'copy-proof')


def validate(value, variant):
    normal = variant == 'normal'
    expected = {'result': 0 if normal else 10, 'created': 6 if normal else 1,
                'deleted': 6 if normal else 1, 'calls': 64 if normal else 0,
                'retained': 0, 'cleanup_errors': 0}
    if variant == 'fail-delete':
        expected = {'result': 14, 'created': 1, 'deleted': 0, 'calls': 60,
                    'retained': 1, 'cleanup_errors': 2}
    if variant in MUTANTS:
        count = {'early': 3, 'cleanup': 4, 'copy-proof': 5}[variant]
        expected = {'result': 21, 'created': count, 'deleted': count,
                    'calls': {'early': 62, 'cleanup': 63, 'copy-proof': 64}[variant], 'retained': 0, 'cleanup_errors': 0}
    if variant not in VARIANTS + MUTANTS or value != expected or any(type(v) is not int for v in value.values()):
        raise ValueError('native host campaign or teardown incomplete')


def run(directory, image):
    root = Path(__file__).resolve().parents[2]
    def checkout():
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=root):
            raise ValueError('clean source checkout required')
        return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    commit = checkout()
    if hashlib.sha256(image.read_bytes()).hexdigest() != IMAGE_SHA256:
        raise ValueError('unchanged signed research enclave image required')
    build = json.loads((directory / 'host-build.json').read_text())
    for name, expected in build['archives'].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError('host archive does not match cross-build: ' + name)
    for path, expected in build['generated_sha256'].items():
        if hashlib.sha256((directory / path).read_bytes()).hexdigest() != expected:
            raise ValueError('generated host source does not match cross-build: ' + path)
    for path, expected in build['source_sha256'].items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
            raise ValueError('source checkout does not match cross-build: ' + path)
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
    if commit != checkout():
        raise ValueError('capture checkout changed')
    for path, expected in build['source_sha256'].items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
            raise ValueError('capture source changed: ' + path)
    return {'commit': commit, 'synthetic_only': True, 'strict_qualified': False, 'confidential_ingress': False,
            'captured_at': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'image_sha256': IMAGE_SHA256, 'image_source_commit': '33816b76ee1fe2d59d0274ad5b2c991b8feb7566',
            'build': build, 'records': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    record = run(args.directory.resolve(), args.image.resolve())
    (args.directory / 'host-run.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Native Rust-owned borrowed-input host: PASS; 64 normal-campaign calls; three startup-failure controls; '
          'synthetic deletion failure retained/rejected; two Rust mutants and one native copy-proof mutant rejected; strict qualification: NO')
