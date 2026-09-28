#!/usr/bin/env python3
"""Run a synthetic image in a bounded child; no signing or boot-policy changes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_lifecycle import Native, exercise
from windows_protection_probe import require


def bounded(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr, 'enclave child failed: ' + result.stderr[-2048:])
    require(0 < len(result.stdout) <= 4096, 'bounded child output required')
    value = json.loads(result.stdout)
    require(isinstance(value, dict) and value.get('strict_qualified') is False
            and value.get('production_signed') is False and value.get('synthetic_only') is True
            and value.get('deleted') is True, 'nonqualifying completed child required')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=('unsigned', 'signed'))
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded synthetic DLL required')
    if args.child:
        print(json.dumps(exercise(Native(), image, args.mode == 'unsigned'), sort_keys=True))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    value = bounded([sys.executable, str(source), str(image), args.mode, '--child'])
    require(hashlib.sha256(image.read_bytes()).hexdigest() == before, 'image changed during experiment')
    value.update(schema=1, kind='windows-enclave-lifecycle-experiment', status='OBSERVATIONS_ONLY',
                 commit=commit, image_sha256=before, mode=args.mode,
                 source_sha256={p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in (
                     'scripts/cryptography/check-windows-enclave-lifecycle.py',
                     'scripts/cryptography/windows_enclave_lifecycle.py',
                     'scripts/cryptography/windows_protection_api.py',
                     'scripts/cryptography/windows_protection_probe.py',
                     'assurance/windows-enclave-probe/synthetic.c')})
    print(json.dumps(value, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
