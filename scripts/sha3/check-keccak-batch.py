#!/usr/bin/env python3
"""Independent bit-level differential for ordinary multibuffer Keccak APIs."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'assurance/keccak-batch/Cargo.toml'


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def corpus():
    fips = load('keccak_batch_fips_oracle', 'check-sha3-bit-differential.py')
    custom = load('keccak_batch_custom_oracle', 'check-cshake-differential.py')
    # Refuse to trust an oracle that fails its pinned official vectors.
    for algorithm, n, out, message, expected in fips.selected_vectors():
        if fips.keccak(algorithm, message, n, out) != expected:
            raise ValueError('NIST oracle cross-check failed')
    algorithms = tuple(fips.RATES) + ('cshake128', 'cshake256')
    lines, expected = [], []
    for case in range(256):
        requests, answers = [], []
        for lane in range(4):
            algorithm = algorithms[(case + lane) % 8]
            rate = fips.RATES.get(algorithm, 168 if algorithm == 'cshake128' else 136)
            sizes = (0, 1, 7, 8, rate * 8 - 5, rate * 8 - 3, rate * 8 - 1,
                     rate * 8, rate * 8 + 1, rate * 16 + 7, 8193)
            m = sizes[(case + lane) % len(sizes)]
            n, s = ((0, 0), (1, 0), (5, 9), (rate * 8 - 32, 7), (2001, 2703))[case % 5] if algorithm.startswith('cshake') else (0, 0)
            o = fips.OUTPUTS.get(algorithm, (0, 1, 7, 8, rate * 8 - 1, rate * 8, rate * 16 + 3)[(case + lane) % 7])
            message, name, customization = (custom.canonical(case * 17 + lane * 3 + i, bits) for i, bits in enumerate((m, n, s)))
            if algorithm.startswith('cshake'):
                result = custom.cshake(rate, custom.byte_bits(message)[:m], custom.byte_bits(name)[:n], custom.byte_bits(customization)[:s], o)
            else:
                result = fips.keccak(algorithm, message, m, o)
            requests.append(f'{algorithm} {m} {n} {s} {o} {message.hex() or "-"} {name.hex() or "-"} {customization.hex() or "-"}')
            answers.append(result.hex())
        if case % 2:
            requests.reverse(); answers.reverse()
        lines.append(';'.join(requests)); expected.append(';'.join(answers))
    return '\n'.join(lines) + '\n', expected


def check(mode, manifest=MANIFEST):
    data, expected = corpus()
    command = ['cargo', '+1.98.1', 'run', '--locked', '--offline', '--release', '--manifest-path', str(manifest), '--', mode]
    result = subprocess.run(command, cwd=ROOT, input=data, text=True, capture_output=True, timeout=300, env=os.environ.copy())
    if result.returncode or result.stdout.splitlines() != expected:
        raise ValueError(f'Keccak batch differential failure: {result.stderr[-4000:]}')
    marker = re.search(r'KECCAK_BATCH_ACCEPTANCE: batches=256; vector_calls=(\d+)', result.stderr)
    if not marker or (mode == 'portable' and int(marker[1])) or (mode == 'required' and not int(marker[1])):
        raise ValueError('missing/incorrect execution counter')
    for invalid in ('x\n', 'shake128 1 0 0 8 80 - -\n', 'sha3-256 0 1 0 256 - 01 -\n',
                    'sha3-256 0 0 0 257 - - -\n', 'shake128 999999999999999999999 0 0 8 - - -\n',
                    'shake128 8 0 0 8 éé - -\n'):
        bad = subprocess.run(command, cwd=ROOT, input=invalid, text=True, capture_output=True, timeout=60)
        if not bad.returncode or bad.stdout or 'panicked' in bad.stderr:
            raise ValueError('malformed request did not fail cleanly')
    print(f'Keccak batch: 1024 independent outputs and six malformed requests PASS; mode={mode}; vector_calls={marker[1]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('portable', 'prefer', 'required'), default='portable')
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    args = parser.parse_args()
    check(args.mode, args.manifest)
