#!/usr/bin/env python3
"""Synthetic OS-stack-window mechanics, NOT strict/platform qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_worker import WorkerNative, LIMIT
from windows_protection_probe import require

SIZE = 65536
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/window.c',
           'assurance/windows-enclave-probe/window_x64.asm',
           'scripts/cryptography/windows_enclave_window.py',
           'scripts/cryptography/test-windows-enclave-window.py',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')
NONCLAIMS = ('strict_qualified', 'production_signed', 'rust_unwind_qualified',
             'dump_exclusion_verified', 'residency_verified', 'guard_bounds_verified',
             'full_worker_cleanup_proved')


def validate_call(values, base, unwind, mutant):
    require(len(values) == 6 and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
            'complete integer window observation')
    result, low, high, handler, marker, steps = values
    expected = 47 if unwind else 31
    require(steps == expected and result == (0 if mutant else expected | 64),
            'exact window work and whole-window cleanup result')
    require(base <= low < high <= base + LIMIT and high - low == SIZE
            and low % 16 == 0 and high % 16 == 0, 'bounded aligned enclave window')
    require(low <= handler < high and low <= marker <= high - 256
            and not marker <= handler < marker + 256, 'distinct live frames inside window')
    return {'result': result, 'steps': steps, 'window_low_offset': low - base,
            'window_high_offset': high - base, 'handler_offset': handler - base,
            'marker_offset': marker - base}


def exercise(api, image, unwind, mutant):
    require(api.machine == '0x8664', 'native x64 window experiment required')
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'window image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one initialized window worker required')
        routine = api.check(api.GetProcAddress(base, b'PublicWindow'), 'window export')
        require(api.call(routine, 7) == 0, 'unknown window operation must reject')
        calls = []
        for _ in range(3):
            values = [api.call(routine, int(unwind))]
            values.extend(api.call(routine, op) for op in range(2, 7))
            calls.append(validate_call(values, base, unwind, mutant))
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {**dict.fromkeys(NONCLAIMS, False), 'synthetic_only': True,
            'native_machine': api.machine, 'deleted': True, 'unwind': unwind,
            'missing_clear_mutant': mutant, 'calls': calls}


def bounded(command, unwind, mutant):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'window child failed/inconclusive; exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in NONCLAIMS)
            and value.get('synthetic_only') is True and value.get('deleted') is True
            and value.get('native_machine') == '0x8664' and value.get('unwind') is unwind
            and value.get('missing_clear_mutant') is mutant, 'nonqualifying exact window mode')
    calls = value.get('calls')
    require(type(calls) is list and len(calls) == 3, 'three complete window repetitions')
    for call in calls:
        require(type(call) is dict, 'window call record')
        validate_call([call.get(key) for key in ('result', 'window_low_offset',
                      'window_high_offset', 'handler_offset', 'marker_offset', 'steps')],
                      0, unwind, mutant)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--unwind', action='store_true')
    parser.add_argument('--missing-clear-mutant', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing synthetic image required')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), image, args.unwind, args.missing_clear_mutant)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, str(source), str(image), '--child']
    if args.unwind:
        command.append('--unwind')
    if args.missing_clear_mutant:
        command.append('--missing-clear-mutant')
    record = bounded(command, args.unwind, args.missing_clear_mutant)
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
    require(hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    record.update(schema=1, kind='windows-enclave-os-stack-window-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
