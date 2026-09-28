#!/usr/bin/env python3
"""Bounded synthetic enclave stack/TLS inventory; no full-stack qualification."""
import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_lifecycle import Native, InitInfo
from windows_protection_api import Windows
from windows_protection_probe import require

SIZE = 8192
LIMIT = 0x10000000
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/worker.c',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/test-windows-enclave-worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


class WorkerNative(Native):
    def initialize_worker(self, address):
        info = InitInfo(8, 1)
        self.check(self.InitializeEnclave(self.GetCurrentProcess(), address,
                                         c.byref(info), 8, None), 'initialize')
        return info.threads


def checked_inventory(values, base, cleared):
    require(len(values) == 9 and all(type(value) is int and 0 <= value < 1 << 64 for value in values),
            'complete integer worker inventory required')
    require(values[8] == (SIZE if cleared else 0), 'worker clearing status mismatch')
    result = {}
    for name, offset in (('stack', 0), ('tls', 4)):
        address, allocation, region, length = values[offset:offset + 4]
        require(base <= allocation <= region <= address and SIZE <= length <= LIMIT and
                address + SIZE <= region + length <= base + LIMIT, 'worker region outside enclave')
        result[name] = {'address': address, 'allocation_base': allocation,
                        'region_base': region, 'region_size': length, 'checked_marker_bytes': SIZE}
    require(abs(values[0] - values[4]) >= SIZE, 'stack and TLS markers must be distinct')
    return result


def mapped_ranges(host, item, base):
    # Enumerate this allocation only; bounded even for corrupted query results.
    address = item['allocation_base']
    stop = base + LIMIT
    ranges = []
    for _ in range(128):
        info = host.query(address)
        if info.allocation != item['allocation_base']:
            break
        require(info.base == address and 0 < info.size <= stop - address, 'bounded worker mapping')
        ranges.append({'offset': address - item['allocation_base'], 'size': info.size,
                       'state': info.state, 'protect': info.protect})
        address += info.size
    else:
        raise ValueError('worker mapping exceeds descriptor limit')
    require(ranges, 'worker allocation not observed')
    return ranges


def exercise(api, host, image, mutant):
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'worker image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'exactly one initialized worker required')
        routine = api.check(api.GetProcAddress(base, b'PublicWorker'), 'worker export')
        require(api.call(routine, 10) == 0, 'unknown worker operation must reject')
        observations = []
        for _ in range(3):
            result = api.call(routine, 0)
            require(result == (0 if mutant else SIZE), 'synthetic clearing result mismatch')
            item = checked_inventory([api.call(routine, index) for index in range(1, 10)],
                                     base, not mutant)
            for name in ('stack', 'tls'):
                item[name]['allocation_ranges'] = mapped_ranges(host, item[name], base)
            observations.append(item)
        stable = all(item == observations[0] for item in observations)
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    # Addresses are public diagnostic values, but report offsets to reduce noise.
    for item in observations:
        for name in ('stack', 'tls'):
            for field in ('address', 'allocation_base', 'region_base'):
                item[name][field + '_offset'] = item[name].pop(field) - base
    return {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
            'native_machine': api.machine, 'deleted': True, 'initialized_workers': count,
            'mode': 'missing-clear-mutant' if mutant else 'normal',
            'marker_clear_rejected': mutant, 'normal_marker_clear_passed': not mutant,
            'full_worker_cleanup_proved': False, 'stable_observed_layout': stable,
            'calls': observations}


def bounded(command, mutant):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            'bounded clean worker child required: ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and value.get('strict_qualified') is False and
            value.get('production_signed') is False and value.get('synthetic_only') is True
            and value.get('deleted') is True and value.get('full_worker_cleanup_proved') is False,
            'completed nonqualifying worker observation required')
    require(value.get('marker_clear_rejected') is mutant and
            value.get('normal_marker_clear_passed') is (not mutant), 'worker mode mismatch')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--missing-clear-mutant', action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing synthetic image required')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.missing_clear_mutant)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    command = [sys.executable, str(source), str(image), '--child']
    if args.missing_clear_mutant:
        command.append('--missing-clear-mutant')
    record = bounded(command, args.missing_clear_mutant)
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
    require(hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    record.update(schema=1, kind='windows-enclave-worker-inventory-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
