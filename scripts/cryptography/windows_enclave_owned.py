#!/usr/bin/env python3
"""Synthetic owned enclave allocation lifecycle; never strict qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_worker import WorkerNative, LIMIT
from windows_protection_api import Windows
from windows_protection_probe import require, Layout, locked_pages

SIZE, PAGE, RESERVED = 8192, 4096, 65536
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/owned.c',
           'scripts/cryptography/windows_enclave_owned.py',
           'scripts/cryptography/test-windows-enclave-owned.py',
           'scripts/cryptography/windows_enclave_owned_faults.py',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


def geometry(values, base, address):
    require(len(values) == 13 and all(type(v) is int and 0 <= v < 1 << 64 for v in values),
            'complete owned geometry required')
    allocation, data = values[:2]
    require(base <= allocation < allocation + RESERVED <= base + LIMIT and
            allocation % PAGE == 0 and data == allocation + PAGE == address,
            'owned allocation inside enclave required')
    require(values[2:] == [RESERVED, SIZE, PAGE, 0x2000, 0x1000, 4, 0x2000,
                           SIZE, PAGE, RESERVED - PAGE - SIZE, data + SIZE],
            'exact enclave guards and payload required')
    return {'allocation_offset': allocation - base, 'payload_offset': data - base,
            'reserved_bytes': RESERVED, 'payload_bytes': SIZE,
            'leading_reserved_bytes': PAGE, 'trailing_reserved_bytes': RESERVED - PAGE - SIZE}


def snapshot(host, address):
    flags = host.working_set(address, Layout(PAGE, SIZE, RESERVED))
    require(len(flags) == SIZE // PAGE and all(type(f) is int and 0 <= f < 1 << 64 for f in flags),
            'complete owned working-set observation')
    locked_pages(flags)
    return flags


def release_owned(call, host, address, locked):
    """Recover an interrupted public-marker operation before releasing storage.

    A failed cleanup leaves the enclave for outer teardown, never explicit
    unlock of dirty storage. The original operation error remains an error.
    """
    phase = call(6)
    require(phase in (1, 2, 3), 'known owned cleanup phase required')
    if phase == 2:
        require(locked, 'dirty cleanup must retain its lock')
        require(call(3) == SIZE and call(6) == 3, 'failure-path clearing required')
    require(call(5) == SIZE, 'zero verification before release required')
    if locked:
        snapshot(host, address)
        host.unlock(address, SIZE)
    require(call(4) == 1 and call(6) == 0, 'owned release required')


def allocation_cycle(api, host, routine, base, mutant):
    call = lambda operation: api.call(routine, operation)
    for op in (2, 3, 4, 5, 99):
        require(call(op) == 0, 'empty/unknown operation must reject')
    address = call(1)
    require(address != 0, f'owned allocation failed: phase={call(6)}, error={call(7)}')
    shape = geometry([call(i) for i in range(16, 29)], base, address)
    require(call(6) == 1 and call(5) == SIZE, 'allocated zero payload required')
    require(call(1) == 0 and call(3) == 0, 'duplicate allocation/premature clear must reject')
    locked = dirty = False
    before = after = cleared = None
    try:
        host.lock(address, SIZE)
        locked = True
        before = snapshot(host, address)
        # Set before dispatch: a failed call might already have written its marker.
        dirty = True
        require(call(2) == SIZE and call(6) == 2, 'public fill/verification required')
        require(call(4) == 0 and call(5) == 0, 'dirty release/zero query must reject')
        after = snapshot(host, address)
        result = call(3)
        if mutant:
            require(result == 0 and call(6) == 2 and call(4) == 0 and call(5) == 0,
                    'missing-clear mutant must reject clearing and release')
            return dict(shape, before=before, after=after, cleared=None,
                        explicit_unlock=False, explicit_release=False,
                        missing_clear_rejected=True)
        require(result == SIZE and call(6) == 3 and call(5) == SIZE,
                'complete clearing readback required')
        dirty = False
        require(call(2) == 0, 'cleared state must reject refill')
        cleared = snapshot(host, address)
    finally:
        # Expected missing-clear rejection is not an erasure result. Ordinary
        # operation failures still attempt full clearing while the lock is held.
        # Any cleanup failure propagates; outer enclave teardown is not erasure.
        if not (mutant and dirty):
            release_owned(call, host, address, locked)
    for op in (2, 3, 4, 5, 16):
        require(call(op) == 0, 'released state must reject access')
    return dict(shape, before=before, after=after, cleared=cleared,
                explicit_unlock=True, explicit_release=True, missing_clear_rejected=False)


def exercise(api, host, image, mutant):
    require(host.geometry() == (PAGE, RESERVED), 'synthetic x64 page geometry required')
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'owned image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'exactly one initialized worker required')
        routine = api.check(api.GetProcAddress(base, b'PublicOwned'), 'owned export')
        cycles = [allocation_cycle(api, host, routine, base, mutant)]
        if not mutant:
            cycles.append(allocation_cycle(api, host, routine, base, False))
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
            'full_worker_cleanup_proved': False, 'dump_exclusion_verified': False,
            'native_machine': api.machine, 'deleted': True, 'mode':
            'missing-clear-mutant' if mutant else 'normal', 'cycles': cycles}


def bounded(command, mutant, fault=None):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            'bounded clean owned child required: ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in
            ('strict_qualified', 'production_signed', 'full_worker_cleanup_proved', 'dump_exclusion_verified'))
            and value.get('synthetic_only') is True and value.get('deleted') is True,
            'completed nonqualifying owned observation required')
    if fault:
        from windows_enclave_owned_faults import validate_record
        require(not mutant, 'fault and mutant modes are distinct')
        validate_record(value, fault)
        return value
    require(value.get('mode') == ('missing-clear-mutant' if mutant else 'normal'), 'owned mode mismatch')
    cycles = value.get('cycles')
    require(type(cycles) is list and len(cycles) == (1 if mutant else 2), 'exact owned cycle count')
    for item in cycles:
        require(type(item) is dict and item.get('missing_clear_rejected') is mutant and
                item.get('explicit_unlock') is (not mutant) and item.get('explicit_release') is (not mutant),
                'owned clearing/release outcome mismatch')
        for stage in ('before', 'after') if mutant else ('before', 'after', 'cleared'):
            flags = item.get(stage)
            require(type(flags) is list and len(flags) == 2 and
                    all(type(f) is int and 0 <= f < 1 << 64 for f in flags), 'owned page coverage')
            locked_pages(flags)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--missing-clear-mutant', action='store_true')
    from windows_enclave_owned_faults import STAGES
    parser.add_argument('--fault', choices=STAGES)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(not (args.fault and args.missing_clear_mutant), 'fault and mutant modes are distinct')
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing synthetic image required')
    if args.child:
        if args.fault:
            from windows_enclave_owned_faults import exercise as run_fault
            record = run_fault(WorkerNative(), Windows(), image, args.fault)
        else:
            record = exercise(WorkerNative(), Windows(), image, args.missing_clear_mutant)
        print(json.dumps(record))
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
    if args.fault:
        command.extend(['--fault', args.fault])
    record = bounded(command, args.missing_clear_mutant, args.fault)
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
    require(hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    record.update(schema=1, kind='windows-enclave-owned-lifecycle-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
