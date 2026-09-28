#!/usr/bin/env python3
"""Paired native stack/SEH experiment. No production or Rust-unwind qualification."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from windows_enclave_worker import WorkerNative, LIMIT
from windows_protection_api import Windows
from windows_protection_probe import require, Layout, locked_pages

SIZE, PAGE, RESERVED = 65536, 4096, 131072
MODES = {'os-normal': 10, 'os-unwind': 11, 'owned-normal': 12, 'owned-unwind': 13}
SOURCES = ('assurance/windows-enclave-probe/synthetic.c',
           'assurance/windows-enclave-probe/stack.c',
           'assurance/windows-enclave-probe/stack_x64.asm',
           'scripts/cryptography/windows_enclave_stack.py',
           'scripts/cryptography/test-windows-enclave-stack.py',
           'scripts/cryptography/windows_enclave_worker.py',
           'scripts/cryptography/windows_enclave_lifecycle.py',
           'scripts/cryptography/windows_protection_api.py',
           'scripts/cryptography/windows_protection_probe.py')


def snapshot(host, address):
    flags = host.working_set(address, Layout(PAGE, SIZE, RESERVED))
    require(len(flags) == SIZE // PAGE and all(type(f) is int and 0 <= f < 1 << 64 for f in flags),
            'complete stack page observation required')
    locked_pages(flags)
    return flags


def exercise(api, host, image, mode):
    require(mode in MODES and host.geometry() == (PAGE, 65536) and api.machine == '0x8664',
            'known native x64 stack experiment required')
    base = api.create()
    initialized = False
    try:
        loaded, error = api.load(base, image)
        require(loaded, f'stack image load failed: {error}')
        count = api.initialize_worker(base)
        initialized = True
        require(count == 1, 'one initialized stack worker required')
        routine = api.check(api.GetProcAddress(base, b'PublicStack'), 'stack export')
        call = lambda op: api.call(routine, op)
        require(call(0) == 0, 'unknown stack operation must reject')
        data = call(1)
        require(type(data) is int and base + PAGE <= data <= base + LIMIT - RESERVED + PAGE
                and data % PAGE == 0 and call(2) == 1, 'owned guarded stack geometry required')
        locked = False
        try:
            host.lock(data, SIZE)
            locked = True
            before = snapshot(host, data)
            result = call(MODES[mode])
            expected = 47 if mode.endswith('unwind') else 31
            require(result == expected and call(8) == expected, 'complete stack execution/cleanup markers')
            frame = call(9)
            require(type(frame) is int and base <= frame <= base + LIMIT - 256,
                    'public frame address must be inside enclave')
            in_owned = data <= frame <= data + SIZE - 256
            require(in_owned is mode.startswith('owned'), 'actual frame must match selected stack')
            after = snapshot(host, data)
        finally:
            # Clear from the original stack only AFTER the alternate call left.
            # A failed call/cleanup is never recorded as successful qualification.
            require(call(6) == SIZE, 'full owned stack zero readback required')
            if locked:
                snapshot(host, data)
                host.unlock(data, SIZE)
            require(call(7) == 1 and call(2) == 0, 'owned stack release required')
    finally:
        try:
            if initialized:
                api.terminate(base)
        finally:
            api.delete(base)
    return {'strict_qualified': False, 'production_signed': False, 'synthetic_only': True,
            'rust_unwind_qualified': False, 'dump_exclusion_verified': False,
            'native_machine': api.machine, 'deleted': True, 'mode': mode,
            'markers': result, 'frame_in_owned': in_owned, 'frame_offset': frame - base,
            'payload_offset': data - base, 'payload_bytes': SIZE,
            'locked_before': before, 'locked_after': after,
            'whole_owned_region_cleared': True, 'released': True}


def bounded(command, mode):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 32768,
            f'stack child failed/inconclusive; exit={result.returncode} '
            f'(0x{result.returncode & 0xffffffff:08x}); ' + result.stderr[-2048:])
    value = json.loads(result.stdout)
    require(type(value) is dict and all(value.get(name) is False for name in
            ('strict_qualified', 'production_signed', 'rust_unwind_qualified', 'dump_exclusion_verified'))
            and all(value.get(name) is True for name in
                    ('synthetic_only', 'deleted', 'whole_owned_region_cleared', 'released')),
            'completed nonqualifying stack observation required')
    require(mode in MODES and value.get('mode') == mode and
            value.get('markers') == (47 if mode.endswith('unwind') else 31) and
            value.get('frame_in_owned') is mode.startswith('owned'), 'exact stack mode and outcome')
    for stage in ('locked_before', 'locked_after'):
        flags = value.get(stage)
        require(type(flags) is list and len(flags) == SIZE // PAGE and
                all(type(f) is int and 0 <= f < 1 << 64 for f in flags), 'all stack pages observed')
        locked_pages(flags)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('mode', choices=MODES)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    require(image.suffix.lower() == '.dll' and 0 < image.stat().st_size <= 4 * 1024 * 1024,
            'bounded existing synthetic image required')
    if args.child:
        print(json.dumps(exercise(WorkerNative(), Windows(), image, args.mode)))
        return
    source = Path(__file__).resolve()
    root = source.parents[2]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'clean checkout required')
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    record = bounded([sys.executable, str(source), str(image), args.mode, '--child'], args.mode)
    require(image_hash == hashlib.sha256(image.read_bytes()).hexdigest(), 'image changed')
    require(hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES},
            'sources changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root), 'checkout became dirty')
    record.update(schema=1, kind='windows-enclave-stack-seh-experiment', status='OBSERVATIONS_ONLY',
                  commit=commit, source_sha256=hashes, image_sha256=image_hash,
                  os=sys.getwindowsversion().build)
    print(json.dumps(record, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
